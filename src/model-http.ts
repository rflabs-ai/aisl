/**
 * HTTP model provider adapter (ADR-005): OpenAI-compatible chat-completions.
 *
 * TRANSPORT ONLY — not a trust boundary. The provider is assumed compromised,
 * exactly like every other model: output is parsed through the whitelist parser
 * in ./model.ts and the session's guard still owns output policy. What this
 * module adds is the egress gate, evaluated BEFORE any bytes leave:
 *   1. Egress classification vs. the configured ceiling (default-deny above;
 *      there is no configuration that turns this check off).
 *   2. A PDP decision for `model.invoke` on the synthetic provider resource,
 *      so no capability issued = no egress.
 * The API key is resolved by the caller from the secret broker and lives only
 * in the Authorization header: never in an event, an error message, or
 * telemetry. Error messages never include provider response bodies.
 */

import {
  classificationRank,
  type Classification,
  type DenyReason,
  type Principal,
} from './domain.ts';
import { type EventLog } from './events.ts';
import { ModelOutputError, type ModelInput, type ModelOutput, type ModelPort, parseModelOutput } from './model.ts';
import { type AuthorizationService } from './pdp.ts';
import { type ResourceRegistry } from './registry.ts';
import { deriveClassification } from './runtime.ts';

export class ModelEgressDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ModelEgressDeniedError';
  }
}

export class ModelProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ModelProviderError';
  }
}

/** Structural telemetry sink: any object with this shape satisfies it. */
export interface ModelCallTelemetry {
  emit(name: string, attrs: Readonly<Record<string, unknown>>): void;
}

export interface HttpModelConfig {
  readonly id: string;
  /** The model name sent in the provider request body. */
  readonly providerModel: string;
  readonly baseUrl: string;
  /** RESOLVED by the caller from the secret broker. Header only — never logged, never in events or errors. */
  readonly apiKey: string;
  /** The acting agent; the adapter egresses on its behalf and under its authority. */
  readonly principal: Principal;
  readonly authorization: AuthorizationService;
  readonly registry: ResourceRegistry;
  readonly eventLog: EventLog;
  /** Egress classification ceiling. Derived classification above this is refused before the PDP is consulted. */
  readonly ceiling: Classification;
  /** Synthetic provider resource the PDP gates `model.invoke` on. */
  readonly providerResourceId: string;
  /** Same content map the session holds — input to egress classification. */
  readonly content?: ReadonlyMap<string, string>;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly retryBackoffMs?: number;
  readonly telemetry?: ModelCallTelemetry;
}

const SYSTEM_INSTRUCTION =
  'You are the reasoning backend for a high-assurance agent runtime. Reply ONLY with minified JSON of shape '
  + '{"text":string,"requests":[{"action":string,"resourceId":string,"justification"?:string}]}. '
  + 'No prose, no markdown fences, no extra fields.';

type Egress = 'allow' | 'refused-above-ceiling' | 'pdp-denied' | 'provider-error' | 'parse-error';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function contentOfProviderResponse(body: unknown): string {
  if (typeof body !== 'object' || body === null) throw new ModelOutputError('provider response body is not an object');
  const choices = (body as Record<string, unknown>).choices;
  if (!Array.isArray(choices)) throw new ModelOutputError('provider response has no choices array');
  const first = choices[0];
  if (typeof first !== 'object' || first === null) throw new ModelOutputError('provider response has no choices');
  const message = (first as Record<string, unknown>).message;
  if (typeof message !== 'object' || message === null) throw new ModelOutputError('provider choice has no message');
  const content = (message as Record<string, unknown>).content;
  if (typeof content !== 'string') throw new ModelOutputError('provider message content is not a string');
  return content;
}

function usageOfProviderResponse(body: unknown): { prompt: number | undefined; completion: number | undefined } {
  if (typeof body !== 'object' || body === null) return { prompt: undefined, completion: undefined };
  const usage = (body as Record<string, unknown>).usage;
  if (typeof usage !== 'object' || usage === null) return { prompt: undefined, completion: undefined };
  const u = usage as Record<string, unknown>;
  return {
    prompt: typeof u.prompt_tokens === 'number' ? u.prompt_tokens : undefined,
    completion: typeof u.completion_tokens === 'number' ? u.completion_tokens : undefined,
  };
}

export class HttpModelAdapter implements ModelPort {
  readonly id: string;
  private readonly cfg: HttpModelConfig;
  private readonly doFetch: typeof fetch;

  constructor(cfg: HttpModelConfig) {
    if (!cfg.id || !cfg.providerModel || !cfg.baseUrl) {
      throw new Error('HttpModelAdapter requires id, providerModel and baseUrl');
    }
    if (!cfg.apiKey) throw new Error('HttpModelAdapter requires an apiKey resolved from the secret broker');
    if (!cfg.providerResourceId) throw new Error('HttpModelAdapter requires providerResourceId');
    this.cfg = cfg;
    this.id = cfg.id;
    this.doFetch = cfg.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async complete(input: ModelInput): Promise<ModelOutput> {
    const startedAt = Date.now();

    // 1. Egress classification — a security measure, never simplified away.
    const derived = deriveClassification({
      capabilities: this.cfg.authorization.capabilitiesFor(this.cfg.principal.id),
      content: this.cfg.content,
      registry: this.cfg.registry,
      requestedResourceIds: input.contextResourceIds ?? [],
    });

    // 2. Ceiling check: default-deny. Refuse BEFORE the PDP consult and before
    // any fetch, so content above the ceiling never leaves the process.
    if (classificationRank(derived) > classificationRank(this.cfg.ceiling)) {
      this.record({
        startedAt,
        decision: 'deny',
        denyReason: 'classification-ceiling',
        egress: 'refused-above-ceiling',
        classification: derived,
      });
      throw new ModelEgressDeniedError(
        `model egress refused: derived classification '${derived}' exceeds ceiling '${this.cfg.ceiling}'`,
      );
    }

    // 3. PDP consult: no capability for the provider resource = no egress.
    const decision = this.cfg.authorization.authorize({
      principal: this.cfg.principal,
      action: 'model.invoke',
      resourceId: this.cfg.providerResourceId,
    });
    if (decision.decision === 'deny') {
      this.record({
        startedAt,
        decision: 'deny',
        denyReason: decision.denyReason,
        policyId: decision.policyId,
        egress: 'pdp-denied',
        classification: derived,
      });
      throw new ModelEgressDeniedError(`model egress denied by policy: ${decision.reason}`);
    }

    // 4. Send with bounded retry.
    const { res, attempts } = await this.send(input, derived, startedAt);
    if (res.status < 200 || res.status >= 300) {
      // Non-retryable HTTP failure: fail closed without reading the body.
      const detail = `HTTP ${res.status}`;
      this.record({
        startedAt,
        decision: 'allow',
        egress: 'provider-error',
        classification: derived,
        error: detail,
        attempts,
      });
      throw new ModelProviderError(`provider call failed after ${attempts} attempt(s): ${detail}`);
    }

    // 5. Parse: hostile-input rule — the whitelist parser, always.
    let output: ModelOutput;
    let usagePromptTokens: number | undefined;
    let usageCompletionTokens: number | undefined;
    try {
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        throw new ModelOutputError('provider response body is not valid JSON');
      }
      const content = contentOfProviderResponse(body);
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(content);
      } catch {
        // Fixed message on purpose: JSON.parse errors quote the offending text,
        // and the provider can echo context (canaries) back in malformed output.
        throw new ModelOutputError('provider content is not valid JSON');
      }
      const outputParsed = parseModelOutput(parsedJson);
      const usage = usageOfProviderResponse(body);
      usagePromptTokens = usage.prompt;
      usageCompletionTokens = usage.completion;
      output = outputParsed;
    } catch (error) {
      if (error instanceof ModelOutputError) {
        this.record({
          startedAt,
          decision: 'allow',
          egress: 'parse-error',
          classification: derived,
          error: error.message,
          attempts,
        });
      }
      throw error;
    }

    // 6. Success: event + telemetry, then return. No post-processing — the
    // session's guard owns output policy.
    this.record({
      startedAt,
      decision: 'allow',
      egress: 'allow',
      classification: derived,
      attempts,
      usagePromptTokens,
      usageCompletionTokens,
    });
    return output;
  }

  /**
   * Bounded retry: network rejection, HTTP 429 and HTTP 5xx are retryable;
   * everything else returns immediately for the caller to fail closed.
   */
  private async send(
    input: ModelInput,
    classification: Classification,
    startedAt: number,
  ): Promise<{ res: Response; attempts: number }> {
    const maxAttempts = (this.cfg.maxRetries ?? 2) + 1;
    const backoff = this.cfg.retryBackoffMs ?? 250;
    const body = JSON.stringify({
      model: this.cfg.providerModel,
      messages: [
        { role: 'system', content: SYSTEM_INSTRUCTION },
        { role: 'user', content: JSON.stringify({ task: input.prompt, context: input.context }) },
      ],
    });
    let lastFailure: { kind: 'network' } | { kind: 'status'; status: number } = { kind: 'network' };

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const res = await this.doFetch(`${this.cfg.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: { authorization: `Bearer ${this.cfg.apiKey}`, 'content-type': 'application/json' },
          body,
          signal: AbortSignal.timeout(this.cfg.timeoutMs ?? 30_000),
        });
        if (res.status === 429 || res.status >= 500) {
          lastFailure = { kind: 'status', status: res.status };
        } else {
          return { res, attempts: attempt };
        }
      } catch {
        // Any rejection is a transport failure (TypeError / AbortError / timeout).
        // Fails closed after bounded retries; never surfaces the request.
        lastFailure = { kind: 'network' };
      }
      if (attempt < maxAttempts) await sleep(backoff * 2 ** (attempt - 1));
    }

    const detail = lastFailure.kind === 'status' ? `HTTP ${lastFailure.status}` : 'network error';
    this.record({
      startedAt,
      decision: 'allow',
      egress: 'provider-error',
      classification,
      error: detail,
      attempts: maxAttempts,
    });
    throw new ModelProviderError(`provider call failed after ${maxAttempts} attempt(s): ${detail}`);
  }

  /** Exactly one `model.call` event + one telemetry emit per outcome. */
  private record(args: {
    readonly startedAt: number;
    readonly decision: 'allow' | 'deny';
    readonly denyReason?: DenyReason;
    readonly policyId?: string;
    readonly egress: Egress;
    readonly classification: Classification;
    readonly error?: string;
    readonly attempts?: number;
    readonly usagePromptTokens?: number;
    readonly usageCompletionTokens?: number;
  }): void {
    const durationMs = Date.now() - args.startedAt;
    const result: 'success' | 'denied' | 'error' =
      args.decision === 'deny' ? 'denied' : args.error !== undefined ? 'error' : 'success';
    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.principal.id,
      actorKind: this.cfg.principal.kind,
      action: 'model.call',
      resourceId: this.cfg.providerResourceId,
      decision: args.decision,
      denyReason: args.denyReason,
      policyId: args.policyId,
      result,
      metadata: {
        phase: 'model',
        model: this.cfg.id,
        providerModel: this.cfg.providerModel,
        durationMs,
        classification: args.classification,
        ceiling: this.cfg.ceiling,
        egress: args.egress,
        ...(args.denyReason !== undefined ? { denyReason: args.denyReason } : {}),
        ...(args.policyId !== undefined ? { policyId: args.policyId } : {}),
        ...(args.usagePromptTokens !== undefined ? { usagePromptTokens: args.usagePromptTokens } : {}),
        ...(args.usageCompletionTokens !== undefined
          ? { usageCompletionTokens: args.usageCompletionTokens }
          : {}),
        ...(args.error !== undefined ? { error: args.error } : {}),
      },
    });
    this.cfg.telemetry?.emit('model.call', {
      decision: args.decision,
      result,
      egress: args.egress,
      model: this.cfg.id,
      providerModel: this.cfg.providerModel,
      durationMs,
      classification: args.classification,
      ceiling: this.cfg.ceiling,
      ...(args.denyReason !== undefined ? { denyReason: args.denyReason } : {}),
      ...(args.usagePromptTokens !== undefined ? { usagePromptTokens: args.usagePromptTokens } : {}),
      ...(args.usageCompletionTokens !== undefined
        ? { usageCompletionTokens: args.usageCompletionTokens }
        : {}),
      ...(args.error !== undefined ? { error: args.error } : {}),
    });
  }
}