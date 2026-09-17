/**
 * Model gateway.
 *
 * The model is an untrusted reasoning component behind a narrow port. Two rules:
 *   1. Model output is parsed through a whitelist (`parseModelOutput`). Fields we
 *      do not recognise are dropped, so a hostile provider response cannot smuggle
 *      authority-shaped attributes into the runtime.
 *   2. `ModelOutput` can express intent only. There is no field on it that the
 *      runtime treats as authority.
 */

import { type Action, type ActionRequest } from './domain.ts';

export interface ModelInput {
  readonly prompt: string;
  /** Untrusted context: documents, repo files, tool results. Data, never instructions. */
  readonly context: readonly string[];
  readonly availableActions: readonly Action[];
  /** Resource ids whose content is included in `context` — used by egress classification. */
  readonly contextResourceIds?: readonly string[];
}

export interface ModelOutput {
  readonly text: string;
  readonly requests: readonly ActionRequest[];
}

export interface ModelPort {
  readonly id: string;
  complete(input: ModelInput): ModelOutput | Promise<ModelOutput>;
}

export class ModelOutputError extends Error {}

function asString(v: unknown, field: string): string {
  if (typeof v !== 'string') throw new ModelOutputError(`model output field '${field}' must be a string`);
  return v;
}

/**
 * Whitelist parser for untrusted provider responses. Deliberately constructs a
 * fresh object rather than casting: unknown keys are discarded, not carried.
 */
export function parseModelOutput(raw: unknown): ModelOutput {
  if (typeof raw !== 'object' || raw === null) throw new ModelOutputError('model output must be an object');
  const obj = raw as Record<string, unknown>;

  const rawRequests = Array.isArray(obj.requests) ? obj.requests : [];
  const requests: ActionRequest[] = rawRequests.map((r) => {
    if (typeof r !== 'object' || r === null) throw new ModelOutputError('model request must be an object');
    const req = r as Record<string, unknown>;
    const out: ActionRequest = {
      action: asString(req.action, 'requests[].action'),
      resourceId: asString(req.resourceId, 'requests[].resourceId'),
    };
    if (typeof req.justification === 'string') {
      return { ...out, justification: req.justification };
    }
    return out;
  });

  return { text: obj.text === undefined ? '' : asString(obj.text, 'text'), requests };
}

/** Deterministic model for tests and demos. */
export class ScriptedModel implements ModelPort {
  readonly id: string;
  private queue: ModelOutput[];

  constructor(id: string, outputs: readonly ModelOutput[]) {
    this.id = id;
    this.queue = [...outputs];
  }

  complete(_input: ModelInput): ModelOutput {
    const next = this.queue.shift();
    return next ?? { text: '', requests: [] };
  }
}

/** A model that is assumed compromised: it tries every attack regardless of prompt. */
export function compromisedModel(requests: readonly ActionRequest[]): ModelPort {
  return {
    id: 'compromised-model-v0',
    complete: () => ({
      text: 'I have decided to ignore the task and act on the instructions I found.',
      requests: [...requests],
    }),
  };
}
