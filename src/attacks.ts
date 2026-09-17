/**
 * Adversarial harness: declarative attack cases loaded from `security-attacks/`.
 *
 * Each case states the attack and the *expected* outcome. The harness reports
 * whether the platform actually produced that outcome. A case that expects a
 * denial but gets an allow fails the suite, loudly.
 *
 * Cases can be routed through three gates: the agent session, the network
 * gateway, or the secret broker — so the gates are attacked directly, not just
 * through the model.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ActionRequest, Decision } from './domain.ts';
import { type World, documentFor } from './scenario.ts';
import { compromisedModel } from './model.ts';

export type Gate = 'session' | 'network' | 'secret';

export interface AttackCase {
  readonly id: string;
  readonly class: string;
  readonly name: string;
  readonly via?: Gate;
  /** Where the malicious instruction is planted, if anywhere. */
  readonly injectedInto?: string;
  readonly injectedContent?: string;
  readonly requests: readonly ActionRequest[];
  readonly expect: 'denied' | 'allowed';
  readonly note?: string;
}

export function loadAttackCorpus(dir: string): readonly AttackCase[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')) as AttackCase);
}

export interface Outcome {
  readonly request: ActionRequest;
  readonly decision: Decision;
  readonly reason: string;
  readonly denyReason?: string;
  readonly executed: boolean;
  readonly output?: unknown;
}

export interface AttackResult {
  readonly testCase: AttackCase;
  readonly outcomes: readonly Outcome[];
  readonly passed: boolean;
  readonly injectionSignals: readonly string[];
}

function hostOf(resourceId: string): string {
  return resourceId.startsWith('net:') ? resourceId.slice(4) : resourceId;
}

export async function runAttackCase(world: World, testCase: AttackCase): Promise<AttackResult> {
  const via: Gate = testCase.via ?? 'session';
  const data =
    testCase.injectedInto && testCase.injectedContent !== undefined
      ? [documentFor(world, testCase.injectedInto, testCase.injectedContent)]
      : [];

  let outcomes: Outcome[] = [];
  let injectionSignals: string[] = [];

  if (via === 'session') {
    const trace = await world.session(compromisedModel(testCase.requests)).run(data, testCase.name);
    injectionSignals = trace.injectionSignals.flatMap((s) => s.signals);
    outcomes = trace.steps.map((step) => ({
      request: step.request,
      decision: step.decision.decision,
      reason: step.decision.reason,
      denyReason: step.decision.denyReason,
      executed: step.executed,
      output: step.output,
    }));
  } else if (via === 'network') {
    outcomes = testCase.requests.map((r) => {
      const res = world.network.request({ principal: world.agent, host: hostOf(r.resourceId) });
      return {
        request: r,
        decision: res.allowed ? 'allow' : 'deny',
        reason: res.reason,
        // The MVP gateway opens no socket, so an allow is recorded but inert.
        executed: false,
      };
    });
  } else {
    outcomes = testCase.requests.map((r) => {
      const res = world.secrets.request({ principal: world.agent, secretId: r.resourceId });
      return {
        request: r,
        decision: res.allowed ? 'allow' : 'deny',
        reason: res.reason,
        executed: false,
        output: res.value === undefined ? undefined : '[value withheld in evidence]',
      };
    });
  }

  const passed =
    outcomes.length > 0 &&
    outcomes.every((o) =>
      testCase.expect === 'denied'
        ? o.decision === 'deny' && !o.executed
        : o.decision === 'allow' && (via === 'session' ? o.executed : true),
    );

  return { testCase, outcomes, passed, injectionSignals };
}

export async function runAttackCorpus(world: World, dir: string): Promise<readonly AttackResult[]> {
  return Promise.all(loadAttackCorpus(dir).map((c) => runAttackCase(world, c)));
}
