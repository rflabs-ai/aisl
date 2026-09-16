/**
 * Verification plane.
 *
 * Authorization answers "may this happen?". Verification answers "did it stay
 * inside the lines?". A capability that permits reading `repo-a` does not permit
 * reading `customer-b`, and we check the result rather than trusting the request.
 */

import { randomUUID } from 'node:crypto';

export type VerificationResult = 'pass' | 'fail' | 'error';

export interface Verification {
  readonly id: string;
  readonly subject: string;
  readonly test: string;
  readonly command: string;
  readonly result: VerificationResult;
  readonly evidence: string;
  readonly timestamp: number;
}

export interface CheckContext {
  readonly resourceId: string;
  readonly action: string;
  readonly params: Readonly<Record<string, unknown>>;
  readonly output: unknown;
}

export interface Check {
  readonly name: string;
  /** Reproducible description of the check, recorded with the result. */
  readonly command: string;
  run(ctx: CheckContext): { readonly result: VerificationResult; readonly evidence: string };
}

export function runVerifications(
  subject: string,
  checks: readonly Check[],
  ctx: CheckContext,
  timestamp = Date.now(),
): readonly Verification[] {
  return checks.map((check) => {
    let result: VerificationResult;
    let evidence: string;
    try {
      const r = check.run(ctx);
      result = r.result;
      evidence = r.evidence;
    } catch (error) {
      result = 'error';
      evidence = (error as Error).message;
    }
    return {
      id: randomUUID(),
      subject,
      test: check.name,
      command: check.command,
      result,
      evidence,
      timestamp,
    };
  });
}

export function secretLeakCheck(secretValues: readonly string[], label = 'secret-leak'): Check {
  return {
    name: label,
    command: `assert output contains none of ${secretValues.length} registered secret value(s)`,
    run(ctx) {
      const rendered = typeof ctx.output === 'string' ? ctx.output : JSON.stringify(ctx.output ?? null);
      const leaked = secretValues.filter((v) => v.length > 0 && rendered.includes(v));
      return leaked.length === 0
        ? { result: 'pass', evidence: 'no registered secret value appears in output' }
        : { result: 'fail', evidence: `output contains ${leaked.length} secret value(s)` };
    },
  };
}

export function scopeCheck(expectedResourceId: string): Check {
  return {
    name: 'scope-containment',
    command: `assert execution touched only ${expectedResourceId}`,
    run(ctx) {
      return ctx.resourceId === expectedResourceId
        ? { result: 'pass', evidence: `resource ${ctx.resourceId} in scope` }
        : { result: 'fail', evidence: `execution reached out-of-scope resource ${ctx.resourceId}` };
    },
  };
}
