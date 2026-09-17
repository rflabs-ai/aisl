/**
 * M13 CommandCheck tests: allowlisted argv-array command execution with
 * artifact-via-stdin, no shell, and configuration-time refusal.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { CommandCheck } from '../src/check-command.ts';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';

const NODE = process.execPath;
const ALLOW = [NODE];

function ctxWith(output: unknown) {
  return { resourceId: 'doc:x', action: 'write', params: {}, output };
}

describe('CommandCheck', () => {
  test('exit 0 passes', () => {
    const check = new CommandCheck({ name: 'noop', argv: [NODE, '-e', 'process.exit(0)'], allowlist: ALLOW });
    const r = check.run(ctxWith('anything'));
    assert.equal(r.result, 'pass');
    assert.equal(r.evidence, 'exit=0');
  });

  test('nonzero exit fails', () => {
    const check = new CommandCheck({ name: 'lint', argv: [NODE, '-e', 'process.exit(3)'], allowlist: ALLOW });
    const r = check.run(ctxWith('anything'));
    assert.equal(r.result, 'fail');
    assert.equal(r.evidence, 'exit=3');
  });

  test('artifact reaches the command via stdin only', () => {
    const script = `let d='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>d+=c).on('end',()=>process.exit(d.includes('EXPECTED-TOKEN')?0:1));`;
    const check = new CommandCheck({ name: 'scan', argv: [NODE, '-e', script], allowlist: ALLOW });
    assert.equal(check.run(ctxWith('artifact EXPECTED-TOKEN body')).result, 'pass');
    assert.equal(check.run(ctxWith('artifact without the token')).result, 'fail');
  });

  test('metacharacters in the artifact are data, not instructions', () => {
    const payload = 'x; process.exit(0); x';
    const script = `let d='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>d+=c).on('end',()=>process.exit(d === 'x; process.exit(0); x' ? 0 : 1));`;
    const check = new CommandCheck({ name: 'echo', argv: [NODE, '-e', script], allowlist: ALLOW });
    assert.equal(check.run(ctxWith(payload)).result, 'pass', 'payload arrived byte-exact via stdin');
    const blind = new CommandCheck({ name: 'blind', argv: [NODE, '-e', 'process.exit(1)'], allowlist: ALLOW });
    assert.equal(blind.run(ctxWith(payload)).result, 'fail', 'payload as argv text must not execute');
  });

  test('timeout fails fast', () => {
    const check = new CommandCheck({
      name: 'hang',
      argv: [NODE, '-e', 'setInterval(()=>{},1000)'],
      allowlist: ALLOW,
      timeoutMs: 300,
    });
    const r = check.run(ctxWith('x'));
    assert.equal(r.result, 'fail');
    assert.match(r.evidence, /timed out after 300ms/);
  });

  test('non-allowlisted command is refused at configuration time', () => {
    assert.throws(() => new CommandCheck({ name: 'evil', argv: ['evil.exe', 'arg'], allowlist: ALLOW }), /not allowlisted/);
    assert.throws(() => new CommandCheck({ name: 'noallow', argv: [NODE, '-e', 'process.exit(0)'], allowlist: [] }), /allowlist/);
  });

  test('empty argv is refused at configuration time', () => {
    assert.throws(
      () => new CommandCheck({ name: 'empty', argv: [] as unknown as [string, ...string[]], allowlist: ALLOW }),
      /argv/,
    );
  });

  test('command that does not exist yields error result', () => {
    const check = new CommandCheck({ name: 'ghost', argv: ['definitely-not-a-real-command-xyz'], allowlist: ['definitely-not-a-real-command-xyz'] });
    const r = check.run(ctxWith('x'));
    assert.equal(r.result, 'error');
    assert.equal(r.evidence, 'command not found');
  });

  test('artifact content never appears in evidence or command fields', () => {
    const secret = 'service/ CLASSIFIED-CANARY-777';
    const check = new CommandCheck({ name: 'lint', argv: [NODE, '-e', 'process.exit(1)'], allowlist: ALLOW });
    const r = check.run(ctxWith(secret));
    const rendered = JSON.stringify({ command: check.command, evidence: r.evidence, test: check.name });
    assert.equal(rendered.includes('CLASSIFIED-CANARY-777'), false);
  });
});

describe('CommandCheck integration (no new authority)', () => {
  test('check results flow through runVerifications and a failure marks the step errored', async () => {
    const world = testWorld();
    const pass = new CommandCheck({ name: 'lint-ok', argv: [NODE, '-e', 'process.exit(0)'], allowlist: ALLOW });
    const fail = new CommandCheck({ name: 'lint-bad', argv: [NODE, '-e', 'process.exit(1)'], allowlist: ALLOW });
    const session = world.session(
      new ScriptedModel('scripted-v1', [{ text: 't', requests: [{ action: 'read', resourceId: world.resources.repoA! }] }]),
      { checks: [pass, fail] },
    );
    const trace = await session.run([]);
    const step = trace.steps[0]!;
    assert.equal(step.decision.decision, 'allow');
    assert.deepEqual(step.verifications.map((v) => v.result), ['pass', 'fail']);
    assert.deepEqual(step.verifications.map((v) => v.command), [JSON.stringify([NODE, '-e', 'process.exit(0)']), JSON.stringify([NODE, '-e', 'process.exit(1)'])]);
    const stepEvent = world.eventLog
      .all()
      .filter((e) => e.action === 'read' && (e.metadata as { sessionId?: string }).sessionId === session.sessionId)
      .at(-1)!;
    assert.equal(stepEvent.result, 'error');
    const rendered = JSON.stringify(stepEvent.metadata);
    assert.equal(rendered.includes('service/'), false, 'artifact content must not leak into the verification record');
  });
});
