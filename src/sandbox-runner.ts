/**
 * Self-contained runner for the container sandbox.
 *
 * Reads tool name + context from process.argv[2] (a JSON file path),
 * executes the serialized invoke function, writes result JSON to stdout.
 *
 * No tool implementations are hardcoded here — the host sends the function
 * source in the context JSON, so the image stays generic.
 */

import { readFileSync } from 'node:fs';

const arg = process.argv[2];
if (!arg) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no context path provided' }));
  process.exit(1);
}

const raw = readFileSync(arg, 'utf8');
const ctx = JSON.parse(raw) as { tool: string; fnSource: string; context: Record<string, unknown> };

if (!ctx.fnSource) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no fnSource provided' }));
  process.exit(1);
}

try {
  const handler = new Function('ctx', ctx.fnSource);
  const result = handler(ctx.context);
  process.stdout.write(JSON.stringify({ ok: true, value: result }));
} catch (err) {
  process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }));
  process.exit(1);
}