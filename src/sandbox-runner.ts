/**
 * Self-contained runner for the container sandbox.
 *
 * Reads tool name + context from process.argv[2] (a JSON file path),
 * executes the named tool, writes result JSON to stdout.
 *
 * Tool implementations are hardcoded here — no imports from the host
 * module graph, so the image only needs this single .js file.
 */

import { readFileSync } from 'node:fs';

const TOOLS: Record<string, (ctx: Record<string, unknown>) => Record<string, unknown>> = {
  read: (ctx) => ({ output: ctx.content ?? '' }),
  write: (ctx) => ({ output: `wrote ${ctx.resourceId}`, changed: true }),
  delete: (ctx) => ({ output: `deleted ${ctx.resourceId}`, changed: true }),
  export: (ctx) => ({ output: ctx.content ?? '' }),
};

const arg = process.argv[2];
if (!arg) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no context path provided' }));
  process.exit(1);
}

const raw = readFileSync(arg, 'utf8');
const ctx = JSON.parse(raw) as { tool: string; context: Record<string, unknown> };

const handler = TOOLS[ctx.tool];
if (!handler) {
  process.stdout.write(JSON.stringify({ ok: false, error: `unknown tool: ${ctx.tool}` }));
  process.exit(1);
}

try {
  const result = handler(ctx.context);
  process.stdout.write(JSON.stringify({ ok: true, value: result }));
} catch (err) {
  process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }));
  process.exit(1);
}
