#!/usr/bin/env node
/**
 * Launcher for the `aisl` CLI.
 *
 * Launches the compiled entry in `dist/cli.js`. The source tree stays
 * buildless for development (`node src/cli.ts demo`), but Node refuses type
 * stripping inside `node_modules`
 * (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so the published package
 * ships JavaScript. `npm run build` is what produces it.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// pathToFileURL, not a bare path: a Windows drive letter is not a valid ESM
// specifier, and this file has to work on every platform npm installs to.
await import(pathToFileURL(join(here, '..', 'dist', 'cli.js')).href);
