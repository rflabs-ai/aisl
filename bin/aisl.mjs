#!/usr/bin/env node
/**
 * Launcher for the `aisl` CLI.
 *
 * The runtime is TypeScript and there is no build step: Node strips types at
 * load, which `engines` pins to >=22.18 (the version where that became the
 * default). This file exists only so `npm i -g aisl` produces a command, and so
 * the entry point stays stable if a compile step is ever added.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// pathToFileURL, not a bare path: a Windows drive letter is not a valid ESM
// specifier, and this file has to work on every platform npm installs to.
await import(pathToFileURL(join(here, '..', 'src', 'cli.ts')).href);
