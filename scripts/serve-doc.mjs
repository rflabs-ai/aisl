#!/usr/bin/env node
/**
 * Serve one HTML document on the local network, for reading on a phone.
 *
 *   node scripts/serve-doc.mjs docs/pilot.html 8080
 *
 * Binds 0.0.0.0 so another device on the same Wi-Fi can open it. That is the
 * whole point, and it is also the whole risk: anything on your network can read
 * the page. Stop it (Ctrl+C) when you are done. It serves exactly one file and
 * ignores the request path.
 */

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const file = resolve(process.argv[2] ?? 'docs/pilot.html');
const port = Number(process.argv[3] ?? 8080);

let html;
try {
  html = readFileSync(file);
} catch {
  console.error(`cannot read ${file}`);
  process.exit(1);
}

const server = createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(html);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`serving ${file}`);
  console.log(`  local: http://localhost:${port}`);
  console.log(`  LAN:   http://<your-lan-ip>:${port}   (Ctrl+C to stop)`);
});
