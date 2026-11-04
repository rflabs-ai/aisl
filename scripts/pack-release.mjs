#!/usr/bin/env node
/**
 * Release packaging check (safety ticket 02).
 *
 *   node scripts/pack-release.mjs            # verify only
 *   node scripts/pack-release.mjs --write    # verify, then write dist/aisl-<version>.zip
 *
 * Refuses to produce an archive if the tracked tree contains a token-shaped
 * string or a local absolute path. The claim is verifiable by the recipient:
 * the script prints the entry count, the byte count, and the forbidden-path
 * result, and `git archive` packs exactly the tracked tree, so anything
 * gitignored (`.scratch/`, `.env`, build keys) cannot leak in by accident.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const write = process.argv.includes('--write');

const FORBIDDEN = [
  { name: 'openai-style key', re: /sk-[A-Za-z0-9]{20,}/ },
  { name: 'github token', re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: 'anthropic-style key', re: /syt_[A-Za-z0-9_-]{20,}/ },
  { name: 'aws key id', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'local absolute path', re: /[A-Za-z]:\\Users\\[A-Za-z0-9._-]+/ },
  { name: 'macOS home path', re: /\/Users\/[A-Za-z0-9._-]+\/(?:projects|repos|src)\// },
];

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' });
const files = git('ls-files').split('\n').filter(Boolean);

const findings = [];
let bytes = 0;
let scanned = 0;

for (const file of files) {
  let stat;
  try {
    stat = statSync(file);
  } catch {
    continue;
  }
  bytes += stat.size;
  if (stat.size > 1_000_000) continue; // not a source file

  let text;
  try {
    const raw = readFileSync(file);
    if (raw.subarray(0, 8192).includes(0)) continue; // binary
    text = raw.toString('utf8');
  } catch {
    continue;
  }
  scanned += 1;

  for (const rule of FORBIDDEN) {
    const match = rule.re.exec(text);
    if (match) {
      const line = text.slice(0, match.index).split('\n').length;
      findings.push(`${file}:${line}  ${rule.name}`);
    }
  }
}

const version = JSON.parse(readFileSync('package.json', 'utf8')).version;

console.log(`entries   ${files.length}`);
console.log(`scanned   ${scanned} (binary and >1MB skipped)`);
console.log(`bytes     ${bytes}`);
console.log(`forbidden ${findings.length === 0 ? 'none' : findings.length + ' finding(s)'}`);

if (findings.length > 0) {
  for (const f of findings.slice(0, 20)) console.error(`  ${f}`);
  console.error('\nrefusing to package: fix or exclude the paths above');
  process.exit(1);
}

if (write) {
  mkdirSync('dist', { recursive: true });
  const out = join('dist', `aisl-${version}.zip`);
  execFileSync('git', ['archive', '--format=zip', `--output=${out}`, 'HEAD'], { stdio: 'inherit' });
  console.log(`wrote     ${out}`);
} else {
  console.log('ok        (pass --write to produce dist/aisl-<version>.zip)');
}
