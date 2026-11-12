/**
 * H10 — Signed builds and supply-chain security (ADR-024).
 *
 * Four controls, all in code, zero new dependencies:
 *   1. SBOM generated from the lockfile and diffed against a committed
 *      baseline — the SBOM diff IS the dependency review gate.
 *   2. Pinning with hash verification: exact versions, sha512 integrity for
 *      every lockfile package, registry-pinned resolved URLs, and a
 *      code-enforced allowlist of admitted runtime dependencies.
 *   3. A signed build manifest (SLSA-shaped provenance for a source-artifact
 *      project): Ed25519 over the canonical manifest binding treeDigest,
 *      sbomDigest, gitHead, and the gate result. `build sign` runs the full
 *      gate and refuses to sign on any failure; `build verify` recomputes
 *      and verifies fail-closed.
 *   4. The gate is code, not convention: every violation names the dep and
 *      the rule; every refusal names the reason.
 *
 * The artifact of record is the SOURCE TREE: TypeScript ships as source, so
 * the build input set is every git-tracked file except `artifacts/*`
 * (outputs). The tree digest uses `git ls-files -s` blob SHAs — committed
 * content hashes — so the same commit verifies identically on any platform
 * (CRLF checkouts cannot break or forge a manifest).
 *
 * ponytail: signing key custody is an env var (ADR-008 posture) and there is
 * no CI/transparency log in-repo — HSM custody, `npm run supply-chain` in a
 * real pipeline, and manifest publication (H11) are the upgrade paths when a
 * release pipeline or a second maintainer exists.
 */

import { spawnSync } from 'node:child_process';
import { createHash, sign as cryptoSign, verify as cryptoVerify, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson } from './domain.ts';

export const SBOM_FORMAT = 'ASL-SBOM';
export const SBOM_VERSION = 1;

/** The runtime dependency allowlist, with the ADR that admits each one. */
export const ADMITTED_RUNTIME_DEPS: Readonly<Record<string, string>> = {
  jose: 'ADR-015',
  postgres: 'ADR-018',
};

/** Registry base every lockfile `resolved` URL must carry. */
const REGISTRY_BASE = 'https://registry.npmjs.org/';

/** Exact-version pin: `1.2.3`, `1.2.3-beta.1`, `1.2.3+build`. No ranges. */
const EXACT_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;

/** Generated outputs — recorded, digested separately, never inputs to the tree digest. */
const TREE_EXCLUDED_PREFIXES: readonly string[] = ['artifacts/'];
const TREE_EXCLUDED_FILES: readonly string[] = ['benchmarks/results.json'];

export interface PackageManifest {
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
}

export interface SbomEntry {
  readonly name: string;
  readonly version: string;
  readonly resolved: string;
  readonly integrity: string;
  /** Named directly in package.json (runtime or dev). */
  readonly direct: boolean;
  /** dev-only package (lockfile flag or devDependencies membership). */
  readonly dev: boolean;
}

export interface AslSbom {
  readonly format: typeof SBOM_FORMAT;
  readonly version: typeof SBOM_VERSION;
  readonly packages: readonly SbomEntry[];
}

export interface SupplyChainDrift {
  readonly changed: boolean;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  readonly versionChanged: readonly string[];
}

export interface SupplyChainGateResult {
  readonly ok: boolean;
  readonly violations: readonly string[];
  readonly drift: SupplyChainDrift;
  readonly sbom: AslSbom;
  readonly digest: string;
}

interface LockfileEntry {
  version?: unknown;
  resolved?: unknown;
  integrity?: unknown;
  dev?: unknown;
}

function manifestDepNames(manifest: PackageManifest, which: 'dependencies' | 'devDependencies'): readonly string[] {
  return Object.keys(manifest[which] ?? {});
}

function directProdNames(manifest: PackageManifest): readonly string[] {
  return manifestDepNames(manifest, 'dependencies');
}

/** Narrow a parsed package.json: string-valued dep records only; malformed input throws (the gate catches). */
function readPackageManifest(repoRoot: string): PackageManifest {
  const parsed: unknown = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
  if (typeof parsed !== 'object' || parsed === null) throw new Error('package.json is not an object');
  const obj = parsed as { dependencies?: unknown; devDependencies?: unknown };
  const deps = (record: unknown): Record<string, string> | undefined => {
    if (typeof record !== 'object' || record === null) return undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(record)) if (typeof v === 'string') out[k] = v;
    return out;
  };
  return { dependencies: deps(obj.dependencies), devDependencies: deps(obj.devDependencies) };
}

function readLockfile(repoRoot: string): unknown {
  // npm never publishes package-lock.json, so a packaged CLI ships the same
  // content as npm-shrinkwrap.json (the one lockfile npm does publish).
  for (const name of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const path = join(repoRoot, name);
    if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8'));
  }
  throw new Error('no lockfile found: expected package-lock.json or npm-shrinkwrap.json');
}

function sbomOf(sbom: unknown): sbom is AslSbom {
  return (
    typeof sbom === 'object' && sbom !== null
    && (sbom as { format?: unknown }).format === SBOM_FORMAT
    && Array.isArray((sbom as { packages?: unknown }).packages)
  );
}

/** Deterministic SBOM over the lockfile + `package.json` at repoRoot. */
export function computeSbom(repoRoot: string): AslSbom {
  const manifest = readPackageManifest(repoRoot);
  const lockfile: unknown = readLockfile(repoRoot);
  const packages = (typeof lockfile === 'object' && lockfile !== null ? (lockfile as { packages?: unknown }).packages : undefined);
  if (typeof packages !== 'object' || packages === null) throw new Error('lockfile has no packages map');
  const prod = new Set(directProdNames(manifest));
  const dev = new Set(manifestDepNames(manifest, 'devDependencies'));

  const entries: SbomEntry[] = [];
  for (const [key, entryRaw] of Object.entries(packages)) {
    if (key === '' || !key.startsWith('node_modules/')) continue;
    const name = key.slice('node_modules/'.length);
    if (name.includes('/node_modules/')) continue; // nested copies: the hoisted entry is the inventory
    const entry = (entryRaw ?? {}) as LockfileEntry;
    entries.push({
      name,
      version: typeof entry.version === 'string' ? entry.version : '',
      resolved: typeof entry.resolved === 'string' ? entry.resolved : '',
      integrity: typeof entry.integrity === 'string' ? entry.integrity : '',
      direct: prod.has(name) || dev.has(name),
      dev: entry.dev === true || dev.has(name),
    });
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { format: SBOM_FORMAT, version: SBOM_VERSION, packages: entries };
}

/** `sha256-<hex>` over the canonical SBOM — the Claim 26 primitive. */
export function sbomDigest(sbom: AslSbom): string {
  return `sha256-${createHash('sha256').update(canonicalJson(sbom)).digest('hex')}`;
}

export function checkPins(manifest: PackageManifest): readonly string[] {
  const violations: string[] = [];
  for (const which of ['dependencies', 'devDependencies'] as const) {
    for (const [name, range] of Object.entries(manifest[which] ?? {})) {
      if (!EXACT_VERSION.test(range)) {
        violations.push(`package.json: '${name}' uses range '${range}' — exact version pin required (H10/ADR-015 item 3)`);
      }
    }
  }
  return violations;
}

/**
 * Hash verification over the lockfile: every package entry carries a sha512
 * integrity value, resolves to the registry, and (for direct deps) matches
 * the exact pin. Malformed input is a violation, never a throw.
 */
export function checkLockfileIntegrity(lockfile: unknown, manifest: PackageManifest): readonly string[] {
  const violations: string[] = [];
  if (typeof lockfile !== 'object' || lockfile === null) {
    return ['lockfile is not an object — refuse (fail closed)'];
  }
  const packages = (lockfile as { packages?: unknown }).packages;
  if (typeof packages !== 'object' || packages === null) {
    return ['lockfile has no packages map — refuse (fail closed)'];
  }
  for (const [key, entry] of Object.entries(packages as Record<string, unknown>)) {
    if (key === '') continue;
    const e = (entry ?? {}) as LockfileEntry;
    const integrity = typeof e.integrity === 'string' ? e.integrity : '';
    if (!integrity.startsWith('sha512-')) {
      violations.push(`lockfile ${key}: no sha512 integrity hash — hash verification required (H10)`);
    }
    const resolved = typeof e.resolved === 'string' ? e.resolved : '';
    if (!resolved.startsWith(REGISTRY_BASE)) {
      violations.push(`lockfile ${key}: resolved URL '${resolved || '(none)'}' is not the npm registry (${REGISTRY_BASE}) — registry pinning required (H10)`);
    }
    const name = key.startsWith('node_modules/') ? key.slice('node_modules/'.length) : '';
    if (name && directProdNames(manifest).includes(name)) {
      const pin = manifest.dependencies?.[name];
      if (typeof e.version === 'string' && pin !== undefined && e.version !== pin) {
        violations.push(`lockfile ${key}: version ${e.version} does not match the exact pin for '${name}' (${pin}) — regenerate the lockfile`);
      }
    }
  }
  return violations;
}

export function checkRuntimeAllowlist(manifest: PackageManifest): readonly string[] {
  const violations: string[] = [];
  const admitted = Object.entries(ADMITTED_RUNTIME_DEPS).map(([n, adr]) => `${n} — ${adr}`).join(', ');
  for (const name of directProdNames(manifest)) {
    if (!(name in ADMITTED_RUNTIME_DEPS)) {
      violations.push(`runtime dep '${name}' is not admitted (admitted: ${admitted}) — write the admission ADR and update ADMITTED_RUNTIME_DEPS in src/supply-chain.ts, then regenerate the SBOM (ADR-015 policy)`);
    }
  }
  return violations;
}

/**
 * The gate: regenerate the SBOM, diff against the committed baseline, and run
 * every check. `ok === false` means the commit/release is blocked until the
 * baseline is regenerated (with the admission ADR named) or the violation is
 * fixed.
 */
export function runSupplyChainGate(opts: { repoRoot: string; baselineSbomPath: string }): SupplyChainGateResult {
  const violations: string[] = [];
  const emptyDrift: SupplyChainDrift = { changed: false, added: [], removed: [], versionChanged: [] };
  let sbom: AslSbom = { format: SBOM_FORMAT, version: SBOM_VERSION, packages: [] };
  try {
    sbom = computeSbom(opts.repoRoot);
    const manifest = readPackageManifest(opts.repoRoot);
    violations.push(...checkPins(manifest), ...checkRuntimeAllowlist(manifest), ...checkLockfileIntegrity(readLockfile(opts.repoRoot), manifest));
  } catch (err) {
    violations.push(`supply-chain gate cannot read the manifest/lockfile: ${(err as Error).message}`);
    return { ok: false, violations, drift: emptyDrift, sbom, digest: '' };
  }

  let baseline: unknown;
  try {
    baseline = JSON.parse(readFileSync(opts.baselineSbomPath, 'utf8'));
  } catch {
    violations.push(`baseline SBOM missing at ${opts.baselineSbomPath} — generate it (npm run sbom -- --write) and commit it as the review artifact (H10)`);
    return { ok: false, violations, drift: emptyDrift, sbom, digest: sbomDigest(sbom) };
  }
  if (!sbomOf(baseline)) {
    violations.push(`baseline SBOM at ${opts.baselineSbomPath} is not an ${SBOM_FORMAT} v${SBOM_VERSION} document — regenerate it (npm run sbom -- --write)`);
    return { ok: false, violations, drift: emptyDrift, sbom, digest: sbomDigest(sbom) };
  }

  const drift = diffSbom(baseline, sbom);
  return {
    ok: violations.length === 0 && !drift.changed,
    violations,
    drift,
    sbom,
    digest: sbomDigest(sbom),
  };
}

function diffSbom(baseline: AslSbom, computed: AslSbom): SupplyChainDrift {
  const baseEntries = new Map(baseline.packages.map((p) => [p.name, p]));
  const computedEntries = new Map(computed.packages.map((p) => [p.name, p]));
  const added = [...computedEntries.keys()].filter((n) => !baseEntries.has(n)).sort();
  const removed = [...baseEntries.keys()].filter((n) => !computedEntries.has(n)).sort();
  const versionChanged = [...baseEntries.keys()]
    .filter((n) => computedEntries.has(n) && canonicalJson(baseEntries.get(n)) !== canonicalJson(computedEntries.get(n)))
    .sort();
  return { changed: added.length > 0 || removed.length > 0 || versionChanged.length > 0, added, removed, versionChanged };
}

/** `gitHead` at sign time — recorded for provenance, never verified (the tree digest is the binding). */
export function gitHead(repoRoot: string): string | null {
  const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

/**
 * Tree digest over `git ls-files -s` blob SHAs (committed content), excluding
 * generated outputs. Platform-independent by construction: the same commit
 * hashes identically on any OS/filesystem.
 */
export function computeTreeDigest(repoRoot: string): string {
  const r = spawnSync('git', ['ls-files', '-s'], { cwd: repoRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git ls-files failed: ${r.stderr.trim()}`);
  const pairs: Array<[string, string]> = [];
  for (const line of r.stdout.split('\n')) {
    if (line.trim() === '') continue;
    const [meta, path] = line.split('\t', 2);
    const fields = (meta ?? '').trim().split(/\s+/);
    const sha = fields[1] ?? '';
    const p = path ?? '';
    if (TREE_EXCLUDED_PREFIXES.some((prefix) => p.startsWith(prefix)) || TREE_EXCLUDED_FILES.includes(p)) continue;
    pairs.push([p, sha]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return `sha256-${createHash('sha256').update(canonicalJson(pairs)).digest('hex')}`;
}

export interface BuildManifest {
  readonly type: 'asl-build-manifest';
  readonly version: 1;
  /** Recorded at sign time; informational. The tree digest is the binding. */
  readonly gitHead: string | null;
  readonly source: { readonly treeDigest: string };
  readonly dependencies: { readonly sbomDigest: string; readonly runtimeDeps: readonly string[] };
  readonly gate: { readonly typecheck: boolean; readonly tests: boolean; readonly supplyChain: boolean };
  readonly issuedAt: string;
  readonly issuedBy: string;
}

/** Ed25519 over the canonical manifest. A bad key throws — fail closed. */
export function signManifest(manifest: BuildManifest, privateKeyPem: string): string {
  const data = Buffer.from(canonicalJson(manifest), 'utf8');
  return cryptoSign(null, data, privateKeyPem).toString('base64');
}

export interface ManifestVerifyResult {
  readonly valid: boolean;
  readonly reason?: 'not-a-build-manifest' | 'gate-not-passed' | 'bad-signature' | 'stale-source' | 'stale-dependencies';
}

/**
 * Fail-closed verification: recomputes both digests from the live repo,
 * demands the recorded gate fields are true, and verifies the Ed25519
 * signature. Every refusal names its reason. The manifest arrives as
 * `unknown` — structure is verified here, not trusted from the caller.
 */
export function verifyManifest(
  rawManifest: unknown,
  signature: string,
  publicKeyPem: string,
  opts: { repoRoot: string },
): ManifestVerifyResult {
  const manifest = rawManifest as
    | {
        type?: unknown;
        version?: unknown;
        gate?: { typecheck?: unknown; tests?: unknown; supplyChain?: unknown };
        source?: { treeDigest?: unknown };
        dependencies?: { sbomDigest?: unknown; runtimeDeps?: unknown };
      }
    | null
    | undefined;
  if (
    typeof manifest !== 'object' || manifest === null
    || manifest.type !== 'asl-build-manifest' || manifest.version !== 1
  ) {
    return { valid: false, reason: 'not-a-build-manifest' };
  }
  const gate = manifest.gate ?? {};
  if (gate.typecheck !== true || gate.tests !== true || gate.supplyChain !== true) {
    return { valid: false, reason: 'gate-not-passed' };
  }
  if (typeof manifest.source?.treeDigest !== 'string' || typeof manifest.dependencies?.sbomDigest !== 'string') {
    return { valid: false, reason: 'not-a-build-manifest' };
  }
  const data = Buffer.from(canonicalJson(manifest), 'utf8');
  const sig = Buffer.from(signature, 'base64');
  let signatureValid: boolean;
  try {
    signatureValid = cryptoVerify(null, data, publicKeyPem, sig);
  } catch {
    return { valid: false, reason: 'bad-signature' };
  }
  if (!signatureValid) return { valid: false, reason: 'bad-signature' };

  // Dependencies first: a lockfile change ALSO changes the tree digest, so
  // the more specific reason must win.
  const sbom = computeSbom(opts.repoRoot);
  const expectedDeps = directProdNamesFromSbom(sbom);
  const runtimeDeps = manifest.dependencies.runtimeDeps;
  const depsStale = manifest.dependencies.sbomDigest !== sbomDigest(sbom)
    || !Array.isArray(runtimeDeps)
    || canonicalJson(runtimeDeps.map(String).sort()) !== canonicalJson(expectedDeps);
  if (depsStale) return { valid: false, reason: 'stale-dependencies' };

  if (manifest.source.treeDigest !== computeTreeDigest(opts.repoRoot)) {
    return { valid: false, reason: 'stale-source' };
  }

  return { valid: true };
}

function directProdNamesFromSbom(sbom: AslSbom): readonly string[] {
  return sbom.packages.filter((p) => p.direct && !p.dev).map((p) => p.name).sort();
}

/**
 * The release gate: typecheck + tests + supply-chain, all run and all must
 * pass before a manifest is signed. Spawned argv-array via the Node binary
 * running npm-cli.js — no shell, no .cmd (the CommandCheck posture).
 */
export function releaseGate(repoRoot: string): { pass: boolean; steps: Record<'typecheck' | 'tests' | 'supplyChain', boolean> } {
  const npmCli = npmCliPath();
  const run = (script: string): boolean =>
    spawnSync(process.execPath, [npmCli, 'run', script], { cwd: repoRoot, encoding: 'utf8', timeout: 900_000 }).status === 0;
  const steps = {
    typecheck: run('typecheck'),
    tests: run('test'),
    supplyChain: run('supply-chain'),
  };
  return { pass: steps.typecheck && steps.tests && steps.supplyChain, steps };
}

function npmCliPath(): string {
  const path = join(process.execPath, '..', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (!existsSync(path)) {
    throw new Error(`npm-cli.js not found at ${path} — the release gate cannot run`);
  }
  return path;
}

/** Dev keygen for `build keygen`: paths only — never key material to stdout. */
export function generateSigningKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = (key: KeyObject, type: 'pkcs8' | 'spki'): string => {
    const exported = key.export({ type, format: 'pem' });
    return typeof exported === 'string' ? exported : exported.toString('utf8');
  };
  return { privateKeyPem: pem(privateKey, 'pkcs8'), publicKeyPem: pem(publicKey, 'spki') };
}
