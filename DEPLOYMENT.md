# DEPLOYMENT, HARDWARE, AND OPERATING MODEL

Architected, not built. One deployment exists today: development.

## 1. Deployment models

For each: trust boundary, threat model, secrets, networking, updates, logging,
backups, DR, admin access, customer responsibility, vendor responsibility.

### Development (works today)

- **Trust boundary:** one process; the developer is fully trusted.
- **Threat model:** none adversarial; the value is the test suite.
- **Secrets:** env var `CAPABILITY_SIGNING_KEY`; ephemeral fallback with a warning.
- **Networking:** none. The gateway opens no sockets.
- **Updates:** git pull.
- **Logging:** stdout + SQLite file.
- **Backups / DR:** none.
- **Admin access:** filesystem.
- **Customer responsibility:** n/a. **Vendor:** n/a.
- **Setup (M15, ADR-020):** `scripts/setup.ps1` / `scripts/setup.sh` — a
  reproducible, offline environment: Node ≥ 22.5 / git / npm checks, `npm
  install`, typecheck, and tests, exiting nonzero on the first failed check.
  No `curl | bash`, no remote fetches, no privilege escalation — the repo is
  the review gate. `-WithPostgres` / `--with-postgres` optionally bootstraps
  the disposable Postgres 16 container from the M12 workflow below.

### Single-node private (one organization)

- **Trust boundary:** host OS; the org's admins are inside it.
- **Threat model:** malicious insider with host access, malicious documents,
  hostile model.
- **Secrets:** local KMS or HSM if available; at minimum a file with 0600 and an
  operator-managed passphrase.
- **Networking:** egress proxy allowlist; no inbound except the UI.
- **Updates:** signed release bundles, verified before apply.
- **Logging:** local evidence store; per-event head-hash anchor file (M3); periodic publication of the anchor to a customer-held WORM bucket or transparency log.
- **Backups:** encrypted, tested restore.
- **DR:** rebuild from bundle + restore evidence; RPO/RTO declared per customer.
- **Admin access:** named accounts, MFA, dual control for policy changes.
- **Customer:** host, accounts, physical. **Vendor:** software, updates.

### Postgres mode (multi-node control plane — M12, opt-in)

The default stays SQLite (ADR-010's single-process mode). Postgres mode is
**opt-in**: set `EVENT_STORE=postgres` **and** `DATABASE_URL`. An ambient
`DATABASE_URL` alone does nothing.

- **Provisioning:**
  1. Postgres 16 (container or native). Create a database for the runtime,
     e.g. `docker run -d --name sec-layer-pg -e POSTGRES_PASSWORD=... -p 5433:5432 postgres:16`.
  2. Set `DATABASE_URL=postgres://...` (the runtime role connection; the URL
     is a secret — inject via secret broker/env, never log it, never in argv).
  3. First connect with `MIGRATION_DATABASE_URL` set to a DDL-capable
     (superuser or owner) connection: the runner bootstraps the `migrations`
     bookkeeping table, the cluster-level `app_rw`/`app_reader` roles
     (NOLOGIN, no passwords in DDL), then applies forward-only migrations
     ids 1–4 (id 4 = the H13 revocation channel), each sha256-recorded. A
     recorded id with a changed hash is a tamper signal and refuses to open;
     an already-deployed instance that has only ids 1–3 must run once with
     `MIGRATION_DATABASE_URL` set, or the open refuses (fail closed).
  4. Operator out-of-band (migration framework never does this): grant
     `LOGIN` + passwords to `app_rw` (runtime) and `app_reader` (audit path)
     with the documented privileges, set `pg_hba` to TLS-only from the
     runtime's hosts, and restrict the DDL role to the migration runner.
  5. Run the runtime as `app_rw` only. **A superuser connection bypasses
     row-level security entirely** — that bypass is operator discipline,
     not a control.
- **Row-level security (what the database enforces):** all control-plane
  tables are `FORCE RLS` with deny-by-default per-role policies. The runtime
  role (`app_rw`) reads the whole evidence chain (global seq, one signer)
  and appends; the audit role (`app_reader`) is tenant-scoped via the
  per-transaction context (`set_config('app.tenant_id', ..., is_local :=
  true)`): unset context reads **zero rows**, a hostile query without
  context reads **zero rows**, wrong context reads only that tenant. The
  live-DB test suite proves this against a real server
  (`tests/tenant-rls.test.ts`).
- **Backup cadence:** `tools/backup.ps1` — plain-SQL `pg_dump` (host
  `pg_dump` on PATH preferred, docker-exec fallback; password via
  `PGPASSWORD` env, never argv, never logged). Cadence: at minimum daily,
  plus before every upgrade; the head-hash anchor file (M3) is NOT part of
  the dump and must be backed up separately on its own schedule — it is the
  external witness that makes a restored store trustworthy.
- **Restore drill:** rehearsed in CI by test
  (`tests/persistence-restore.test.ts`: dump → restore into a scratch
  database → chain `verify()` + signature check + `verifyBundle()` +
  persistence row parity). Manual drill: restore the dump into a scratch
  database, run the verifier against it, compare the chain head against the
  anchor file, THEN promote. A restore that does not pass `verify()` is not
  a restore.
- **Fail-closed:** an unreachable, unauthenticatable, or mid-migration
  Postgres denies every decision that needs the store with
  `denyReason: 'store-unavailable'` and one loud health event (H15). There
  is no silent fallback.

### REST API exposure (M14, ADR-019)

The REST surface (`src/rest-api.ts`) is the platform's first network
ingress. Its own in-process story is deliberately modest: it binds
**loopback only** and does no TLS.

- **TLS terminates at the deployment** — reverse proxy / load balancer in
  front of the API (operator-owned, same discipline as `pg_hba` TLS above).
  Never expose the Node process directly on an untrusted network; there is
  no in-process TLS and no rate limiting (H15/deployment territory) — a
  proxy that terminates TLS and applies connection budgets/rate limits is
  the required front door.
- **Identity:** clients authenticate with `Authorization: Bearer <JWT>` from
  the trusted IdP (ADR-016). The deployment registers the principal table
  the resolver maps verified tokens onto — tokens decide *who*; the
  registration decides *what they may reach*. `X-*` identity headers are
  ignored by construction.
- **Health:** `GET /healthz` (no auth, no secrets) → `{ idp, store }` —
  wire your monitor to it; IdP `unreachable` or store `unavailable` means
  every decision is failing closed (H15).
- **Minimal UI (M15):** the static operator page (`tools/ui/index.html`) is
  served by the same loopback server when the embedder wires it via
  `staticPages` (`GET /ui`, `GET /`). It is a plain client of `/v1` — the
  bearer-JWT contract and every PDP rule apply unchanged; the page embeds no
  secrets (the token is typed at runtime).
- **Client bodies:** the server rejects >1 MiB bodies with 413 before
  parsing and returns structured errors on garbage — treat the whitelist
  contract as part of the deployment story: nothing client-supplied is
  interpreted beyond the whitelisted fields (ADR-019).

### SaaS multi-tenant

- **Trust boundary:** tenant isolation is logical and must be tested continuously.
- **Threat model:** cross-tenant, noisy neighbour, vendor insider, supply chain.
- **Secrets:** per-tenant keys in a KMS; no key shared across tenants.
- **Networking:** per-tenant segmentation; egress proxy per session.
- **Updates:** staged rollout, canary, automated halt on anomaly.
- **Logging:** centralized with tenant-scoped access; evidence export per tenant.
- **Backups:** continuous with point-in-time recovery.
- **DR:** multi-AZ, declared RPO/RTO, annual restore drill.
- **Admin access:** break-glass with dual approval, session recording, full audit.
- **Customer:** their users, their data classification, their policy content.
- **Vendor:** isolation, availability, evidence integrity, patching.

### Customer VPC (control plane vendor-side, data plane customer-side)

- **Trust boundary:** the customer's data never leaves their account; control
  plane holds metadata and policy only.
- **Threat model:** vendor compromise must not reach customer data.
- **Secrets:** customer-held keys; the control plane never holds data-plane keys.
- **Networking:** outbound-only agent from the customer VPC; no inbound.
- **Updates:** customer approves data-plane upgrades.
- **Logging:** security events stay in the customer account.
- **Backups / DR:** customer-owned, customer-tested.
- **Admin access:** vendor has no standing access; break-glass requires customer
  approval and is logged in both planes.
- **Customer:** data plane entirely. **Vendor:** control plane availability.

### On-premises (entire platform customer-controlled)

- **Trust boundary:** customer network perimeter plus the platform's own.
- **Threat model:** same as single-node, plus customer ops maturity variance.
- **Secrets:** customer KMS/HSM.
- **Networking:** customer-determined; the platform requires an egress allowlist.
- **Updates:** signed bundles delivered through customer change control.
- **Logging / backups / DR:** customer-run; vendor supplies runbooks and tooling.
- **Admin access:** entirely customer.
- **Customer:** everything operational. **Vendor:** software and support.

### Offline (no external network dependency)

- **Trust boundary:** the deployment is its own world.
- **Threat model:** insider, removable media, update channel.
- **Secrets:** local HSM or air-gapped key ceremony.
- **Networking:** no egress; the gateway denies by construction.
- **Updates:** signed physical or reviewed transfer; hash-verified.
- **Logging:** local; evidence anchored to an internal, append-only store.
- **Backups:** offline, encrypted, stored separately.
- **DR:** warm spare on-site.
- **Customer:** all. **Vendor:** signed bundles, no remote access.

### Air-gapped (controlled transfer of software, models, and updates)

- **Trust boundary:** the transfer mechanism is the primary attack surface.
- **Threat model:** malicious update bundle, malicious model weights, insider with
  media access, electromagnetic/acoustic side channels (HA regimes).
- **Secrets:** key ceremony on-site; keys never leave.
- **Networking:** none, enforced physically and by policy.
- **Updates:** two-person review, hash and signature verification, quarantine scan,
  staged on a non-production copy first.
- **Logging:** local; evidence exported only through the reviewed transfer path.
- **Backups / DR:** offline replicas; documented reconstitution procedure.
- **Admin access:** dual control; no remote administration, ever.
- **Customer:** physical control and transfer procedure. **Vendor:** signed
  artifacts, model packaging, transfer manifests.

### Sandbox lifecycle (M16, ADR-021)
Who creates, who destroys, and what happens on process exit:

- **Who creates:** the embedder/runtime — not the agent. `SandboxRegistry.create`
  spawns synchronously (Docker-backed when the daemon is up, `LocalSandbox`
  fallback when not — the handle's `kind` says which, so a deployment that
  requires isolation can refuse to run on `fallback/...`) and registers the
  sandbox as a tenant-bound resource. The agent's only authority is a
  `sandbox.execute` capability scoped to the sandbox resource id; the handle
  stays with the runtime.
- **Who destroys:** the embedder calls `destroy` when work completes; destroy
  is idempotent and refuses unknown ids. An operator never tears down sandboxes
  by hand — the lifecycle events are the record.
- **Process exit:** `installExitSweep()` (opt-in, call once at startup) sweeps
  every active sandbox on `beforeExit`/SIGINT/SIGTERM, appending one sealed
  `sandbox.destroy` event per sandbox — no unaccounted teardown. Call it in any
  long-running deployment; short-lived CLIs that destroy explicitly do not
  need it.
- **Evidence:** `sandbox.create`/`sandbox.destroy`/`sandbox.attest` events
  carry sealed payloads (pid, kind, effective-vs-declared limits, duration)
  under the tenant's key plus a limit-config digest; the plaintext log shows
  digest + keyId only. A crashing process loses the sweep, not the history —
  `sandbox.create` has no matching `sandbox.destroy` in the event log is the
  operational signal for "sandbox was active when the process died".
- **Limits:** declared at create time as the container sandbox's own options
  (memory/CPU/PID/timeout); enforced by the kernel/cgroup when Docker is
  present. Without Docker the sandbox degrades to in-process execution and
  says so — treat that as a deployment misconfiguration, not a mode.

### Build and release (H10, ADR-024)

The artifact of record is the source tree (TypeScript ships as source). The
release flow is gate → sign → verify-before-start:

1. **Gate (every commit, every release):** `npm run supply-chain` — generates
   the deterministic `ASL-SBOM v1` from the lockfile and diffs it against the
   committed `artifacts/sbom.json`, enforces exact version pins, sha512
   integrity + `registry.npmjs.org` resolved URLs on every lockfile package,
   and the `ADMITTED_RUNTIME_DEPS` allowlist. Dependency changes fail until
   the baseline is regenerated (`npm run sbom -- --write`) and the admission
   ADR is named in the same reviewed PR. The local pre-commit hook runs this
   gate (hooks are untracked — copy `.git/hooks/pre-commit` on a fresh clone;
   wire `npm run supply-chain` into CI when a pipeline exists). CI installs
   with `npm ci` — never `npm install` (drift prevention).
2. **Sign (release only):** `npm run build:sign` — runs the full release gate
   (typecheck + tests + supply-chain), then Ed25519-signs the canonical
   manifest binding `treeDigest` (git blob SHAs over tracked files,
   `artifacts/*` and `benchmarks/results.json` excluded — outputs, not
   inputs), `sbomDigest`, `gitHead`, and the gate result; writes
   `artifacts/build-manifest.json` + `.sig`. Requires
   `BUILD_SIGNING_PRIVATE_PEM`; refuses to sign on any gate failure.
3. **Verify (before every start):** `npm run build:verify` — recomputes both
   digests from the live tree and the lockfile, demands the recorded gate
   fields are true, and verifies the Ed25519 signature with
   `BUILD_SIGNING_PUBLIC_PEM`. Fail-closed with distinct reasons:
   `bad-signature` / `stale-source` / `stale-dependencies` /
   `gate-not-passed` / `not-a-build-manifest`. A start script in a controlled
   deployment runs this before boot; refusal is a stop condition, not a
   warning.
4. **Key custody:** dev keys via `npm run build:keygen` into gitignored
   `.build-keys/`. The production release key lives OUTSIDE the repo (CI
   secret or HSM per the hardware tier; ceremony documented in the operator's
   key-management procedure — ADR-008 is the rotation/migration path). Env
   vars: `BUILD_SIGNING_PRIVATE_PEM` (sign), `BUILD_SIGNING_PUBLIC_PEM`
   (verify), `BUILD_SIGNING_IDENTITY` (recorded in the manifest as `issuedBy`).
   Key material is never printed.

   **Ceremony record (2026-09-29, dev key):** first keypair generated via
   `npm run build:keygen`; public-key fingerprint
   `sha256-caa343b2a11a22e941727013950c6b95d402fb0f05776848d61fd43ec1518cb7`;
   `BUILD_SIGNING_IDENTITY = dev key 2026-09-29`. Custody (durable
   copy pending hardware): working copy in gitignored `.build-keys/`; the
   durable copy is planned for a dedicated encrypted container on a
   whole-drive-encrypted external SSD plus an offline bank-HDD copy
   (procedure: "Key custody runbook" below); container passphrase and
   fingerprint go in a password manager. The
   public key is distributed out-of-band and never committed — an in-repo
   key could be swapped together with an attacker-signed manifest. The first
   signed manifest landed the same day (`artifacts/build-manifest.json` +
   `.sig`; `gitHead` inside the manifest records the commit it was signed
   from). Rotation is the ADR-008 path: new pair, re-sign, destroy the old
   private key, record the rotation.
5. **Residuals:** no transparency-log publication of the manifest/SBOM
   (H11/Stage-3); no CI enforcement in-repo; a coerced maintainer with
   repo-write can still land a reviewed PR - H10 raises the cost, it does not
   remove the trusted-maintainer risk (IMPOSSIBLE+).

### Key custody runbook (operator steps)

One-time procedure for a new signing key (or after a rotation). Steps that
touch secrets are human-only: passphrases never enter an agent session, a
shell command line, a chat, or a repository file.

1. **Know what you protect.** The private PEM (~120 bytes) is the signing
   identity; the public PEM is shareable. Working copies live in gitignored
   `.build-keys/` and are what `build:sign` reads.
2. **Encrypt the carrier drive.** Windows Pro: BitLocker To Go (right-click
   the drive -> Turn on BitLocker; save the recovery key). Windows Home:
   VeraCrypt -> Create Volume -> encrypt a non-system partition. Use a strong
   unique passphrase; store it in the password manager. Result: someone who
   finds the drive sees ciphertext only.
3. **Build the key container (second layer).** Select both PEM files in
   Explorer -> 7-Zip -> "Add to archive": format `7z`, AES-256, **Encrypt
   file names ON**, long unique passphrase. Result: `build-signing-keys.7z`.
   Never store loose PEMs on the carrier.
4. **Place copies.** `build-signing-keys.7z` -> the encrypted SSD (e.g.
   `E:\asl-backup\`) and -> the offline bank-HDD. The working copies stay in
   `.build-keys/` for day-to-day signing; never delete them.
5. **Password-manager entry.** Fingerprint (public), container passphrase,
   copy locations, ceremony date. The fingerprint is how a restored or
   swapped key is detected.
6. **Restore drill (do not skip).** Extract the `.7z` into a temp folder,
   fingerprint the extracted public key, compare against the recorded value:

   ```powershell
   node -e "const c=require('node:crypto'),f=require('node:fs');const k=c.createPublicKey(f.readFileSync('<extracted>\build-signing-public.pem','utf8'));console.log('sha256-'+c.createHash('sha256').update(k.export({type:'spki',format:'der'})).digest('hex'))"
   ```

   A matching output proves the backup is real. Delete the temp extraction.
7. **Rules.** Never commit, print, email, or cloud-sync the private key;
   GitHub is for projects only. Re-sign manifests only at release points.
   Lost or stolen carrier -> treat as compromise -> rotate (ADR-008 path):
   new pair, re-sign, destroy the old private key, record the rotation here
   and in the session log.

### Updates (H12, ADR-025)

Applying a release is its own fail-closed flow on top of build-and-release:
the descriptor carries the signed build manifest, and the target machine's
high-water mark decides freshness. Release-side and instance-side steps:

1. **Issue (release machine, after `npm run build:sign`):**
   `node src/cli.ts update sign <releaseVersion> <channel> [stages]` —
   e.g. `update sign 3 stable 10,50,100`. Refuses without an issued build
   manifest, refuses if the manifest does not match the live tree at sign
   time, refuses malformed stages (ascending, ending in 100). Writes
   `artifacts/update.json` + `.sig`. `releaseVersion` is a monotonic integer
   per instance — never reuse a number.
2. **Transport:** out of band (this repo verifies updates; it does not host
   them). Move `update.json` + `update.sig` to the target the same way the
   build manifest travels.
3. **Verify (target, before start):** `npm run update:verify` — the full
   chain against the live tree with `BUILD_SIGNING_PUBLIC_PEM`. Refusal is a
   stop condition, never a warning.
4. **Apply (target):** `node src/cli.ts update apply` — verification again
   plus the high-water mark. Success lands the rollout at **canary** and
   raises the mark. A stale or replayed descriptor is refused
   (`rollback-blocked`) no matter how valid its signature is.
5. **Promote:** `node src/cli.ts update promote ok|fail` — one stage per
   explicit `ok`; `fail` halts the rollout (`halted` is sticky: a later `ok`
   does not clear it). A halt is resolved by issuing a NEW descriptor or by
   rollback. There is no default-healthy path.
6. **Status:** `npm run update:status` — high-water mark, current release,
   rollout stage/halt reason. A corrupt state file refuses (exit 1) rather
   than resetting — investigate, do not delete.
7. **Emergency rollback (incident):**
   `node src/cli.ts update grant <targetVersion> "<reason>"` signs a
   single-use grant (requires `BUILD_SIGNING_PRIVATE_PEM`; target must be
   below current; the CLI embeds the current rollback generation), then
   `node src/cli.ts update rollback` applies it. The grant works exactly once
   against the exact version it names and generation it carries — a used
   grant never revives, even if the same version becomes current again — and
   the
   high-water mark is NOT lowered — the version you rolled back from stays
   burned; recovering forward means a new descriptor with a higher number.
8. **State custody:** `artifacts/update-state.json` is per-instance runtime
   state — code-written only, atomic, gitignored. It holds the mark and the
   rollback generation; losing
   or resetting it re-opens the replay window. Keep it on storage the update
   process does not share with an untrusted writer, and back it up with the
   instance.

Key material: same `BUILD_SIGNING_*` env vars as build-and-release (one
release key). Residuals: caller-supplied health signal, no descriptor
transparency log (H11/Stage-3), signed-but-malicious release (Claim 34).

### Incident response (H13, ADR-026)

Runbooks for a live incident. In Postgres mode the revocation channel is the
shared table (`revocation_channel`, migration 4) — an operator CLI process
reaches the running node(s) within the poll interval (default 1 s). A server
whose embedder wires `RestApiDeps.incidentSync` also pulls once per authorized
request; otherwise convergence rides the PDP `authorize`/`issue` paths. In
SQLite mode the channel is in-memory: the CLI's kill switch is local to that
process, and the CLI says so.

1. **Assess:** `npm run incident:status` — freeze state (scope, tenant,
   reason, actor), revoked-capability count, channel cursor / applied records
   / sync + channel error counters. A non-zero channel error means the
   broadcast did not propagate; the local effect still applies.
2. **Kill switch (freeze + revoke-all):**
   `node src/cli.ts incident engage tenant <tenantId> "<reason>"` or
   `... engage global "<reason>"`. Freezes issuance + authorization
   (`incident-frozen`), revokes every registered capability and session in
   scope, and broadcasts. Evidence-read capabilities (`query.audit`,
   `audit.export`, `evidence.decrypt`) survive so you can still reconstruct.
   A non-zero exit means the local action landed but the broadcast did not —
   check `incident status` and the channel before trusting other nodes.
3. **Contained (lift):** `node src/cli.ts incident lift tenant <tenantId>
   "<reason>"`. Clears the freeze only. Revoked capabilities stay revoked;
   re-issue authority through the ordinary issuance/approval paths.
4. **Narrow revocation:** `incident revoke-cap <capabilityId> <tenantId>
   "<reason>"`, `incident revoke-session <sessionId> <tenantId> "<reason>"` —
   local + broadcast, single-target.
5. **Preserve evidence:**
   `node src/cli.ts incident preserve <tenantId | *> <fromSeq> <toSeq> [outPath]`
   — pages the authorized audit export past the 1000-event cap, verifies the
   bundle offline, writes `asl-incident-bundle` JSON (digest + head inside),
   and records an `incident.preserve` event with digest + head + counts only.
   Archive the artifact; it verifies offline with `verifyIncidentBundle` +
   the event public key (and against the anchor when the window reaches the
   head). `*` is the global-incident view (`engage global` evidence).
   **Precondition:** the operator process must share the event-signing key
   with the signing node — set `EVENT_SIGNING_PRIVATE_KEY_PEM` +
   `EVENT_SIGNING_PUBLIC_KEY_PEM` on both. Without them each process signs
   with an ephemeral key and preserve refuses fail-closed with a
   `signature mismatch` (and now says so in the error).
6. **Reconstruct:** `node src/cli.ts incident report <tenantId | *> <fromSeq>
   <toSeq>` — decision counts by deny reason, revocation/freeze counts,
   actors, time bounds; `*` for global-incident evidence.
7. **Channel custody:** `revocation_channel` is append-only by privilege
   (`app_rw` SELECT/INSERT; no UPDATE/DELETE), deliberately not RLS-scoped
   (it coordinates tenants and nodes), and must carry no secrets in `reason`
   text. Treat write access as incident authority — a channel writer can
   freeze legitimate work (the accepted H15 DoS trade).
8. **Restart behaviour:** a fresh node replays the channel from cursor 0 and
   reconstructs freeze + revocation state; a SQLite-mode process loses its
   in-memory freeze on restart (the channel is the durable story).

Residuals: poll-based propagation, a channel writer can freeze, response can
be slower than the attack (Claim 35, ADR-026).

## 2. Hardware tiers

| Tier | Compute | Storage | Keys | Network |
| --- | --- | --- | --- | --- |
| Developer | workstation, 8+ cores, 32 GB | local disk | env var | unrestricted (dev only) |
| Small deployment | 4–8 vCPU, 32–64 GB, optional GPU | encrypted volume | KMS or file-backed | egress allowlist |
| Enterprise | redundant compute, 64–256 GB, optional GPU pool | encrypted, replicated, backed up | KMS/HSM, per-tenant keys | segmented, proxy-mediated |
| High assurance | dedicated hosts, dedicated GPU, no multi-tenancy | dedicated encrypted storage, controlled destruction | HSM/TPM, hardware-backed attestation | isolated management network, no shared egress |

Premature hardware requirements are a cost, not a security property. Do not buy
HSMs before there is a key management design that needs them.

## 3. Operating model (future requirements)

Security is not only software. These belong on the roadmap and in runbooks:

- **Employee access control:** least privilege, MFA, joiner/mover/leaver process.
- **Privileged access management:** just-in-time elevation, session recording,
  dual control for production.
- **Security training:** onboarding plus annual; secure coding for engineers.
- **Incident response:** documented plan, on-call rotation, severity taxonomy,
  post-incident reviews with tracked actions.
- **Vulnerability disclosure:** published policy, safe harbour, response SLAs.
- **Penetration testing:** annual external test, plus a standing internal red team.
- **Supply-chain management:** SBOM for every release, pinning, provenance,
  vendor review — the SBOM/pinning/provenance parts are built (H10, above);
  vendor review stays operational.
- **Vendor management:** security review before integration, annual re-review.
- **Backups:** 3-2-1, encrypted, restore tested on a schedule with recorded results.
- **DR / business continuity:** declared RPO/RTO, annual exercise, documented
  reconstitution.
- **Change management:** review, staging, canary, rollback; emergency path logged.
- **Access reviews:** quarterly review of human and service access, with evidence.
- **Key management:** documented rotation, ceremony, and destruction procedures.
- **Security monitoring:** alerting on denied-action spikes, capability issuance
  anomalies, egress volume, and evidence chain failures.
- **Breach notification:** customer notification path with defined timelines.
- **Evidence preservation:** legal hold, retention policy, immutable copies.
