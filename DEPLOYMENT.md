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
     ids 1–3, each sha256-recorded. A recorded id with a changed hash is a
     tamper signal and refuses to open.
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
  vendor review.
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
