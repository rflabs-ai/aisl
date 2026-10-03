# H2 audit — short-lived credentials (ADR-028)

Date: 2026-10-03. Auditor: opencode subagent (independent pass).
Work under audit: branch `feat/h2-short-lived-credentials` (checked out), commits
`a5ec515` (ADR-028 docs) and `26c0d67` (tests + implementation + docs), off
`main` at `6d9ddf4`. Audit only; nothing merged, no code changed (one temporary
reverse probe reverted immediately; working tree for `src/` verified clean).

## Verdict: SHIP-WITH-NOTES

No must-fix defect found in the H2 code. Every load-bearing claim checked holds
under a fresh run or probe. One should-fix is a documentation-drift ticket
(ticket 01: the new `revoke-token` action is missing from three living
enumerations that H2 touched adjacent to). Nits and one pre-existing note are
listed below. The branch's own report claim of **653 tests / 634 pass / 0 fail
/ 19 skips** is confirmed exactly.

## Gate (run fresh in this audit)

| Command | Result |
| --- | --- |
| `npm run typecheck` | `TYPECHECK_EXIT=0` (clean) |
| `npm test` | `tests 653`, `suites 181`, `pass 634`, `fail 0`, `cancelled 0`, `skipped 19`, `todo 0`, `duration_ms 73632.2754` |

All 19 skips carry a Postgres-mode reason (`DATABASE_URL is not set` /
`DATABASE_URL and RESTORE_DATABASE_URL are not both set`); see
`evidence/gate-skips.txt`, `evidence/gate-summary.txt`.

## Checks

### 1. `clockToleranceSec` → `clockTolerance` — CONFIRMED (old key was a no-op; new test is red without the fix)

- jose's option is `clockTolerance`: `node_modules/jose/dist/types/types.d.ts:491` →
  `clockTolerance?: string | number`; a search of `node_modules/jose` for
  `clockToleranceSec` returns **0** matches.
- Pre-H2 (`git show 6d9ddf4:src/identity.ts`) the verify options were
  `clockToleranceSec: this.config.clockToleranceSec,`. It was assigned to a
  `const verifyOptions` object and then passed as a variable, so TypeScript's
  excess-property check never fired — genuinely silent.
- HEAD `src/identity.ts:448` → `clockTolerance: this.config.clockToleranceSec,`
  with the correction comment at lines 445–447.
- Reverse probe: temporarily reverted line 448 to the old key, ran
  `node --test --test-name-pattern "clock tolerance" tests/h2-short-lived-credentials.test.ts` →
  `✖ clock tolerance is bounded but actually applied: expired-by-10s verifies, expired-by-45s does not`,
  `fail 1`. Restored → `pass 1`, `fail 0`; `git diff --name-only -- src/identity.ts`
  returns 0. Full output: `evidence/reverse-probe.txt`.

### 2. `RevocationAction` enum-exhaustive — CLEAN (all 7 members traced)

Union (`src/incident.ts:45-53`): `freeze`, `unfreeze`, `revoke-caps`,
`revoke-sessions`, `revoke-cap`, `revoke-session`, `revoke-token`.

| Member | `incident.ts applyRecord` | `pdp.ts applyIncidentRecord` | PG allowlist `incident-store-pg.ts` | CLI |
| --- | --- | --- | --- | --- |
| `freeze` | default | `case` :546 | `:36` | engage |
| `unfreeze` | default | `case` :553 | `:37` | lift |
| `revoke-caps` | default | `case` :557 | `:38` | engage |
| `revoke-sessions` | `case` :635 | default (session) | `:39` | engage |
| `revoke-cap` | default | `case` :566 | `:40` | `cli.ts:1536` |
| `revoke-session` | `case` :639 | default (session) | `:41` | `cli.ts:1537` |
| `revoke-token` | `case` :642 | default (credential) | `:43` | `cli.ts:1483,1538` |

`incident.ts applyRecord` routes the three session/credential actions to their
owners and everything else to the PDP; the PDP's `default` explicitly no-ops
session/credential actions ("applied by IncidentService"). No path reaches the
PDP with `revoke-token` (the only production caller is `applyRecord`). The
allowlist now uses `satisfies Record<RevocationAction, true>` +
`isRevocationAction` predicate (`incident-store-pg.ts:47-49,107`), so a future
union member is a compile error until admitted. The PG DDL
(`incident-store-pg.ts:59-67`) has no action `CHECK` constraint, so the new
action cannot be rejected at INSERT. No REST incident route exists to update.

### 3. `validateTokenClaims` admission contract — CONFIRMED, no bypass

- `jwtVerify` appears only in `src/identity.ts` (lines 13/454); `verifyJwt` is
  private; its only caller is `verifyToken` (`:299`); `validateTokenClaims` is
  called at `:305`. REST calls `idp.verifyToken` (`src/rest-api.ts:305`). Other
  `AuthContext` producers in `src/` are test/fixture infrastructure
  (`testing.ts mockAuth`, `scenario.ts scenarioAuth`, `rest-api.ts`
  `ANONYMOUS_AUTH` for unauthenticated routes) — no production authentication
  path skips the seam.
- Edge probe (throwaway file, deleted after; full output `evidence/probe-output.txt`):

```
PROBE claims | exp === iat (zero lifetime)                    | ok=false reason=claims-lifetime-not-positive
PROBE claims | exp < iat (inverted)                           | ok=false reason=claims-lifetime-not-positive
PROBE claims | exp === now (exactly)                          | ok=true
PROBE claims | exp === now - tolerance (exactly)              | ok=true
PROBE claims | exp === now - tolerance - 1ms                  | ok=false reason=claims-expired
PROBE claims | iat === now + tolerance (exactly)              | ok=true
PROBE claims | iat === now + tolerance + 1s                   | ok=false reason=claims-issued-in-future
PROBE claims | missing jti / empty jti / non-string jti       | ok=false reason=claims-missing-jti
PROBE claims | missing sub / empty sub                        | ok=false reason=claims-missing-sub
PROBE claims | string exp / NaN exp / Infinity exp            | ok=false reason=claims-missing-exp
PROBE claims | lifetime === ceiling (3600)                    | ok=true
PROBE claims | lifetime === ceiling + 1                       | ok=false reason=claims-lifetime-exceeds-ceiling
PROBE config | clock 0 / max 1, clock 60 / max 86400         | accepted (caps inclusive)
PROBE config | clock 61 / -1 / NaN, max 0 / 86401            | IdentityConfigError
```

### 4. `workloadAuth` and MFA consumers — CONFIRMED, no widening

- Code (`src/identity.ts:363-386`): `subject = workloadId`, `tokenId =
  wl:<workloadId>:<parent.tokenId>` (:380), `issuedAt = now`,
  `expiresAt = min(parent.expiresAt, now + maxLifetimeSec*1000)`, `amr: []`
  (:382), `claims: {}` (:383), `derivedFrom` (:385). `sessionAgent` routes
  through it (`:408`).
- Probe: tokenId `wl:agent:summarizer:parent-jti-9`; default expiry `now+900s`;
  short parent keeps parent expiry; expired parent yields an already-expired
  context; `maxLifetimeSec 86400` ok / `86401` throws.
- MFA: `hasMfa(parent)=true`, `hasMfa(derived)=false`; `SessionManager.create`
  with a derived auth throws `requires MFA at the IdP` (fail-closed, no
  widening). Approval MFA checks the stored `reviewerAuth` (`pdp.ts:938`) and
  REST session creation uses the caller's verified token (`rest-sessions.ts:82`),
  not a workload context.
- Denial-regression check: `git grep sessionAgent` at `6d9ddf4` and at HEAD
  finds **zero** production consumers (only the definition and the H2 test).
  The behavioral change (agents no longer inherit the human's MFA) cannot
  regress an in-repo call site. External embedders using `sessionAgent`'s auth
  to create sessions will now be refused — that is the intended ADR-028
  direction, not a ticket.

### 5. Claim 37 / ROADMAP H2 / THREAT_MODEL vs code — CONSISTENT

- Claim 37 (`SECURITY_CLAIMS.md:1871+`) required claims, ceilings, tolerance
  bounds, `wl:` token id, `amr/claims` clearing, `derivedFrom`, local-first and
  cross-node revocation — each maps to the code/probes above. The evidence
  count "31 cases" splits from the fresh run: 8 admission + 6 end-to-end + 6
  workload + 8 revocation + 3 credential-scanning = 31.
- ROADMAP H2 (`ROADMAP.md:187+`) and TM-005 (`threat-models/TM-005...`) text
  match the implementation; TM-005 no longer repeats the old false
  "short-circuit before signature verification" phrasing.
- `DEPLOYMENT.md:135-140` describes the embedder wiring
  (`IdentityProvider.attachRevocationFeed(channel)`) rather than claiming it is
  automatic; no in-repo production entry point constructs `RestApi`/an
  `IdentityProvider` (pre-existing posture: `createRestApi` is the embedder
  assembly point, `src/rest-api.ts:189`).

### 6. `as unknown as ChannelRow[]` — PRE-EXISTS H2 (note, not a ticket)

`src/incident-store-pg.ts:194` (in `load()`). `git show 6d9ddf4:src/incident-store-pg.ts`
contains the same cast; the H2 diff does not touch that line.

### 7. `.scratch/h2/red.txt` — GENUINE red signal

The file shows the ESM link error for a missing export:
`SyntaxError: The requested module '../src/identity.ts' does not provide an export named 'DEFAULT_MAX_TOKEN_LIFETIME_SEC'`,
with the import at test line 27. `git show 6d9ddf4:src/identity.ts |
Select-String DEFAULT_MAX_TOKEN_LIFETIME_SEC` → **0** matches, so running the
new test against the pre-implementation tree produces exactly this failure.
(The file's runner summary glyphs are mojibake — nit.)

### 8. Debt markers — PASS

New markers added by the diff:
- `src/identity.ts:181`: `ponytail: revoked jtis are kept for the process lifetime; bounded by the 24h token ceiling and revocation volume. upgrade: store (jti, exp) and prune on expiry if revocation volume strains memory.` — ceiling + upgrade path present.
- `DECISIONS.md:2039`: `ponytail: strict claim contract; add a configurable claims profile if a real IdP cannot ...` — upgrade path + trigger present, but the trigger sentence is truncated mid-clause → nit.
- `ℹ todo 0` in `red.txt` is runner output, not a marker.
No new `TODO`/`FIXME`; no `as any`/`as never`/new `as unknown` casts; `package.json` untouched (zero new runtime dependencies).

## Findings

**Should-fix → ticket 01.** `revoke-token` is missing from three living
enumerations the H2 change made stale: `SECURITY_CLAIMS.md:1669-1670` (Claim 35:
"Records are scope-level (...) and single-target (`revoke-cap`/`revoke-session`)"),
`SECURITY_CLAIMS.md:1681-1682` and `CURRENT_STATE.md:146-148` (CLI command
lists), `DEPLOYMENT.md:424-425` (runbook "Narrow revocation"). File:
`.scratch/session-audit/2026-10-03-h2-short-lived-credentials/issues/01-revoke-token-doc-enumerations.md`.

**Nits (no ticket):**
1. `DECISIONS.md:1976-1978` says "an agent cannot outlive the launching session
   or the workload ceiling". The code caps by the parent *token* expiry
   (`min(parent.expiresAt, ...)`) — revoking a `SessionManager` session does not
   shorten an already-derived auth context. Claim 37 states the real bound
   correctly; the ADR prose overstates it.
2. `DECISIONS.md:2039-2041` ponytail trigger ends mid-sentence: "trigger: a
   deployment whose IdP cannot`);" — finish or drop the clause.
3. `.scratch/h2/red.txt` committed with mojibake glyphs (`Γ£û` for ✖, `Γä╣` for
   ℹ); the signal line itself is intact.
4. `TokenRevoker.isTokenRevoked` (`src/incident.ts:78-81`) is required by the
   interface but never called by `IncidentService`; only tests call
   `IdentityProvider.isTokenRevoked` directly.
5. `AGENT-SESSION.md` evidence says the implementation commit hash is "recorded
   in the session report" but no hash appears; the branch log gives `26c0d67`.

## Clean axes (justified by commands run)

- **Enum exhaustiveness:** all 7 union members traced through every parser,
  filter, switch, CLI branch and the PG allowlist; `satisfies` makes future
  omissions compile errors. No silent absence.
- **Admission coverage:** only `jose` usage in `src/` is inside the seam;
  `verifyJwt` private; `validateTokenClaims` called on every `verifyToken`.
- **Boundary semantics:** probe matrix confirms ceil/tolerance boundaries are
  exactly the claim wording (`<=` ceiling, `<=` future-iat tolerance, accepted
  exp not older than tolerance).
- **MFA:** derived contexts have no MFA and cannot create sessions; no
  production consumer of `sessionAgent`, so no widening and no in-repo denial
  regression.
- **Credential hygiene:** event/response scanning test passes in the fresh gate;
  no raw token/JWT prefix (`eyJ`) on the AuthContext.
- **Dependencies:** `package.json` absent from the diff; no new imports in the
  changed `src/` files.

## Evidence ledger

| # | Command | Result |
| --- | --- | --- |
| 1 | `git status --porcelain=v1 && git log --oneline -5 && git branch --show-current` | HEAD `26c0d67`, base `6d9ddf4`, branch `feat/h2-short-lived-credentials`; only `benchmarks/results.json` dirty |
| 2 | `npm run typecheck` | exit 0 |
| 3 | `npm test` | 653 / 634 pass / 0 fail / 19 skip; `evidence/gate-summary.txt`, `evidence/gate-skips.txt` |
| 4 | `Select-String node_modules/jose -Pattern clockTolerance` | `types.d.ts:491 clockTolerance?: string \| number`; `clockToleranceSec` count 0 |
| 5 | `git show 6d9ddf4:src/identity.ts \| Select-String clockToleranceSec` | pre-H2 verify option used the ignored key |
| 6 | reverse probe (revert → test → restore) | `fail 1` without fix, `pass 1` after; `evidence/reverse-probe.txt`; identity.ts diff count 0 |
| 7 | throwaway probe `node --test .scratch/h2-audit-probe/probe.test.ts` (deleted) | full edge matrix; `evidence/probe-output.txt` |
| 8 | `grep RevocationAction\|revoke-token\|...` across `src/` | trace table in Check 2; no missing consumer |
| 9 | `git show 6d9ddf4:src/incident-store-pg.ts \| Select-String "as unknown as ChannelRow"` | cast pre-exists H2 |
| 10 | `git show 6d9ddf4:src/identity.ts \| Select-String DEFAULT_MAX_TOKEN_LIFETIME_SEC` | 0 matches → red.txt genuine |
| 11 | `git diff 6d9ddf4..26c0d67 \| Select-String "^\+.*(ponytail:\|TODO\|FIXME)"` | 2 real markers (identity.ts:181, DECISIONS.md:2039); `ℹ todo 0` is runner output |
| 12 | `git diff ... -- src/ \| Select-String "as any\|as never\|as unknown\|from '[^.]"`; `package.json` diff | no casts/imports added; package.json untouched |

`benchmarks/results.json` was already modified before this audit and is
excluded from the audit commit.
