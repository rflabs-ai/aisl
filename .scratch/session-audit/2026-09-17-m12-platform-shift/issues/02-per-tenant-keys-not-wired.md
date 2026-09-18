Status: resolved (06eaf50)
Source: session-audit M12 (range 007a8a6..1298ed0)

## What's wrong

Per-tenant evidence keys exist only as an unused module API. `sealFor`/
`openFor` (src/seal.ts:132/154) are exercised solely by tests/tenant-rls
key tests; every RUNTIME sealing path still uses the legacy global-tenant
derivation: src/guard.ts:162 (`seal(txt, options.classification)`), src/guard.ts:188
(`seal(ctx.modelText, ...)`) and src/runtime.ts:428
(`seal(rendered, classification)`). So actual sealed evidence is still keyed
by classification only — one tenant's ciphertext opens under the same key
as any other tenant's. The docs claim the hardening as done: ROADMAP
"Tenant isolation hardening [DONE] (… per-tenant evidence keys … bind
decryption to tenant identity …)", CURRENT_STATE ("per-tenant evidence
keys … bind decryption to tenant identity with no silent re-encryption"),
Claim 9 mechanism ("per-tenant evidence keys … bind decryption to tenant
identity"). The read path is fine (pdp.ts:281 `open()` already dispatches
on v2 keyId shape) — it is the WRITE path that never produces v2 ids.

## Why it matters

The isolation hardening the milestone row exists for is not in effect for
the data it is about: a master-key leak still opens every tenant's sealed
evidence, which is exactly what per-tenant keys were supposed to shrink.
Claim-vs-code drift on a security control (SECURITY_PRINCIPLES defect bar).

## Minimal fix

Wire the three write sites to `sealFor(principalTenantId, plaintext,
classification)` (runtime.ts:428 and guard.ts's two call sites — the
tenant comes from the principal/ctx already in scope); the decrypt
authorization resource becomes the v2 keyId
(`evidence-key:v2:<tenant>:<level>`), so clearance capabilities for that
tenant's level authorize `openFor` (pdp.ts:281 path passes the principal's
tenant). Tests: a session in tenant A produces v2-keyed sealed content that
tenant A's clearance decrypts and tenant B's does not (cross-tenant open →
undefined); legacy sealed records still open (no re-encryption). If wiring
is deferred, the alternative is amending the three docs to say derivation
landed but the write path still seals globally — but the wiring is the
right fix and small.
