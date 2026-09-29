# COMPLIANCE

Mapping, not certification. Nothing here is a claim of compliance. Implementing a
control is not the same as being audited against it, and neither is the same as
being certified.

Format per row: Requirement / component / status / gap / evidence required /
implementation needed / external validation needed.

---

## NIST Cybersecurity Framework 2.0

| Req | Component | Status | Gap | Evidence | Implementation | External validation |
| --- | --- | --- | --- | --- | --- | --- |
| GV-01 policy & governance | this doc set | partial | no formal policy set, no owner | doc set + review records | written policies, review cadence | no |
| ID-AM identity & authn | none | **absent** | no authentication at all | authn event log | OIDC + MFA (ADR-006) | yes, penetration test |
| ID-AM-08 (service identities) | Principal kinds | design only | no workload identity | service authn events | workload identity | yes |
| PR-AA-01 least privilege | capabilities | implemented | operator scope discipline | capability issuance events | approval workflow | yes |
| PR-AA-05 separation of duties | Approvals | implemented | no authenticated approver | approval records | M2 | yes |
| PR-DS-01 confidentiality at rest | none | **absent** | no encryption at rest | encryption config | envelope encryption + KMS | yes |
| PR-DS-02 integrity | capability signatures, event chain + per-event Ed25519 + anchor | partial | DB at-rest unencrypted; key rotation not implemented | verify() + verifyBundle() output | M3 done, key rotation HARD | yes |
| PR-PS-06 secure disposal | none | absent | no retention or deletion policy | retention records | retention lifecycle | yes |
| DE-AE-03 event correlation | EventLog | partial | no shipping, no alerting | queryable evidence | OTel + SIEM export | no |
| DE-AE-06 deletion/destruction alerts | none | absent | no detection for destructive actions | alert records | verification plane + alerting | no |
| DE-CM-06 incident drill | none | absent | no IR plan | game-day report | H13 | yes |
| RS-MA-02 remediation | supply-chain gate (H10) | partial | no patch process as operations; dependency freshness is gated (SBOM diff, exact pins, integrity verification) | `npm run supply-chain` output + `artifacts/sbom.json` history | patch cadence + review records (process) | yes |
| RC-CO communication | none | absent | no notification process | notification records | operating model | yes |

## NIST SP 800-53 (selected, representative)

| Control | Component | Status | Gap | Evidence | Implementation | External |
| --- | --- | --- | --- | --- | --- | --- |
| AC-3 access enforcement | PDP | implemented | policy not signed | decision events | policy signing | yes |
| AC-4 information flow | capability scope, egress | partial | no real egress enforcement | gateway decisions | M1, H7 | yes |
| AC-6 least privilege | capabilities | implemented | — | issuance events | — | yes |
| AC-17 remote access | none | absent | no product surface yet | — | future | yes |
| AU-2/3/12 audit events | EventLog | implemented | signed (M3), anchored when configured | chain verification + signature verification | M3 | yes |
| AU-9 protection of audit info | EventLog + append-only triggers | partial | anchor lives on attacker-accessible storage by default; SQLite is not WORM | — | anchor on WORM/witness storage is HARD stage | yes |
| CM-3 configuration change | none | absent | no change control | — | change management | yes |
| IA-2/IA-5 authentication | none | absent | no authn | — | M2 | yes |
| SC-7 boundary protection | NetworkGateway | design only | no enforcement | — | M1 | yes |
| SC-8 transmission confidentiality | none | absent | no transport | — | TLS everywhere | yes |
| SC-12 key management | capability key (env) | weak | env var, no rotation, no HSM | — | ADR-008 | yes |
| SC-28 protection at rest | none | absent | — | — | encryption | yes |
| SI-10 information input validation | `parseModelOutput` | implemented | model output only | parser tests | extend to all inputs | no |
| SI-7 software integrity | build manifest signing (H10) | partial | dev-key custody (encrypted SSD + offline bank HDD); first manifest signed 2026-09-29; gate verifies pins/integrity/SBOM | `build verify` output + manifest + signature | CI signing + HSM custody (ADR-008) | yes |

## NIST SP 800-207 (Zero Trust)

| Pillar | Status | Gap |
| --- | --- | --- |
| Identity | absent | no IdP, no MFA, no device posture |
| Device | absent | no device inventory or attestation |
| Network | design only | no micro-segmentation or proxy |
| Application/workload | partial | capabilities exist; no workload identity |
| Data | partial | classification exists; no encryption or DLP |
| Visibility & analytics | partial | events exist; no analytics or alerting |
| Automation & orchestration | partial | decisions are automated; response is not |

## OWASP

| Item | Status | Notes |
| --- | --- | --- |
| ASVS (web) | N/A | no web surface yet |
| LLM01 prompt injection | **architecture** | data/authority split; detector is not the control (ADR-011) |
| LLM02 insecure output handling | partial | whitelist parser; no output encoding for downstream systems yet |
| LLM03 training-data poisoning | N/A | no training, no fine-tuning |
| LLM04 model DoS | absent | no quotas, timeouts, or budgets |
| LLM05 supply chain | partial | 2 runtime deps exact-pinned + integrity-verified; SBOM diffed on every build; signed build manifests (H10); signing-key custody + transparency log remain |
| LLM06 sensitive info disclosure | partial | secrets denied by default; no DLP on outputs |
| LLM07 insecure plugin design | partial | scoped tool context; no isolation |
| LLM08 excessive agency | **core strength** | capabilities, ceilings, approvals |
| LLM09 overreliance | partial | verification plane exists; no human review workflow |
| LLM10 model theft | N/A | no model hosted |

## SOC 2 Trust Services Criteria (mapping only)

| Criterion | Status | Gap |
| --- | --- | --- |
| CC6.1 logical access | partial | authn absent |
| CC6.2 registration/authorization | partial | no self-service, no review cadence |
| CC6.3 access modification/removal | absent | no deprovisioning |
| CC6.6 boundary protection | partial | no egress enforcement |
| CC6.7 transmission/movement | partial | no encryption, no DLP |
| CC6.8 unauthorized software | absent | no change control |
| CC7.2 monitoring | partial | events exist, no alerting |
| CC7.3/7.4 incident | absent | no IR plan |
| CC8.1 change management | absent | no SDLC controls |
| A1.2 availability | absent | no SLAs, no HA, no DR |

## ISO/IEC 27001 (Annex A, selected)

A.5 (policies) absent; A.8 (asset management) partial via registry; A.9 (access
control) partial; A.10 (cryptography) weak — env-var key, no rotation; A.12
(operations security) partial — logging yes, malware protection no, backup no;
A.13 (communications) absent; A.14 (system acquisition/development) partial —
ADRs exist, secure SDLC does not; A.15 (supplier) absent; A.16 (incident)
absent; A.17 (BCP/DR) absent; A.18 (compliance) partial — this mapping.

## HIPAA Security Rule (if deployed with PHI)

| Standard | Status | Gap |
| --- | --- | --- |
| §164.308(a)(1) risk analysis | partial | THREAT_MODEL exists; no formal risk register |
| §164.308(a)(3) workforce security | absent | no HR controls |
| §164.308(a)(4) information access mgmt | partial | capabilities; no authenticated users |
| §164.308(a)(5) security awareness | absent | no training |
| §164.308(a)(6) incident procedures | absent | H13 |
| §164.308(a)(7) contingency plan | absent | no DR |
| §164.310 physical safeguards | N/A | deployment-dependent |
| §164.312(a)(1) access control | partial | no unique user identification yet |
| §164.312(a)(2)(i) emergency access | absent | no break-glass procedure |
| §164.312(b) audit controls | implemented | unsigned but chained |
| §164.312(c)(1) integrity | partial | capability signatures |
| §164.312(d) person/entity authentication | absent | M2 |
| §164.312(e)(1) transmission security | absent | no transport |

**Encryption alone is not HIPAA compliance. Audit logs alone are not SOC 2.**
Both require process, people, and an external assessor.

## Privacy (GDPR/CCPA-style)

Data minimisation: partial (capability scope). Purpose limitation: absent (no
purpose binding on capabilities — worth adding). Subject rights: absent (no
export/delete path for a data subject). Residency: absent. Retention: absent.
DPIA: not performed.

## Government / high assurance

Claiming FedRAMP, StateRAMP, IL4/IL5, or classified readiness at this stage would
be fraudulent. The architectural preconditions are listed in the VERY HARD stage
of ROADMAP.md: hardware-backed keys, attestation, reproducible builds, controlled
update channels, air-gapped operation, and cross-domain transfer controls. Until
those exist and are independently assessed, the only honest statement is:
"architected for, not authorized for."

## Rules this project follows

1. A control is "implemented" only when a test asserts it.
2. A control is "compliant" only after an external assessor says so.
3. Every framework row above is updated by evidence, never by intention.
