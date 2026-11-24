# aiSL 0.1.2

Patch release. No API change.

## Fix

The offline evidence verifier rejected a valid bundle when an event carried a
redacted `value: undefined` metadata field. The bundle exporter hashed the raw
event, turning that key into `"value": null`, while the event had been signed
with the key dropped. The exporter now builds every event from the same
normalized body used for hashing and signing, so the exported bundle verifies.

Reported as `seq 27: eventHash recomputation mismatch`. The demo now prints
`offline verifier (no DB): VALID`.

## Verified

- 879 tests, 857 pass, 22 Postgres skips, 0 fail
- 893 tests, 893 pass with a disposable Postgres 16, 0 skip
- signed build manifest
- CI green on Node 22 and 24

Install: `npm install -g @kcpatt27/aisl@0.1.2`
