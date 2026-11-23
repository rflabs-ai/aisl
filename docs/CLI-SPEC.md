# aisl CLI specification

The contract for the `aisl` command line. This is design, not implementation:
the code follows the spec, not the other way round.

Status: design, 2026-11-17. Target: the 1.0 surface. Today's surface differs in
the places listed in [Migration](#13-migration). Ticket 20 builds `serve` from
[section 10](#10-serve-contract); the other changes land one command at a time.

The binary is `aisl`, always lowercase, spoken "aisle" (`BRAND.md`). Every
string the CLI prints says `aisl`, never `ASL` or `AISL`.

---

## 1. Read this page and you can use it

Five commands cover the common path:

| You want to | Run | You get |
| --- | --- | --- |
| see it work | `aisl demo` | the acceptance walkthrough, no keys, no config |
| know this host can run it | `aisl doctor` | a check table, exit 1 on any failure |
| run the enforcement plane | `aisl serve --port 8787` | REST on loopback, evidence in a local store |
| prove an artifact is the signed one | `aisl verify build` | exit 0 only when signature and tree match |
| stop an incident | `aisl incident engage global --reason "..."` | freeze, revoke, broadcast |

A first `serve` needs durable keys or the explicit throwaway override; section
3.1 shows that form. `verify` needs an artifact to check. The rest run in a
clean checkout.

`doctor` asks whether this host can run `aisl`. `verify` asks whether an
artifact is the one that was signed. If `doctor` fails, nothing `verify` says
can be trusted.

### The three rules that explain the rest

1. **A noun command with no verb does the read-only default.** `aisl verify`
   checks what is present, `aisl incident` prints status, `aisl build` runs the
   gate. A bare noun command never mutates.
2. **Required operands are positional; optional inputs are flags.** There are no
   optional positional operands. Free text is always `--reason "..."`. A second
   identifier of the same shape is a named flag (`--tenant`) so two ids cannot
   be swapped by accident.
3. **Every line starts with a verdict word.** `PASS`, `FAIL`, `WARN`, `INFO`,
   `SKIP`, `ALLOW`, `DENY`. Color is reinforcement, never the message.

## 2. Command tree

| Command | Job | Today |
| --- | --- | --- |
| `aisl serve` | run the REST enforcement plane | new, ticket 20 |
| `aisl doctor` | check this host and config | new |
| `aisl demo` | the acceptance walkthrough | today |
| `aisl verify` / `verify build` / `verify update` / `verify evidence` | read-only cryptographic checks | rename, plus a new bare form |
| `aisl benchmark` | measure the assurance targets, write an artifact | today, `--json` new |
| `aisl corpus run` / `corpus check` | run the security corpus; check the pins | rename of `attack` and `adversarial` |
| `aisl policy analyze` / `policy golden` | analyze rules; verify or re-bless the golden set | today, optional file becomes `--rules` |
| `aisl evidence status` / `checkpoint` / `hold` / `release` | operate the evidence plane | today, optional positionals become flags |
| `aisl incident status` / `engage` / `lift` / `revoke` / `preserve` / `report` | operate an incident | today, `revoke-*` becomes `revoke` |
| `aisl build gate` / `sbom` / `keygen` / `sign` | attest the build | today, `verify` moves |
| `aisl update sign` / `apply` / `promote` / `status` / `grant` / `rollback` | distribute a signed update | today, `verify` moves |
| `aisl completion <shell>` | print a completion script | new |
| `aisl help [command]` | help | new as an explicit command |
| `aisl version` | version | new |

Rules the tree obeys:

- One level of command plus one level of verb. `aisl incident revoke` is the
  deepest shape.
- Top-level commands are one lowercase word, no hyphens. Verbs are full words,
  never abbreviations (`capability`, not `cap`).
- Milestone codes (`M3`, `H10`, `ADR-024`) never appear in user-facing output.
  A heading says what the thing is, not which milestone built it.

Why the renames:

- `attack` and `adversarial` are two names for one corpus, and `adversarial` is
  an adjective. A reader cannot tell which one they want. `corpus run` runs,
  `corpus check` gates.
- `revoke-cap`, `revoke-session`, `revoke-token` are a hyphen family of
  abbreviations. `revoke capability` is one verb and its object.
- `evidence verify`, `build verify`, and `update verify` are three copies of one
  idea. `verify` is promoted to level one so there is exactly one place a
  read-only cryptographic check lives. `evidence witness` folds in as
  `verify evidence --witness`.
- `build` and `update` keep their names. Each one produces an artifact with that
  name (`build-manifest.json`, `update.json`), and the release docs already use
  the words. Renaming them would touch every release document for no clarity.
- `aisl` with no arguments prints help, not `demo`. Running a long walkthrough
  because you typed the binary name is a surprise.

## 3. Commands

### 3.1 `aisl serve`

Runs the REST enforcement plane: verifies OIDC tokens, authorizes through the
PDP, appends to the signed event chain, and serves `/healthz`. Long lived and
fail closed. The full contract is [section 10](#10-serve-contract).

```bash
aiSL_ALLOW_EPHEMERAL_KEYS=1 \
aiSL_IDP_ISSUER=https://login.example.com aiSL_IDP_AUDIENCE=aisl \
aisl serve --port 8787 --principals ./principals.json
```

The override is for a first run whose evidence may die with the process; the
principals file is in [section 10.3](#103-identity-and-the-principals-file).

Exit: 0 clean shutdown, 3 config, 4 store unreachable, 70 internal, 130 forced.

### 3.2 `aisl doctor`

Checks everything `serve` and `verify` need: Node version, install layout, git
checkout, config file, durable keys, event store, TLS files, principals file,
IdP settings, signed artifacts, anchors, port, and the evidence chain. Reads
only. Never starts a server, never writes, and opens no socket except a bind
test for the port.

```bash
aisl doctor
aisl doctor --json --port 8787
aisl doctor --online            # also reach the IdP JWKS and the witness
```

Every check has a stable id: `node-version`, `install`, `git`, `config`, `keys`,
`store`, `tls`, `principals`, `idp`, `artifacts`, `anchors`, `port`, `evidence`,
`jwks`, `witness`. The `source` field says where the setting came from: `flag`,
`env`, `file`, or `default`. Scripts read `id`, never the message text.

Two flags are specific to `doctor`: `--port <n>` tests a port (default: the
configured port, or 8787), and `--online` also reaches the IdP JWKS and the
witness. Without `--online`, the run needs no egress.

A group that is entirely absent is `WARN` (you may not be serving). A group that
is half configured is `FAIL`. Any `FAIL` exits 1; `WARN` does not.

```text
$ aisl doctor
DOCTOR

  PASS   node-version              node 24.1.0, floor 22.18
  PASS   install                   git checkout, no dist/
  PASS   config                    ./aisl.config.json, no secrets
  FAIL   keys                      2 of 5 unset: CAPABILITY_SIGNING_KEY,
                                   EVIDENCE_SEALING_KEY
  FAIL   idp                       idp.issuer is set, idp.audience is not
  PASS   store                     sqlite ./data/events.sqlite, writable
  WARN   port                      8787 is in use; serve will refuse
  PASS   evidence                  120 events, chain and signatures valid

aisl doctor: 2 failures, 1 warning
```

### 3.3 `aisl demo`

The acceptance walkthrough: legitimate work succeeds, every corpus attack
behaves as specified, an approval mints a single-use capability, the replay is
denied, and the chain verifies offline. No keys and no config; it uses ephemeral
keys on purpose and says so.

```bash
aisl demo
```

Exit 1 if any section fails, naming the section. In an installed package with no
git checkout, the supply-chain sections fail by design: they digest the tracked
tree (`docs/RELEASE.md`). Use a checkout for a green demo.

### 3.4 `aisl verify`

The read-only verification command. It never signs, never writes, and never
starts a service.

```bash
aisl verify                    # every artifact present; SKIP the absent
aisl verify build              # signed manifest matches this tree
aisl verify update             # signed descriptor matches this tree
aisl verify evidence artifacts/incident-acme-0-500.json \
  --anchor ./evidence/anchor.txt --checkpoint ./evidence/checkpoint.json
```

Bare `verify` surveys what is present and exits 3 when nothing is, so a CI step
cannot pass by verifying nothing. An explicit subject fails (3) when its
artifact is absent; that difference is deliberate.

```text
aiSL VERIFY

  PASS   build manifest            signed tree matches the live tree
  SKIP   update                    no update descriptor on this host
  SKIP   evidence                  no bundle named on the command line
```

Exit: 0 verified, 1 refused, 2 usage, 3 nothing to verify or unreadable input,
4 witness unreachable. `--require-anchor` turns `UNANCHORED` into exit 1.

### 3.5 `aisl benchmark`

Runs the measured assurance targets and writes a result artifact. A hard miss
exits 1. Latency targets are advisory and only `WARN`, because a noisy CI
machine is not a security finding.

```bash
aisl benchmark
aisl benchmark --out .scratch/results.json
aisl benchmark --json
```

The artifact keeps its current shape (`benchmarks/results.json`) and gains
`schemaVersion`. `--json` prints that document to stdout and nothing else.

### 3.6 `aisl corpus`

One corpus, two questions.

```bash
aisl corpus run                # did every case behave as specified?
aisl corpus check              # do the pins still hold, and does the policy
                               # still disagree with every mutant?
aisl corpus check --bless      # re-pin after a reviewed change
```

`run` was `attack`: it sounds like the tool attacks you. `check` was
`adversarial`: an adjective does not say what the command does. `run` is the
regression test; `check` is the pinned gate, and `--bless` is the only thing
that rewrites a committed oracle. The diff is the review.

Exit 1 on a case that did not behave, on digest drift, or on a surviving mutant.

### 3.7 `aisl policy`

```bash
aisl policy analyze                # analyzes the compiled baseline
aisl policy analyze --rules ./policies/prod.json
aisl policy golden                 # verify hash and every expected decision
aisl policy golden --bless         # rewrite the golden set, review the diff
```

`analyze` reports `unreachable`, `shadowed`, `ambiguous-allow`, and
`unknown-action` findings. `golden` exits 1 when the policy hash or any expected
decision moved.

### 3.8 `aisl evidence`

Operates the evidence plane. Operator commands build a world with no fixture
bootstrap, so they never mint fixture authority into a real chain.

```bash
aisl evidence status
aisl evidence checkpoint --out evidence/2026-11-17.json \
  --previous evidence/2026-11-16.json
aisl evidence hold acme 0 500 --reason "litigation hold 2026-11-17"
aisl evidence release 42 --reason "hold lifted by counsel"
```

`checkpoint` signs the current head and is meant to leave this host: it is the
external witness. `hold` and `release` are signed events; a released hold stays
in the log. `evidence verify` and `evidence witness` moved to
`aisl verify evidence`.

Exit 1 on refusal: cross-tenant hold, empty chain, or a chain this process
cannot verify under its own key.

### 3.9 `aisl incident`

```bash
aisl incident status
aisl incident engage global --reason "suspected key compromise"
aisl incident lift global --reason "contained, keys rotated"
aisl incident revoke capability cap_7f3a --tenant acme --reason "leaked"
aisl incident revoke session sess_2b --tenant acme --reason "hostile output"
aisl incident revoke token jti_9c --tenant acme --reason "token theft"
aisl incident preserve acme 0 500 --out artifacts/acme-0-500.json
aisl incident report global 0 500
```

A revocation is `PASS` only when the channel write succeeded. A local-only
broadcast is `FAIL` and exit 1, because a revocation that did not leave the
process revoked nothing on another node. In memory mode the help says so
instead of pretending the broadcast was global.

```text
INCIDENT STATUS

  PASS   freeze                    frozen: global, by operator:cli
  INFO   capabilities              3 revoked
  WARN   channel                   degraded, 1 error since start
  PASS   result                    status read
```

### 3.10 `aisl build`

Attests the build you are about to ship: SBOM, signed manifest, supply-chain
gate. It does not compile anything; `npm run build` does that.

```bash
aisl build gate                # the commit and release blocker
aisl build sbom --write
aisl build sign                # runs the full release gate first
aisl build keygen              # development only
```

`sign` refuses to sign when any gate step fails or the signing key is unset
(exit 3, not 1: your environment is wrong, the gate is not). `keygen` writes a
private key to `.build-keys/`, refuses if that path is tracked by git, and never
prints key material. `build verify` moved to `aisl verify build`.

### 3.11 `aisl update`

Distributes a signed update to a running node.

```bash
aisl update sign 2 --channel stable --stages 10,50,100
aisl update apply
aisl update promote ok
aisl update status
aisl update grant 1 --reason "canary regression"
aisl update rollback
```

`grant` and `rollback` are a pair: `grant` signs a single-use backward permit,
`rollback` consumes it. The high-water mark never lowers. A promotion needs an
explicit health signal; there is no default-healthy path. `update verify` moved
to `aisl verify update`.

### 3.12 `aisl completion`, `help`, `version`

```bash
aisl completion bash
aisl help incident
aisl --version
```

Covered in [section 11](#11-completion) and [section 12](#12-version).

## 4. Help

Every command accepts `-h` and `--help` at any position and prints help for the
innermost command, then exits 0. `aisl help <command>` is the same thing.
`aisl help nope` exits 2.

Help has a fixed shape, max 80 columns:

1. one line: `aisl <command>: <what it does>`
2. `Usage:` with the full synopsis
3. a short paragraph, only if the command needs one
4. `Example:` one runnable example, copy-pasteable
5. `Options:` one per line, aligned, wrapped below if needed
6. `Exit codes:` only the codes this command can return
7. `See also:` at most two commands

Every command section above shows a runnable example. Each help block is
generated from the same command table and follows this shape, so the help cannot
drift from the command it describes.

`aisl --help` and `aisl help` list the tree, one line per command, with the five
first-page commands marked. Unknown commands get one suggestion when the edit
distance is 2 or less:

```text
$ aisl serv
aisl: unknown command "serv"
  did you mean: aisl serve
```

### Sample: `aisl serve --help`

```text
aisl serve: run the REST enforcement plane

Usage:
  aisl serve [--host <addr>] [--port <n>] [--tls-cert <path>]
             [--tls-key <path>] [--principals <path>] [--sqlite <path>]

Binds loopback by default. A non-loopback host needs --tls-cert and
--tls-key, and is refused before a socket exists if either is missing.

Example:
  aiSL_ALLOW_EPHEMERAL_KEYS=1 \
  aiSL_IDP_ISSUER=https://login.example.com aiSL_IDP_AUDIENCE=aisl \
  aisl serve --port 8787 --principals ./principals.json

Options:
  --host <addr>        bind address (default 127.0.0.1; localhost is not
                       treated as loopback)
  --port <n>           TCP port (default 8787; 0 picks a free port)
  --tls-cert <path>    PEM certificate, read from disk
  --tls-key <path>     PEM private key, read from disk, never a PEM value
  --principals <path>  subject map (default ./principals.json)
  --sqlite <path>      event store file (default ./data/events.sqlite)
  --json               JSON log lines on stderr
  -h, --help           this help

Environment:
  aiSL_IDP_ISSUER, aiSL_IDP_AUDIENCE, aiSL_IDP_JWKS_URI,
  aiSL_IDP_ALGORITHMS, aiSL_IDP_MAX_TOKEN_LIFETIME_SEC,
  aiSL_IDP_CLOCK_TOLERANCE_SEC, EVENT_STORE, DATABASE_URL,
  MIGRATION_DATABASE_URL, EVENT_ANCHOR_PATH, EVENT_ANCHOR_WITNESS_URL,
  EVENT_SIGNING_PRIVATE_KEY_PEM, EVENT_SIGNING_PUBLIC_KEY_PEM,
  CAPABILITY_SIGNING_KEY, EVIDENCE_SEALING_KEY, SECRET_MASTER_KEY,
  aiSL_ALLOW_EPHEMERAL_KEYS

Exit codes:
  0    clean shutdown
  3    missing or unusable config
  4    store unreachable
  70   internal error
  130  forced stop

See also:
  aisl doctor    check this configuration before you start
  aisl verify    check the signed artifacts after you stop
```

### Sample: `aisl verify evidence --help`

```text
aisl verify evidence: verify a bundle offline

Usage:
  aisl verify evidence <bundle.json> [--anchor <path>]
                       [--checkpoint <path>] [--witness <url>]
                       [--require-anchor]

Checks the hash chain, every Ed25519 signature, and any anchor or
checkpoint you present. Reads no store and opens no socket unless
--witness is given.

Example:
  aisl verify evidence artifacts/incident-global-0-500.json \
    --anchor ./evidence/anchor.txt --checkpoint ./evidence/checkpoint.json

Options:
  --anchor <path>       anchor file to check the bundle head against
  --checkpoint <path>   signed checkpoint that must cover the bundle
  --witness <url>       fetch heads from the external witness
  --require-anchor      exit 1 when no source covers the head

Exit codes:
  0    verified
  1    refused
  2    usage
  3    unreadable input
  4    witness unreachable

See also:
  aisl evidence checkpoint
  aisl incident preserve
```

## 5. Output model

### Human output is the default

Results go to stdout. Errors, deprecations, and environment notes go to stderr.
`WARN` verdict rows are results and stay on stdout with the rest of the table.
One fact per line, verdict first:

```text
  PASS   build manifest            signed tree matches the live tree
  FAIL   tls                       --tls-key is not readable: ./tls/key.pem
```

Layout, at the default width of 80:

| Part | Width | Notes |
| --- | --- | --- |
| indent | 2 | always |
| verdict | 5 | `PASS`, `FAIL`, `WARN`, `INFO`, `SKIP`, `ALLOW`, `DENY` |
| gap | 2 | always |
| subject | 24 | not truncated; if longer, the detail moves to the next line |
| gap | 2 | always |
| detail | remaining | wrapped at the width, continuation at the detail column |

At 80 columns the detail gets 45 characters. A detail that does not fit starts
on the next line at the detail column (35) so it stays visually attached to its
subject. A hash, path, URL, or id is never split across lines; it moves to its
own line whole. Human output shortens a hash to 12 hex characters plus `...`;
the full value is always in `--json` and in `--full`.

The verdict vocabulary is closed:

| Verdict | Means | Color |
| --- | --- | --- |
| `PASS` | the check ran and held | green |
| `FAIL` | the check ran and did not hold | red |
| `WARN` | held, but something needs attention | yellow |
| `INFO` | a fact, no verdict | none |
| `SKIP` | not applicable here | none |
| `ALLOW` | a policy decision permitted the action | none |
| `DENY` | a policy decision refused the action | none |

`ALLOW` and `DENY` are uncolored on purpose. In the attack corpus a `DENY` is the
desired result; painting it red would teach the wrong thing. Color encodes the
verdict, not the policy decision.

A state word (`FROZEN`, `UNANCHORED`, `DEGRADED`, `REVOKED`) belongs in the
detail, never in the verdict column.

Headings are a blank line, the name in capitals, and a blank line. No rule of
dashes: it is screen-reader noise and adds nothing.

### `--json` is the machine contract

`--json` writes exactly one JSON document to stdout, including when the command
fails. Nothing else goes to stdout, and stderr stays empty unless `--debug` is
set. The exit code is still the answer. `--json` is read before any other flag is
validated, so a usage error is still a JSON document when JSON was requested.
JSON output never contains ANSI escapes, whatever `--color` says.

```json
{
  "schemaVersion": 1,
  "command": "verify.evidence",
  "aisl": "0.1.0",
  "node": "22.18.0",
  "startedAt": "2026-11-17T12:00:00.000Z",
  "durationMs": 41,
  "ok": true,
  "exitCode": 0,
  "data": {
    "subject": "evidence",
    "valid": true,
    "unanchored": false,
    "bundlePath": "C:\\work\\acme\\artifacts\\incident-acme-0-500.json",
    "eventCount": 120,
    "sources": [
      { "name": "anchor-file", "lines": 120, "headSeq": 119,
        "matchesBundleHead": true }
    ],
    "checkpoint": null,
    "fork": null
  },
  "warnings": [],
  "errors": []
}
```

Field rules:

- Keys are `camelCase`. No exceptions.
- Every documented field is always present. "Does not apply" is `null`; an
  empty list is `[]`; never omit a field to mean null.
- Timestamps are RFC 3339 UTC with `Z`. Durations are integer milliseconds with
  an `Ms` suffix.
- Hashes are full lowercase hex, never truncated. Counts are numbers, never
  strings. Booleans are `true` and `false`, never `"yes"`.
- Enum values are lowercase: `allow`, `deny`, `pass`, `fail`, `warn`, `skip`,
  `info`, `verified`, `refused`, `unanchored`.
- Paths are absolute, resolved against the current directory, because a machine
  reading the result later is not in the same directory.
- `data` mirrors the human output. If a human line states a fact, the fact is in
  `data`.
- Adding a field does not bump `schemaVersion`. Renaming or removing one does.
- The exception is a document that is itself an artifact (`build sbom`, the
  `benchmark` metrics): it keeps its own published shape.

`--quiet` and `--verbose` change human output only. `--json` is always complete,
so a script never has to pass `--verbose` to get a fact.

`data` by command:

| Command | `data` |
| --- | --- |
| `doctor` | `{ checks: [{ id, status, detail, source }] }` |
| `demo` | `{ sections: [{ id, status, detail }] }` |
| `verify` | `{ subjects: [{ subject, valid, reason }] }` |
| `verify build` | `{ subject, valid, manifestPath, gitHead, signedTree, liveTree, reason }` |
| `verify update` | `{ subject, valid, descriptorPath, releaseVersion, channel, highWaterMark, reason }` |
| `verify evidence` | `{ subject, valid, unanchored, bundlePath, eventCount, sources, checkpoint, fork }` |
| `benchmark` | the metrics document, plus `{ slo: { pass, hardFailures, targets } }` |
| `corpus run` | `{ passed, total, cases: [{ id, status, detail }] }` |
| `corpus check` | `{ passed, lanes: [{ lane, passed, detail }], digests, baseline }` |
| `policy analyze` | `{ findings: [{ severity, kind, rules, detail }], errors, warnings, points }` |
| `policy golden` | `{ policyHash, hashMatches, expected, mismatches }` |
| `evidence status` | `{ chain, anchor, witness, holds }` |
| `evidence checkpoint` | `{ path, seq, digest, previousSeq }` |
| `evidence hold` / `release` | `{ eventSeq, tenantId, fromSeq, toSeq, reason }` |
| `incident status` | `{ frozen, freezes, revokedCapabilities, channel }` |
| `incident engage` / `lift` | `{ scope, tenantId, frozen, capabilitiesRevoked, sessionsRevoked, broadcastOk }` |
| `incident revoke` | `{ kind, targetId, tenantId, broadcastOk }` |
| `incident preserve` | `{ path, events, digest, chainValid }` |
| `incident report` | `{ events, decisions, revocations, freezes, lifts, actions, denyReasons, actors }` |
| `build gate` | `{ passed, digest, packages, violations, drift }` |
| `build sbom` | the SBOM document |
| `build keygen` | `{ privatePath, publicPath }` |
| `build sign` | `{ manifestPath, signaturePath, treeDigest, sbomDigest }` |
| `update sign` | `{ descriptorPath, signaturePath, releaseVersion, channel, stages }` |
| `update apply` | `{ applied, releaseVersion, highWaterMark, rollout }` |
| `update promote` | `{ status, stageIndex, pendingVersion, haltReason }` |
| `update status` | `{ highWaterMark, current, rollout, rollbackGeneration }` |
| `update grant` | `{ grantPath, targetVersion, fromVersion, generation }` |
| `update rollback` | `{ current, highWaterMark }` |
| `version` | `{ aisl, node, platform, arch, gitHead }` |

`serve` is the one data command with no envelope: a long-lived process has no
single result. Its `--json` means one JSON log object per line on stderr. `help`
and `completion` print text by definition and refuse `--json` with
`usage.unsupported-flag` (exit 2), so a script never mistakes a help page for a
result document.

### Global flags

| Flag | Short | Meaning |
| --- | --- | --- |
| `--json` | | machine output, one document on stdout (`serve`: JSON logs) |
| `--quiet` | `-q` | suppress headings and `INFO`, keep verdicts and errors |
| `--verbose` | `-v` | add per-case rows and full detail text |
| `--full` | | do not shorten hashes or ids |
| `--no-color` | | same as `--color never` |
| `--color <mode>` | | `auto`, `always`, `never` (default `auto`) |
| `--width <n>` | | 60 to 120, default 80 |
| `--debug` | | stack traces and redacted internals |
| `--config <path>` | | config file, default `./aisl.config.json` |
| `--help` | `-h` | help for the innermost command, exit 0 |
| `--version` | `-V` | version, top level only |

Short flags exist only for `-h`, `-V`, `-q`, and `-v`. Everything else is long,
so a typo cannot become a destructive short flag. `--quiet` and `--verbose`
together: `--quiet` wins.

## 6. Error model

Errors are typed, one line of verdict, one line of cause, one line of next
action. The line is `aisl: <command> <verdict>: <message>`. Exit code 0 means
the command did what you asked; every other code means something specific:

| Code | Meaning | Example |
| --- | --- | --- |
| 0 | the command did what you asked | verify passed, gate passed |
| 1 | a check ran and the answer is no | signature refused, SLO missed, drift |
| 2 | usage | unknown command or flag, bad operand |
| 3 | config or input missing | durable key unset, principals file absent, bad TLS |
| 4 | could not reach what the check needs | store down, witness unreachable |
| 70 | internal error, a bug | unhandled exception |
| 130 | forced stop | second SIGINT during shutdown |

Code 4 exists so "could not check" is never confused with "checked, and no".
That is the difference between a false alarm and a real one at 3am. CI that only
cares about pass or fail treats any nonzero as fail, which stays correct.

When a run could return more than one, the order is fixed: an input error (3)
wins, then a definite negative (1), then an unreachable dependency (4). A bad
argument is not a security finding, and a signature that failed is not made
ambiguous by a witness that is down.

Human form:

```text
$ aisl verify build
aisl: verify refused: the signed manifest does not match this tree
  code:  verify.manifest-mismatch
  cause: signed tree 3f2a9c0d4e11... does not match live tree 91bc44ae7f02...
  fix:   check out the signed commit, or re-sign with aisl build sign
```

`--json` form, in `errors`:

```json
{
  "code": "verify.manifest-mismatch",
  "message": "the signed manifest does not match this tree",
  "detail": {
    "manifestPath": "C:\\work\\acme\\artifacts\\build-manifest.json",
    "treeMatches": false,
    "signedAt": "2026-11-17T11:00:00.000Z"
  },
  "fix": "check out the signed commit, or re-sign with aisl build sign",
  "stack": null
}
```

`stack` is `null` unless `--debug` or `aiSL_DEBUG=1`. No command ever prints a
stack trace by default.

Error codes are stable strings in a dotted namespace, lowercase kebab:

| Prefix | Used for |
| --- | --- |
| `usage.` | `unknown-command`, `unknown-flag`, `missing-operand`, `unexpected-operand`, `invalid-value`, `unsupported-flag`, `secret-in-argv` |
| `config.` | `missing-key`, `missing-idp`, `missing-principals`, `missing-database-url`, `unreadable-file`, `invalid-file`, `invalid-key`, `secret-in-file`, `insecure-bind`, `bind-failed`, `conflict` |
| `store.` | `unavailable`, `refused` |
| `verify.` | `signature-invalid`, `manifest-mismatch`, `descriptor-mismatch`, `anchor-mismatch`, `unanchored`, `nothing-to-verify` |
| `evidence.` | `no-chain`, `unverifiable-chain`, `hold-refused` |
| `update.` | `descriptor-missing`, `rollback-refused`, `rollout-halted`, `mark-refused` |
| `incident.` | `frozen`, `scope-refused` |
| `policy.` | `invalid`, `drift` |
| `corpus.` | `regressed`, `baseline-invalid` |
| `benchmark.` | `slo-miss` |
| `internal.` | `unexpected` |

Rules:

- One error boundary. Command handlers throw a typed `CliError` with `code`,
  `exitCode`, `detail`, and `fix`. The dispatcher formats it and sets the exit
  code once. No handler calls `process.exit`.
- The verdict word is one of `refused`, `failed`, `unavailable`, `invalid
  usage`, `internal error`, and it matches the exit code.
- A `fix` is mandatory for exit 2 and 3, because those are the two the user can
  act on. It is optional for 1 and 4, and absent for 70.
- Never echo `argv`. Echo the flag name and a sanitized value (basename for
  paths, first 12 characters for ids).
- Never include a JWT, a PEM, a connection string, or the value of any variable
  whose name ends in `KEY`, `PEM`, `SECRET`, or `TOKEN`. Name the variable, not
  its value. Redaction still runs, as a second line of defense.

## 7. Configuration

Precedence, highest first:

1. flag
2. environment variable
3. config file
4. built-in default

Resolution happens once at startup. There is no file watching, no reload, and
no hot config: restart the process. A resolution algorithm that changes under a
running server is an incident, not a feature.

The config file is `./aisl.config.json`, or the path in `--config` or
`aiSL_CONFIG`. A path named explicitly that does not exist is exit 3. The
default path, when absent, is simply no config file. There is no parent
directory walk and no home directory config, because a config you cannot see is
a config that surprises you.

The file is strict JSON: UTF-8, no comments, no trailing commas. `JSON.parse`
is the parser, which is zero dependencies and no new attack surface.

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "tls": { "certPath": "./tls/cert.pem", "keyPath": "./tls/key.pem" },
  "principalsPath": "./principals.json",
  "sqlitePath": "./data/events.sqlite",
  "output": { "color": "auto", "width": 80 },
  "benchmark": { "outPath": "benchmarks/results.json" },
  "incident": { "operator": "operator:cli" },
  "idp": {
    "issuer": "https://login.example.com",
    "audience": "aisl",
    "jwksUri": "https://login.example.com/.well-known/jwks.json",
    "algorithms": ["RS256", "ES256"],
    "maxTokenLifetimeSec": 3600,
    "clockToleranceSec": 30
  }
}
```

An unknown key is exit 3 with a suggestion. A typo must not silently disable a
check.

A secret may not appear in the config file. The loader refuses a leaf key that
ends in `Key`, `Secret`, `Token`, `Password`, `Pem`, or `Credential`, unless it
also ends in `Path` or `Url`. It also refuses any string value that parses as a
URL with an inline password, whatever the key is called. Secrets come from the
environment, by reference. That rule is what keeps a config file safe to commit
or paste into a ticket.

An empty environment variable is unset, never "empty string". A boolean env
variable is `1`/`true` (any case) or `0`/`false`; anything else is exit 3.
`aiSL_ALLOW_EPHEMERAL_KEYS` is the exception: it is `1`, exactly, because that
is the existing fail-closed behavior.

### Settings

| Setting | Flag | Environment | Config key | Default |
| --- | --- | --- | --- | --- |
| bind address | `--host` | `aiSL_HOST` | `host` | `127.0.0.1` |
| port | `--port` | `aiSL_PORT` | `port` | `8787` |
| TLS certificate | `--tls-cert` | `aiSL_TLS_CERT` | `tls.certPath` | none |
| TLS private key | `--tls-key` | `aiSL_TLS_KEY` | `tls.keyPath` | none |
| principals file | `--principals` | `aiSL_PRINCIPALS` | `principalsPath` | `./principals.json` |
| SQLite store | `--sqlite` | `aiSL_SQLITE_PATH` | `sqlitePath` | `./data/events.sqlite` |
| config file | `--config` | `aiSL_CONFIG` | n/a | `./aisl.config.json` |
| color | `--color`, `--no-color` | `NO_COLOR` | `output.color` | `auto` |
| width | `--width` | `COLUMNS` | `output.width` | `80` |
| debug | `--debug` | `aiSL_DEBUG` | n/a | off |
| benchmark output | `--out` | `aiSL_BENCHMARK_OUT` | `benchmark.outPath` | `benchmarks/results.json` |
| incident actor | none | `INCIDENT_OPERATOR` | `incident.operator` | `operator:cli` |
| IdP issuer | none | `aiSL_IDP_ISSUER` | `idp.issuer` | none |
| IdP audience | none | `aiSL_IDP_AUDIENCE` | `idp.audience` | none |
| IdP JWKS | none | `aiSL_IDP_JWKS_URI` | `idp.jwksUri` | issuer discovery |
| IdP algorithms | none | `aiSL_IDP_ALGORITHMS` | `idp.algorithms` | `RS256,ES256` |
| token lifetime ceiling | none | `aiSL_IDP_MAX_TOKEN_LIFETIME_SEC` | `idp.maxTokenLifetimeSec` | `3600` |
| clock tolerance | none | `aiSL_IDP_CLOCK_TOLERANCE_SEC` | `idp.clockToleranceSec` | `30` |
| event backend | none | `EVENT_STORE` | none | SQLite for `serve`, memory elsewhere |
| ephemeral key override | none | `aiSL_ALLOW_EPHEMERAL_KEYS` | none | off |

Backend selection is deliberately environment-only. A typo in argv cannot point
a server at a different evidence store. There is also no `--database-url`: a
connection string contains a password, and argv is world readable.

### Key material and deployment inputs

These are read by the code and have no flag. Secret values are never printed;
public values are shown at most as a fingerprint.

| Variable | Secret | Used by |
| --- | --- | --- |
| `CAPABILITY_SIGNING_KEY` | yes | `serve` |
| `EVENT_SIGNING_PRIVATE_KEY_PEM` | yes | `serve`, persistent stores |
| `EVENT_SIGNING_PUBLIC_KEY_PEM` | no | `serve`, `verify`, `evidence` |
| `EVIDENCE_SEALING_KEY` | yes | `serve`, persistent stores |
| `SECRET_MASTER_KEY` | yes | `serve` |
| `DATABASE_URL` | yes | Postgres store |
| `MIGRATION_DATABASE_URL` | yes | Postgres migrations |
| `EVENT_ANCHOR_PATH` | no | event appends, `evidence checkpoint` |
| `EVENT_ANCHOR_WITNESS_URL` | no | `serve`, `evidence`, `verify evidence` |
| `EVENT_ANCHOR_WITNESS_TOKEN` | yes | `verify evidence --witness` |
| `BUILD_SIGNING_PRIVATE_PEM` | yes | `build sign`, `update sign`, `update grant` |
| `BUILD_SIGNING_PUBLIC_PEM` | no | `verify build`, `verify update`, `update rollback` |
| `BUILD_SIGNING_IDENTITY` | no | signed manifest and descriptor label |
| `NO_COLOR`, `COLUMNS`, `TERM` | no | output |

Naming rule: CLI-owned variables use `aiSL_`. The unprefixed names
(`CAPABILITY_SIGNING_KEY`, `EVENT_*`, `BUILD_SIGNING_*`, `DATABASE_URL`) predate
the rule, are documented in `README.md` and `DEPLOYMENT.md`, and are read by
`src/key-policy.ts`. They are frozen until 1.0. Adding an alias for each would
create two names for one setting, which is how a server gets misconfigured.

## 8. Security

### No secret in argv

- No flag accepts key material. `--tls-key` and `--tls-cert` take paths; the
  files are read after parsing.
- Before dispatch, every flag value is checked. A value containing a PEM header
  (`-----BEGIN`), a JWT shape (`eyJ` plus 20 characters), or a URL with an
  inline password is refused with `usage.secret-in-argv` and exit 2. Nothing
  runs.
- `--reason` text is written to the evidence log. The help says so on the same
  line it introduces the flag. Redaction still applies.
- `DATABASE_URL`, `MIGRATION_DATABASE_URL`, `EVENT_ANCHOR_WITNESS_TOKEN`, and
  every `*_KEY` / `*_PEM` / `*_SECRET` value are read from the environment only.

### Redaction

One function runs at the output boundary, over stdout, stderr, JSON, and logs:

- exact values of every non-empty secret variable, including the password part
  of a connection string
- world canaries and sealed secret values
- `Bearer <token>` and JWT-shaped strings
- PEM blocks

Replacement is `[redacted]`, whole. Never a prefix: a prefix of a short key is
still key material. The public key is not a secret and is printed as usual.

Acceptance test: for every command that can fail, set a distinct sentinel in
each secret variable and assert the sentinel appears in no output stream, with
and without `--json` and `--debug`.

### Color and logs

`NO_COLOR` (any non-empty value) disables color. `TERM=dumb` disables it. A
non-TTY disables it. `--color=always` overrides all three, because an explicit
flag is more specific than the environment, and it is the only way to capture a
colored screenshot.

`serve` logs to stderr. Human lines are one request per line; JSON lines are one
object per line. Neither ever contains an `Authorization` header, a token, a
request body, a query string (it can carry a token), a capability secret, or key
material. The startup banner prints a public-key fingerprint, never the key.

## 9. Accessibility

- **No color-only meaning.** The verdict word is always printed. Color is
  redundant. A `DENY` in a passing attack case is not red, because the color
  encodes the verdict, not the decision.
- **80 columns by default.** `--width` accepts 60 to 120; `COLUMNS` is honored
  when the flag is absent. Help is tested at 60 and 120.
- **ASCII only** in help and output: no em dash, curly quote, emoji, box
  drawing, or spinner. Windows code pages, screen readers, and copy-paste all
  behave.
- **No motion.** No in-place redraw, cursor movement, progress spinner, or bell.
  Progress is one line per completed section, which also leaves a usable log.
- **One fact per line.** No terminal tables in results. Help options are one per
  line; a description wraps below its flag rather than forming a column.
- **Nothing splits a token.** A hash, path, URL, or id moves to the next line
  whole. A truncated hash is always 12 characters plus `...`, never a bare
  fragment.
- **Plain words.** "refused" not "negative authorization outcome"; "could not
  reach the store" not "dependency unavailable". The code field can be precise;
  the message is for a human.
- **Exit 2 and 3 say what next.** Input and config errors always carry a `fix`
  line. Exit 1 and 4 say what happened; the operator decides.
- **`--json` carries everything.** A screen reader or a script never has to
  parse a human line to recover a fact.

## 10. Serve contract

This is the section ticket 20 implements. It is deliberately concrete.

### 10.1 Shape

```text
aisl serve [--host <addr>] [--port <n>] [--tls-cert <path>]
           [--tls-key <path>] [--principals <path>] [--sqlite <path>]
```

No positional operands. Six flags, all optional, plus the global flags. A
seventh serve-specific flag is a design change to this document.

### 10.2 Startup, in order

1. Parse flags and resolve config. An unknown flag exits 2 before any file or
   socket is touched.
2. Refuse if any flag value carries a connection string, a token, or key
   material (section 8).
3. Require `aiSL_IDP_ISSUER` and `aiSL_IDP_AUDIENCE` (or the config keys). One
   missing exits 3 with `config.missing-idp`, naming both.
4. Call `assertDurableKeys('server')` before opening the store. Missing keys
   exit 3 with `config.missing-key`, one line per missing variable, its reason,
   and how to produce it. The existing `MissingDurableKeysError` message is
   reused and wrapped to the width, not reworded. `aiSL_ALLOW_EPHEMERAL_KEYS=1`
   is the explicit, warned override.
5. Load the principals file. Missing exits 3 `config.missing-principals`.
   Invalid exits 3 `config.invalid-file`.
6. Resolve TLS. Both files or neither. A missing or unreadable pair exits 3.
   A non-loopback `--host` without TLS exits 3 `config.insecure-bind` before the
   world is built. Loopback is exactly `127.0.0.1` and `::1`. `localhost` is not
   loopback: the OS resolves it, so it can point anywhere.
7. Build the world with `bootstrap: false`, the identity service, and the
   store. Store open failure exits 4 `store.unavailable`.
8. Bind. Print the banner, then start logging. A bind failure exits 3
   `config.bind-failed`; the banner prints the port actually bound, never `0`.

Store selection: `EVENT_STORE=postgres` uses `DATABASE_URL`; unset or `sqlite`
uses `--sqlite`; any other value, including `memory`, is exit 3. A server whose
evidence dies with the process is a demo, not a deployment, so `serve` refuses
it instead of warning. `postgres` without `DATABASE_URL` is exit 3
`config.missing-database-url`. `--sqlite` together with `EVENT_STORE=postgres`
is exit 3 `config.conflict`, never a silently ignored flag. The other commands
keep today's behavior: `postgres` opts in, everything else is in-memory.

The banner, human mode, on stderr:

```text
aisl 0.1.0 serving
  url         http://127.0.0.1:8787
  tls         off, loopback only
  idp         https://login.example.com (audience aisl)
  store       sqlite ./data/events.sqlite
  policy      baseline, sha256 3f2a9c0d4e11...
  event key   ed25519, sha256 9c1d7a2b44e0...
  revocation  attached
  principals  3 (acme, beta)
```

With TLS the `tls` line reads `on, cert <path>`. In `--json` mode the banner is
one log object (shown wrapped here, one line in the stream):

```json
{"ts":"2026-11-17T12:00:00Z","level":"info","msg":"listening",
 "url":"http://127.0.0.1:8787","host":"127.0.0.1","port":8787,"tls":false,
 "store":"sqlite","policyId":"baseline","policyFingerprint":"3f2a9c0d4e11",
 "eventKeyFingerprint":"9c1d7a2b44e0","revocation":"attached",
 "principals":3}
```

`event key` is a fingerprint of the public key: `sha256(publicPem)`, lowercase
hex, 12 characters plus `...` in human output, the 12 characters alone in the
startup log object. A fingerprint identifies the running key; it is not a
substitute for the key itself, and it never discloses it.

### 10.3 Identity and the principals file

The token proves who the caller is. The principals file says what that subject
is allowed to be here. The file is required; there is no claim-based fallback,
because mapping authority from token claims is the trust inversion this product
exists to prevent.

```json
{
  "principals": [
    {
      "subject": "00u1abc2def3",
      "id": "user:kcpat",
      "kind": "user",
      "tenantId": "acme",
      "roles": ["operator"],
      "attributes": { "region": "us-east" }
    },
    {
      "subject": "svc_agent_build",
      "id": "agent:builder",
      "kind": "agent",
      "tenantId": "acme",
      "roles": ["worker"]
    }
  ]
}
```

- `subject` is the verified `sub` claim. Required, unique, exact match.
- `id` is the internal principal id. Required, unique.
- `kind` is one of `user`, `service`, `authorization`, `agent`, `model`, `tool`.
- `tenantId` and `roles` are required. `attributes` is optional and may hold
  strings, numbers, and booleans only.
- `auth` is refused if present. It is set from the verified token, never from
  the file.
- Unknown keys are refused. A typo in a security file is an error, not a
  default.

Mapping, in one sentence: a verified `AuthContext` looks up `subject`; a hit
becomes that `Principal` with `auth` attached, and a miss is refused at the REST
boundary with 403 `unauthenticated-principal` before the PDP sees the request.
There is no default principal and no guest.

This is `resolvePrincipal` for `startRestServer`. It must be a pure lookup: no
registration, no first-use trust, no fallback to `world.user`.

### 10.4 Policy

The server enforces the compiled `BASELINE_POLICY` plus the audit and egress
rules that `buildWorldAsync` adds. It prints the policy id and a fingerprint at
startup so the running policy is identifiable. The fingerprint is the first 12
hex characters of sha256 over the canonical JSON of the rule list and its
version, the same construction `policyBundleHash` uses.

`--policy <bundle.json>` is not in v1. A bundle loader is the next ticket, and
this document will grow a section for it. Until then, `serve` never pretends to
load a policy it did not load.

### 10.5 Health

`GET /healthz` returns `200` with:

```json
{
  "idp": "healthy",
  "store": "ok",
  "engine": "ok",
  "clock": "ok",
  "revocation": "ok"
}
```

- `idp`: `healthy`, `degraded`, or `unreachable`, from the identity provider.
- `store`, `engine`, `clock`: `ok` or `unavailable`.
- `revocation`: `ok` or `unavailable`. `unavailable` means the feed is not
  attached or its last read failed. Verification still works from local state,
  which is why this degrades instead of refusing to start.

Status is always 200 in v1, including when a field is degraded. A load balancer
reads the body. A `--strict-health` mode that returns 503 on any non-ok value is
a named follow-up, not a hidden default.

The exact routes are `GET /healthz` and `POST /v1/authorize`. Unknown paths are
closed without a response body, which is today's behavior. A JSON 404 is a
follow-up; it is not a security fix.

### 10.6 Logs

Human, one line per request:

```text
2026-11-17T12:00:01Z  ALLOW  POST /v1/authorize  200  12ms  acme  user:kcpat
```

JSON, one object per line:

```json
{"ts":"2026-11-17T12:00:01Z","level":"info","msg":"request",
 "method":"POST","path":"/v1/authorize","status":200,"durationMs":12,
 "tenant":"acme","principal":"user:kcpat","outcome":"allow","eventSeq":118}
```

Never logged: `Authorization`, any token, any request body, any query string,
any capability secret, any key material. A request that is dropped (unknown
path) logs `msg:"request-dropped"` with the method and path only.

`--json` switches the log stream to one JSON object per line. Logs always go to
stderr. stdout stays empty for the whole life of the process.

### 10.7 Shutdown

SIGINT and SIGTERM: log `shutting down`, stop accepting, drain in-flight
requests for up to 10 seconds, flush anchors, flush the incident channel, close
the store, exit 0.

A drain that times out exits 1 and names what was still open. A second signal
exits 130 immediately. The port is released before exit; a supervisor can
restart at once.

### 10.8 What `serve` does not do

- It does not mint fixture authority. `bootstrap: false`, always.
- It does not serve a UI. No static pages in v1.
- It does not invent schema. The Postgres store applies its own versioned
  migrations when `MIGRATION_DATABASE_URL` names a DDL-capable role, and
  refuses to open an unmigrated schema otherwise (exit 4). Startup never runs
  ad hoc DDL.
- It does not load a policy bundle. Baseline only in v1.
- It does not rate limit, proxy auth, set CORS headers, or terminate TLS for
  anyone else. A reverse proxy owns those. TLS is terminated in-process only
  when both files are given.
- It does not daemonize, fork, write a pid file, or restart itself. Use a
  supervisor.
- It does not watch files. Restart to pick up a new principals file, key, or
  config.
- It does not expose an admin API. Operator actions are `aisl incident` and
  `aisl evidence`, which talk to the store directly.
- It does not accept a connection string, a token, or a key on argv.

### 10.9 Acceptance for ticket 20

- `RestApiDeps` gains `port?: number`; `startRestServer` passes it through. `0`
  keeps the ephemeral port the tests rely on; `serve` defaults to 8787.
- `aisl serve --help` prints the block in section 4 and exits 0.
- Missing durable keys exit 3 before a socket exists, naming every missing
  variable.
- `aiSL_ALLOW_EPHEMERAL_KEYS=1` starts and warns once.
- `--host 0.0.0.0` without TLS exits 3 before bind; with both TLS files it
  serves HTTPS.
- `--host localhost` is treated as non-loopback.
- `GET /healthz` has `idp` and `revocation`.
- SIGTERM exits 0, the port is free, and the store is closed.
- No secret env value appears in stdout or stderr, with and without `--json`.
- A flag value containing `-----BEGIN` exits 2 and starts nothing.
- `resolvePrincipal` returns the file principal with the verified `auth`
  attached; an unknown subject is refused at the REST boundary, not mapped to a
  guest.

## 11. Completion

`aisl completion bash|zsh|fish|powershell` writes a script to stdout and nothing
else. An unknown shell exits 2 and lists the four.

```bash
# bash
source <(aisl completion bash)

# zsh
aisl completion zsh > "${fpath[1]}/_aisl"

# fish
aisl completion fish > ~/.config/fish/completions/aisl.fish

# PowerShell
aisl completion powershell | Out-String | Invoke-Expression
```

The scripts are generated from the same table that drives help and dispatch, so
a new command or long flag cannot be missing from completion. A test asserts
that every command and every long flag in the table appears in all four scripts.

Completion is static. It does not call `aisl` at completion time: that runs in
every new shell and must be instant and side-effect free. Ids are not completed;
they come from the store, which a shell must not touch.

## 12. Version

`aisl --version`, `aisl -V`, and `aisl version` print one line:

```text
aisl 0.1.0 (node 22.18.0, win32-x64)
```

`--json`:

```json
{
  "schemaVersion": 1,
  "command": "version",
  "aisl": "0.1.0",
  "node": "22.18.0",
  "startedAt": "2026-11-17T12:00:00.000Z",
  "durationMs": 3,
  "ok": true,
  "exitCode": 0,
  "data": {
    "aisl": "0.1.0",
    "node": "22.18.0",
    "platform": "win32",
    "arch": "x64",
    "gitHead": "96e77ec1a2b3c4d5e6f708192a3b4c5d6e7f8091"
  },
  "warnings": [],
  "errors": []
}
```

`gitHead` is the full 40-character HEAD when the package sits in a git
checkout, `null` otherwise. Human output may shorten it to 12 characters plus
`...`, like any hash. The version has one source: `package.json`. `--help` and
`--version` never load the config and never fail because of it; both exit 0.

## 13. Migration

Every item below is a target. Old command spellings keep working until 1.0.0,
print one `deprecated` warning (`warnings[]` in JSON, one stderr line in human
mode), and never change the exit code. Two exceptions: the no-argument default
changes immediately (there is no way to both run a demo and print help), and the
output changes land once because an output shape cannot be aliased.

| Today | Target | Why |
| --- | --- | --- |
| `aisl` (no args) runs `demo` | prints help | running a demo by accident is a surprise |
| `attack` | `corpus run` | one corpus; "attack" reads hostile |
| `adversarial` | `corpus check` | an adjective is not a command |
| `evidence verify <bundle> [anchor] [checkpoint]` | `verify evidence <bundle> --anchor --checkpoint` | one home for read-only checks |
| `evidence witness <url> [anchor]` | `verify evidence --witness <url> --anchor` | same |
| `build verify` | `verify build` | same |
| `update verify` | `verify update` | same |
| `incident revoke-cap/session/token` | `incident revoke capability/session/token` | one verb plus its object |
| `build` / `update` / `incident` / `evidence` / `policy` default subcommand | unchanged | bare noun does the read-only thing |
| `update sign <v> [channel] [stages]` | `update sign <v> --channel --stages` | no optional positionals |
| `update apply [desc] [sig]` | `update apply --descriptor --signature` | same |
| `update grant <v> <reason...>` | `update grant <v> --reason "..."` | prose is a flag |
| `update rollback [grant] [sig]` | `update rollback --grant --signature` | same |
| `evidence checkpoint [out] [previous]` | `evidence checkpoint --out --previous` | same |
| `incident preserve <...> [out]` | `incident preserve <...> --out` | same |
| `incident engage ... <reason...>` | `--reason "..."` | same |
| `policy analyze [rules.json]` | `policy analyze --rules <path>` | same |
| `benchmark` prints JSON after the table | human table; `--json` for JSON | one output mode at a time |
| `build sbom` prints JSON by default | human summary; `--json` for the SBOM | same |
| headings like `H10`, `M3`, `ASL`, and the em dash | plain names, `aisl`, ASCII punctuation | a user does not know the milestone map, and the console is not a typography showcase |
| a missing key or input exits 1 | exits 3, `config.*` | the answer is not "no", it is "not configured" |
| an unreachable store or witness exits 1 | exits 4, `store.*` or `verify.*` | could not check is not a failed check |

`package.json` scripts keep their current names (`npm run attack`,
`npm run adversarial`, `npm run supply-chain`, `npm run build:sign`,
`npm run update:verify`) until the command modules land. They are aliases, not
the interface.

## 14. Open questions

1. **Policy bundle for `serve`.** v1 enforces the compiled baseline. Should a
   first `serve` block on a bundle loader instead, or is baseline-only honest
   enough for a local run?
2. **`corpus` as a name.** It is precise to an auditor and unfamiliar to
   everyone else. Keep it, or use `test` and accept the collision with
   `npm test`?
3. **Exit 4.** Confirm no CI consumer assumes "nonzero means the check ran and
   failed". A store outage must not look like a signature failure.
4. **Postgres schema on start.** The store applies its versioned migrations
   when `MIGRATION_DATABASE_URL` is set. Should `serve` instead require a
   pre-migrated schema and never hold DDL credentials?
5. **Alias lifetime.** One minor release, or every alias until 1.0.0? The table
   above assumes until 1.0.0.
6. **Config discovery.** Current-directory only, by design. Confirm no parent
   walk and no per-user config before someone asks for one.
7. **`doctor` network checks.** Local by default, `--online` for JWKS and the
   witness. Confirm that a doctor run in CI should not need egress.

## 15. References

- `src/cli.ts`: today's dispatcher and the command bodies (ticket 11 splits it).
- `src/server.ts`: `startRestServer`, the production assembly.
- `src/rest-api.ts`: `GET /healthz`, `POST /v1/authorize`, loopback and TLS
  refusal.
- `src/identity.ts`: `IdPConfig`, token admission, IdP health.
- `src/key-policy.ts`: durable keys, `MissingDurableKeysError`, the override.
- `src/scenario.ts`: `buildWorldAsync`, `WorldOptions`, store selection.
- `src/events.ts`: `EventLog`, the anchor file, the bundle verifier.
- `tickets/20-serve-cli.md`: the implementation ticket this section feeds.
- `tickets/21-cli-design-spec.md`: this document's ticket.
- `README.md`, `docs/RELEASE.md`, `BRAND.md`, `AGENTS.md`: the constraints this
  spec is written inside.
