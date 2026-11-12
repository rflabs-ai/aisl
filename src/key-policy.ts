/**
 * Durable key policy (safety ticket 04, item 2).
 *
 * The runtime reads signing and sealing keys from the environment. When one is
 * missing it generates an ephemeral key and warns. That is correct for
 * `npm run demo`, the test suite, and any in-memory world: nothing survives the
 * process, so a key that dies with it costs nothing.
 *
 * It is wrong for a long-lived instance. A REST server or a persistent event
 * store that starts without a durable key writes evidence that cannot be
 * verified after a restart and sealed payloads that cannot be decrypted. The
 * failure stays silent until the restart, which is the worst time to find out.
 *
 * This module is the one place that decides whether ephemeral keys are
 * acceptable. The long-lived seams call it before they start:
 *   - `RestApi.start()` with mode `'server'`;
 *   - the world's persistent event-store factory with mode `'persistent'`.
 * A direct `new EventLog(path)` in a benchmark or a unit test is a low-level
 * primitive, not a deployment seam, and does not consult this policy.
 *
 * The override is explicit and never the default:
 * `AISL_ALLOW_EPHEMERAL_KEYS=1` starts anyway and prints one warning that
 * evidence will not survive a restart.
 */

export const EPHEMERAL_KEYS_OVERRIDE = 'AISL_ALLOW_EPHEMERAL_KEYS';

export const DURABLE_KEY_VARS = [
  'CAPABILITY_SIGNING_KEY',
  'EVENT_SIGNING_PRIVATE_KEY_PEM',
  'EVENT_SIGNING_PUBLIC_KEY_PEM',
  'EVIDENCE_SEALING_KEY',
  'SECRET_MASTER_KEY',
] as const;

export type DurableKeyVar = (typeof DURABLE_KEY_VARS)[number];

/** `demo` never requires keys; the other modes are long-lived instances. */
export type KeyMode = 'demo' | 'server' | 'persistent';

type DurableMode = Exclude<KeyMode, 'demo'>;

interface KeyRequirement {
  readonly name: DurableKeyVar;
  /** Why an ephemeral key breaks this mode. */
  readonly why: string;
  /** How to produce a durable value. */
  readonly how: string;
}

const SERVER_REQUIREMENTS: readonly KeyRequirement[] = [
  {
    name: 'CAPABILITY_SIGNING_KEY',
    why: 'capabilities minted before a restart stop verifying after it',
    how: 'a random 32-byte value (openssl rand -hex 32)',
  },
  {
    name: 'EVENT_SIGNING_PRIVATE_KEY_PEM',
    why: 'a restarted process cannot sign new events under the key the existing chain was signed with',
    how: 'an Ed25519 PKCS8 PEM (openssl genpkey -algorithm ed25519)',
  },
  {
    name: 'EVENT_SIGNING_PUBLIC_KEY_PEM',
    why: 'a restarted process cannot verify the existing event chain',
    how: 'the matching SPKI PEM (openssl pkey -pubout)',
  },
  {
    name: 'EVIDENCE_SEALING_KEY',
    why: 'sealed evidence written before a restart cannot be decrypted',
    how: 'a random 32-byte value (openssl rand -hex 32)',
  },
  {
    name: 'SECRET_MASTER_KEY',
    why: 'envelope secrets encrypted before a restart cannot be decrypted',
    how: 'a random 32-byte value (openssl rand -hex 32)',
  },
];

/**
 * A persistent store must verify the chain it resumes and decrypt the evidence
 * it already holds. Capability signing and envelope secrets are process-level
 * concerns, so they are required of the server, not of the store.
 */
const PERSISTENT_REQUIREMENTS: readonly KeyRequirement[] = [
  {
    name: 'EVENT_SIGNING_PRIVATE_KEY_PEM',
    why: 'a restarted process cannot sign new events under the key the stored chain was signed with',
    how: 'an Ed25519 PKCS8 PEM (openssl genpkey -algorithm ed25519)',
  },
  {
    name: 'EVENT_SIGNING_PUBLIC_KEY_PEM',
    why: 'a restarted process cannot verify the stored event chain',
    how: 'the matching SPKI PEM (openssl pkey -pubout)',
  },
  {
    name: 'EVIDENCE_SEALING_KEY',
    why: 'sealed evidence in the store cannot be decrypted after a restart',
    how: 'a random 32-byte value (openssl rand -hex 32)',
  },
];

const REQUIREMENTS: Readonly<Record<DurableMode, readonly KeyRequirement[]>> = {
  server: SERVER_REQUIREMENTS,
  persistent: PERSISTENT_REQUIREMENTS,
};

const ACTION: Readonly<Record<DurableMode, string>> = {
  server: 'start the REST server',
  persistent: 'open a persistent event store',
};

export class MissingDurableKeysError extends Error {
  readonly mode: DurableMode;
  readonly missing: readonly DurableKeyVar[];

  constructor(mode: DurableMode, missing: readonly DurableKeyVar[]) {
    super(messageFor(mode, missing));
    this.name = 'MissingDurableKeysError';
    this.mode = mode;
    this.missing = missing;
  }
}

function messageFor(mode: DurableMode, missing: readonly DurableKeyVar[]): string {
  const requirements = REQUIREMENTS[mode].filter((requirement) => missing.includes(requirement.name));
  const names = requirements.map((requirement) => requirement.name).join(', ');
  const plural = requirements.length > 1;
  const lines = requirements.map(
    (requirement) => `  ${requirement.name}: ${requirement.why}. Set it to ${requirement.how}.`,
  );
  return [
    `refusing to ${ACTION[mode]} with ephemeral keys: ${names} ${plural ? 'are' : 'is'} unset.`,
    ...lines,
    `Export ${plural ? 'them' : 'it'} in the process environment before you ${ACTION[mode]}.`,
    `For a throwaway instance whose evidence does not need to survive a restart, set ${EPHEMERAL_KEYS_OVERRIDE}=1.`,
  ].join('\n');
}

export interface KeyPolicyDeps {
  /** Environment to read. Defaults to `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Warning sink for the override. Defaults to `process.emitWarning`. */
  readonly warn?: (message: string) => void;
}

/**
 * Refuse to start a long-lived seam when a durable key is missing. `demo`
 * returns immediately; the other modes throw `MissingDurableKeysError` unless
 * the explicit override is set, in which case they warn once and continue.
 */
export function assertDurableKeys(mode: KeyMode, deps: KeyPolicyDeps = {}): void {
  if (mode === 'demo') return;
  const env = deps.env ?? process.env;
  const missing = REQUIREMENTS[mode]
    .map((requirement) => requirement.name)
    .filter((name) => !isSet(env[name]));
  if (missing.length === 0) return;

  if (env[EPHEMERAL_KEYS_OVERRIDE] === '1') {
    const warn = deps.warn ?? ((message: string) => process.emitWarning?.(message));
    warn(
      `${EPHEMERAL_KEYS_OVERRIDE}=1: using ephemeral keys (${missing.join(', ')} unset); evidence written by this process will not be verifiable or decryptable after a restart`,
    );
    return;
  }

  throw new MissingDurableKeysError(mode, missing);
}

function isSet(value: string | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}
