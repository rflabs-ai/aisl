/**
 * Evidence sealing.
 *
 * Output content is encrypted before it touches the store, with one key per
 * classification level derived from a master key. Anyone can verify integrity
 * (the digest stays plaintext); only a principal authorized for
 * `evidence.decrypt` on that level's key resource can read content.
 *
 * ponytail: single master key from the environment, HKDF-derive per level.
 * No KMS, no rotation, no per-tenant keys. Upgrade path in ADR-013 — and note
 * that a master key sitting next to the database degrades this to obfuscation.
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { type Classification } from './domain.ts';

export interface Sealed {
  readonly keyId: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
}

const SALT = Buffer.from('ai-security-layer/evidence/v1');
const KEY_PREFIX = 'evidence-key:';

let master: Buffer | undefined;

function masterKey(): Buffer {
  if (master) return master;
  const fromEnv = process.env.EVIDENCE_SEALING_KEY;
  if (fromEnv && fromEnv.length > 0) {
    master = Buffer.from(fromEnv, 'utf8');
  } else {
    master = randomBytes(32);
    process.emitWarning?.(
      'EVIDENCE_SEALING_KEY unset: using an ephemeral key; sealed evidence cannot be decrypted after restart',
    );
  }
  return master;
}

export function keyIdFor(classification: Classification): string {
  return `${KEY_PREFIX}${classification}`;
}

export function classificationFromKeyId(keyId: string): string {
  return keyId.startsWith(KEY_PREFIX) ? keyId.slice(KEY_PREFIX.length) : 'x-unknown';
}

function keyFor(classification: Classification): Buffer {
  return Buffer.from(hkdfSync('sha256', masterKey(), SALT, Buffer.from(`evidence:${classification}`), 32));
}

export function seal(plaintext: string, classification: Classification): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyFor(classification), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    keyId: keyIdFor(classification),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

/** Returns undefined on a wrong key or tampered ciphertext — never partial plaintext. */
export function open(sealed: Sealed): string | undefined {
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      keyFor(classificationFromKeyId(sealed.keyId)),
      Buffer.from(sealed.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(sealed.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return undefined;
  }
}
