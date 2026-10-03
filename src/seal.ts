/**
 * Evidence sealing.
 *
 * Output content is encrypted before it touches the store, with one key per
 * (tenant, classification) pair derived from a master key. Anyone can verify
 * integrity (the digest stays plaintext); only a principal authorized for
 * `evidence.decrypt` on that key's resource can read content.
 *
 * Key derivation (ADR-013, extended by ADR-018 — no re-encryption):
 * - legacy `seal`/`open`: info `evidence:<classification>`, keyId
 *   `evidence-key:<classification>` — the global-tenant derivation every
 *   existing sealed record keeps decrypting under, byte-for-byte as before;
 * - tenant-bound `sealFor`/`openFor`: info `evidence:<tenantId>:<classification>`,
 *   keyId `evidence-key:v2:<tenantId>:<classification>`. `open`/`openFor`
 *   dispatch on keyId shape, so old records decrypt exactly as they always
 *   did and nothing is ever silently re-encrypted.
 *
 * HKDF info collision analysis: the tenant is the FIRST component after
 * `evidence:`. A tenantId containing `:`, whitespace, or control characters
 * would make that split ambiguous, so such tenants are rejected at the seam
 * (fail closed beats clever) — with a colon-free tenant, the first colon
 * after `evidence:` delimits it unambiguously and no two (tenantId,
 * classification) pairs can share an info string.
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
const V2_PREFIX = 'evidence-key:v2:';

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

/**
 * Tenant ids enter the HKDF info string and the keyId verbatim. The bound is
 * collision safety (see the header) plus bounded keyIds in the resource
 * registry; 128 chars is generous and never a secret.
 */
function isTenantId(tenantId: string): boolean {
  return tenantId.length > 0 && tenantId.length <= 128 && !/[:\s\x00-\x1f\x7f]/.test(tenantId);
}

export function keyIdFor(classification: Classification): string {
  return `${KEY_PREFIX}${classification}`;
}

/** Versioned, tenant-bound keyId: `evidence-key:v2:<tenantId>:<classification>`. */
export function keyIdForTenant(tenantId: string, classification: Classification): string {
  if (!isTenantId(tenantId)) throw new Error('invalid tenantId for evidence sealing: must be 1-128 chars with no ":" or control characters');
  return `${V2_PREFIX}${tenantId}:${classification}`;
}

/** v2 keyId shape -> { tenantId, classification }; undefined for any other shape. */
function splitV2KeyId(keyId: string): { tenantId: string; classification: string } | undefined {
  if (!keyId.startsWith(V2_PREFIX)) return undefined;
  const rest = keyId.slice(V2_PREFIX.length);
  const sep = rest.indexOf(':');
  if (sep <= 0) return undefined;
  return { tenantId: rest.slice(0, sep), classification: rest.slice(sep + 1) };
}

export function classificationFromKeyId(keyId: string): string {
  const v2 = splitV2KeyId(keyId);
  if (v2) return v2.classification;
  return keyId.startsWith(KEY_PREFIX) ? keyId.slice(KEY_PREFIX.length) : 'x-unknown';
}

/**
 * H8 (ADR-030): the tenant a v2 keyId is bound to; undefined for legacy
 * (`evidence-key:<level>`) and unknown shapes. Callers that authorize
 * decryption use this to bind a seal to exactly one tenant.
 */
export function tenantFromKeyId(keyId: string): string | undefined {
  return splitV2KeyId(keyId)?.tenantId;
}

/** Legacy derivation (ADR-013 as shipped): info `evidence:<classification>`. */
function legacyKeyFor(classification: Classification): Buffer {
  return Buffer.from(hkdfSync('sha256', masterKey(), SALT, Buffer.from(`evidence:${classification}`), 32));
}

/** Tenant-bound derivation (ADR-018): info `evidence:<tenantId>:<classification>`. */
function tenantKeyFor(tenantId: string, classification: Classification): Buffer {
  if (!isTenantId(tenantId)) throw new Error('invalid tenantId for evidence sealing: must be 1-128 chars with no ":" or control characters');
  return Buffer.from(hkdfSync('sha256', masterKey(), SALT, Buffer.from(`evidence:${tenantId}:${classification}`), 32));
}

function encryptWith(key: Buffer, keyId: string, plaintext: string): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    keyId,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptWith(key: Buffer, sealed: Sealed): string | undefined {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(sealed.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return undefined;
  }
}

/** Legacy global-tenant seal — unchanged behavior; existing records keep it. */
export function seal(plaintext: string, classification: Classification): Sealed {
  return encryptWith(legacyKeyFor(classification), keyIdFor(classification), plaintext);
}

/** Tenant-bound seal: the keyId binds the tenant and the level (ADR-018). */
export function sealFor(tenantId: string, plaintext: string, classification: Classification): Sealed {
  return encryptWith(tenantKeyFor(tenantId, classification), keyIdForTenant(tenantId, classification), plaintext);
}

/**
 * Returns undefined on a wrong key or tampered ciphertext — never partial
 * plaintext. Dispatches on keyId shape: v2 seals derive the tenant key from
 * the tenant bound in the keyId; everything else keeps the legacy derivation.
 */
export function open(sealed: Sealed): string | undefined {
  const v2 = splitV2KeyId(sealed.keyId);
  return v2
    ? decryptWith(tenantKeyFor(v2.tenantId, v2.classification), sealed)
    : decryptWith(legacyKeyFor(classificationFromKeyId(sealed.keyId)), sealed);
}

/**
 * Opens with the caller-claimed tenant: v2 seals derive with THAT tenant, so
 * a mismatch fails the GCM tag -> undefined. Legacy seals keep the old
 * global-tenant derivation (the tenant argument does not apply to them).
 * Invalid tenants and unknown keyId shapes fail closed (undefined, no throw).
 */
export function openFor(tenantId: string, sealed: Sealed): string | undefined {
  const v2 = splitV2KeyId(sealed.keyId);
  if (!v2) return open(sealed);
  if (!isTenantId(tenantId)) return undefined;
  return decryptWith(tenantKeyFor(tenantId, v2.classification), sealed);
}
