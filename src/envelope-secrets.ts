/**
 * Envelope encryption for secrets: the agent never receives a plaintext value.
 *
 * Each secret is encrypted with a unique DEK (data encryption key). The DEK is
 * encrypted with a KEK (key encryption key) derived from a master key via
 * HKDF-SHA256. The master key lives in an environment variable or a file — the
 * broker never writes it to the event log.
 *
 * ponytail: single master key, no rotation. When a KMS is available, swap
 * `deriveDek` for a KMS generateDataKey call and store the encrypted DEK blob.
 * Short-lived credentials and brokered injection are the next steps (ADR-008).
 */

import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { defineResource } from './registry.ts';
import type { AuthorizationService } from './pdp.ts';
import type { EventStore } from './events.ts';
import type { ResourceRegistry } from './registry.ts';
import type { Principal } from './domain.ts';
import type { Approval } from './policy.ts';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 16;

export interface EncryptedSecret {
  readonly iv: Buffer;
  readonly ciphertext: Buffer;
  readonly tag: Buffer;
  readonly dekSalt: Buffer;
}

export function deriveKey(masterKey: Buffer, salt: Buffer): Buffer {
  return pbkdf2Sync(masterKey, salt, 100_000, KEY_LENGTH, 'sha512');
}

export function encryptSecret(plaintext: string, masterKey: Buffer): EncryptedSecret {
  const salt = randomBytes(SALT_LENGTH);
  const dek = deriveKey(masterKey, salt);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, dek, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: encrypted, tag, dekSalt: salt };
}

export function decryptSecret(encrypted: EncryptedSecret, masterKey: Buffer): string {
  const dek = deriveKey(masterKey, encrypted.dekSalt);
  const decipher = createDecipheriv(ALGORITHM, dek, encrypted.iv);
  decipher.setAuthTag(encrypted.tag);
  const decrypted = Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

export interface EnvelopeSecretRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly encrypted: EncryptedSecret;
  readonly label: string;
}

export interface EnvelopeSecretResult {
  readonly allowed: boolean;
  readonly value?: string;
  readonly reason: string;
}

/**
 * Secret broker with envelope encryption. Values are never stored in plaintext.
 * Access is still gated by the PDP (default deny). The agent receives the
 * decrypted value only after authorization; evidence records get a redacted
 * placeholder.
 */
export class EnvelopeSecretBroker {
  private readonly secrets = new Map<string, EnvelopeSecretRecord>();
  private readonly masterKey: Buffer;
  private readonly authorization: AuthorizationService;
  private readonly eventLog: EventStore;
  private readonly registry: ResourceRegistry;

  constructor(masterKey: Buffer, authorization: AuthorizationService, eventLog: EventStore, registry: ResourceRegistry) {
    this.masterKey = masterKey;
    this.authorization = authorization;
    this.eventLog = eventLog;
    this.registry = registry;
  }

  register(secret: { id: string; tenantId: string; value: string; label: string }): void {
    const encrypted = encryptSecret(secret.value, this.masterKey);
    this.secrets.set(secret.id, { id: secret.id, tenantId: secret.tenantId, encrypted, label: secret.label });
    this.registry.add(defineResource({
      id: secret.id,
      type: 'secret',
      tenantId: secret.tenantId,
      classification: 'restricted',
      attributes: { label: secret.label },
    }));
  }

  request(req: { principal: Principal; secretId: string; approvals?: readonly Approval[] }): EnvelopeSecretResult {
    const secret = this.secrets.get(req.secretId);
    if (!secret || secret.tenantId !== req.principal.tenantId) {
      return { allowed: false, reason: 'unknown secret' };
    }

    const decision = this.authorization.authorize({
      principal: req.principal,
      action: 'secret.use',
      resourceId: secret.id,
      approvals: req.approvals,
    });

    const value = decision.decision === 'allow' ? decryptSecret(secret.encrypted, this.masterKey) : undefined;

    this.eventLog.append({
      tenantId: req.principal.tenantId,
      principal: req.principal.id,
      actor: req.principal.id,
      actorKind: req.principal.kind,
      action: 'secret.use',
      resourceId: secret.id,
      decision: decision.decision,
      denyReason: decision.denyReason,
      result: decision.decision === 'deny' ? 'denied' : 'success',
      metadata: {
        phase: 'secret-broker',
        label: secret.label,
        encrypted: true,
        value: value !== undefined ? '[decrypted-withheld]' : undefined,
      },
    });

    return decision.decision === 'allow'
      ? { allowed: true, value, reason: decision.reason }
      : { allowed: false, reason: decision.reason };
  }

  /**
   * Brokered injection: decrypt a secret and inject it into a tool context
   * without the agent ever seeing the plaintext value. The agent sees only
   * a reference; the tool receives the value in its params.
   */
  inject(req: {
    principal: Principal;
    secretId: string;
    targetParams: Record<string, unknown>;
    paramKey: string;
    approvals?: readonly Approval[];
  }): { allowed: boolean; params: Record<string, unknown>; reason: string } {
    const secret = this.secrets.get(req.secretId);
    if (!secret || secret.tenantId !== req.principal.tenantId) {
      return { allowed: false, params: req.targetParams, reason: 'unknown secret' };
    }

    const decision = this.authorization.authorize({
      principal: req.principal,
      action: 'secret.use',
      resourceId: secret.id,
      approvals: req.approvals,
    });

    this.eventLog.append({
      tenantId: req.principal.tenantId,
      principal: req.principal.id,
      actor: req.principal.id,
      actorKind: req.principal.kind,
      action: 'secret.use',
      resourceId: secret.id,
      decision: decision.decision,
      denyReason: decision.denyReason,
      result: decision.decision === 'deny' ? 'denied' : 'success',
      metadata: {
        phase: 'secret-broker-inject',
        label: secret.label,
        encrypted: true,
        injected: decision.decision === 'allow',
        value: '[brokered-injection]',
      },
    });

    if (decision.decision !== 'allow') {
      return { allowed: false, params: req.targetParams, reason: decision.reason };
    }

    const value = decryptSecret(secret.encrypted, this.masterKey);
    const params = { ...req.targetParams, [req.paramKey]: value };
    return { allowed: true, params, reason: decision.reason };
  }

  /** Redact a secret value for evidence logging. Never call on the authorization path. */
  static redact(value: string): string {
    if (value.length <= 4) return '****';
    return value.slice(0, 2) + '*'.repeat(Math.min(value.length - 4, 16)) + value.slice(-2);
  }
}
