/**
 * Credential IDs are stored as unpadded base64url of the raw ID bytes — the
 * form relying parties put in allowCredentials and the form the vault decodes
 * into rawId when signing.
 *
 * Bitwarden's JSON export writes them differently: a 16-byte ID as a GUID
 * string ("674880d4-06ed-1af1-e8dd-2d901d9dbd3d") and any other length as
 * "b64." + base64url. Earlier builds stored those strings verbatim, so the
 * vault never matched allowCredentials and signed with an ID the relying party
 * had never issued (issue #17). Neither shape is valid base64url — GUIDs are
 * 36 characters of hex and dashes where our IDs are 22, and "." is outside the
 * alphabet — so a stored ID in either shape can only be one of these.
 */

import { arrayBufferToBase64URL } from '../utils/base64';
import type { SyncDeletion } from './merge';

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BITWARDEN_B64_PREFIX = 'b64.';
const GUID_BYTES = 16;

/** Normalise base64 or base64url to the unpadded base64url the vault stores. */
export function toBase64Url(value: string): string {
  return value.trim().replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Base64url form of a Bitwarden-encoded credential ID, or null when the value is not one. */
export function decodeBitwardenCredentialId(value: string): string | null {
  const trimmed = (value || '').trim();
  if (trimmed.startsWith(BITWARDEN_B64_PREFIX)) {
    return toBase64Url(trimmed.slice(BITWARDEN_B64_PREFIX.length)) || null;
  }
  if (!GUID.test(trimmed)) return null;

  const hex = trimmed.replace(/-/g, '');
  const bytes = new Uint8Array(GUID_BYTES);
  for (let i = 0; i < GUID_BYTES; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arrayBufferToBase64URL(bytes.buffer);
}

interface PasskeyIdentity {
  id: string;
  credentialId?: string;
  createdAt: number;
  updatedAt?: number;
}

export interface CredentialIdRepair<T> {
  passkeys: T[];
  /** Deletion records for the old IDs; empty when nothing needed repair. */
  deletions: SyncDeletion[];
}

/**
 * Re-key passkeys that carry a Bitwarden-encoded credential ID.
 *
 * Sync merges records by id, so the repair is a delete plus an add: the old id
 * gets a deletion record, which every peer already honours (including builds
 * that predate this repair), and the record returns under the decoded id.
 * Every device derives the same decoded id, so repairs made independently on
 * two devices converge instead of duplicating. A record whose decoded id is
 * already present is dropped in favour of that one.
 */
export function repairCredentialIds<T extends PasskeyIdentity>(
  passkeys: T[],
  now = Date.now()
): CredentialIdRepair<T> {
  const byId = new Map(passkeys.map((passkey) => [passkey.id, passkey]));
  const deletions: SyncDeletion[] = [];

  for (const passkey of passkeys) {
    const decoded =
      decodeBitwardenCredentialId(passkey.credentialId || '') ??
      decodeBitwardenCredentialId(passkey.id);
    if (!decoded) continue;

    const revision = passkey.updatedAt ?? passkey.createdAt;
    byId.delete(passkey.id);
    deletions.push({ kind: 'passkey', id: passkey.id, deletedAt: Math.max(now, revision) });
    if (!byId.has(decoded)) {
      byId.set(decoded, {
        ...passkey,
        id: decoded,
        credentialId: decoded,
        updatedAt: Math.max(now, revision + 1),
      });
    }
  }

  return { passkeys: deletions.length > 0 ? [...byId.values()] : passkeys, deletions };
}
