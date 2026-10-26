import {
  decodeBitwardenCredentialId,
  repairCredentialIds,
  toBase64Url,
} from '../../src/sync/credential-ids';
import { mergeDeletions, mergeRecords } from '../../src/sync/merge';

// Bitwarden writes these 16 bytes as the GUID below; relying parties know them
// by the base64url form. Captured from a live webauthn.io registration.
const GUID = '674880d4-06ed-1af1-e8dd-2d901d9dbd3d';
const DECODED = 'Z0iA1AbtGvHo3S2QHZ29PQ';

function passkey(id: string, extra: { updatedAt?: number; counter?: number } = {}) {
  return { id, credentialId: id, rpId: 'webauthn.io', createdAt: 1000, counter: 1, ...extra } as {
    id: string;
    credentialId: string;
    rpId: string;
    createdAt: number;
    counter: number;
    updatedAt?: number;
  };
}

describe('decodeBitwardenCredentialId', () => {
  it('turns a GUID into the base64url of its 16 bytes', () => {
    expect(decodeBitwardenCredentialId(GUID)).toBe(DECODED);
    expect(Buffer.from(DECODED, 'base64url').toString('hex')).toBe(GUID.replace(/-/g, ''));
  });

  it('accepts upper-case GUIDs', () => {
    expect(decodeBitwardenCredentialId(GUID.toUpperCase())).toBe(DECODED);
  });

  it('strips the b64. prefix Bitwarden uses for other lengths', () => {
    const raw = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7));
    expect(decodeBitwardenCredentialId(`b64.${raw.toString('base64url')}`)).toBe(
      raw.toString('base64url')
    );
    expect(decodeBitwardenCredentialId(`b64.${raw.toString('base64')}`)).toBe(
      raw.toString('base64url')
    );
  });

  it('leaves real base64url credential IDs alone', () => {
    expect(decodeBitwardenCredentialId(DECODED)).toBeNull();
    expect(decodeBitwardenCredentialId('Y3JlZC1pZA')).toBeNull();
    expect(decodeBitwardenCredentialId('')).toBeNull();
    expect(decodeBitwardenCredentialId('b64.')).toBeNull();
  });
});

describe('toBase64Url', () => {
  it('normalises padded base64 to unpadded base64url', () => {
    expect(toBase64Url('a+b/cw==')).toBe('a-b_cw');
  });
});

describe('repairCredentialIds', () => {
  it('re-keys the record and tombstones the old id', () => {
    const { passkeys, deletions } = repairCredentialIds([passkey(GUID)], 5000);

    expect(passkeys).toEqual([
      expect.objectContaining({ id: DECODED, credentialId: DECODED, updatedAt: 5000 }),
    ]);
    expect(deletions).toEqual([{ kind: 'passkey', id: GUID, deletedAt: 5000 }]);
  });

  it('returns the input untouched when nothing needs repair', () => {
    const input = [passkey(DECODED)];
    const result = repairCredentialIds(input, 5000);
    expect(result.passkeys).toBe(input);
    expect(result.deletions).toEqual([]);
  });

  it('drops the broken copy when the decoded id is already stored', () => {
    const real = passkey(DECODED, { counter: 7 });
    const { passkeys, deletions } = repairCredentialIds([passkey(GUID), real], 5000);
    expect(passkeys).toEqual([real]);
    expect(deletions.map((entry) => entry.id)).toEqual([GUID]);
  });

  it('keeps the repaired revision ahead of a record updated in the future', () => {
    const { passkeys, deletions } = repairCredentialIds([passkey(GUID, { updatedAt: 9000 })], 5000);
    expect(passkeys[0].updatedAt).toBe(9001);
    expect(deletions[0].deletedAt).toBe(9000);
  });

  it('converges on a peer that predates the repair', () => {
    // The repairing device publishes its vault and deletion records; an old
    // peer only runs the existing merge, which already honours deletions.
    const repaired = repairCredentialIds([passkey(GUID)], 5000);
    const oldPeerVault = [passkey(GUID), passkey('other')];
    const deletions = mergeDeletions([], repaired.deletions);

    const merged = mergeRecords(oldPeerVault, repaired.passkeys, deletions, 'passkey');
    expect(merged.map((entry) => entry.id).sort()).toEqual([DECODED, 'other']);
  });

  it('converges when two devices repair independently', () => {
    const a = repairCredentialIds([passkey(GUID)], 5000);
    const b = repairCredentialIds([passkey(GUID)], 6000);
    const deletions = mergeDeletions(a.deletions, b.deletions);

    const merged = mergeRecords(a.passkeys, b.passkeys, deletions, 'passkey');
    expect(merged.map((entry) => entry.id)).toEqual([DECODED]);
  });
});
