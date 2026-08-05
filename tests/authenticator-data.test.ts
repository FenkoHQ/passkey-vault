import {
  createAuthenticatorData,
  ANONYMOUS_AAGUID,
  PASSKEY_VAULT_AAGUID,
} from '../src/background/cbor';

const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

async function flagsOf(authData: ArrayBuffer): Promise<number> {
  // rpIdHash (32 bytes) then the flags byte.
  return new Uint8Array(authData)[32];
}

describe('createAuthenticatorData', () => {
  it('sets UP and UV on assertions', async () => {
    const authData = await createAuthenticatorData('example.com', null, null, false, 7, null);
    const flags = await flagsOf(authData);

    // UV clear here means every RP that requires user verification — Google
    // among them — rejects the assertion as a second factor. See issue #5.
    expect(flags & UV).toBe(UV);
    expect(flags & UP).toBe(UP);
    expect(flags & AT).toBe(0);
    expect(new Uint8Array(authData).length).toBe(37);
  });

  it('sets AT alongside UP and UV on registration', async () => {
    const credentialId = new Uint8Array(16).fill(9);
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

    const authData = await createAuthenticatorData(
      'example.com',
      credentialId,
      publicKeyRaw,
      true,
      0,
      null
    );
    const flags = await flagsOf(authData);

    expect(flags & UV).toBe(UV);
    expect(flags & UP).toBe(UP);
    expect(flags & AT).toBe(AT);
  });

  it('sets ED only when extension data is appended', async () => {
    const withoutExt = await createAuthenticatorData('example.com', null, null, false, 1, null);
    expect((await flagsOf(withoutExt)) & ED).toBe(0);

    const extensionsData = new Uint8Array([0xa0]);
    const withExt = await createAuthenticatorData(
      'example.com',
      null,
      null,
      false,
      1,
      extensionsData
    );
    expect((await flagsOf(withExt)) & ED).toBe(ED);
    expect(new Uint8Array(withExt).length).toBe(38);
  });

  it('clears UV when the user turns verification reporting off', async () => {
    const authData = await createAuthenticatorData('example.com', null, null, false, 1, null, {
      userVerified: false,
    });
    const flags = await flagsOf(authData);

    expect(flags & UV).toBe(0);
    expect(flags & UP).toBe(UP);
  });

  it('sets BE and BS from the backup options', async () => {
    const eligible = await createAuthenticatorData('example.com', null, null, false, 1, null, {
      backupEligible: true,
    });
    expect((await flagsOf(eligible)) & BE).toBe(BE);
    expect((await flagsOf(eligible)) & BS).toBe(0);

    const backedUp = await createAuthenticatorData('example.com', null, null, false, 1, null, {
      backupEligible: true,
      backupState: true,
    });
    expect((await flagsOf(backedUp)) & (BE | BS)).toBe(BE | BS);
  });

  it('never sets BS without BE', async () => {
    const authData = await createAuthenticatorData('example.com', null, null, false, 1, null, {
      backupEligible: false,
      backupState: true,
    });

    expect((await flagsOf(authData)) & (BE | BS)).toBe(0);
  });

  it('writes the requested AAGUID into attested credential data', async () => {
    const credentialId = new Uint8Array(16).fill(3);
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const aaguidOf = (authData: ArrayBuffer) => new Uint8Array(authData).slice(37, 53);

    const branded = await createAuthenticatorData(
      'example.com',
      credentialId,
      publicKeyRaw,
      true,
      0,
      null
    );
    expect(aaguidOf(branded)).toEqual(PASSKEY_VAULT_AAGUID);

    const anonymous = await createAuthenticatorData(
      'example.com',
      credentialId,
      publicKeyRaw,
      true,
      0,
      null,
      { aaguid: ANONYMOUS_AAGUID }
    );
    expect(aaguidOf(anonymous)).toEqual(new Uint8Array(16));
  });

  it('writes the counter big-endian', async () => {
    const authData = await createAuthenticatorData('example.com', null, null, false, 258, null);
    const view = new DataView(authData);

    expect(view.getUint32(33, false)).toBe(258);
  });
});
