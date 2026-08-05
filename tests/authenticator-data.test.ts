import { createAuthenticatorData } from '../src/background/cbor';

const UP = 0x01;
const UV = 0x04;
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

  it('writes the counter big-endian', async () => {
    const authData = await createAuthenticatorData('example.com', null, null, false, 258, null);
    const view = new DataView(authData);

    expect(view.getUint32(33, false)).toBe(258);
  });
});
