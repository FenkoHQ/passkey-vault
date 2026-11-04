/**
 * Key derivation specs: what is stored, what is accepted back, and that each
 * KDF derives the same bytes as Node's native implementation.
 *
 * tests/setup.ts runs the suite on a cheap scrypt profile (N=2^10); the
 * production profile is checked here through jest.requireActual.
 */

import { pbkdf2Sync, scryptSync } from 'crypto';
import {
  deriveKey,
  isWeakerThanDefault,
  legacyKdfSpec,
  newKdfSpec,
  parseKdfSpec,
  sameKdfSpec,
  UnsupportedKdfError,
  type KdfSpec,
} from '../src/crypto/kdf';

const SALT = Buffer.alloc(32, 7).toString('base64');
const scryptSpec = (N: number, r = 8, p = 1): KdfSpec => ({
  kdf: 'scrypt',
  params: { N, r, p },
  salt: SALT,
});

describe('the production KDF profile', () => {
  const { DEFAULT_KDF } = jest.requireActual('../src/crypto/kdf-profile');

  it('is scrypt at the OWASP parameters', () => {
    expect(DEFAULT_KDF).toEqual({ kdf: 'scrypt', params: { N: 131072, r: 8, p: 1 } });
  });

  it('is within the bounds a reader accepts', () => {
    expect(parseKdfSpec({ ...DEFAULT_KDF, salt: SALT })).toEqual({ ...DEFAULT_KDF, salt: SALT });
  });
});

describe('new specs', () => {
  it('use the default profile with a fresh 32-byte salt', () => {
    const a = newKdfSpec();
    const b = newKdfSpec();
    expect(a.kdf).toBe('scrypt');
    expect(a.params).toEqual({ N: 1024, r: 8, p: 1 });
    expect(Buffer.from(a.salt, 'base64')).toHaveLength(32);
    expect(a.salt).not.toBe(b.salt);
    expect(sameKdfSpec(a, b)).toBe(false);
    expect(sameKdfSpec(a, JSON.parse(JSON.stringify(a)))).toBe(true);
  });

  it('are not weaker than the default', () => {
    expect(isWeakerThanDefault(newKdfSpec())).toBe(false);
  });
});

describe('the legacy spec', () => {
  it('is PBKDF2-SHA256 at 100,000 iterations and weaker than the default', () => {
    const spec = legacyKdfSpec(SALT);
    expect(spec).toEqual({ kdf: 'pbkdf2-sha256', params: { iterations: 100000 }, salt: SALT });
    expect(isWeakerThanDefault(spec)).toBe(true);
  });

  it('derives the key earlier builds derived, from the raw password bytes', async () => {
    const key = await deriveKey('123456', legacyKdfSpec(SALT));
    expect(Buffer.from(key)).toEqual(
      pbkdf2Sync('123456', Buffer.from(SALT, 'base64'), 100000, 32, 'sha256')
    );
  });
});

describe('scrypt', () => {
  it('derives what native scrypt derives', async () => {
    const key = await deriveKey('correct horse battery staple', scryptSpec(1024, 8, 2));
    expect(Buffer.from(key)).toEqual(
      scryptSync('correct horse battery staple', Buffer.from(SALT, 'base64'), 32, {
        N: 1024,
        r: 8,
        p: 2,
      })
    );
  });

  it('normalises the passphrase to NFC, so composed and decomposed input match', async () => {
    const composed = await deriveKey('café au lait', scryptSpec(1024));
    const decomposed = await deriveKey('café au lait', scryptSpec(1024));
    expect(Buffer.from(decomposed)).toEqual(Buffer.from(composed));
  });

  it('gives different passwords and salts different keys', async () => {
    const base = Buffer.from(await deriveKey('123456', scryptSpec(1024)));
    expect(Buffer.from(await deriveKey('123457', scryptSpec(1024)))).not.toEqual(base);
    const otherSalt = { ...scryptSpec(1024), salt: Buffer.alloc(32, 8).toString('base64') };
    expect(Buffer.from(await deriveKey('123456', otherSalt))).not.toEqual(base);
  });

  it('is weaker than the default with less memory or less work', () => {
    expect(isWeakerThanDefault(scryptSpec(512))).toBe(true);
    expect(isWeakerThanDefault(scryptSpec(1024, 4))).toBe(true);
    expect(isWeakerThanDefault(scryptSpec(1024))).toBe(false);
    // A stronger spec, as a newer build may write, is never lowered.
    expect(isWeakerThanDefault(scryptSpec(4096))).toBe(false);
    expect(isWeakerThanDefault(scryptSpec(1024, 8, 2))).toBe(false);
  });
});

describe('reading a spec back', () => {
  it('returns a clean copy of a valid spec', () => {
    const stored = { ...scryptSpec(1024), extra: 'ignored' };
    expect(parseKdfSpec(stored)).toEqual(scryptSpec(1024));
  });

  it.each([
    ['an unknown KDF', { kdf: 'argon2id', params: { m: 65536, t: 3, p: 1 }, salt: SALT }],
    ['no KDF name', { params: { N: 1024, r: 8, p: 1 }, salt: SALT }],
    ['no record at all', null],
    ['an N that is not a power of two', scryptSpec(1000)],
    ['scrypt that needs 1 GiB', scryptSpec(2 ** 20)],
    ['scrypt with excessive work', scryptSpec(2 ** 17, 8, 64)],
    ['a fractional parameter', { kdf: 'scrypt', params: { N: 1024, r: 8.5, p: 1 }, salt: SALT }],
    ['a string parameter', { kdf: 'scrypt', params: { N: '1024', r: 8, p: 1 }, salt: SALT }],
    ['PBKDF2 with a billion iterations', { ...legacyKdfSpec(SALT), params: { iterations: 1e9 } }],
    ['PBKDF2 with ten iterations', { ...legacyKdfSpec(SALT), params: { iterations: 10 } }],
    ['a short salt', { ...scryptSpec(1024), salt: Buffer.alloc(8).toString('base64') }],
    ['a salt that is not base64', { ...scryptSpec(1024), salt: '***' }],
    ['no salt', { kdf: 'scrypt', params: { N: 1024, r: 8, p: 1 } }],
  ])('rejects %s as unsupported, not as a wrong password', (_label, value) => {
    expect(() => parseKdfSpec(value)).toThrow(UnsupportedKdfError);
  });

  it('refuses to derive with an unsupported spec', async () => {
    await expect(deriveKey('123456', scryptSpec(2 ** 22))).rejects.toMatchObject({
      code: 'UNSUPPORTED_KDF',
    });
  });
});
