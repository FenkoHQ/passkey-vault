import { createHash } from 'crypto';
import {
  CHAIN_SCRYPT,
  deriveChainKeys,
  legacyChainId,
  wipeChainKeys,
} from '../../src/sync/chain-keys';
import { mnemonicToBytes } from '../../src/crypto/bip39';

// Computed once with Node's own scrypt and HKDF (node:crypto), not with the
// module under test. Every device on a chain must derive exactly these, so a
// change here strands every existing chain.
const VECTORS = [
  {
    name: 'the phrase "abandon ... about"',
    seedHash: createHash('sha256')
      .update(
        mnemonicToBytes(
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        )
      )
      .digest('hex'),
    chainId: '8fc61ad8d0c0c37bf0b1c1c53ec3642c',
    encryptionKey: 'fbed94394945cb23ae345b2f30c7bc85928acfcb1ef0b440d948b7da1b65078b',
    nostrPrivateKey: 'fc58179e5f855e30129310483afbb264cb084d8316ef13ce3e38d10c79580adc',
  },
  {
    name: 'the seed the sync regression tests use',
    seedHash: 'ab'.repeat(32),
    chainId: '707571ea9119f5dd95a71a1b0429ae48',
    encryptionKey: 'a41e0348c18667c27952ec1b2e7d83aa887f96fd70fd7cb102183e1afbb024dd',
    nostrPrivateKey: 'd5571e38b61af162b25e66e43f54de06da07ccc2965a5419a60af63e193bc53e',
  },
];

// The AES key is not extractable, so check it by what it decrypts.
async function encryptsLike(key: CryptoKey, rawKeyHex: string): Promise<boolean> {
  const iv = new Uint8Array(12);
  const plaintext = new TextEncoder().encode('fenko');
  const reference = await crypto.subtle.importKey(
    'raw',
    Buffer.from(rawKeyHex, 'hex'),
    'AES-GCM',
    false,
    ['encrypt']
  );
  const expected = Buffer.from(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, reference, plaintext)
  );
  const actual = Buffer.from(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  return expected.equals(actual);
}

describe('sync chain keys', () => {
  jest.setTimeout(30000);

  it('uses the OWASP scrypt cost', () => {
    expect(CHAIN_SCRYPT).toEqual({ N: 2 ** 17, r: 8, p: 1 });
  });

  it.each(VECTORS)('derives the pinned keys for $name', async (vector) => {
    const keys = await deriveChainKeys(vector.seedHash);
    expect(keys.chainId).toBe(vector.chainId);
    expect(Buffer.from(keys.nostrPrivateKey).toString('hex')).toBe(vector.nostrPrivateKey);
    expect(await encryptsLike(keys.encryptionKey, vector.encryptionKey)).toBe(true);
    expect(keys.encryptionKey.extractable).toBe(false);
    wipeChainKeys(keys);
    expect(keys.nostrPrivateKey.every((byte) => byte === 0)).toBe(true);
  });

  it.each(VECTORS)(
    'no longer publishes a prefix of the seed for $name',
    ({ seedHash, chainId }) => {
      expect(legacyChainId(seedHash)).toBe(seedHash.slice(0, 32));
      expect(chainId).toHaveLength(32);
      expect(chainId).not.toBe(legacyChainId(seedHash));
      expect(seedHash).not.toContain(chainId);
    }
  );
});
