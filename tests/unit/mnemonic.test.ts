/**
 * Recovery phrases. The word list is the vault's own, not BIP39 English, and
 * every phrase already issued decodes through it, so it is pinned here word
 * for word; changing it would move existing users to a different sync chain.
 */

import { createHash } from 'crypto';

jest.mock('@noble/hashes/utils', () => {
  const actual = jest.requireActual('@noble/hashes/utils');
  return { ...actual, randomBytes: jest.fn(actual.randomBytes) };
});

import { randomBytes } from '@noble/hashes/utils';
import {
  bytesToMnemonic,
  generateMnemonic,
  mnemonicToBytes,
  validateMnemonic,
} from '../../src/crypto/bip39';

const draws = randomBytes as jest.MockedFunction<typeof randomBytes>;

/** 16 bytes of entropy whose first 11-bit group is the given index. */
function entropyStartingWith(index: number): Uint8Array {
  const entropy = new Uint8Array(16);
  entropy[0] = index >> 3;
  entropy[1] = (index & 7) << 5;
  return entropy;
}

/** The word at a position in the vault's list, read through the encoder. */
const wordAt = (index: number): string => bytesToMnemonic(entropyStartingWith(index)).split(' ')[0];

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

beforeEach(() => {
  draws.mockClear();
});

describe('the word list', () => {
  it('is the one every issued phrase decodes through', () => {
    const words = Array.from({ length: 2046 }, (_, index) => wordAt(index));

    expect(new Set(words).size).toBe(2046);
    expect(createHash('sha256').update(words.join(' ')).digest('hex')).toBe(
      'fd973009e02732d71cb401308724d89c188246e5fa95155b5f84c91d51bc6bcf'
    );
  });

  it('is not BIP39 English, and must not become it', () => {
    // BIP39 has 'correct' at 388; from there on, positions differ.
    expect(wordAt(387)).toBe('corn');
    expect(wordAt(388)).toBe('corner');
    expect(wordAt(2045)).toBe('zoo');
  });

  it('has no word for the last two 11-bit groups', () => {
    expect(() => wordAt(2046)).toThrow(RangeError);
    expect(() => wordAt(2047)).toThrow(RangeError);
  });
});

describe('phrases issued by earlier versions', () => {
  it.each([
    [
      '0f1e2d3c4b5a69788796a5b4c3d2e1f0',
      'audit vanish execute note pledge rotate bundle stand regular burden reunion tide',
    ],
    [
      'c0ffee00deadbeef0123456789abcdef5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
      'school zero lens rule swift jeans afraid hand guilt estate vicious teach ' +
        'pizza coffee hat enter foil sport notable regret pizza coffee hat flag',
    ],
  ])('%s still decodes to the same seed', (entropy, phrase) => {
    expect(validateMnemonic(phrase)).toBe(true);
    expect(hex(mnemonicToBytes(phrase))).toBe(entropy);
    expect(bytesToMnemonic(Buffer.from(entropy, 'hex'), phrase.split(' ').length)).toBe(phrase);
  });
});

describe('generateMnemonic', () => {
  it('draws again when the entropy has a group with no word', async () => {
    const unusable = entropyStartingWith(2047);
    const usable = entropyStartingWith(5);
    draws.mockReturnValueOnce(unusable).mockReturnValueOnce(usable);

    const phrase = await generateMnemonic(12);

    expect(draws).toHaveBeenCalledTimes(2);
    expect(phrase).toBe(bytesToMnemonic(usable));
  });

  // About 1 draw in 85 used to come out with the word "undefined", so 2000
  // draws all but guarantee a hit if it comes back.
  it.each([12, 24])('hands out %i-word phrases that decode to their entropy', async (count) => {
    for (let i = 0; i < 2000; i++) {
      const phrase = await generateMnemonic(count);
      const words = phrase.split(' ');

      expect(words).toHaveLength(count);
      expect(validateMnemonic(phrase)).toBe(true);
      expect(bytesToMnemonic(mnemonicToBytes(phrase), count)).toBe(phrase);
    }
  });
});
