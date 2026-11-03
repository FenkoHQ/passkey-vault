/**
 * Property tests for the vault's hand-written encoders: base64, CBOR, DER,
 * authenticator data, clientDataJSON. Each is checked against an
 * independent strict decoder (tests/helpers) over boundary values and
 * seeded random inputs, so a failure replays from its seed.
 */

import {
  arrayBufferToBase64,
  arrayBufferToBase64URL,
  base64URLToArrayBuffer,
  base64urlToBase64,
  decodeBase64Flexible,
} from '../../src/utils/base64';
import {
  convertP1363ToDER,
  createAttestationObjectNone,
  createAuthenticatorData,
  encodeByteString,
  encodeMapHeader,
  encodeTextString,
  rawPublicKeyToCose,
} from '../../src/background/cbor';
import { serializeClientData } from '../../src/background/client-data';
import { decodeCbor } from '../helpers/cbor-strict';
import { bs, equalBytes, hex, prng, randomBytes, sha256 } from '../helpers/bytes';
import {
  ccdToString,
  derToP1363,
  limitedVerifyClientData,
  parseAuthenticatorData,
} from '../helpers/rp-verifier';

const SEEDS = [1, 2, 3, 0xdecaf, 0xfeedface];

function bytesOf(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

describe('base64 and base64url', () => {
  it.each(SEEDS)('round-trips random bytes of every length up to 300 (seed %i)', (seed) => {
    const random = prng(seed);
    for (let length = 0; length <= 300; length++) {
      const bytes = randomBytes(random, length);
      const url = arrayBufferToBase64URL(bytes.slice().buffer as ArrayBuffer);

      expect(url).toMatch(/^[A-Za-z0-9_-]*$/);
      if (length > 0) {
        expect(bytesOf(base64URLToArrayBuffer(url))).toEqual(bytes);
        expect(bytesOf(decodeBase64Flexible(url))).toEqual(bytes);
        expect(
          bytesOf(decodeBase64Flexible(arrayBufferToBase64(bytes.slice().buffer as ArrayBuffer)))
        ).toEqual(bytes);
        expect(base64urlToBase64(url)).toBe(
          arrayBufferToBase64(bytes.slice().buffer as ArrayBuffer)
        );
      }
    }
  });
});

describe('CBOR encoders', () => {
  const lengths = [0, 1, 23, 24, 25, 255, 256, 257, 1000, 65535, 65536, 70000];

  it.each(lengths)('encodes a %i-byte byte string canonically', (length) => {
    const bytes = new Uint8Array(length).map((_, i) => i & 0xff);
    const { value } = decodeCbor(new Uint8Array(encodeByteString(bytes)));

    expect(equalBytes(value as Uint8Array, bytes)).toBe(true);
  });

  it.each(lengths)('encodes a %i-byte text string canonically', (length) => {
    const text = 'a'.repeat(length);
    const { value } = decodeCbor(new Uint8Array(encodeTextString(text)));

    expect(value).toBe(text);
  });

  it('encodes multi-byte UTF-8 text by byte length', () => {
    for (const text of ['é', '日本語', '🔑🔐', 'a'.repeat(22) + '€']) {
      expect(decodeCbor(new Uint8Array(encodeTextString(text))).value).toBe(text);
    }
  });

  it.each([0, 1, 23, 24, 255, 256, 65535, 65536])(
    'encodes a map header for %i entries',
    (count) => {
      const header = new Uint8Array(encodeMapHeader(count));
      const body: number[] = [];
      for (let i = 0; i < count; i++)
        body.push(...encodeTextString(String(i).padStart(6, '0')), 0xf6);
      const { value } = decodeCbor(new Uint8Array([...header, ...body]), { canonical: false });

      expect((value as Map<unknown, unknown>).size).toBe(count);
    }
  );

  it('wraps authenticator data of any size in a canonical "none" attestation', () => {
    for (const length of [37, 200, 255, 256, 1000, 65535, 65536]) {
      const authData = new Uint8Array(length).fill(7);
      const { value } = decodeCbor(
        bytesOf(createAttestationObjectNone(authData.buffer as ArrayBuffer))
      );

      expect(
        equalBytes((value as Map<string, unknown>).get('authData') as Uint8Array, authData)
      ).toBe(true);
    }
  });

  it('turns a raw P-256 key into the canonical COSE key', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
    ]);
    const raw = bytesOf(await crypto.subtle.exportKey('raw', pair.publicKey));
    const cose = decodeCbor(rawPublicKeyToCose(raw.buffer as ArrayBuffer)).value as Map<
      number,
      unknown
    >;

    expect([...cose.keys()]).toEqual([1, 3, -1, -2, -3]);
    expect(cose.get(-2)).toEqual(raw.slice(1, 33));
    expect(cose.get(-3)).toEqual(raw.slice(33, 65));
  });
});

describe('P1363 to DER signatures', () => {
  function forced(random: () => number): Uint8Array {
    const sig = randomBytes(random, 64);
    const choice = Math.floor(random() * 6);
    if (choice === 0) sig[0] = 0; // r with one leading zero byte
    if (choice === 1) sig.fill(0, 0, 3); // r with several
    if (choice === 2) sig[32] = 0; // s with a leading zero
    if (choice === 3) sig[0] |= 0x80; // r needs a padding byte
    if (choice === 4) sig[32] |= 0x80; // s needs a padding byte
    if (choice === 5) {
      sig.fill(0, 0, 31); // a tiny r
      sig[31] = 1;
    }
    // Keep r and s below the group order (whose top byte is 0xff), as any
    // real signature is, so the strict parser's range check holds.
    if (sig[0] === 0xff) sig[0] = 0xfe;
    if (sig[32] === 0xff) sig[32] = 0xfe;
    return sig;
  }

  it.each(SEEDS)('produces strict DER that decodes to the same r and s (seed %i)', (seed) => {
    const random = prng(seed);
    for (let i = 0; i < 500; i++) {
      const sig = forced(random);
      if (sig.slice(0, 32).every((b) => b === 0) || sig.slice(32).every((b) => b === 0)) continue;
      const issues: string[] = [];
      const decoded = derToP1363(
        bytesOf(convertP1363ToDER(sig.slice().buffer as ArrayBuffer)),
        issues
      );

      expect(issues).toEqual([]);
      expect(hex(decoded!)).toBe(hex(sig));
    }
  });

  it('converts real WebCrypto signatures into DER that still verifies', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    for (let i = 0; i < 64; i++) {
      const message = new TextEncoder().encode(`message ${i}`);
      const p1363 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.privateKey,
        message
      );
      const issues: string[] = [];
      const back = derToP1363(bytesOf(convertP1363ToDER(p1363)), issues);

      expect(issues).toEqual([]);
      expect(
        await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          pair.publicKey,
          bs(back!),
          message
        )
      ).toBe(true);
    }
  });
});

describe('authenticator data', () => {
  const rpIds = [
    'example.com',
    'a.b.c.d.example.co.uk',
    'xn--bcher-kva.example',
    'localhost',
    'x'.repeat(253),
  ];

  it.each(rpIds)('lays out an assertion for %s', async (rpId) => {
    for (const counter of [0, 1, 255, 256, 2 ** 31, 2 ** 32 - 1]) {
      const issues: string[] = [];
      const parsed = parseAuthenticatorData(
        bytesOf(await createAuthenticatorData(rpId, null, null, false, counter)),
        issues
      );

      expect(issues).toEqual([]);
      expect(hex(parsed!.rpIdHash)).toBe(hex(await sha256(rpId)));
      expect(parsed!.signCount).toBe(counter);
    }
  });

  it('lays out attested credential data for every flag combination', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
    ]);
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    for (const userVerified of [true, false]) {
      for (const backupEligible of [true, false]) {
        for (const backupState of [true, false]) {
          const credentialId = new Uint8Array(16).map((_, i) => i);
          const issues: string[] = [];
          const parsed = parseAuthenticatorData(
            bytesOf(
              await createAuthenticatorData('example.com', credentialId, raw, true, 0, null, {
                userVerified,
                backupEligible,
                backupState,
              })
            ),
            issues
          );

          expect(issues).toEqual([]);
          expect(Boolean(parsed!.flags & 0x04)).toBe(userVerified);
          expect(Boolean(parsed!.flags & 0x08)).toBe(backupEligible);
          expect(Boolean(parsed!.flags & 0x10)).toBe(backupEligible && backupState);
          expect(parsed!.credentialId).toEqual(credentialId);
        }
      }
    }
  });
});

describe('clientDataJSON serialization', () => {
  function randomText(random: () => number, length: number): string {
    const pool = [
      'a',
      'Z',
      '0',
      '"',
      '\\',
      '/',
      ' ',
      '\n',
      '\u0000',
      '\u001f',
      '\u007f',
      'é',
      '€',
      ' ',
      '🔑',
    ];
    let text = '';
    for (let i = 0; i < length; i++) text += pool[Math.floor(random() * pool.length)];
    return text;
  }

  it.each(SEEDS)('is valid JSON that round-trips every field (seed %i)', (seed) => {
    const random = prng(seed);
    for (let i = 0; i < 300; i++) {
      const data = {
        type: random() < 0.5 ? ('webauthn.create' as const) : ('webauthn.get' as const),
        challenge: randomText(random, Math.floor(random() * 40)),
        origin: 'https://' + randomText(random, Math.floor(random() * 20)),
        crossOrigin: random() < 0.3,
        topOrigin: random() < 0.5 ? 'https://' + randomText(random, 8) : undefined,
      };
      const text = serializeClientData(data);
      const parsed = JSON.parse(text);

      expect(parsed.type).toBe(data.type);
      expect(parsed.challenge).toBe(data.challenge);
      expect(parsed.origin).toBe(data.origin);
      expect(parsed.crossOrigin).toBe(data.crossOrigin);
      if (data.crossOrigin && data.topOrigin) expect(parsed.topOrigin).toBe(data.topOrigin);
      else expect(parsed).not.toHaveProperty('topOrigin');
      // Byte for byte what CCDToString in §5.8.1.1 produces.
      expect(
        text.startsWith(
          '{"type":' + ccdToString(data.type) + ',"challenge":' + ccdToString(data.challenge)
        )
      ).toBe(true);
    }
  });

  it('passes the limited verification algorithm for real challenges', () => {
    const random = prng(7);
    for (let i = 0; i < 100; i++) {
      const challenge = randomBytes(random, 32);
      const text = serializeClientData({
        type: 'webauthn.get',
        challenge: Buffer.from(challenge).toString('base64url'),
        origin: 'https://example.com',
        crossOrigin: false,
      });

      expect(
        limitedVerifyClientData(new TextEncoder().encode(text), {
          type: 'webauthn.get',
          challenge,
          origin: 'https://example.com',
        })
      ).toBe(true);
    }
  });
});
