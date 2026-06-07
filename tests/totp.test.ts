import {
  generateTotp,
  generateHotp,
  timeRemaining,
  base32Decode,
  base32Encode,
  parseOtpauth,
  buildOtpauth,
} from '../src/crypto/totp';

describe('TOTP module', () => {
  describe('RFC 6238 test vectors', () => {
    // Vectors from RFC 6238 Appendix B. The reference impl pads the secret
    // out to the hash output length: 32 bytes for SHA-256, 64 for SHA-512.
    const sha1Secret = new TextEncoder().encode('12345678901234567890');
    const sha256Secret = new TextEncoder().encode('12345678901234567890123456789012');
    const sha512Secret = new TextEncoder().encode(
      '1234567890123456789012345678901234567890123456789012345678901234'
    );

    // SHA-1 vectors
    it('SHA-1 @ 59s -> 94287082', () => {
      expect(
        generateTotp({ secret: sha1Secret, algorithm: 'SHA1', digits: 8, timestamp: 59000 })
      ).toBe('94287082');
    });
    it('SHA-1 @ 1111111109s -> 07081804', () => {
      expect(
        generateTotp({
          secret: sha1Secret,
          algorithm: 'SHA1',
          digits: 8,
          timestamp: 1111111109000,
        })
      ).toBe('07081804');
    });
    it('SHA-1 @ 1111111111s -> 14050471', () => {
      expect(
        generateTotp({
          secret: sha1Secret,
          algorithm: 'SHA1',
          digits: 8,
          timestamp: 1111111111000,
        })
      ).toBe('14050471');
    });
    it('SHA-1 @ 1234567890s -> 89005924', () => {
      expect(
        generateTotp({
          secret: sha1Secret,
          algorithm: 'SHA1',
          digits: 8,
          timestamp: 1234567890000,
        })
      ).toBe('89005924');
    });
    it('SHA-1 @ 2000000000s -> 69279037', () => {
      expect(
        generateTotp({
          secret: sha1Secret,
          algorithm: 'SHA1',
          digits: 8,
          timestamp: 2000000000000,
        })
      ).toBe('69279037');
    });

    // SHA-256 / SHA-512 use padded secrets in the RFC
    it('SHA-256 @ 59s -> 46119246', () => {
      expect(
        generateTotp({ secret: sha256Secret, algorithm: 'SHA256', digits: 8, timestamp: 59000 })
      ).toBe('46119246');
    });
    it('SHA-256 @ 1111111109s -> 68084774', () => {
      expect(
        generateTotp({
          secret: sha256Secret,
          algorithm: 'SHA256',
          digits: 8,
          timestamp: 1111111109000,
        })
      ).toBe('68084774');
    });
    it('SHA-256 @ 1234567890s -> 91819424', () => {
      expect(
        generateTotp({
          secret: sha256Secret,
          algorithm: 'SHA256',
          digits: 8,
          timestamp: 1234567890000,
        })
      ).toBe('91819424');
    });
    it('SHA-512 @ 59s -> 90693936', () => {
      expect(
        generateTotp({ secret: sha512Secret, algorithm: 'SHA512', digits: 8, timestamp: 59000 })
      ).toBe('90693936');
    });
    it('SHA-512 @ 1111111109s -> 25091201', () => {
      expect(
        generateTotp({
          secret: sha512Secret,
          algorithm: 'SHA512',
          digits: 8,
          timestamp: 1111111109000,
        })
      ).toBe('25091201');
    });
    it('SHA-512 @ 1234567890s -> 93441116', () => {
      expect(
        generateTotp({
          secret: sha512Secret,
          algorithm: 'SHA512',
          digits: 8,
          timestamp: 1234567890000,
        })
      ).toBe('93441116');
    });
  });

  describe('RFC 4226 HOTP test vectors', () => {
    // Vectors from RFC 4226 Appendix D
    const secret = new TextEncoder().encode('12345678901234567890');

    const expected = [
      '755224', '287082', '359152', '969429', '338314',
      '254676', '287922', '162583', '399871', '520489',
    ];

    expected.forEach((code, i) => {
      it(`HOTP counter ${i} -> ${code}`, () => {
        expect(generateHotp({ secret, counter: i })).toBe(code);
      });
    });
  });

  describe('TOTP defaults', () => {
    const secret = new TextEncoder().encode('12345678901234567890');

    it('defaults to 6 digits', () => {
      const code = generateTotp({ secret, timestamp: 59 * 1000 });
      expect(code).toHaveLength(6);
    });

    it('uses SHA-1 by default', () => {
      const defaultCode = generateTotp({ secret, timestamp: 59 * 1000 });
      const sha1Code = generateTotp({
        secret,
        algorithm: 'SHA1',
        timestamp: 59 * 1000,
      });
      expect(defaultCode).toBe(sha1Code);
    });
  });

  describe('TOTP windowing', () => {
    it('same window returns same code', () => {
      const secret = new TextEncoder().encode('test-secret');
      const a = generateTotp({ secret, timestamp: 30 * 1000 });
      const b = generateTotp({ secret, timestamp: 30 * 1000 + 15 * 1000 });
      expect(a).toBe(b);
    });

    it('different windows return different codes (usually)', () => {
      const secret = new TextEncoder().encode('test-secret');
      const a = generateTotp({ secret, timestamp: 0 });
      const b = generateTotp({ secret, timestamp: 30 * 1000 });
      expect(a).not.toBe(b);
    });
  });

  describe('timeRemaining', () => {
    it('returns period at start of window', () => {
      expect(timeRemaining(0, 30)).toBe(30);
    });
    it('returns 1 at end of window', () => {
      expect(timeRemaining(29 * 1000, 30)).toBe(1);
    });
    it('returns period exactly at boundary', () => {
      expect(timeRemaining(30 * 1000, 30)).toBe(30);
    });
  });

  describe('base32', () => {
    it('encodes empty', () => {
      expect(base32Encode(new Uint8Array(0))).toBe('');
    });
    it('round-trips a typical secret', () => {
      const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x42, 0xfe, 0xed]);
      const encoded = base32Encode(bytes);
      const decoded = base32Decode(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(bytes));
    });
    it('decodes RFC 4648 vector', () => {
      // "foobar" -> MZXW6YTBOI======
      expect(base32Decode('MZXW6YTBOI')).toEqual(
        new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72])
      );
    });
    it('ignores padding and whitespace', () => {
      expect(base32Decode('MZXW 6YTB OI==')).toEqual(
        new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72])
      );
    });
    it('rejects non-base32 input', () => {
      expect(() => base32Decode('INVALID8')).toThrow();
    });
  });

  describe('parseOtpauth / buildOtpauth', () => {
    it('parses a typical Google Authenticator URI', () => {
      const uri =
        'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30';
      const parsed = parseOtpauth(uri);
      expect(parsed.type).toBe('totp');
      expect(parsed.issuer).toBe('Example');
      expect(parsed.account).toBe('alice@example.com');
      expect(parsed.algorithm).toBe('SHA1');
      expect(parsed.digits).toBe(6);
      expect(parsed.period).toBe(30);
      expect(parsed.secret).toEqual(base32Decode('JBSWY3DPEHPK3PXP'));
    });

    it('parses HOTP with counter', () => {
      const uri =
        'otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=5';
      const parsed = parseOtpauth(uri);
      expect(parsed.type).toBe('hotp');
      expect(parsed.counter).toBe(5);
    });

    it('falls back to label issuer when no issuer param', () => {
      const uri = 'otpauth://totp/Acme:user?secret=JBSWY3DPEHPK3PXP';
      const parsed = parseOtpauth(uri);
      expect(parsed.issuer).toBe('Acme');
      expect(parsed.account).toBe('user');
    });

    it('rejects non-otpauth URI', () => {
      expect(() => parseOtpauth('https://example.com')).toThrow(/Not an otpauth/);
    });

    it('rejects missing secret', () => {
      expect(() => parseOtpauth('otpauth://totp/Acme:user')).toThrow(/Missing secret/);
    });

    it('rejects unknown algorithm', () => {
      expect(() =>
        parseOtpauth('otpauth://totp/Acme:user?secret=JBSWY3DPEHPK3PXP&algorithm=MD5')
      ).toThrow(/Unsupported algorithm/);
    });

    it('rejects out-of-range digits', () => {
      expect(() =>
        parseOtpauth('otpauth://totp/Acme:user?secret=JBSWY3DPEHPK3PXP&digits=4')
      ).toThrow(/digits/);
    });

    it('round-trips through buildOtpauth', () => {
      const params = {
        type: 'totp' as const,
        label: 'Acme:bob',
        issuer: 'Acme',
        account: 'bob',
        secret: base32Decode('JBSWY3DPEHPK3PXP'),
        algorithm: 'SHA1' as const,
        digits: 6,
        period: 30,
        counter: 0,
      };
      const uri = buildOtpauth(params);
      const parsed = parseOtpauth(uri);
      expect(parsed.issuer).toBe('Acme');
      expect(parsed.account).toBe('bob');
      expect(parsed.algorithm).toBe('SHA1');
      expect(parsed.digits).toBe(6);
      expect(parsed.period).toBe(30);
    });

    it('omits default values in built URI', () => {
      const uri = buildOtpauth({
        type: 'totp',
        label: 'X:y',
        issuer: '',
        account: 'y',
        secret: base32Decode('JBSWY3DPEHPK3PXP'),
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        counter: 0,
      });
      expect(uri).not.toMatch(/algorithm=/);
      expect(uri).not.toMatch(/digits=/);
      expect(uri).not.toMatch(/period=/);
    });
  });
});
