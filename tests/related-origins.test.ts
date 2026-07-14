import { registrableLabel, isOriginAuthorized } from '../src/background/related-origins';

describe('Related Origin Requests', () => {
  describe('registrableLabel', () => {
    it('derives the label before a single-part TLD', () => {
      expect(registrableLabel('facebook.com')).toBe('facebook');
      expect(registrableLabel('accountscenter.facebook.com')).toBe('facebook');
      expect(registrableLabel('accounts.meta.com')).toBe('meta');
    });

    it('derives the label before a known two-level public suffix', () => {
      expect(registrableLabel('shopping.co.uk')).toBe('shopping');
      expect(registrableLabel('www.example.com.au')).toBe('example');
    });

    it('returns null for a bare label', () => {
      expect(registrableLabel('localhost')).toBeNull();
      expect(registrableLabel('')).toBeNull();
    });
  });

  describe('isOriginAuthorized', () => {
    // The real Meta case that regressed in 0.9.3.
    const metaOrigins = [
      'https://messenger.com',
      'https://www.facebook.com',
      'https://accountscenter.facebook.com',
      'https://www.instagram.com',
      'https://accounts.meta.com',
    ];

    it('authorizes a listed cross-site origin (Meta/Facebook)', () => {
      expect(isOriginAuthorized('https://accountscenter.facebook.com', metaOrigins)).toBe(true);
    });

    it('authorizes the RP-ID origin itself when listed', () => {
      expect(isOriginAuthorized('https://accounts.meta.com', metaOrigins)).toBe(true);
    });

    it('rejects an origin that is not in the list', () => {
      expect(isOriginAuthorized('https://evil.com', metaOrigins)).toBe(false);
    });

    it('rejects a scheme mismatch', () => {
      expect(isOriginAuthorized('http://accountscenter.facebook.com', metaOrigins)).toBe(false);
    });

    it('rejects a port mismatch', () => {
      expect(isOriginAuthorized('https://accountscenter.facebook.com:8443', metaOrigins)).toBe(
        false
      );
    });

    it('ignores non-https and malformed entries', () => {
      const origins = ['http://a.com', 'not-a-url', 42, 'https://good.com'];
      expect(isOriginAuthorized('https://good.com', origins)).toBe(true);
      expect(isOriginAuthorized('https://a.com', origins)).toBe(false);
    });

    it('rejects non-array input', () => {
      expect(isOriginAuthorized('https://good.com', null)).toBe(false);
      expect(isOriginAuthorized('https://good.com', { origins: [] })).toBe(false);
    });

    it('enforces the 5-distinct-label cap', () => {
      // Six distinct labels; the match sits after five others have been seen.
      const origins = [
        'https://one.com',
        'https://two.com',
        'https://three.com',
        'https://four.com',
        'https://five.com',
        'https://six.com', // 6th distinct label -> beyond budget
      ];
      expect(isOriginAuthorized('https://six.com', origins)).toBe(false);
      // Fifth label is still within budget.
      expect(isOriginAuthorized('https://five.com', origins)).toBe(true);
    });

    it('allows many origins that share already-counted labels', () => {
      const origins = [
        'https://a.com',
        'https://www.a.com',
        'https://login.a.com',
        'https://b.com',
        'https://c.com',
        'https://d.com',
        'https://e.com',
        'https://deep.e.com', // same label "e" -> fine even though it appears late
      ];
      expect(isOriginAuthorized('https://deep.e.com', origins)).toBe(true);
    });
  });
});
