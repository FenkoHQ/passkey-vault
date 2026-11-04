import {
  RelatedOriginVerifier,
  isOriginAuthorized,
  registrableLabel,
} from '../src/background/related-origins';
import { isPublicHost } from '../src/utils/domain';

describe('Related Origin Requests', () => {
  describe('registrableLabel', () => {
    it('derives the label before a single-part TLD', () => {
      expect(registrableLabel('facebook.com')).toBe('facebook');
      expect(registrableLabel('accountscenter.facebook.com')).toBe('facebook');
      expect(registrableLabel('accounts.meta.com')).toBe('meta');
    });

    it('derives the label before a two-level public suffix', () => {
      expect(registrableLabel('shopping.co.uk')).toBe('shopping');
      expect(registrableLabel('www.example.com.au')).toBe('example');
      expect(registrableLabel('www.example.com.ar')).toBe('example');
      expect(registrableLabel('app.github.io')).toBe('app');
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

const META = 'accounts.meta.com';
const FACEBOOK = 'https://accountscenter.facebook.com';

function wellKnown(origins: unknown, init: { status?: number; type?: string; body?: string } = {}) {
  const body = init.body ?? JSON.stringify({ origins });
  return {
    ok: (init.status ?? 200) < 300,
    status: init.status ?? 200,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === 'content-type' ? (init.type ?? 'application/json') : null,
    },
    text: async () => body,
  } as unknown as Response;
}

function verifier(answer: (url: string) => Response = () => wellKnown([FACEBOOK])) {
  let now = 1_000_000;
  const fetch = jest.fn(async (url: string) => answer(url));
  const subject = new RelatedOriginVerifier({ fetch, now: () => now });
  return { subject, fetch, advance: (ms: number) => (now += ms) };
}

describe('which RP IDs may be fetched from', () => {
  it.each([
    // IP literals in every notation the URL parser accepts.
    '192.168.1.1',
    '169.254.169.254',
    '127.0.0.1',
    '0x7f.1',
    '0x7f000001',
    '2130706433',
    '0177.0.0.1',
    '[::1]',
    '[fe80::1]',
    // Names that are not on the public Internet.
    'localhost',
    'router',
    'router.lan',
    'printer.local',
    'git.corp',
    'service.internal',
    'router.home.arpa',
    '1.168.192.in-addr.arpa',
    'site.test',
    'x.example',
    'hidden.onion',
    // Public suffixes themselves, and malformed names.
    'com',
    'co.uk',
    'github.io',
    'Accounts.Meta.com',
    'meta.com.',
    'meta.com:443',
    'evil.com/x',
    '',
  ])('refuses %p without a request', async (rpId) => {
    const { subject, fetch } = verifier();

    expect(await subject.verify(rpId, FACEBOOK)).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    expect(isPublicHost(rpId)).toBe(false);
  });

  it.each([META, 'login.microsoft.com', 'shopify.com', 'amazon.de', 'app.github.io'])(
    'fetches %s',
    (rpId) => {
      expect(isPublicHost(rpId)).toBe(true);
    }
  );

  it('authorizes a listed origin from the RP ID’s own HTTPS origin', async () => {
    const { subject, fetch } = verifier();

    expect(await subject.verify(META, FACEBOOK)).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      `https://${META}/.well-known/webauthn`,
      expect.objectContaining({ credentials: 'omit', redirect: 'error' })
    );
  });

  it('does not fetch for a caller that is not https', async () => {
    const { subject, fetch } = verifier();

    expect(await subject.verify(META, 'http://accountscenter.facebook.com')).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('Related Origin Request lookups', () => {
  it('caches a missing file as well as a good one', async () => {
    const { subject, fetch } = verifier((url) =>
      url.includes(META) ? wellKnown([FACEBOOK]) : wellKnown(null, { status: 404 })
    );

    for (let i = 0; i < 3; i++) {
      expect(await subject.verify('nope.example.com', FACEBOOK)).toBe(false);
      expect(await subject.verify(META, FACEBOOK)).toBe(true);
    }
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('caches a file that is not JSON, or too large', async () => {
    const big = JSON.stringify({ origins: [FACEBOOK], pad: 'x'.repeat(70 * 1024) });
    const { subject, fetch } = verifier((url) =>
      url.includes('html')
        ? wellKnown(null, { type: 'text/html', body: '<html>' })
        : wellKnown(null, { body: big })
    );

    expect(await subject.verify('html.example.com', FACEBOOK)).toBe(false);
    expect(await subject.verify('big.example.com', FACEBOOK)).toBe(false);
    expect(await subject.verify('html.example.com', FACEBOOK)).toBe(false);
    expect(await subject.verify('big.example.com', FACEBOOK)).toBe(false);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('asks again once the cached answer expires', async () => {
    const { subject, fetch, advance } = verifier();
    await subject.verify(META, FACEBOOK);

    advance(11 * 60 * 1000);
    await subject.verify(META, FACEBOOK);

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('shares one request between concurrent lookups of the same RP ID', async () => {
    const { subject, fetch } = verifier();

    const answers = await Promise.all([1, 2, 3].map(() => subject.verify(META, FACEBOOK)));

    expect(answers).toEqual([true, true, true]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('gives each calling site a few lookups, shared by its subdomains', async () => {
    const { subject, fetch, advance } = verifier(() => wellKnown(null, { status: 404 }));
    const probe = (n: number, origin: string) => subject.verify(`h${n}.example.com`, origin);

    for (let n = 0; n < 4; n++) await probe(n, `https://s${n}.evil.co.uk`);
    await probe(4, 'https://www.evil.co.uk');
    await probe(5, 'https://evil.co.uk');
    expect(fetch).toHaveBeenCalledTimes(4);

    // Another site has its own budget, and a site's budget comes back.
    await probe(6, 'https://other.com');
    expect(fetch).toHaveBeenCalledTimes(5);
    advance(11 * 60 * 1000);
    await probe(7, 'https://evil.co.uk');
    expect(fetch).toHaveBeenCalledTimes(6);
  });

  it('caps lookups across all sites', async () => {
    const { subject, fetch } = verifier(() => wellKnown(null, { status: 404 }));

    for (let n = 0; n < 40; n++) {
      await subject.verify(`h${n}.example.com`, `https://site${n}.com`);
    }

    expect(fetch).toHaveBeenCalledTimes(30);
  });

  it('still answers from the cache when the budget is spent', async () => {
    const { subject, fetch } = verifier((url) =>
      url.includes(META) ? wellKnown([FACEBOOK]) : wellKnown(null, { status: 404 })
    );
    await subject.verify(META, FACEBOOK);
    for (let n = 0; n < 5; n++) await subject.verify(`h${n}.example.com`, FACEBOOK);

    expect(await subject.verify(META, FACEBOOK)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('reads a streamed body only up to its limit', async () => {
    const chunk = new TextEncoder().encode(' '.repeat(16 * 1024));
    let reads = 0;
    const cancel = jest.fn(async () => undefined);
    const streamed = (chunks: number) =>
      ({
        ok: true,
        status: 200,
        headers: { get: (name: string) => (name === 'content-type' ? 'application/json' : null) },
        body: {
          getReader: () => {
            let left = chunks;
            const tail = new TextEncoder().encode(JSON.stringify({ origins: [FACEBOOK] }));
            return {
              read: async () => {
                reads++;
                if (left > 0) return { done: false, value: left-- === 1 ? tail : chunk };
                return { done: true, value: undefined };
              },
              cancel,
            };
          },
        },
      }) as unknown as Response;
    const { subject } = verifier((url) => streamed(url.includes('small') ? 2 : 1000));

    expect(await subject.verify('small.example.com', FACEBOOK)).toBe(true);
    reads = 0;
    expect(await subject.verify('huge.example.com', FACEBOOK)).toBe(false);
    expect(reads).toBeLessThan(10);
    expect(cancel).toHaveBeenCalled();
  });

  it('refuses a declared length over the limit without reading it', async () => {
    const text = jest.fn(async () => JSON.stringify({ origins: [FACEBOOK] }));
    const { subject } = verifier(
      () =>
        ({
          ok: true,
          status: 200,
          headers: {
            get: (name: string) =>
              name === 'content-type' ? 'application/json' : String(10 * 1024 * 1024),
          },
          text,
        }) as unknown as Response
    );

    expect(await subject.verify(META, FACEBOOK)).toBe(false);
    expect(text).not.toHaveBeenCalled();
  });
});
