/**
 * Which RP IDs a page may claim: the host, or one of its parents down to
 * the registrable domain (WebAuthn Level 3 §5.1.3 step 8). Checked against
 * a table of the cases browsers decide, and as a property against a small
 * reference implementation over generated hosts. The reference's suffixes
 * are all in the Public Suffix List except "example", which the list does
 * not know and so treats as a top-level suffix, as Chrome does.
 */

import { isRpIdValidForHost } from '../../src/utils/rp-id';
import { prng } from '../helpers/bytes';

describe('isRpIdValidForHost', () => {
  it.each([
    ['example.com', 'example.com', true],
    ['www.example.com', 'example.com', true],
    ['a.b.example.com', 'b.example.com', true],
    ['Example.COM', 'example.com', true],
    ['www.example.co.uk', 'example.co.uk', true],
    ['localhost', 'localhost', true],
    ['127.0.0.1', '127.0.0.1', false],
    ['[::1]', '[::1]', false],
    ['10.0.0.1', '10.0.0.1', false],
    ['example.com', 'EXAMPLE.COM', false],
    ['www.example.com', 'Example.com', false],
    ['example.com', 'com', false],
    ['www.example.co.uk', 'co.uk', false],
    ['www.example.co.uk', 'uk', false],
    ['example.com', 'www.example.com', false],
    ['a.example.com', 'b.example.com', false],
    ['notexample.com', 'example.com', false],
    ['example.com.evil.com', 'example.com', false],
    ['192.168.1.10', '168.1.10', false],
    ['192.168.1.10', '1.10', false],
    ['10.0.0.1', '0.1', false],
    ['example.com', '', false],
    ['example.com', 'example.com.', false],
    ['example.com', '.example.com', false],
    ['example.com', 'example.com:443', false],
    ['example.com', 'https://example.com', false],
    ['example.com', 'exa mple.com', false],
    ['sub.example.com', 'ex*mple.com', false],
    // Public suffixes from the full list, private section included, as
    // Chrome checks them.
    ['foo.github.io', 'github.io', false],
    ['a.foo.github.io', 'foo.github.io', true],
    ['a.b.blogspot.com', 'blogspot.com', false],
    ['shop.example.com.ar', 'com.ar', false],
    ['shop.example.com.ar', 'example.com.ar', true],
    ['www.example.gov.au', 'gov.au', false],
    // Inside the page's own public suffix (up.railway.app is listed).
    ['foo.up.railway.app', 'up.railway.app', false],
    ['foo.up.railway.app', 'railway.app', false],
    // A top-level domain the list does not know is a suffix of one label.
    ['www.nas.lan', 'nas.lan', true],
    ['www.nas.lan', 'lan', false],
  ])('host %s, RP ID %s -> %s', (host, rpId, expected) => {
    expect(isRpIdValidForHost(rpId, host)).toBe(expected);
  });

  // A reference built from first principles over a known suffix list.
  const SUFFIXES = ['com', 'org', 'example', 'co.uk', 'com.au'];
  function reference(rpId: string, host: string): boolean {
    if (rpId === host) return true;
    if (!host.endsWith('.' + rpId)) return false;
    const suffix = SUFFIXES.filter((s) => host === s || host.endsWith('.' + s)).sort(
      (a, b) => b.length - a.length
    )[0];
    if (!suffix) return false;
    const registrable = host
      .split('.')
      .slice(-(suffix.split('.').length + 1))
      .join('.');
    return rpId === registrable || rpId.endsWith('.' + registrable);
  }

  it('agrees with the reference on generated hosts and every suffix of them', () => {
    const random = prng(0x5eed);
    const label = () =>
      ['a', 'login', 'www', 'x-y', 'b2', 'accounts', 'm'][Math.floor(random() * 7)];
    for (let i = 0; i < 2000; i++) {
      const suffix = SUFFIXES[Math.floor(random() * SUFFIXES.length)];
      const host = [...Array.from({ length: 1 + Math.floor(random() * 4) }, label), suffix].join(
        '.'
      );
      const parts = host.split('.');
      for (let start = 0; start < parts.length; start++) {
        const rpId = parts.slice(start).join('.');
        expect([host, rpId, isRpIdValidForHost(rpId, host)]).toEqual([
          host,
          rpId,
          reference(rpId, host),
        ]);
      }
    }
  });
});
