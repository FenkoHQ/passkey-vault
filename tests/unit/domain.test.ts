/**
 * Registrable domains from the full Public Suffix List: the list's own test
 * vectors, the cases a hand-picked suffix list got wrong, the generator's
 * trie format, and the generated data itself.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { domainToASCII } from 'url';
import {
  createSuffixMatcher,
  isDomainName,
  publicSuffix,
  registrableDomain,
  registrableLabel,
} from '../../src/utils/domain';
import { PUBLIC_SUFFIX_TRIE } from '../../src/utils/public-suffix-list';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const generator = require('../../scripts/update-public-suffix-list.js');

const VECTORS = readFileSync(join(__dirname, '../fixtures/public-suffix-test-vectors.txt'), 'utf8')
  .split('\n')
  .map((line) => /^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\);$/.exec(line))
  .filter((match): match is RegExpExecArray => match !== null)
  .map(([, input, expected]) => {
    const value = (text: string) => (text === 'null' ? null : text.slice(1, -1));
    return [value(input), value(expected)] as const;
  });

describe('registrableDomain', () => {
  it('has the list’s test vectors to run', () => {
    expect(VECTORS.length).toBe(78);
  });

  // Hostnames reach the vault in ASCII, so the IDN vectors are run punycoded.
  it.each(VECTORS)('checkPublicSuffix(%p) is %p', (input, expected) => {
    const host = input === null ? '' : input.startsWith('.') ? input : domainToASCII(input);
    const want = expected === null ? null : domainToASCII(expected);
    expect(registrableDomain(host)).toBe(want);
  });

  it.each([
    // Private registries count, as in Chrome's WebAuthn check.
    ['foo.github.io', 'foo.github.io'],
    ['github.io', null],
    ['a.b.blogspot.com', 'b.blogspot.com'],
    ['x.up.railway.app', 'x.up.railway.app'],
    // ICANN two-level suffixes the previous built-in list did not have.
    ['shop.example.com.ar', 'example.com.ar'],
    ['www.example.gov.au', 'example.gov.au'],
    ['www.example.ac.nz', 'example.ac.nz'],
    // Unknown top-level domains are their own public suffix.
    ['router.lan', 'router.lan'],
    ['lan', null],
    // Not domain names.
    ['192.168.1.1', null],
    ['0x7f.1', null],
    ['[::1]', null],
    ['example.com.', null],
  ])('%s -> %p', (host, expected) => {
    expect(registrableDomain(host)).toBe(expected);
  });

  it('derives the label the related-origin cap counts', () => {
    expect(registrableLabel('accountscenter.facebook.com')).toBe('facebook');
    expect(registrableLabel('www.shopping.co.uk')).toBe('shopping');
    expect(registrableLabel('one.github.io')).toBe('one');
    expect(registrableLabel('github.io')).toBeNull();
  });

  it('says whether the list or only the default rule matched', () => {
    expect(publicSuffix('www.example.co.uk')).toEqual({ suffix: 'co.uk', listed: true });
    expect(publicSuffix('nas.home.lan')).toEqual({ suffix: 'lan', listed: false });
    expect(publicSuffix('127.0.0.1')).toBeNull();
  });
});

describe('isDomainName', () => {
  it.each([
    ['example.com', true],
    ['a-b.example', true],
    ['xn--85x722f.xn--fiqs8s', true],
    ['localhost', true],
    // IPv4 in every notation the URL parser accepts, and IPv6.
    ['127.0.0.1', false],
    ['2130706433', false],
    ['0x7f000001', false],
    ['0x7f.1', false],
    ['0177.0.0.1', false],
    ['169.254.169.254', false],
    ['example.0x', false],
    ['[::1]', false],
    ['::1', false],
    // Not a bare lower-case name.
    ['Example.com', false],
    ['example.com.', false],
    ['.example.com', false],
    ['example..com', false],
    ['-example.com', false],
    ['example.com:443', false],
    ['*.example.com', false],
    ['exa mple.com', false],
    ['', false],
    [`${'a'.repeat(64)}.com`, false],
  ])('%s -> %p', (host, expected) => {
    expect(isDomainName(host)).toBe(expected);
  });
});

describe('the generated suffix trie', () => {
  const LIST = [
    '// ===BEGIN ICANN DOMAINS===',
    'com',
    'uk',
    'co.uk',
    '*.ck',
    '!www.ck',
    'jp',
    '*.kawasaki.jp',
    '!city.kawasaki.jp',
    '公司.cn',
    'cn',
    '// ===END ICANN DOMAINS===',
    '// ===BEGIN PRIVATE DOMAINS===',
    'github.io',
    'blogspot.com',
    '// ===END PRIVATE DOMAINS===',
  ].join('\n');

  it('round-trips rules, wildcards, exceptions and IDNs', () => {
    const matcher = createSuffixMatcher(generator.serialize(generator.parseList(LIST)));
    const suffix = (host: string) => matcher.publicSuffix(host);

    expect(suffix('www.example.co.uk')).toEqual({ suffix: 'co.uk', listed: true });
    expect(suffix('a.b.ck')).toEqual({ suffix: 'b.ck', listed: true });
    expect(suffix('www.ck')).toEqual({ suffix: 'ck', listed: true });
    expect(suffix('x.city.kawasaki.jp')).toEqual({ suffix: 'kawasaki.jp', listed: true });
    expect(suffix('x.other.kawasaki.jp')).toEqual({ suffix: 'other.kawasaki.jp', listed: true });
    expect(suffix('shop.xn--55qx5d.cn')).toEqual({ suffix: 'xn--55qx5d.cn', listed: true });
    expect(suffix('me.github.io')).toEqual({ suffix: 'github.io', listed: true });
    expect(suffix('io')).toEqual({ suffix: 'io', listed: false });
  });

  it('writes one entry per top-level domain', () => {
    expect(generator.serialize(generator.parseList(LIST))).toEqual([
      'ck?(*,www!)',
      'cn(xn--55qx5d)',
      'com(blogspot)',
      'io?(github)',
      'jp(kawasaki?(*,city!))',
      'uk(co)',
    ]);
  });

  it('refuses a list without both sections', () => {
    expect(() => generator.parseList('// ===BEGIN ICANN DOMAINS===\ncom\n')).toThrow();
  });

  it('holds the whole list: every rule the header counts', () => {
    const source = readFileSync(join(__dirname, '../../src/utils/public-suffix-list.ts'), 'utf8');
    const [, icann, privateRules] = /Rules: +(\d+) ICANN, (\d+) private/.exec(source)!;
    // Rules are labels with no marker; exceptions carry "!", paths "?".
    const rules = PUBLIC_SUFFIX_TRIE.join(',').match(/[a-z0-9*-]+(?=[(),]|$)/g)!;
    const exceptions = PUBLIC_SUFFIX_TRIE.join(',').match(/!/g)!;
    expect(rules.length + exceptions.length).toBe(Number(icann) + Number(privateRules));
    expect(Number(icann)).toBeGreaterThan(6000);
    expect(Number(privateRules)).toBeGreaterThan(2000);
  });
});
