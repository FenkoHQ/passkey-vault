// Host names, public suffixes and registrable domains, from the full Public
// Suffix List (public-suffix-list.ts, both its ICANN and PRIVATE sections).
//
// This is the one place the extension decides what a site is: which RP IDs
// a page may claim (rp-id.ts), which hosts a Related Origin Requests file
// may be fetched from and how its origins are counted (related-origins.ts),
// and which passkeys share a site icon (site-icons). It matches what Chrome's
// WebAuthn uses, net::registry_controlled_domains with
// INCLUDE_UNKNOWN_REGISTRIES and INCLUDE_PRIVATE_REGISTRIES: a top-level
// domain the list does not know is its own public suffix, as the list's
// default "*" rule says.
//
// The list is about 90 KB, so this module must stay out of the content
// script, which runs on every page: the content script asks the background.

import { PUBLIC_SUFFIX_TRIE } from './public-suffix-list';

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DOMAIN_NAME = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*$`);
// The URL parser reads a host whose last label is a number (decimal, octal
// or 0x hex) as an IPv4 address: 0x7f.1 and 2130706433 are 127.0.0.1.
const NUMERIC_LAST_LABEL = /(^|\.)(0x[0-9a-f]*|[0-9]+)$/;

/**
 * A lower-case DNS name of letter-digit-hyphen labels, as a URL parser would
 * leave it: no IPv4 address in any notation, no IPv6 literal, no trailing
 * dot, port, scheme or wildcard.
 */
export function isDomainName(host: string): boolean {
  return DOMAIN_NAME.test(host) && !NUMERIC_LAST_LABEL.test(host);
}

interface SuffixNode {
  /** 0: only a path to longer rules; 1: a rule; 2: an exception rule. */
  rule: 0 | 1 | 2;
  children: Map<string, SuffixNode> | null;
}

export interface PublicSuffix {
  /** The public suffix, e.g. "co.uk" for www.example.co.uk. */
  suffix: string;
  /** False when no rule matched and the top-level domain stood in for one. */
  listed: boolean;
}

export interface SuffixMatcher {
  publicSuffix(host: string): PublicSuffix | null;
}

function parseTrie(entries: readonly string[]): Map<string, SuffixNode> {
  const root = new Map<string, SuffixNode>();
  for (const entry of entries) {
    let pos = 0;
    const node = (into: Map<string, SuffixNode>): void => {
      const start = pos;
      while (pos < entry.length && !'!?(),'.includes(entry[pos])) pos++;
      const label = entry.slice(start, pos);
      let rule: SuffixNode['rule'] = 1;
      if (entry[pos] === '!') {
        rule = 2;
        pos++;
      } else if (entry[pos] === '?') {
        rule = 0;
        pos++;
      }
      const parsed: SuffixNode = { rule, children: null };
      if (entry[pos] === '(') {
        parsed.children = new Map();
        do {
          pos++;
          node(parsed.children);
        } while (entry[pos] === ',');
        if (entry[pos] !== ')') throw new Error(`Malformed suffix trie at ${label}`);
        pos++;
      }
      into.set(label, parsed);
    };
    node(root);
    if (pos !== entry.length) throw new Error(`Malformed suffix trie entry ${entry.slice(0, 20)}`);
  }
  return root;
}

/** A Public Suffix List matcher over trie entries in the generated format. */
export function createSuffixMatcher(entries: readonly string[]): SuffixMatcher {
  let root: Map<string, SuffixNode> | null = null;
  return {
    publicSuffix(host: string): PublicSuffix | null {
      const name = host.toLowerCase();
      if (!isDomainName(name)) return null;
      root ??= parseTrie(entries);

      const labels = name.split('.').reverse();
      // The longest matching rule wins; an exception beats every rule and
      // makes its parent the suffix. The list only has wildcards leftmost,
      // so a wildcard node never has children to walk into.
      let length = 0;
      let children: Map<string, SuffixNode> | null = root;
      for (let depth = 0; depth < labels.length && children; depth++) {
        const exact = children.get(labels[depth]);
        if (exact?.rule === 2) {
          length = depth;
          break;
        }
        if (exact?.rule === 1 || children.get('*')?.rule === 1) {
          length = depth + 1;
        }
        children = exact?.children ?? null;
      }
      const listed = length > 0;
      const count = listed ? length : 1;
      return {
        suffix: labels.slice(0, count).reverse().join('.'),
        listed,
      };
    },
  };
}

const matcher = createSuffixMatcher(PUBLIC_SUFFIX_TRIE);

/** The public suffix of a host name, or null when it is not a domain name. */
export function publicSuffix(host: string): PublicSuffix | null {
  return matcher.publicSuffix(host);
}

/**
 * The registrable domain of a host: its public suffix plus one label, e.g.
 * accounts.google.com -> google.com, www.shop.co.uk -> shop.co.uk,
 * a.b.github.io -> b.github.io. Null for a host that is itself a public
 * suffix (com, github.io), a single label, or not a domain name at all.
 */
export function registrableDomain(host: string): string | null {
  const found = publicSuffix(host);
  if (!found) return null;
  const labels = host.toLowerCase().split('.');
  const suffixLabels = found.suffix.split('.').length;
  if (labels.length <= suffixLabels) return null;
  return labels.slice(-(suffixLabels + 1)).join('.');
}

/**
 * The label of the registrable domain in front of its public suffix:
 * accountscenter.facebook.com -> "facebook", shopping.co.uk -> "shopping".
 * WebAuthn's Related Origin Requests count origins by this label.
 */
export function registrableLabel(host: string): string | null {
  const domain = registrableDomain(host);
  return domain === null ? null : domain.split('.')[0];
}

// Special-use names (RFC 6761, 6762, 7686, 8375, 9476, and ICANN's
// .internal): never a public website, even when the list has a rule for
// them (it lists arpa and home.arpa).
const SPECIAL_USE_TLDS = new Set([
  'alt',
  'arpa',
  'example',
  'internal',
  'invalid',
  'local',
  'localhost',
  'onion',
  'test',
]);

/**
 * Whether a host is a name on the public Internet: a domain name under a
 * suffix the Public Suffix List actually lists (not the default rule for an
 * unknown top-level domain such as .lan or .corp), with a registrable
 * domain of its own, outside the special-use names. Used before the
 * extension fetches from a host a web page named.
 */
export function isPublicHost(host: string): boolean {
  if (host !== host.toLowerCase()) return false;
  const found = publicSuffix(host);
  if (!found || !found.listed) return false;
  if (SPECIAL_USE_TLDS.has(host.slice(host.lastIndexOf('.') + 1))) return false;
  return registrableDomain(host) !== null;
}
