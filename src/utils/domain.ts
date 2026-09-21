// Hostname → registrable domain, without shipping the full Public Suffix List.
//
// A small set of common two-level public suffixes so a derived base domain is
// the registrable one rather than the country-code second level. This is a
// best-effort list used for grouping and display (icon keying, the related
// origin label cap) — never as a security boundary. Getting `foo.co.nz` wrong
// costs a wrong grouping key, nothing more.
const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'co.nz',
  'co.za',
  'co.in',
  'co.kr',
  'com.br',
  'com.mx',
  'com.tr',
  'com.cn',
  'com.hk',
  'com.sg',
  'com.tw',
]);

const MIN_LABELS = 2;
const LABELS_WITH_TWO_LEVEL_SUFFIX = 3;

/**
 * Derive the registrable domain of a hostname: the effective TLD plus one
 * label. e.g. accounts.google.com -> "google.com", shopping.co.uk ->
 * "shopping.co.uk". Returns null for hostnames with no registrable label.
 */
export function baseDomain(hostname: string): string | null {
  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length < MIN_LABELS) {
    return null;
  }

  const hasTwoLevelSuffix =
    parts.length >= LABELS_WITH_TWO_LEVEL_SUFFIX &&
    TWO_LEVEL_SUFFIXES.has(parts.slice(-2).join('.'));

  return parts.slice(hasTwoLevelSuffix ? -LABELS_WITH_TWO_LEVEL_SUFFIX : -MIN_LABELS).join('.');
}

/**
 * Derive the registrable-domain label of a hostname: the label directly
 * preceding the effective TLD. e.g. accountscenter.facebook.com -> "facebook",
 * shopping.co.uk -> "shopping". Returns null for hostnames with no label.
 */
export function registrableLabel(hostname: string): string | null {
  const base = baseDomain(hostname);
  if (base === null) {
    return null;
  }
  return base.split('.')[0];
}
