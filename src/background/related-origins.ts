// WebAuthn Related Origin Requests (WebAuthn L3 §5.11).
//
// Some RPs deliberately use an RP ID that is not same-site with the page the
// ceremony runs on. The canonical example is Meta: passkeys are created on
// https://accountscenter.facebook.com but with RP ID accounts.meta.com. A
// strict same-site check rejects this, so the spec lets the RP authorize such
// origins by publishing them at https://<rpId>/.well-known/webauthn. The trust
// anchor is that this file is served from the RP ID's own HTTPS origin, which
// only the RP controls.

import { logger } from '../utils/logger';

// Max number of distinct registrable-domain labels a well-known file may
// authorize. The spec requires clients to support at least 5; we cap there.
const MAX_LABELS = 5;

// Cache successful/failed lookups briefly so we don't refetch on every
// ceremony. Best-effort: lost when the service worker is torn down.
const CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5000;

// A small set of common two-level public suffixes so the derived label is the
// registrable label rather than the country-code second level. This only
// affects the anti-abuse label cap — the security gate is the exact origin
// match below, which does not depend on this list.
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

// rpId must be a bare hostname: dot-separated labels of letters/digits/hyphens,
// at least one dot. Rejects scheme/path/port injection and bare hosts before
// they reach the fetch URL.
const HOSTNAME_RE =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const originsCache = new Map<string, { origins: unknown; expiry: number }>();

/**
 * Derive the registrable-domain label of a hostname: the label directly
 * preceding the effective TLD. e.g. accountscenter.facebook.com -> "facebook",
 * shopping.co.uk -> "shopping". Returns null for hostnames with no label.
 */
export function registrableLabel(hostname: string): string | null {
  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return null;
  const lastTwo = parts.slice(-2).join('.');
  if (parts.length >= 3 && TWO_LEVEL_SUFFIXES.has(lastTwo)) {
    return parts[parts.length - 3];
  }
  return parts[parts.length - 2];
}

/**
 * Decide whether `callerOrigin` is authorized by the parsed `origins` list from
 * an RP's /.well-known/webauthn file.
 *
 * The caller origin must appear verbatim (scheme + host + port) in the list,
 * and its registrable-domain label must fall within the first MAX_LABELS
 * distinct labels encountered — the WebAuthn Related Origin Requests rule that
 * stops an RP from federating an unbounded number of unrelated sites.
 */
export function isOriginAuthorized(callerOrigin: string, origins: unknown): boolean {
  if (!Array.isArray(origins)) return false;
  const labelsSeen = new Set<string>();
  for (const entry of origins) {
    if (typeof entry !== 'string') continue;
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      continue;
    }
    if (url.protocol !== 'https:') continue;
    const label = registrableLabel(url.hostname);
    if (label === null) continue;

    if (url.origin === callerOrigin) {
      // A match only counts while its label is within the label budget.
      return labelsSeen.has(label) || labelsSeen.size < MAX_LABELS;
    }
    if (!labelsSeen.has(label) && labelsSeen.size < MAX_LABELS) {
      labelsSeen.add(label);
    }
  }
  return false;
}

async function fetchOrigins(rpId: string, now: number): Promise<unknown> {
  const cached = originsCache.get(rpId);
  if (cached && cached.expiry > now) return cached.origins;

  const url = `https://${rpId}/.well-known/webauthn`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      credentials: 'omit',
      redirect: 'error', // cross-origin redirects are not honoured by the spec
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const contentType = (res.headers.get('content-type') || '').toLowerCase();
    if (!contentType.includes('application/json')) return null;
    const body = (await res.json()) as Record<string, unknown> | null;
    const origins = body?.origins ?? null;
    originsCache.set(rpId, { origins, expiry: now + CACHE_TTL_MS });
    return origins;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Returns true iff `callerOrigin` is authorized to use `rpId` via Related
 * Origin Requests. Fetches and caches the RP's well-known file. Never throws.
 */
export async function verifyRelatedOrigin(rpId: string, callerOrigin: string): Promise<boolean> {
  const id = (rpId || '').toLowerCase();
  if (!HOSTNAME_RE.test(id)) return false;

  let originToMatch: string;
  try {
    // Normalise (drop default port, lower-case host) so the compare is exact.
    originToMatch = new URL(callerOrigin).origin;
  } catch {
    return false;
  }

  const origins = await fetchOrigins(id, Date.now());
  if (origins === null) return false;

  const ok = isOriginAuthorized(originToMatch, origins);
  if (ok) {
    logger.info('Related Origin Requests: authorized', originToMatch, 'for RP', id);
  }
  return ok;
}
