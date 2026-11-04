// WebAuthn Related Origin Requests (WebAuthn L3 §5.11).
//
// Some RPs deliberately use an RP ID that is not same-site with the page the
// ceremony runs on. The canonical example is Meta: passkeys are created on
// https://accountscenter.facebook.com but with RP ID accounts.meta.com. A
// strict same-site check rejects this, so the spec lets the RP authorize such
// origins by publishing them at https://<rpId>/.well-known/webauthn. The trust
// anchor is that this file is served from the RP ID's own HTTPS origin, which
// only the RP controls.
//
// The RP ID comes from the web page, and the fetch goes out from the
// extension with its host permissions, so a page could otherwise point it at
// anything the browser can reach: a router at 192.168.1.1, a metadata
// service at 169.254.169.254, an intranet name. So the RP ID must be a public
// Internet name (isPublicHost: a registrable domain under a suffix the Public
// Suffix List lists, never an IP literal, a single label, an unlisted or
// special-use TLD), every answer is cached, failures included, and each site
// gets only a few lookups that miss the cache.

import { logger } from '../utils/logger';
import { isPublicHost, registrableDomain, registrableLabel } from '../utils/domain';

// Re-exported: the label cap below is the only consumer inside this module.
export { registrableLabel };

// Max number of distinct registrable-domain labels a well-known file may
// authorize. The spec requires clients to support at least 5; we cap there.
const MAX_LABELS = 5;

// Answers are kept this long, a missing or broken file as well as a good one,
// so a page cannot make the vault fetch the same RP ID again and again. Lost
// when the service worker stops.
const CACHE_TTL_MS = 10 * 60 * 1000;
const MAX_CACHED_RP_IDS = 256;
const FETCH_TIMEOUT_MS = 5000;
// Meta's file, one of the largest in use, lists 130 origins in about 5 KB.
const MAX_BODY_BYTES = 64 * 1024;

// Lookups that miss the cache, per calling site (registrable domain, so all
// of a site's subdomains and tabs share one budget) and in total, within a
// sliding window. A real site uses one RP ID; when a budget runs out the
// request is left to the browser, which runs its own Related Origin check.
const LOOKUP_WINDOW_MS = 10 * 60 * 1000;
const LOOKUPS_PER_SITE = 4;
const LOOKUPS_TOTAL = 30;

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

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export interface RelatedOriginOptions {
  fetch?: Fetch;
  now?: () => number;
}

/** Read a response body as text, giving up past `limit` bytes. */
async function readCapped(response: Response, limit: number): Promise<string | null> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) return null;
  const reader = response.body?.getReader?.();
  if (!reader) {
    const text = await response.text();
    return text.length > limit ? null : text;
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export class RelatedOriginVerifier {
  private readonly cache = new Map<string, { origins: unknown; expiry: number }>();
  private readonly inFlight = new Map<string, Promise<unknown>>();
  private lookups: Array<{ site: string; at: number }> = [];
  private readonly fetch: Fetch;
  private readonly now: () => number;

  constructor(options: RelatedOriginOptions = {}) {
    this.fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.now = options.now ?? Date.now;
  }

  /**
   * Whether `callerOrigin` may use `rpId` through the RP's
   * /.well-known/webauthn file. Never throws.
   */
  async verify(rpId: string, callerOrigin: string): Promise<boolean> {
    if (typeof rpId !== 'string' || !isPublicHost(rpId)) return false;
    let caller: URL;
    try {
      caller = new URL(callerOrigin);
    } catch {
      return false;
    }
    // The file can only list https origins, so nothing else needs a fetch.
    if (caller.protocol !== 'https:') return false;

    const site = registrableDomain(caller.hostname) ?? caller.hostname;
    const origins = await this.originsFor(rpId, site);
    if (origins === null) return false;

    // Normalised (default port dropped, host lower-cased) so the compare is exact.
    const ok = isOriginAuthorized(caller.origin, origins);
    if (ok) {
      logger.info('Related Origin Requests: authorized', caller.origin, 'for RP', rpId);
    }
    return ok;
  }

  private originsFor(rpId: string, site: string): Promise<unknown> {
    const now = this.now();
    const cached = this.cache.get(rpId);
    if (cached && cached.expiry > now) return Promise.resolve(cached.origins);
    const pending = this.inFlight.get(rpId);
    if (pending) return pending;
    if (!this.takeLookup(site, now)) {
      logger.warn('Related Origin Requests: lookup budget spent for', site);
      return Promise.resolve(null);
    }
    const lookup = this.fetchOrigins(rpId)
      .then((origins) => {
        this.remember(rpId, origins);
        return origins;
      })
      .finally(() => this.inFlight.delete(rpId));
    this.inFlight.set(rpId, lookup);
    return lookup;
  }

  private takeLookup(site: string, now: number): boolean {
    this.lookups = this.lookups.filter((lookup) => lookup.at > now - LOOKUP_WINDOW_MS);
    const forSite = this.lookups.filter((lookup) => lookup.site === site).length;
    if (forSite >= LOOKUPS_PER_SITE || this.lookups.length >= LOOKUPS_TOTAL) return false;
    this.lookups.push({ site, at: now });
    return true;
  }

  private remember(rpId: string, origins: unknown): void {
    this.cache.delete(rpId);
    this.cache.set(rpId, { origins, expiry: this.now() + CACHE_TTL_MS });
    // Maps keep insertion order: the first key is the oldest answer.
    while (this.cache.size > MAX_CACHED_RP_IDS) {
      this.cache.delete(this.cache.keys().next().value as string);
    }
  }

  /** The file's `origins` member, or null when it cannot be had. */
  private async fetchOrigins(rpId: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await this.fetch(`https://${rpId}/.well-known/webauthn`, {
        method: 'GET',
        credentials: 'omit',
        redirect: 'error', // cross-origin redirects are not honoured by the spec
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!res.ok) return null;
      const contentType = (res.headers.get('content-type') || '').toLowerCase();
      if (!contentType.includes('application/json')) return null;
      const text = await readCapped(res, MAX_BODY_BYTES);
      if (text === null) return null;
      const body = JSON.parse(text) as Record<string, unknown> | null;
      return body?.origins ?? null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}

const verifier = new RelatedOriginVerifier();

/**
 * Returns true iff `callerOrigin` is authorized to use `rpId` via Related
 * Origin Requests. Fetches and caches the RP's well-known file. Never throws.
 */
export function verifyRelatedOrigin(rpId: string, callerOrigin: string): Promise<boolean> {
  return verifier.verify(rpId, callerOrigin);
}
