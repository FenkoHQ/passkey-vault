// Read an icon out of the browser's own favicon cache (Chrome/Edge only).
//
// chrome://favicon is a local lookup: the browser answers from the profile's
// cache and makes no network request, so this reveals nothing about the vault
// to anyone. Firefox has no equivalent API, so this layer is simply absent
// there and callers fall back to the placeholder glyph.
//
// Chrome answers an unknown page with a generic default icon rather than a
// miss. To tell "no icon" from "default icon" we ask once for a hostname that
// cannot be in any cache, and treat a byte-identical answer as a miss.
import { logger } from '../utils/logger';
import { uint8ArrayToBase64 } from '../utils/base64';
import { PNG_DATA_URL_PREFIX } from './store';

const FAVICON_PERMISSION = 'favicon';
const FAVICON_PATH = '/_favicon/';
const FAVICON_PIXELS = 32;
const UNCACHED_PROBE_URL = 'https://fenko-vault-uncached-probe.invalid/';
const WWW_PREFIX = 'www.';

let defaultIconBytes: Uint8Array | null | undefined;
let bytesUnreadable = false;

function faviconUrl(pageUrl: string): string {
  const base = chrome.runtime.getURL(FAVICON_PATH);
  return `${base}?pageUrl=${encodeURIComponent(pageUrl)}&size=${FAVICON_PIXELS}`;
}

export function hasFaviconPermission(): boolean {
  try {
    return chrome.runtime.getManifest().permissions?.includes(FAVICON_PERMISSION) === true;
  } catch {
    return false;
  }
}

/**
 * Page URLs worth asking about, most specific first.
 *
 * The cache is keyed by page URL, not by site, so asking only about the
 * registrable domain misses most real entries: a passkey for
 * login.nvgs.nvidia.com is no reason to have ever loaded https://nvidia.com/,
 * and a Google account lives on www.google.com rather than google.com.
 */
export function candidatePageUrls(rpId: string, domain: string): string[] {
  const hosts = [rpId, WWW_PREFIX + domain, domain];
  return [...new Set(hosts)].map((host) => `https://${host}/`);
}

async function fetchIconBytes(pageUrl: string): Promise<Uint8Array | null> {
  try {
    const response = await fetch(faviconUrl(pageUrl));
    if (!response.ok) {
      return null;
    }
    return new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    // The endpoint is readable as an <img> even where fetch is not allowed to
    // read its bytes, so remember this and stop comparing.
    bytesUnreadable = true;
    logger.debug('Browser favicon bytes unreadable', error);
    return null;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return a.every((byte, i) => byte === b[i]);
}

/**
 * The browser's cached icon for a site, as a PNG data URL, or null when the
 * profile has never seen it.
 */
export async function readCachedSiteIcon(rpId: string, domain: string): Promise<string | null> {
  if (!hasFaviconPermission()) {
    return null;
  }

  const candidates = candidatePageUrls(rpId, domain);

  if (defaultIconBytes === undefined) {
    defaultIconBytes = await fetchIconBytes(UNCACHED_PROBE_URL);
  }

  // Without a baseline we cannot spot Chrome's default globe, so hand the URL
  // straight to the <img>: a generic icon beats no icon at all.
  if (bytesUnreadable) {
    return faviconUrl(candidates[0]);
  }
  if (defaultIconBytes === null) {
    return null;
  }

  for (const pageUrl of candidates) {
    const bytes = await fetchIconBytes(pageUrl);
    if (bytes && !sameBytes(bytes, defaultIconBytes)) {
      return PNG_DATA_URL_PREFIX + uint8ArrayToBase64(bytes);
    }
  }

  return null;
}
