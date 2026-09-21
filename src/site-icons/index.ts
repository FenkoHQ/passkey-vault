// Site icons for vault entries, resolved from local sources only.
//
// Two layers, cheapest first:
//   1. captured — the icon the site served during a passkey ceremony, fetched
//      from the page's own origin and re-encoded (see normalize.ts)
//   2. browser cache — Chrome's local favicon store, no network (browser-cache)
//
// Neither layer ever reaches out to a third party, so opening the vault does not
// disclose which sites the user holds credentials for.
//
// SECURITY: these icons are site-supplied and must never appear in a consent or
// ceremony dialog (src/ui/passkey-ui.ts). Those dialogs render inside the
// calling page, so a logo there would let evil.com wear another brand's mark
// while the user approves a credential. Vault listings are safe: the user opened
// them, and the domain text sits right next to the image.
import { baseDomain } from '../utils/domain';
import { getSiteIcon, isSiteIconStale, putSiteIcon } from './store';
import { readCachedSiteIcon } from './browser-cache';
import { normalizeIcon } from './normalize';
import { base64ToUint8Array } from '../utils/base64';

export { clearSiteIcons } from './store';

// Browser-cache hits are not persisted (they are already local, and persisting
// them would stop a real capture from ever replacing them), so memoize per page
// session to keep list rendering off the lookup path.
const resolved = new Map<string, string | null>();

const MAX_RP_ID_LENGTH = 253;

function iconKey(rpId: unknown): string | null {
  if (typeof rpId !== 'string' || rpId.length === 0 || rpId.length > MAX_RP_ID_LENGTH) {
    return null;
  }
  return baseDomain(rpId);
}

/** A PNG data URL for the site behind an RP ID, or null to use a placeholder. */
export async function resolveSiteIcon(rpId: string): Promise<string | null> {
  const domain = iconKey(rpId);
  if (domain === null) {
    return null;
  }

  const memoized = resolved.get(domain);
  if (memoized !== undefined) {
    return memoized;
  }

  const icon = (await getSiteIcon(domain)) ?? (await readCachedSiteIcon(rpId, domain));
  resolved.set(domain, icon);

  return icon;
}

/** True when a ceremony should spend a cache-warm fetch capturing this icon. */
export async function needsSiteIcon(rpId: string): Promise<boolean> {
  const domain = iconKey(rpId);
  if (domain === null) {
    return false;
  }
  return isSiteIconStale(domain);
}

/**
 * Store an icon captured from a page. Returns false when the bytes were not a
 * decodable image of an accepted type.
 */
export async function saveSiteIcon(
  rpId: string,
  base64: unknown,
  mimeType: unknown
): Promise<boolean> {
  const domain = iconKey(rpId);
  if (domain === null || typeof base64 !== 'string' || typeof mimeType !== 'string') {
    return false;
  }

  let bytes: Uint8Array;
  try {
    bytes = base64ToUint8Array(base64);
  } catch {
    return false;
  }

  const dataUrl = await normalizeIcon(bytes, mimeType);
  if (dataUrl === null) {
    return false;
  }

  await putSiteIcon(domain, dataUrl);
  return true;
}
