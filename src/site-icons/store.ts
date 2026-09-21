// Local-only cache of site icons, keyed by registrable domain.
//
// Deliberately NOT part of the vault: the sync snapshot is published whole on
// every change (see sync-service), so a few KB per credential would multiply
// every broadcast. Each device builds its own cache instead. Nothing here is
// secret beyond what plaintext vault metadata in chrome.storage.local already
// reveals, and the cache is wiped whenever the vault is.
import { logger } from '../utils/logger';

const SITE_ICONS_KEY = 'site_icons';

// Evict the least recently refreshed entry past this count. A vault of a few
// hundred sites stays well inside the chrome.storage.local quota at ~1KB each.
const MAX_ENTRIES = 300;

// Sites redesign. Re-capture an icon this long after it was last stored.
const REFRESH_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

// Everything we persist is re-encoded to PNG first, so anything else in the
// store was not written by us and is not handed to an <img src>.
export const PNG_DATA_URL_PREFIX = 'data:image/png;base64,';

interface SiteIcon {
  dataUrl: string;
  updatedAt: number;
}

type SiteIconMap = Record<string, SiteIcon>;

function isValid(entry: unknown): entry is SiteIcon {
  const icon = entry as SiteIcon | null;
  return (
    !!icon &&
    typeof icon.dataUrl === 'string' &&
    icon.dataUrl.startsWith(PNG_DATA_URL_PREFIX) &&
    Number.isFinite(icon.updatedAt)
  );
}

async function load(): Promise<SiteIconMap> {
  try {
    const result = await chrome.storage.local.get(SITE_ICONS_KEY);
    const raw = result[SITE_ICONS_KEY] as SiteIconMap | undefined;
    if (!raw || typeof raw !== 'object') {
      return {};
    }

    const clean: SiteIconMap = {};
    for (const [domain, entry] of Object.entries(raw)) {
      if (isValid(entry)) {
        clean[domain] = entry;
      }
    }
    return clean;
  } catch (error) {
    logger.error('Failed to read site icon cache', error);
    return {};
  }
}

export async function getSiteIcon(domain: string): Promise<string | null> {
  const icons = await load();
  return icons[domain]?.dataUrl ?? null;
}

/** True when we hold no icon for this domain, or the one we hold is stale. */
export async function isSiteIconStale(domain: string, now = Date.now()): Promise<boolean> {
  const icons = await load();
  const entry = icons[domain];
  return !entry || now - entry.updatedAt > REFRESH_AFTER_MS;
}

export async function putSiteIcon(domain: string, dataUrl: string): Promise<void> {
  if (!dataUrl.startsWith(PNG_DATA_URL_PREFIX)) {
    return;
  }

  const icons = await load();
  icons[domain] = { dataUrl, updatedAt: Date.now() };

  // Oldest-refreshed entries go first; the working set is what the user signs
  // into, which is what keeps getting rewritten.
  const domains = Object.keys(icons);
  if (domains.length > MAX_ENTRIES) {
    domains
      .sort((a, b) => icons[a].updatedAt - icons[b].updatedAt)
      .slice(0, domains.length - MAX_ENTRIES)
      .forEach((stale) => delete icons[stale]);
  }

  await chrome.storage.local.set({ [SITE_ICONS_KEY]: icons });
}

export async function clearSiteIcons(): Promise<void> {
  await chrome.storage.local.remove(SITE_ICONS_KEY);
}
