import { baseDomain, registrableLabel } from '../src/utils/domain';
import { pickIconUrl } from '../src/site-icons/page-capture';
import { candidatePageUrls } from '../src/site-icons/browser-cache';
import { isAllowedIconType, isWithinSourceLimit } from '../src/site-icons/normalize';
import {
  PNG_DATA_URL_PREFIX,
  clearSiteIcons,
  getSiteIcon,
  isSiteIconStale,
  putSiteIcon,
} from '../src/site-icons/store';

const ORIGIN = 'https://example.com';
const PNG = PNG_DATA_URL_PREFIX + 'AAAA';
const DAY_MS = 24 * 60 * 60 * 1000;

// Back the chrome.storage.local mock with a real object so the store's
// read-modify-write cycles behave like they do in the extension.
function useFakeStorage(): { data: Record<string, unknown> } {
  const state: { data: Record<string, unknown> } = { data: {} };
  const local = chrome.storage.local as unknown as {
    get: jest.Mock;
    set: jest.Mock;
    remove: jest.Mock;
  };

  local.get.mockImplementation(async (key: string) => ({ [key]: state.data[key] }));
  local.set.mockImplementation(async (items: Record<string, unknown>) => {
    Object.assign(state.data, items);
  });
  local.remove.mockImplementation(async (key: string) => {
    delete state.data[key];
  });

  return state;
}

function linkHtml(rel: string, href: string, attrs = ''): void {
  document.head.innerHTML = `<link rel="${rel}" href="${href}" ${attrs}>`;
}

describe('baseDomain', () => {
  it('reduces a hostname to the registrable domain', () => {
    expect(baseDomain('accounts.google.com')).toBe('google.com');
    expect(baseDomain('google.com')).toBe('google.com');
    expect(baseDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('keeps the second level of a known two-level suffix', () => {
    expect(baseDomain('login.shopping.co.uk')).toBe('shopping.co.uk');
    expect(baseDomain('shopping.co.uk')).toBe('shopping.co.uk');
    expect(baseDomain('www.example.com.au')).toBe('example.com.au');
  });

  it('rejects hostnames with no registrable label', () => {
    expect(baseDomain('localhost')).toBeNull();
    expect(baseDomain('')).toBeNull();
  });

  it('is case insensitive', () => {
    expect(baseDomain('Accounts.GOOGLE.com')).toBe('google.com');
  });

  it('still derives the label used by the related-origin cap', () => {
    expect(registrableLabel('accountscenter.facebook.com')).toBe('facebook');
    expect(registrableLabel('shopping.co.uk')).toBe('shopping');
    expect(registrableLabel('localhost')).toBeNull();
  });
});

describe('pickIconUrl', () => {
  beforeEach(() => {
    document.head.innerHTML = '';
  });

  it('falls back to /favicon.ico when nothing is declared', () => {
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/favicon.ico`);
  });

  it('resolves a relative href against the page origin', () => {
    linkHtml('icon', '/assets/icon.png');
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/assets/icon.png`);
  });

  it('prefers the largest declared size', () => {
    document.head.innerHTML = `
      <link rel="icon" href="/small.png" sizes="16x16">
      <link rel="icon" href="/big.png" sizes="16x16 180x180">
    `;
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/big.png`);
  });

  it('skips SVG, which is a script container', () => {
    linkHtml('icon', '/icon.svg');
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/favicon.ico`);

    linkHtml('icon', '/icon', 'type="image/svg+xml"');
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/favicon.ico`);
  });

  it('skips cross-origin icons so no new request is made', () => {
    linkHtml('icon', 'https://cdn.other.test/icon.png');
    expect(pickIconUrl(document, ORIGIN)).toBe(`${ORIGIN}/favicon.ico`);
  });
});

describe('candidatePageUrls', () => {
  it('asks about the RP host before the bare domain', () => {
    // The favicon cache is keyed by page URL: nobody loads https://nvidia.com/
    // just because they hold a passkey for login.nvgs.nvidia.com.
    expect(candidatePageUrls('login.nvgs.nvidia.com', 'nvidia.com')).toEqual([
      'https://login.nvgs.nvidia.com/',
      'https://www.nvidia.com/',
      'https://nvidia.com/',
    ]);
  });

  it('covers the www host for a bare registrable RP ID', () => {
    expect(candidatePageUrls('google.com', 'google.com')).toEqual([
      'https://google.com/',
      'https://www.google.com/',
    ]);
  });

  it('does not repeat a host', () => {
    expect(candidatePageUrls('www.example.com', 'example.com')).toEqual([
      'https://www.example.com/',
      'https://example.com/',
    ]);
  });
});

describe('icon source limits', () => {
  it('accepts raster types a worker can decode', () => {
    expect(isAllowedIconType('image/png')).toBe(true);
    expect(isAllowedIconType('image/x-icon; charset=binary')).toBe(true);
    expect(isAllowedIconType('IMAGE/WEBP')).toBe(true);
  });

  it('rejects SVG, HTML and missing types', () => {
    expect(isAllowedIconType('image/svg+xml')).toBe(false);
    expect(isAllowedIconType('text/html')).toBe(false);
    expect(isAllowedIconType('')).toBe(false);
  });

  it('rejects empty and oversized payloads', () => {
    expect(isWithinSourceLimit(0)).toBe(false);
    expect(isWithinSourceLimit(1024)).toBe(true);
    expect(isWithinSourceLimit(128 * 1024 + 1)).toBe(false);
  });
});

describe('site icon store', () => {
  let storage: { data: Record<string, unknown> };

  beforeEach(() => {
    jest.restoreAllMocks();
    storage = useFakeStorage();
  });

  it('round-trips an icon by domain', async () => {
    await putSiteIcon('example.com', PNG);
    expect(await getSiteIcon('example.com')).toBe(PNG);
    expect(await getSiteIcon('other.com')).toBeNull();
  });

  it('refuses anything that is not our re-encoded PNG', async () => {
    await putSiteIcon('evil.com', 'data:text/html;base64,PHNjcmlwdD4=');
    expect(await getSiteIcon('evil.com')).toBeNull();
  });

  it('ignores stored entries that were tampered with', async () => {
    storage.data['site_icons'] = {
      'evil.com': { dataUrl: 'javascript:alert(1)', updatedAt: Date.now() },
    };
    expect(await getSiteIcon('evil.com')).toBeNull();
  });

  it('reports a missing or aged icon as stale', async () => {
    expect(await isSiteIconStale('example.com')).toBe(true);

    await putSiteIcon('example.com', PNG);
    expect(await isSiteIconStale('example.com')).toBe(false);
    expect(await isSiteIconStale('example.com', Date.now() + 31 * DAY_MS)).toBe(true);
  });

  it('evicts the least recently refreshed entry past the cap', async () => {
    const icons: Record<string, unknown> = {};
    for (let i = 0; i < 300; i++) {
      icons[`site${i}.com`] = { dataUrl: PNG, updatedAt: 1000 + i };
    }
    storage.data['site_icons'] = icons;

    await putSiteIcon('fresh.com', PNG);

    expect(await getSiteIcon('site0.com')).toBeNull();
    expect(await getSiteIcon('site1.com')).toBe(PNG);
    expect(await getSiteIcon('fresh.com')).toBe(PNG);
  });

  it('drops the whole cache when the vault is cleared', async () => {
    await putSiteIcon('example.com', PNG);
    await clearSiteIcons();
    expect(await getSiteIcon('example.com')).toBeNull();
  });
});
