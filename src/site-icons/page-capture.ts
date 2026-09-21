// Capture a site's own icon from the page a ceremony is running on.
//
// Runs in the content script, which is why this costs no extra network traffic
// in practice: the page has already loaded its favicon, so a force-cache fetch
// is answered from the HTTP cache. Only same-origin icons are read — a CDN-
// hosted icon would need a cross-origin request the page never made, which is
// exactly the traffic an offline vault should not generate.
import { uint8ArrayToBase64 } from '../utils/base64';
import { isAllowedIconType, isWithinSourceLimit } from './normalize';

const ICON_SELECTOR = 'link[rel~="icon" i], link[rel~="apple-touch-icon" i]';
const DEFAULT_ICON_PATH = '/favicon.ico';
const DEFAULT_DECLARED_PIXELS = 16;

export interface CapturedIcon {
  data: string;
  mimeType: string;
}

// e.g. sizes="16x16 32x32" -> 32. Bigger declared icons downscale better.
function declaredPixels(link: HTMLLinkElement): number {
  const sizes = (link.getAttribute('sizes') || '').toLowerCase().match(/\d+/g);
  if (!sizes) {
    return DEFAULT_DECLARED_PIXELS;
  }
  return Math.max(...sizes.map(Number));
}

function isVector(link: HTMLLinkElement, url: URL): boolean {
  return link.type.toLowerCase() === 'image/svg+xml' || url.pathname.toLowerCase().endsWith('.svg');
}

/**
 * Pick the best same-origin raster icon a document declares, falling back to
 * the well-known /favicon.ico. SVG is skipped: it cannot be decoded in a worker
 * and is a script container.
 */
export function pickIconUrl(doc: Document, origin: string): string | null {
  const candidates: Array<{ href: string; pixels: number }> = [];

  for (const link of Array.from(doc.querySelectorAll<HTMLLinkElement>(ICON_SELECTOR))) {
    const href = link.getAttribute('href');
    if (!href) {
      continue;
    }

    let url: URL;
    try {
      url = new URL(href, origin);
    } catch {
      continue;
    }
    if (url.origin !== origin || isVector(link, url)) {
      continue;
    }

    candidates.push({ href: url.href, pixels: declaredPixels(link) });
  }

  if (candidates.length === 0) {
    return origin + DEFAULT_ICON_PATH;
  }

  return candidates.sort((a, b) => b.pixels - a.pixels)[0].href;
}

/** Read the current page's icon as base64, or null if there is nothing usable. */
export async function readPageIcon(): Promise<CapturedIcon | null> {
  const url = pickIconUrl(document, location.origin);
  if (url === null) {
    return null;
  }

  const response = await fetch(url, { cache: 'force-cache', credentials: 'omit' });
  if (!response.ok) {
    return null;
  }

  const mimeType = response.headers.get('content-type') || '';
  if (!isAllowedIconType(mimeType)) {
    return null;
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!isWithinSourceLimit(bytes.byteLength)) {
    return null;
  }

  return { data: uint8ArrayToBase64(bytes), mimeType };
}
