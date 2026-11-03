/**
 * The vault dialog's frame on the page.
 *
 * The frame shows vault-dialog.html, an extension page, so the page cannot
 * read it. It sits in a closed shadow root: the page cannot reach the
 * iframe element, and the frame is not in the page's `window.frames`, so
 * the page has no handle to post to it or navigate it. The host element
 * is the only part in the page's DOM, and its size does not depend on what
 * the dialog lists.
 */

import { t } from '../i18n';
import {
  DIALOG_FRAME_SIZE,
  DIALOG_TOKEN_MESSAGE,
  VAULT_DIALOG_PAGE,
  type VaultDialogKind,
} from '../utils/vault-dialog';

export interface DialogFrame {
  /** Settles when the page removed or hid the frame, or it navigated. */
  gone: Promise<void>;
  /** Take the frame off the page, and give focus back where it was. */
  unmount(): void;
}

export interface MountOptions {
  token: string;
  kind: VaultDialogKind;
  /** Move focus into the dialog (not for a sign-in the page did not ask for yet). */
  focus: boolean;
}

/**
 * Whether the dialog can be a frame on the page. Only where the browser
 * reports whether the frame is really visible to the user
 * (IntersectionObserver v2), which the dialog needs before it takes a
 * click as consent, and where the build lets pages load the dialog page.
 * Elsewhere (Firefox) it opens in a popup window, which a page cannot
 * cover or fade.
 */
export function supportsFrameDialogs(): boolean {
  const entry = (globalThis as { IntersectionObserverEntry?: { prototype: object } })
    .IntersectionObserverEntry;
  if (!entry || !('isVisible' in entry.prototype)) return false;
  const resources = (chrome.runtime.getManifest?.()?.web_accessible_resources ?? []) as Array<
    string | { resources?: string[] }
  >;
  return resources.some(
    (entry) => typeof entry === 'object' && entry.resources?.includes(VAULT_DIALOG_PAGE)
  );
}

/**
 * The origin the dialog page loads under. Chrome serves a web-accessible
 * page with use_dynamic_url from a per-session URL, which getURL() returns,
 * but the document in the frame still has the extension's own origin.
 */
export function extensionOrigin(): string {
  const url = new URL(chrome.runtime.getURL(''));
  return url.protocol === 'chrome-extension:'
    ? `chrome-extension://${chrome.runtime.id}`
    : url.origin;
}

function hostStyles(kind: VaultDialogKind, zoom: number): string {
  const { width, height } = DIALOG_FRAME_SIZE[kind];
  // :host rules marked !important beat anything the page says about the
  // host, its own !important rules and inline styles included.
  return `
    :host {
      all: initial !important;
      display: block !important;
      position: fixed !important;
      inset: max(16px, min(20vh, calc(100vh - ${height}px - 16px))) 16px auto auto !important;
      width: min(${width}px, calc(100vw - 32px)) !important;
      height: min(${height}px, calc(100vh - 32px)) !important;
      margin: 0 !important;
      padding: 0 !important;
      border: 0 !important;
      background: transparent !important;
      overflow: visible !important;
      z-index: 2147483647 !important;
      zoom: ${zoom} !important;
      pointer-events: auto !important;
    }
    iframe {
      display: block;
      width: 100%;
      height: 100%;
      border: 0;
      border-radius: 14px;
      box-shadow: 0 24px 60px rgba(13, 17, 23, 0.18);
      background: transparent;
      color-scheme: normal;
    }
  `;
}

/** CSS zoom the page put on <html>, which would shrink the dialog with it. */
function pageZoom(): number {
  const zoom = Number.parseFloat(getComputedStyle(document.documentElement).zoom || '1');
  return Number.isFinite(zoom) && zoom > 0 ? zoom : 1;
}

export function mountDialogFrame(options: MountOptions): DialogFrame {
  const host = document.createElement('div');
  // Closed, and attached before the host is in the document, so page
  // script never sees it open.
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = hostStyles(options.kind, 1 / pageZoom());
  const frame = document.createElement('iframe');
  frame.title = t('appName');
  frame.src = chrome.runtime.getURL(VAULT_DIALOG_PAGE);
  root.append(style, frame);

  let resolveGone!: () => void;
  const gone = new Promise<void>((resolve) => (resolveGone = resolve));
  const previousFocus = document.activeElement as HTMLElement | null;
  let loads = 0;
  let mounted = true;

  frame.addEventListener('load', () => {
    loads += 1;
    if (loads > 1) {
      // Something navigated the frame: its token went to the first
      // document only, so this one cannot be the dialog.
      resolveGone();
      return;
    }
    frame.contentWindow?.postMessage(
      { type: DIALOG_TOKEN_MESSAGE, token: options.token },
      extensionOrigin()
    );
    if (options.focus) frame.focus();
  });

  // In the top layer where the browser has it, so the page's stacking and
  // its ancestors' opacity, filters and transforms do not apply.
  const popover = typeof (host as { showPopover?: unknown }).showPopover === 'function';
  if (popover) host.setAttribute('popover', 'manual');
  document.documentElement.appendChild(host);
  if (popover) {
    try {
      host.showPopover();
    } catch {
      // Shown as a fixed element instead.
    }
    host.addEventListener('toggle', (event) => {
      if ((event as Event & { newState?: string }).newState === 'closed' && mounted) resolveGone();
    });
  }

  const observer = new MutationObserver(() => {
    if (!host.isConnected || host.parentNode !== document.documentElement) resolveGone();
  });
  observer.observe(document.documentElement, { childList: true });

  return {
    gone,
    unmount() {
      if (!mounted) return;
      mounted = false;
      observer.disconnect();
      const hadFocus = document.activeElement === host;
      host.remove();
      if (hadFocus && previousFocus?.isConnected) {
        previousFocus.focus({ preventScroll: true });
      }
    },
  };
}
