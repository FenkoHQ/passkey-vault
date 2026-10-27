/**
 * The vault's notices on a web page: "passkey created", "signed in", and
 * errors.
 *
 * They are drawn by the content script into a closed shadow root, in the
 * top layer where the browser has it, and never take a click. They carry
 * nothing the page does not already know: the site, the account name the
 * page itself gave when registering, or an error. The account used to
 * sign in is not named; that is vault data, and the page could read it
 * even from a closed shadow root (window.find(), selections). Nothing is
 * written on the page's own elements: the theme is resolved here, not set
 * on the page's <html>.
 */

import { t } from '../i18n';
import { getStoredTheme, resolveTheme } from '../theme';

type NoticeKind = 'success' | 'error';

const STYLES = `
  :host {
    all: initial !important;
    display: block !important;
    position: fixed !important;
    inset: 20vh 20px auto auto !important;
    width: auto !important;
    height: auto !important;
    max-width: min(360px, calc(100vw - 40px)) !important;
    margin: 0 !important;
    padding: 0 !important;
    border: 0 !important;
    background: transparent !important;
    overflow: visible !important;
    z-index: 2147483647 !important;
    pointer-events: none !important;
  }
  @keyframes in {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }
  @keyframes out {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(20px); }
  }
  .toast {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 20px;
    border: 3px solid;
    border-radius: 14px;
    box-shadow: 0 18px 48px rgba(13, 17, 23, 0.18);
    font: 14px 'Courier New', Courier, monospace;
    animation: in 0.15s ease-out;
  }
  .toast.leaving { animation: out 0.15s ease-in forwards; }
  .icon { font-size: 20px; flex-shrink: 0; }
  .title { font-weight: 700; margin-bottom: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
  .message { font-size: 13px; opacity: 0.9; overflow-wrap: anywhere; }
  .success { background: #dafbe1; border-color: rgba(26, 127, 55, 0.28); color: #1a7f37; }
  .error { background: #ffebe9; border-color: rgba(207, 34, 46, 0.28); color: #cf222e; }
  :host([data-theme='dark']) .toast { background: #161b22; border-color: #30363d; color: #e6edf3; }
`;

let current: HTMLElement | null = null;

async function show(title: string, message: string, kind: NoticeKind, duration: number) {
  const theme = resolveTheme(await getStoredTheme().catch(() => 'system' as const));
  current?.remove();

  const host = document.createElement('div');
  const root = host.attachShadow({ mode: 'closed' });
  if (theme === 'dark') host.setAttribute('data-theme', 'dark');
  const style = document.createElement('style');
  style.textContent = STYLES;
  const toast = document.createElement('div');
  toast.className = `toast ${kind}`;
  toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  const icon = document.createElement('div');
  icon.className = 'icon';
  icon.textContent = kind === 'success' ? '✓' : '✗';
  const content = document.createElement('div');
  const heading = document.createElement('div');
  heading.className = 'title';
  heading.textContent = title;
  const body = document.createElement('div');
  body.className = 'message';
  body.textContent = message;
  content.append(heading, body);
  toast.append(icon, content);
  root.append(style, toast);

  const popover = typeof (host as { showPopover?: unknown }).showPopover === 'function';
  if (popover) host.setAttribute('popover', 'manual');
  document.documentElement.appendChild(host);
  if (popover) {
    try {
      host.showPopover();
    } catch {
      // Shown as a fixed element instead.
    }
  }
  current = host;

  setTimeout(() => {
    toast.classList.add('leaving');
    setTimeout(() => {
      host.remove();
      if (current === host) current = null;
    }, 200);
  }, duration);
}

/** The page registered a passkey; it named the account itself. */
export function showPasskeyCreatedNotification(userName: string, rpId: string): void {
  void show(
    t('pagePasskeyCreated'),
    t('pagePasskeyCreatedMsg', { user: userName, rp: rpId }),
    'success',
    4000
  );
}

/** The user signed in with a vault passkey. Names the site, not the account. */
export function showPasskeyUsedNotification(rpId: string): void {
  void show(t('pageSignedIn'), t('pageSignedInSiteMsg', { rp: rpId }), 'success', 3000);
}

export function showErrorNotification(title: string, message: string): void {
  void show(title, message, 'error', 5000);
}
