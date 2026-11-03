/**
 * Where the vault's dialog opens in a window of its own (Firefox), a
 * conditional (autofill) sign-in must not pop a window up the moment a
 * login page loads. This small card offers it instead: the user clicks it
 * and the background opens the dialog window.
 *
 * It is page DOM, in a closed shadow root, and carries nothing the page
 * does not know: the site's own RP ID and the vault's labels. Clicking it
 * consents to nothing; the choice is made in the window, which a page
 * cannot cover. So a page that tricks the user into a click here gets a
 * window the user can close.
 */

import { t } from '../i18n';

export type LauncherChoice = 'open' | 'passthrough' | 'cancel';

export interface Launcher {
  choice: Promise<LauncherChoice>;
  remove(): void;
}

const STYLES = `
  :host {
    all: initial !important;
    display: block !important;
    position: fixed !important;
    inset: max(16px, 20vh) 16px auto auto !important;
    width: min(340px, calc(100vw - 32px)) !important;
    margin: 0 !important;
    padding: 0 !important;
    border: 0 !important;
    z-index: 2147483647 !important;
  }
  .card {
    box-sizing: border-box;
    padding: 12px 16px;
    border: 1px solid #d1d9e0;
    border-radius: 14px;
    background: #f6f8fa;
    color: #1f2328;
    box-shadow: 0 24px 60px rgba(13, 17, 23, 0.18);
    font: 13px 'Courier New', Courier, monospace;
  }
  .title { margin: 0; font-size: 15px; font-weight: 700; text-transform: uppercase; }
  .subtitle { margin: 2px 0 10px; font-size: 11px; color: #59636e; overflow-wrap: anywhere; }
  .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
  button {
    padding: 10px 12px;
    border: 1px solid #d1d9e0;
    border-radius: 14px;
    background: #fff;
    color: #1f2328;
    font: inherit;
    font-weight: 700;
    text-transform: uppercase;
    cursor: pointer;
  }
  button.primary { grid-column: 1 / -1; background: #d4920a; border-color: #d4920a; color: #fff; }
  button:focus-visible { outline: 2px solid rgba(212, 146, 10, 0.35); outline-offset: 2px; }
  :host([data-theme='dark']) .card { background: #0d1117; border-color: #30363d; color: #e6edf3; }
  :host([data-theme='dark']) .subtitle { color: #8d96a0; }
  :host([data-theme='dark']) button { background: #161b22; border-color: #30363d; color: #e6edf3; }
  :host([data-theme='dark']) button.primary { background: #f5a623; border-color: #f5a623; color: #0d1117; }
`;

export function showLauncher(rpId: string, theme: 'light' | 'dark'): Launcher {
  const host = document.createElement('div');
  const root = host.attachShadow({ mode: 'closed' });
  if (theme === 'dark') host.setAttribute('data-theme', 'dark');

  const style = document.createElement('style');
  style.textContent = STYLES;
  const card = document.createElement('div');
  card.className = 'card';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', t('appName'));
  const title = document.createElement('p');
  title.className = 'title';
  title.textContent = t('appName');
  const subtitle = document.createElement('p');
  subtitle.className = 'subtitle';
  subtitle.textContent = t('pageSignInTo', { rp: rpId });
  const actions = document.createElement('div');
  actions.className = 'actions';
  card.append(title, subtitle, actions);
  root.append(style, card);

  let resolve!: (choice: LauncherChoice) => void;
  const choice = new Promise<LauncherChoice>((done) => (resolve = done));
  const button = (label: string, value: LauncherChoice, primary = false) => {
    const element = document.createElement('button');
    element.type = 'button';
    element.textContent = label;
    if (primary) element.className = 'primary';
    element.addEventListener('click', (event) => {
      if (event.isTrusted) resolve(value);
    });
    return element;
  };
  actions.append(
    button(t('pageChoosePasskeyButton'), 'open', true),
    button(t('commonCancel'), 'cancel'),
    button(t('pageUseOtherPasskey'), 'passthrough')
  );

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

  return { choice, remove: () => host.remove() };
}
