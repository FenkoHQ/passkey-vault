/**
 * The vault's ceremony dialog: the passkey picker and the create
 * confirmation (see src/utils/vault-dialog.ts for how it is wired).
 *
 * This is an extension page. The page that asked for a passkey can neither
 * read it nor script it; what it shows comes from the background, and the
 * user's decision goes back there.
 */

import { initI18n, t } from '../i18n';
import { initTheme } from '../theme';
import {
  DIALOG_MESSAGES,
  DIALOG_TOKEN_MESSAGE,
  type VaultDialogDecision,
  type VaultDialogView,
} from '../utils/vault-dialog';

/** Whether a click on a consent button may count right now. */
export interface ConsentGate {
  isReady(): boolean;
  /** Called whenever isReady() may have changed. */
  onChange(listener: () => void): void;
  dispose(): void;
}

export interface DialogEnvironment {
  window: Window;
  /** The token that names this dialog's session. */
  token(): Promise<string>;
  send(message: Record<string, unknown>): Promise<unknown>;
  /** The gate for consent clicks, once the dialog is on screen. */
  createGate(card: HTMLElement): ConsentGate;
}

const LOCK_ICON =
  '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>';

/**
 * Resolve with the first token the frame's parent posts. Only the content
 * script can reach this frame: it sits in a closed shadow root, so it is
 * not in the page's `window.frames`, and the page has no handle to post to.
 */
export function receiveTokenFromParent(win: Window): Promise<string> {
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (event.source !== win.parent || win.parent === win) return;
      const data = event.data as { type?: unknown; token?: unknown } | null;
      if (data?.type !== DIALOG_TOKEN_MESSAGE || typeof data.token !== 'string') return;
      win.removeEventListener('message', listener);
      resolve(data.token);
    };
    win.addEventListener('message', listener);
  });
}

export class VaultDialog {
  private readonly doc: Document;
  private token = '';
  private gate: ConsentGate | null = null;
  private settled = false;
  private selectedId: string | null = null;
  private readonly consentButtons: HTMLButtonElement[] = [];

  constructor(private readonly env: DialogEnvironment) {
    this.doc = env.window.document;
  }

  private el<T extends HTMLElement = HTMLElement>(id: string): T {
    return this.doc.getElementById(id) as T;
  }

  async start(): Promise<void> {
    this.token = await this.env.token();
    let response: { success?: boolean; view?: VaultDialogView } | undefined;
    try {
      response = (await this.env.send({ type: DIALOG_MESSAGES.ATTACH, token: this.token })) as
        | { success?: boolean; view?: VaultDialogView }
        | undefined;
    } catch {
      response = undefined;
    }
    if (!response?.success || !response.view) {
      this.showInactive();
      return;
    }
    this.render(response.view);
  }

  private render(view: VaultDialogView): void {
    const card = this.el('card');
    const footer = this.el('footer');
    const list = this.el('passkeys');
    footer.textContent = '';
    list.textContent = '';

    if (view.kind === 'get') {
      this.el('title').textContent = t('pageChoosePasskey');
      this.el('subtitle').textContent = t('pageSignInTo', { rp: view.rpId });
      list.setAttribute('aria-label', t('pageChoosePasskey'));
      view.passkeys.forEach((passkey, index) => {
        list.appendChild(this.passkeyItem(passkey, index === 0));
      });
      this.selectedId = view.passkeys[0]?.id ?? null;
      footer.append(
        this.button('pkv-cancel', t('commonCancel'), 'secondary', () =>
          this.decide({ action: 'cancel' })
        ),
        this.button('pkv-passthrough', t('pageUseOtherPasskey'), 'secondary', () =>
          this.decide({ action: 'passthrough' })
        ),
        this.button(
          'pkv-continue',
          t('pageContinue'),
          'primary wide',
          () => {
            if (this.selectedId) this.decide({ action: 'use', id: this.selectedId });
          },
          true
        )
      );
    } else {
      list.hidden = true;
      this.el('title').textContent = t('pageCreatePasskeyTitle');
      this.el('subtitle').textContent = t('pageCreatePasskeyMsg', {
        user: view.userName || t('commonUnknownUser'),
        rp: view.rpId,
      });
      footer.append(
        this.button('pkv-cancel', t('commonCancel'), 'secondary', () =>
          this.decide({ action: 'cancel' })
        ),
        this.button(
          'pkv-create',
          t('pageCreate'),
          'primary',
          () => this.decide({ action: 'create' }),
          true
        )
      );
    }

    this.doc.addEventListener('keydown', (event) => {
      if (event.isTrusted && event.key === 'Escape') this.decide({ action: 'cancel' });
    });

    card.hidden = false;
    this.gate = this.env.createGate(card);
    this.gate.onChange(() => this.updateConsentButtons());
    this.updateConsentButtons();
    // Focus the selection, or the dialog itself: never a consent button, so
    // a keystroke meant for the page cannot confirm.
    const checked = list.querySelector<HTMLElement>('[aria-checked="true"]');
    (checked ?? card).focus();
  }

  private passkeyItem(
    passkey: { id: string; userName: string; userDisplayName: string },
    selected: boolean
  ): HTMLElement {
    const item = this.doc.createElement('button');
    item.type = 'button';
    item.className = 'passkey-item';
    item.setAttribute('role', 'radio');
    item.setAttribute('aria-checked', String(selected));
    item.tabIndex = selected ? 0 : -1;
    item.dataset.id = passkey.id;

    const avatar = this.doc.createElement('span');
    avatar.className = 'passkey-avatar';
    avatar.innerHTML = LOCK_ICON;
    const info = this.doc.createElement('span');
    info.className = 'passkey-info';
    const name = this.doc.createElement('span');
    name.className = 'passkey-name';
    name.textContent = passkey.userDisplayName || passkey.userName || t('commonUnknownUser');
    const detail = this.doc.createElement('span');
    detail.className = 'passkey-detail';
    detail.textContent = passkey.userName || passkey.id.substring(0, 16) + '...';
    info.append(name, detail);
    const check = this.doc.createElement('span');
    check.className = 'passkey-check';
    check.setAttribute('aria-hidden', 'true');
    check.textContent = '✓';
    item.append(avatar, info, check);

    item.addEventListener('click', (event) => {
      if (event.isTrusted) this.select(item);
    });
    item.addEventListener('keydown', (event) => {
      if (!event.isTrusted) return;
      const items = Array.from(
        this.el('passkeys').querySelectorAll<HTMLButtonElement>('.passkey-item')
      );
      const index = items.indexOf(item);
      let next = -1;
      if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = index + 1;
      if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = index - 1;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = items.length - 1;
      if (next < 0 && event.key !== 'Home') return;
      event.preventDefault();
      const target = items[(next + items.length) % items.length];
      this.select(target);
      target.focus();
    });
    return item;
  }

  private select(item: HTMLElement): void {
    this.el('passkeys')
      .querySelectorAll<HTMLElement>('.passkey-item')
      .forEach((other) => {
        other.setAttribute('aria-checked', String(other === item));
        other.tabIndex = other === item ? 0 : -1;
      });
    this.selectedId = item.dataset.id ?? null;
  }

  private button(
    id: string,
    label: string,
    variant: string,
    action: () => void,
    consent = false
  ): HTMLButtonElement {
    const button = this.doc.createElement('button');
    button.type = 'button';
    button.id = id;
    button.className = variant
      .split(' ')
      .map((part) => (part === 'wide' ? 'wide' : `btn-${part}`))
      .concat('btn')
      .join(' ');
    button.textContent = label;
    button.addEventListener('click', (event) => {
      if (!event.isTrusted) return;
      // A consent click counts only once the gate says the dialog has been
      // on screen, in full, long enough for the user to have seen it.
      if (consent && !this.gate?.isReady()) return;
      action();
    });
    if (consent) this.consentButtons.push(button);
    return button;
  }

  private updateConsentButtons(): void {
    const ready = !!this.gate?.isReady() && !this.settled;
    for (const button of this.consentButtons) {
      button.setAttribute('aria-disabled', String(!ready));
    }
  }

  private async decide(decision: VaultDialogDecision): Promise<void> {
    if (this.settled) return;
    this.settled = true;
    this.updateConsentButtons();
    this.gate?.dispose();
    let response: { success?: boolean } | undefined;
    try {
      response = (await this.env.send({
        type: DIALOG_MESSAGES.DECIDE,
        token: this.token,
        decision,
      })) as { success?: boolean } | undefined;
    } catch {
      response = undefined;
    }
    if (!response?.success) this.showInactive();
  }

  /** The request is gone: the page gave up, or another dialog replaced this one. */
  private showInactive(): void {
    this.settled = true;
    this.gate?.dispose();
    this.el('title').textContent = t('appName');
    this.el('subtitle').textContent = t('dialogInactive');
    this.el('passkeys').textContent = '';
    this.el('footer').textContent = '';
    this.el('card').hidden = false;
  }
}

export async function startVaultDialog(env: DialogEnvironment): Promise<VaultDialog> {
  await Promise.all([initI18n(), initTheme()]);
  const dialog = new VaultDialog(env);
  await dialog.start();
  return dialog;
}
