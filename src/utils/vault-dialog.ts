/**
 * The vault's ceremony dialogs: the passkey picker and the create
 * confirmation.
 *
 * They are an extension page (vault-dialog.html), never page DOM. In
 * Chrome the content script shows that page in an iframe inside a closed
 * shadow root, so the page can neither read the dialog (it is another
 * origin, and the frame is not in `window.frames`) nor script it.
 *
 * The dialog gets what it shows from the background, and its decision goes
 * to the background, never through the page or the content script:
 *
 *   content script ── PASSKEY_DIALOG_OPEN ──────────────▶ background
 *        ◀──────────── { dialogId, token } ──────────────  (session)
 *        │ token by postMessage to the frame (targetOrigin: the extension)
 *   dialog page ───── PASSKEY_DIALOG_ATTACH { token } ──▶ background
 *        ◀──────────── what to show ─────────────────────
 *   dialog page ───── PASSKEY_DIALOG_DECIDE { token } ──▶ background
 *   content script ◀─ PASSKEY_DIALOG_RESULT ───────────── background
 *   content script ── GET_PASSKEY / CREATE_PASSKEY ─────▶ background
 *                     (refused unless the dialog approved this request)
 */

export const VAULT_DIALOG_PAGE = 'vault-dialog.html';

export type VaultDialogKind = 'get' | 'create';

/**
 * What the content script learns: whether to go on with the ceremony. It
 * never learns which passkey the user picked; the background keeps that.
 */
export type VaultDialogOutcome = 'approved' | 'cancel' | 'passthrough';

export interface VaultDialogPasskey {
  id: string;
  userName: string;
  userDisplayName: string;
}

export type VaultDialogView =
  | { kind: 'get'; rpId: string; passkeys: VaultDialogPasskey[] }
  | { kind: 'create'; rpId: string; userName: string };

export type VaultDialogDecision =
  | { action: 'use'; id: string }
  | { action: 'create' }
  | { action: 'cancel' }
  | { action: 'passthrough' };

export const DIALOG_MESSAGES = {
  /** Content script: open a dialog for one of its requests. */
  OPEN: 'PASSKEY_DIALOG_OPEN',
  /** Content script: the page gave up on the request. */
  CANCEL: 'PASSKEY_DIALOG_CANCEL',
  /** Dialog page: claim a session with its token and fetch what to show. */
  ATTACH: 'PASSKEY_DIALOG_ATTACH',
  /** Dialog page: the user's decision. */
  DECIDE: 'PASSKEY_DIALOG_DECIDE',
  /** Background to content script: the outcome of a dialog. */
  RESULT: 'PASSKEY_DIALOG_RESULT',
} as const;

/** Messages only the dialog page may send. */
export const DIALOG_PAGE_MESSAGES: ReadonlySet<string> = new Set([
  DIALOG_MESSAGES.ATTACH,
  DIALOG_MESSAGES.DECIDE,
]);

/** The postMessage that hands a framed dialog its token. */
export const DIALOG_TOKEN_MESSAGE = 'fenko-vault-dialog-token';

/**
 * Fixed frame sizes. The picker's does not depend on how many passkeys it
 * lists: the page can measure the frame's host, and must not learn the
 * number of accounts from it.
 */
export const DIALOG_FRAME_SIZE: Record<VaultDialogKind, { width: number; height: number }> = {
  get: { width: 340, height: 372 },
  create: { width: 340, height: 232 },
};

/**
 * Whether a message sender is the vault's dialog page. Only the browser sets
 * `sender.id`, and only this extension's pages have an extension URL with
 * it, so a web page cannot pass for the dialog.
 */
export function isVaultDialogSender(
  sender: { id?: string; url?: string } | undefined,
  extensionId: string
): boolean {
  if (!sender || sender.id !== extensionId || typeof sender.url !== 'string') return false;
  try {
    const url = new URL(sender.url);
    return (
      (url.protocol === 'chrome-extension:' || url.protocol === 'moz-extension:') &&
      url.pathname === `/${VAULT_DIALOG_PAGE}`
    );
  } catch {
    return false;
  }
}
