/**
 * The content script's side of a vault dialog: open a session in the
 * background, show the dialog page in a frame (or let the background open
 * it in a window), and wait for the background to say how it ended. The
 * content script never sees what the dialog lists or which passkey the
 * user picked.
 */

import {
  DIALOG_MESSAGES,
  type VaultDialogKind,
  type VaultDialogOutcome,
} from '../utils/vault-dialog';
import { getStoredTheme, resolveTheme } from '../theme';
import { mountDialogFrame, supportsFrameDialogs, type DialogFrame } from './vault-dialog-frame';
import { showLauncher, type Launcher } from './vault-launcher';

export type DialogRun =
  /** Nothing to show: no vault passkey matches the request, or the vault refused it. */
  { status: 'none' } | { status: 'locked' } | { status: 'decided'; outcome: VaultDialogOutcome };

export interface DialogRequest {
  kind: VaultDialogKind;
  requestId: string;
  /** The RP ID the content script resolved for the request. */
  rpId: string;
  payload: Record<string, unknown>;
  /** A conditional (autofill) sign-in: the page did not ask for a dialog yet. */
  conditional: boolean;
  signal: AbortSignal;
}

type Send = (message: Record<string, unknown>) => Promise<Record<string, unknown>>;

export class VaultDialogClient {
  /** Dialogs on screen, by dialog ID. */
  private waiters = new Map<string, (outcome: VaultDialogOutcome) => void>();
  /** Cancels the dialog on screen; one at a time per frame. */
  private dismissActive: (() => void) | null = null;

  constructor(private readonly send: Send) {
    chrome.runtime.onMessage.addListener((message, sender) => {
      if (sender?.id !== chrome.runtime.id) return;
      const data = message as { type?: string; dialogId?: unknown; outcome?: unknown };
      if (data?.type !== DIALOG_MESSAGES.RESULT || typeof data.dialogId !== 'string') return;
      // A dialog this frame already closed (replaced, or the page gave up)
      // is not waited on any more; its late outcome is dropped.
      this.waiters.get(data.dialogId)?.(data.outcome as VaultDialogOutcome);
    });
  }

  async run(request: DialogRequest): Promise<DialogRun> {
    const { signal } = request;
    if (signal.aborted) return { status: 'decided', outcome: 'cancel' };
    this.dismissActive?.();

    const mode = supportsFrameDialogs() ? 'frame' : 'window';
    // A window for an autofill sign-in waits until the user asks for it.
    const deferWindow = mode === 'window' && request.conditional;
    // A worker that cannot be reached throws here, for the caller to handle.
    const opened = await this.send({
      type: DIALOG_MESSAGES.OPEN,
      requestId: request.requestId,
      payload: { ...request.payload, kind: request.kind, mode, deferWindow },
    });
    if (opened?.code === 'VAULT_LOCKED') return { status: 'locked' };
    if (!opened?.success || opened.status !== 'open') return { status: 'none' };
    const dialogId = String(opened.dialogId);
    const token = String(opened.token ?? '');
    const theme = deferWindow
      ? resolveTheme(await getStoredTheme().catch(() => 'system' as const))
      : 'light';

    if (signal.aborted) {
      this.cancelInBackground(request.requestId);
      return { status: 'decided', outcome: 'cancel' };
    }

    let frame: DialogFrame | null = null;
    let launcher: Launcher | null = null;
    const outcome = await new Promise<VaultDialogOutcome>((resolve) => {
      let settled = false;
      const settle = (value: VaultDialogOutcome) => {
        if (settled) return;
        settled = true;
        this.waiters.delete(dialogId);
        signal.removeEventListener('abort', onAbort);
        document.removeEventListener('keydown', onKeydown, true);
        if (this.dismissActive === dismiss) this.dismissActive = null;
        resolve(value);
      };
      // The page gave up, or replaced this dialog with another: close it in
      // the background too, so a click that is already on its way loses.
      const dismiss = () => {
        this.cancelInBackground(request.requestId);
        settle('cancel');
      };
      const onAbort = () => dismiss();
      // Escape in the page, while focus is still there.
      const onKeydown = (event: KeyboardEvent) => {
        if (event.isTrusted && event.key === 'Escape') dismiss();
      };

      this.waiters.set(dialogId, settle);
      this.dismissActive = dismiss;
      signal.addEventListener('abort', onAbort);
      document.addEventListener('keydown', onKeydown, true);

      if (mode === 'frame') {
        frame = mountDialogFrame({ token, kind: request.kind, focus: !request.conditional });
        // The page took the frame away: the user cannot answer it any more.
        void frame.gone.then(dismiss);
      } else if (deferWindow) {
        launcher = showLauncher(request.rpId, theme);
        void launcher.choice.then((choice) => {
          launcher?.remove();
          if (choice === 'open') {
            this.send({ type: DIALOG_MESSAGES.LAUNCH, requestId: request.requestId }).catch(() =>
              dismiss()
            );
          } else {
            this.cancelInBackground(request.requestId);
            settle(choice);
          }
        });
      }
      // Otherwise the background has opened the dialog's window.
    });
    (frame as DialogFrame | null)?.unmount();
    (launcher as Launcher | null)?.remove();
    return { status: 'decided', outcome };
  }

  private cancelInBackground(requestId: string): void {
    // Also closes the dialog's window, if it has one.
    this.send({ type: DIALOG_MESSAGES.CANCEL, requestId }).catch(() => undefined);
  }
}
