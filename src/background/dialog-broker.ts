/**
 * Sessions for the vault's ceremony dialogs (see src/utils/vault-dialog.ts).
 *
 * A content script opens a session for one of its page's requests and gets
 * back a token, which it hands to the dialog page it frames. The dialog page
 * claims the session with that token, gets what to show, and sends the
 * user's decision here. Nothing the dialog shows passes through the page or
 * the content script, and only the dialog page can decide.
 *
 * Sessions live in chrome.storage.session, which content scripts cannot
 * read, so a service worker that Chrome stops while the user is choosing
 * hands the session to the next one.
 */

import { arrayBufferToBase64URL } from '../utils/base64';
import {
  DIALOG_MESSAGES,
  isVaultDialogSender,
  type VaultDialogDecision,
  type VaultDialogKind,
  type VaultDialogOutcome,
  type VaultDialogPasskey,
  type VaultDialogView,
} from '../utils/vault-dialog';

type Payload = Record<string, unknown>;

export interface DialogSender {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number; url?: string };
  frameId?: number;
  documentId?: string;
}

/** A content script's request, after the background bound it to the sender. */
export interface BoundRequest {
  type: string;
  payload?: Payload;
  requestId?: string;
  requester?: string;
}

interface DialogSession {
  id: string;
  token: string;
  kind: VaultDialogKind;
  state: 'pending' | 'approved';
  /** The requesting content script: tab, frame, and "tab:frame:origin". */
  tabId: number;
  frameId: number;
  requester: string;
  requestId: string;
  rpId: string;
  /** What the user's approval covers; the ceremony must match it exactly. */
  binding: string;
  view: VaultDialogView;
  /** Passkeys the picker offered; the only ones the user can approve. */
  passkeyIds: string[];
  approvedPasskeyId?: string;
  /** The dialog document that claimed the session. */
  dialog?: { tabId: number; frameId: number; documentId?: string };
  expiresAt: number;
  decidedAt?: number;
}

export interface DialogBrokerDeps {
  /** Throws (with the vault's locked error) when the vault is locked. */
  assertUnlocked(): Promise<void>;
  /** The passkeys stored for an RP ID. */
  passkeysFor(rpId: string): Promise<
    Array<{
      id: string;
      credentialId?: string;
      user?: { name?: string; displayName?: string };
    }>
  >;
}

const STORAGE_KEY = 'vault_dialog_sessions';
/** A dialog nobody answers is dropped after this; the page gives up sooner. */
const SESSION_TTL_MS = 10 * 60 * 1000;
/** How long an approval waits for the content script's ceremony message. */
const APPROVAL_TTL_MS = 2 * 60 * 1000;

function randomToken(): string {
  return arrayBufferToBase64URL(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

/**
 * The part of a ceremony the user approves: the origin and frame it runs
 * in, and every option the page passed. The ceremony message must carry the
 * same, so an approval for one request cannot sign or create for another.
 */
export function ceremonyBinding(payload: Payload): string {
  return JSON.stringify([
    payload.origin ?? null,
    payload.crossOrigin === true,
    payload.topOrigin ?? null,
    payload.publicKey ?? null,
  ]);
}

function rpIdOf(payload: Payload): string {
  const publicKey = (payload.publicKey as Payload | undefined) ?? {};
  return String(publicKey.rpId ?? '');
}

export class DialogBroker {
  private queue: Promise<unknown> = Promise.resolve();
  private memory: Record<string, DialogSession> = {};

  constructor(private readonly deps: DialogBrokerDeps) {}

  // ==================== STORAGE ====================

  private area(): chrome.storage.StorageArea | null {
    return (chrome.storage as { session?: chrome.storage.StorageArea }).session ?? null;
  }

  /** Run `change` on the sessions, one change at a time, and save them. */
  private update<T>(change: (sessions: Record<string, DialogSession>) => T | Promise<T>) {
    const run = this.queue.then(async () => {
      const area = this.area();
      const sessions: Record<string, DialogSession> = area
        ? (((await area.get(STORAGE_KEY))[STORAGE_KEY] as Record<string, DialogSession>) ?? {})
        : this.memory;
      const now = Date.now();
      for (const [id, session] of Object.entries(sessions)) {
        if (session.expiresAt <= now) delete sessions[id];
      }
      const result = await change(sessions);
      if (area) await area.set({ [STORAGE_KEY]: sessions });
      return result;
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  // ==================== CONTENT SCRIPT ====================

  /**
   * Open a session for a page request. For a sign-in, the passkeys come from
   * the vault here and go only to the dialog: the content script learns
   * whether there is one to offer, not which.
   */
  async open(message: BoundRequest, sender: DialogSender): Promise<unknown> {
    const payload = message.payload ?? {};
    const kind = payload.kind;
    const requestId = message.requestId;
    const tabId = sender.tab?.id;
    if (
      (kind !== 'get' && kind !== 'create') ||
      typeof requestId !== 'string' ||
      !requestId ||
      typeof tabId !== 'number' ||
      typeof sender.frameId !== 'number' ||
      !message.requester
    ) {
      return { success: false, error: 'Invalid dialog request' };
    }
    const rpId = rpIdOf(payload);
    const publicKey = (payload.publicKey as Payload | undefined) ?? {};

    let view: VaultDialogView;
    let passkeyIds: string[] = [];
    if (kind === 'get') {
      await this.deps.assertUnlocked();
      const allowed = ((publicKey.allowCredentials as Array<{ id?: unknown }> | undefined) ?? [])
        .map((credential) => credential?.id)
        .filter((id): id is string => typeof id === 'string' && id.length > 0);
      const offered = (await this.deps.passkeysFor(rpId)).filter(
        (passkey) => allowed.length === 0 || allowed.includes(passkey.credentialId || passkey.id)
      );
      if (offered.length === 0) {
        return { success: true, status: 'none' };
      }
      passkeyIds = offered.map((passkey) => passkey.id);
      const passkeys: VaultDialogPasskey[] = offered.map((passkey) => ({
        id: passkey.id,
        userName: passkey.user?.name || '',
        userDisplayName: passkey.user?.displayName || '',
      }));
      view = { kind, rpId, passkeys };
    } else {
      const user = (publicKey.user as Payload | undefined) ?? {};
      const userName = String(user.displayName || user.name || '');
      view = { kind, rpId, userName };
    }

    const session: DialogSession = {
      id: randomToken(),
      token: randomToken(),
      kind,
      state: 'pending',
      tabId,
      frameId: sender.frameId,
      requester: message.requester,
      requestId,
      rpId,
      binding: ceremonyBinding(payload),
      view,
      passkeyIds,
      expiresAt: Date.now() + SESSION_TTL_MS,
    };
    const replaced = await this.update((sessions) => {
      // One dialog per frame, as on screen: a new request replaces any
      // dialog the same frame still has open.
      const previous = Object.values(sessions).filter(
        (other) => other.requester === session.requester && other.state === 'pending'
      );
      for (const other of previous) delete sessions[other.id];
      sessions[session.id] = session;
      return previous;
    });
    for (const other of replaced) void this.notify(other, 'cancel');
    return { success: true, status: 'open', dialogId: session.id, token: session.token };
  }

  /** The page stopped waiting: close the request's dialog. */
  async cancel(message: BoundRequest): Promise<unknown> {
    const closed = await this.update((sessions) => {
      const found = Object.values(sessions).filter(
        (session) =>
          session.requester === message.requester && session.requestId === message.requestId
      );
      for (const session of found) delete sessions[session.id];
      return found;
    });
    return { success: closed.length > 0 };
  }

  /**
   * The approval a ceremony message needs: the dialog approved this request
   * (same tab, frame, origin and request ID) for these exact options, and it
   * has not been used yet. Returns the passkey the user picked, for a
   * sign-in. Throws otherwise.
   */
  async consumeApproval(message: BoundRequest, kind: VaultDialogKind): Promise<string | undefined> {
    const binding = ceremonyBinding(message.payload ?? {});
    // Used up even when it does not match: one approval, one attempt.
    const session = await this.update((sessions) => {
      const found = Object.values(sessions).find(
        (candidate) =>
          candidate.requester === message.requester &&
          candidate.requestId === message.requestId &&
          candidate.kind === kind &&
          candidate.state === 'approved'
      );
      if (found) delete sessions[found.id];
      return found;
    });
    if (
      !session ||
      session.binding !== binding ||
      Date.now() - (session.decidedAt ?? 0) > APPROVAL_TTL_MS
    ) {
      throw new Error('The user did not approve this request');
    }
    return session.approvedPasskeyId;
  }

  // ==================== DIALOG PAGE ====================

  /** Route a message from the dialog page. Anything else it sends is refused. */
  async handleDialogMessage(message: Payload, sender: DialogSender): Promise<unknown> {
    if (!isVaultDialogSender(sender, chrome.runtime.id)) {
      throw new Error('Not the vault dialog');
    }
    const token = typeof message.token === 'string' ? message.token : '';
    switch (message.type) {
      case DIALOG_MESSAGES.ATTACH:
        return this.attach(token, sender);
      case DIALOG_MESSAGES.DECIDE:
        return this.decide(token, sender, message.decision as VaultDialogDecision | undefined);
      default:
        throw new Error(`${String(message.type)} is not available to the vault dialog`);
    }
  }

  /**
   * Claim a session. The token reached the dialog only through the content
   * script, by postMessage to the extension's origin; a page that frames the
   * dialog page itself has no token to give it. The claim also has to come
   * from a frame of the requesting tab other than the requester's own, and
   * only the first claim counts.
   */
  private async attach(token: string, sender: DialogSender): Promise<unknown> {
    const view = await this.update((sessions) => {
      const session = Object.values(sessions).find((candidate) => candidate.token === token);
      if (!session || !token || session.state !== 'pending' || session.dialog) return undefined;
      if (!this.mayClaim(session, sender)) return undefined;
      session.dialog = {
        tabId: sender.tab!.id!,
        frameId: sender.frameId!,
        documentId: sender.documentId,
      };
      return session.view;
    });
    if (!view) {
      return { success: false, error: 'This request is no longer active' };
    }
    return { success: true, view };
  }

  private mayClaim(session: DialogSession, sender: DialogSender): boolean {
    return (
      sender.tab?.id === session.tabId &&
      typeof sender.frameId === 'number' &&
      sender.frameId !== 0 &&
      sender.frameId !== session.frameId
    );
  }

  private async decide(
    token: string,
    sender: DialogSender,
    decision: VaultDialogDecision | undefined
  ): Promise<unknown> {
    const decided = await this.update((sessions) => {
      const session = Object.values(sessions).find((candidate) => candidate.token === token);
      if (!session || !token || session.state !== 'pending' || !this.isClaimant(session, sender)) {
        return undefined;
      }
      const outcome = this.apply(session, decision);
      if (!outcome) return undefined;
      if (outcome === 'approved') {
        session.state = 'approved';
        session.decidedAt = Date.now();
      } else {
        delete sessions[session.id];
      }
      return { session: { ...session }, outcome };
    });
    if (!decided) {
      return { success: false, error: 'This request is no longer active' };
    }
    void this.notify(decided.session, decided.outcome);
    return { success: true };
  }

  private isClaimant(session: DialogSession, sender: DialogSender): boolean {
    const claimed = session.dialog;
    return (
      !!claimed &&
      claimed.tabId === sender.tab?.id &&
      claimed.frameId === sender.frameId &&
      (claimed.documentId === undefined || claimed.documentId === sender.documentId)
    );
  }

  /** What a decision means for a session, or undefined if it does not apply. */
  private apply(
    session: DialogSession,
    decision: VaultDialogDecision | undefined
  ): VaultDialogOutcome | undefined {
    switch (decision?.action) {
      case 'cancel':
        return 'cancel';
      case 'passthrough':
        return session.kind === 'get' ? 'passthrough' : undefined;
      case 'use':
        if (session.kind !== 'get' || !session.passkeyIds.includes(decision.id)) return undefined;
        session.approvedPasskeyId = decision.id;
        return 'approved';
      case 'create':
        return session.kind === 'create' ? 'approved' : undefined;
      default:
        return undefined;
    }
  }

  // ==================== HELPERS ====================

  /** Tell the requesting content script how its dialog ended. */
  private async notify(session: DialogSession, outcome: VaultDialogOutcome): Promise<void> {
    try {
      await chrome.tabs.sendMessage(
        session.tabId,
        {
          type: DIALOG_MESSAGES.RESULT,
          dialogId: session.id,
          requestId: session.requestId,
          outcome,
        },
        { frameId: session.frameId }
      );
    } catch {
      // The frame navigated away or closed; nobody is waiting.
    }
  }
}
