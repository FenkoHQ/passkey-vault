/**
 * Content Script for Fenko Vault
 *
 * This script is injected into web pages to intercept WebAuthn API calls
 * and communicate with the background script.
 */

import { initI18n, t } from '../i18n';
import { logger } from '../utils/logger';
import { readPageIcon } from '../site-icons/page-capture';
import { describeFrame } from './frame';
import { acceptsEs256 } from '../utils/algorithms';
import { isRpIdValidForHost } from '../utils/rp-id';
import { VaultDialogClient } from './vault-dialog-client';
import {
  showErrorNotification as _showErrorNotification,
  showPasskeyCreatedNotification as _showPasskeyCreatedNotification,
  showPasskeyUsedNotification as _showPasskeyUsedNotification,
} from './page-notices';

interface DomainRules {
  mode: 'disabled' | 'all' | 'allowlist' | 'blocklist';
  domains: string[];
  passthroughOnNoPasskey?: boolean;
}

/**
 * What a request's RP ID resolved to: an RP ID the page may use, a request
 * the vault must refuse outright (insecure or opaque origin), or one whose
 * RP ID does not fit this page and is left to the browser.
 */
type RpIdResolution = { rpId: string } | { refused: true } | { foreign: true };

/** How long a posted registration can still be taken back; the background allows as long. */
const POSTED_REGISTRATION_MEMORY_MS = 10 * 60 * 1000;

class ContentScript {
  private isInjected = false;
  private originalCreate?: typeof navigator.credentials.create;
  private originalGet?: typeof navigator.credentials.get;
  /** Page requests still being handled, so the page can cancel them. */
  private inFlight = new Map<string, AbortController>();
  /**
   * Registrations whose credential was posted to the page, by request, for
   * a while. A cancel that arrives for one of them crossed the credential in
   * flight: the page had already given up and dropped it.
   */
  private postedRegistrations = new Map<string, number>();

  /** Settles once i18n and logging are ready; page requests wait for it. */
  private ready: Promise<void>;
  /** The vault's own dialogs, which the page can neither read nor click for the user. */
  private dialogs = new VaultDialogClient((message) => this.sendMessage(message));

  constructor() {
    // Both happen before the first await, at document_start: the page can
    // call navigator.credentials as soon as its first script runs, and a
    // request posted before anyone listens is lost, leaving the page waiting.
    this.injectScript();
    this.setupPageCommunication();
    this.ready = this.initialize();
  }

  /**
   * Initialize the content script
   */
  private async initialize(): Promise<void> {
    try {
      // Translations only: the page's own <html> lang and dir stay as they are.
      await initI18n({ applyToDocument: false });

      // Initialize logger first
      await logger.init();

      logger.info('Content script initializing');

      // Set up communication with background script
      this.setupBackgroundCommunication();

      // Listen for activation events
      this.setupActivationListeners();

      this.isInjected = true;
      logger.info('Content script initialized successfully');
    } catch (error) {
      logger.error('Content script initialization failed:', error);
    }
  }

  /**
   * Inject WebAuthn API interception script.
   *
   * Chrome runs it as a MAIN-world content script declared in the manifest,
   * before any page script. Firefox's manifest still supports versions that
   * cannot do that, so there it is added as a script element, which runs a
   * little later: a page that calls WebAuthn first thing can reach the
   * browser's own API before the vault is in place.
   */
  private injectScript(): void {
    const declared = chrome.runtime
      .getManifest?.()
      ?.content_scripts?.some((script) => (script as { world?: string }).world === 'MAIN');
    if (declared) {
      return;
    }
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('webauthn-inject.js');
      script.onload = function () {
        // @ts-expect-error script element type doesn't have remove method
        this.remove();
      };
      (document.head || document.documentElement).appendChild(script);
      logger.debug('Injected webauthn-inject.js');
    } catch (e) {
      logger.error('Injection failed', e);
    }
  }

  /**
   * Set up communication with the page script
   */
  private setupPageCommunication(): void {
    window.addEventListener('message', async (event) => {
      if (event.source !== window) return;
      if (event.data?.source === 'PASSKEY_VAULT_PAGE') {
        this.handlePageMessage(event.data);
      }
    });
  }

  /**
   * Resolve the RP ID for a request against the *real* page origin.
   *
   * SECURITY: the page-supplied `payload.origin` and `publicKey.rpId` cannot be
   * trusted — any script in the page can post a forged message with an
   * arbitrary origin/rpId. The content script runs in the isolated world, so
   * `window.location.origin` is the authoritative caller origin. We overwrite
   * the payload origin with it and require the requested RP ID to be the
   * effective domain or a registrable suffix of it (the same rule the native
   * WebAuthn client enforces).
   *
   * This does not change behaviour for legitimate pages: a real registration
   * already used the true origin, so the stored rpId still resolves.
   *
   * When the RP ID is not same-site with the page, we fall back to WebAuthn
   * Related Origin Requests: some RPs deliberately use a cross-site RP ID (e.g.
   * Meta's accounts.meta.com on accountscenter.facebook.com) and authorize it
   * via their /.well-known/webauthn file. An RP ID that still does not fit is
   * left to the browser, which throws the SecurityError the site expects, or
   * honours a related origin it could verify and we could not.
   */
  private async resolveTrustedRpId(payload: Record<string, unknown>): Promise<RpIdResolution> {
    // WebAuthn is restricted to secure contexts.  The content script also
    // receives direct postMessage requests, so the hook's own secure-context
    // check is not enough here.
    if (
      !window.isSecureContext &&
      !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)
    ) {
      logger.error('Rejected passkey request from insecure origin', location.origin);
      return { refused: true };
    }
    const trueOrigin = window.location.origin;
    let trueHost: string;
    try {
      trueHost = new URL(trueOrigin).hostname;
    } catch {
      // An opaque origin (a sandboxed frame) cannot use WebAuthn at all.
      return { refused: true };
    }
    // Bind the origin that will be written into clientDataJSON to the real one,
    // and say whether the call comes from a frame that is not same-origin with
    // its ancestors (clientData crossOrigin/topOrigin).
    payload.origin = trueOrigin;
    const frame = describeFrame();
    payload.crossOrigin = !frame.sameOriginWithAncestors;
    if (payload.crossOrigin && frame.topOrigin) {
      payload.topOrigin = frame.topOrigin;
    } else {
      delete payload.topOrigin;
    }

    const pk = payload.publicKey as Record<string, unknown> | undefined;
    const pkRp = (pk?.rp as Record<string, string>) || {};
    const requested = String(pk?.rpId ?? pkRp.id ?? trueHost);

    if (isRpIdValidForHost(requested, trueHost)) {
      return { rpId: requested };
    }
    // Not same-site — the RP may still authorize this origin via Related Origin
    // Requests. The background worker fetches the RP's /.well-known/webauthn
    // file (it has host permissions and isn't subject to the page's CSP).
    if (await this.isRelatedOriginAuthorized(requested, trueOrigin)) {
      return { rpId: requested };
    }
    // Not an error: the browser decides, and throws SecurityError if it must.
    logger.debug('RP ID', requested, 'not valid for', trueOrigin, '- leaving it to the browser');
    return { foreign: true };
  }

  /**
   * Whether this document may use WebAuthn under its Permissions Policy
   * (WebAuthn Level 3 §5.9). The features are on by default for a page and
   * its same-origin frames, but a cross-origin iframe only gets them when
   * its embedder delegates them (allow="publickey-credentials-get"), and
   * any page can switch them off with a Permissions-Policy header. Chrome
   * refuses such calls with NotAllowedError; the vault must not open its
   * dialog for them instead. When the browser cannot say (no policy API, or
   * a feature it does not know), a cross-origin frame is left to the
   * browser, which enforces its own rules.
   */
  private frameMayUse(
    feature: 'publickey-credentials-get' | 'publickey-credentials-create',
    crossOrigin: boolean
  ): boolean {
    const policy = (
      document as Document & {
        featurePolicy?: { features(): string[]; allowsFeature(name: string): boolean };
      }
    ).featurePolicy;
    if (!policy?.features?.().includes(feature)) {
      return !crossOrigin;
    }
    return policy.allowsFeature(feature);
  }

  private async isRelatedOriginAuthorized(rpId: string, origin: string): Promise<boolean> {
    try {
      const res = await this.sendMessage({
        type: 'VERIFY_RELATED_ORIGIN',
        payload: { rpId, origin },
      });
      return res?.authorized === true;
    } catch {
      return false;
    }
  }

  /**
   * Handle messages from the page script.
   *
   * The page cancels a request when it times out or the site aborts it.
   * Cancelling closes the request's dialog and skips the background call, so
   * a late click cannot create or sign with a passkey nobody is waiting for.
   */
  private async handlePageMessage(message: {
    type: string;
    payload: Record<string, unknown>;
    requestId: string;
  }): Promise<void> {
    const { type, requestId } = message;
    if (type === 'PASSKEY_CANCEL_REQUEST') {
      this.inFlight.get(requestId)?.abort();
      // The page shim only cancels a request it never got an answer to, so
      // a credential already posted for it went nowhere.
      if (this.postedRegistrations.delete(requestId)) {
        this.discardRegistration(requestId);
      }
      return;
    }

    const controller = new AbortController();
    this.inFlight.set(requestId, controller);
    try {
      await this.ready;
      if (controller.signal.aborted) {
        return;
      }
      await this.handlePageRequest(message, controller.signal);
    } finally {
      if (this.inFlight.get(requestId) === controller) {
        this.inFlight.delete(requestId);
      }
    }
  }

  private async handlePageRequest(
    message: { type: string; payload: Record<string, unknown>; requestId: string },
    signal: AbortSignal
  ): Promise<void> {
    const { type, payload, requestId } = message;

    if (type === 'PASSKEY_CREATE_REQUEST') {
      // Create a new passkey
      try {
        const pk = payload.publicKey as Record<string, unknown> | undefined;
        const resolved = await this.resolveTrustedRpId(payload);
        if ('refused' in resolved) {
          this.postBlockedResponse('PASSKEY_CREATE_RESPONSE', requestId, t('pagePasskeyError'));
          return;
        }
        if ('foreign' in resolved) {
          this.postPassthroughResponse(
            'PASSKEY_CREATE_RESPONSE',
            requestId,
            'RP ID not valid here'
          );
          return;
        }
        if (!this.frameMayUse('publickey-credentials-create', payload.crossOrigin === true)) {
          this.postPassthroughResponse('PASSKEY_CREATE_RESPONSE', requestId, 'Not delegated');
          return;
        }
        const rpId = resolved.rpId;
        const rules = await this.getDomainRules();

        if (!this.shouldInterceptDomain(rpId, rules)) {
          this.postPassthroughResponse(
            'PASSKEY_CREATE_RESPONSE',
            requestId,
            'Domain not intercepted'
          );
          return;
        }

        // The vault only makes ES256 keys. When the site does not accept
        // them, another authenticator may support what it asks for.
        if (!acceptsEs256(pk?.pubKeyCredParams)) {
          this.postPassthroughResponse(
            'PASSKEY_CREATE_RESPONSE',
            requestId,
            'No requested algorithm is supported'
          );
          return;
        }

        // SECURITY: the user confirms every registration in the vault's own
        // dialog, so a page cannot register a credential the user did not
        // intend, silently or with a click it tricked them into. The
        // background makes the passkey only for a request the dialog
        // approved.
        const dialog = await this.dialogs.run({
          kind: 'create',
          requestId,
          rpId,
          payload,
          conditional: false,
          signal,
        });
        if (signal.aborted) {
          return;
        }
        if (dialog.status !== 'decided') {
          throw new Error(t('pagePasskeyError'));
        }
        if (dialog.outcome !== 'approved') {
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_CREATE_RESPONSE',
              requestId,
              result: {
                success: false,
                error: t('commonCancel'),
                name: 'NotAllowedError',
                blockNativeFallback: true,
              },
            },
            '*'
          );
          return;
        }

        const response = await this.sendMessage({
          type: 'CREATE_PASSKEY',
          payload,
          requestId,
          timestamp: Date.now(),
        });

        // The page stopped waiting while the passkey was being made, so the
        // site will never register it. Take it back instead of leaving the
        // user a passkey that cannot sign in.
        if (signal.aborted) {
          if (response.success) {
            this.discardRegistration(requestId);
          }
          return;
        }

        if (response.success && response.credential) {
          const pkUser = (pk?.user as Record<string, string>) || {};
          const userName = pkUser.displayName || pkUser.name || t('commonUnknownUser');
          _showPasskeyCreatedNotification(userName, rpId);
          void this.captureSiteIcon(rpId);

          // Reconstruct a proper PublicKeyCredential object
          const credential = this.createCredentialFromResponse(
            response.credential as Record<string, unknown>,
            'create'
          );
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_CREATE_RESPONSE',
              requestId,
              result: { success: true, credential },
            },
            '*'
          );
          this.rememberPostedRegistration(requestId);
        } else {
          // Show error if it's not a duplicate passkey error
          if (response.name !== 'InvalidStateError') {
            _showErrorNotification(
              t('pagePasskeyError'),
              (response.error as string) || t('pagePasskeyError')
            );
          }
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_CREATE_RESPONSE',
              requestId,
              result: response,
            },
            '*'
          );
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : t('pagePasskeyError');
        _showErrorNotification(t('pagePasskeyError'), msg);
        window.postMessage(
          {
            source: 'PASSKEY_VAULT_CONTENT',
            type: 'PASSKEY_CREATE_RESPONSE',
            requestId,
            result: { success: false, error: msg },
          },
          '*'
        );
      }
    } else if (type === 'PASSKEY_GET_REQUEST') {
      // Once the user has picked a vault passkey, a failure must not pop the
      // browser's own passkey prompt up in its place.
      let userChosePasskey = false;
      // Sign in with existing passkey - show selection UI
      try {
        const pk = payload.publicKey as Record<string, unknown> | undefined;
        const resolved = await this.resolveTrustedRpId(payload);
        if ('refused' in resolved) {
          this.postBlockedResponse('PASSKEY_GET_RESPONSE', requestId, t('pagePasskeyError'));
          return;
        }
        if ('foreign' in resolved) {
          this.postPassthroughResponse('PASSKEY_GET_RESPONSE', requestId, 'RP ID not valid here');
          return;
        }
        if (!this.frameMayUse('publickey-credentials-get', payload.crossOrigin === true)) {
          this.postPassthroughResponse('PASSKEY_GET_RESPONSE', requestId, 'Not delegated');
          return;
        }
        const rpId = resolved.rpId;
        const rules = await this.getDomainRules();

        if (!this.shouldInterceptDomain(rpId, rules)) {
          this.postPassthroughResponse('PASSKEY_GET_RESPONSE', requestId, 'Domain not intercepted');
          return;
        }

        // The vault's dialog lists the site's passkeys. They go from the
        // background to the dialog only: this script, in the page's
        // process, learns whether there is one to offer, never which.
        const dialog = await this.dialogs.run({
          kind: 'get',
          requestId,
          rpId,
          payload,
          conditional: payload.mediation === 'conditional',
          signal,
        });
        if (signal.aborted) {
          return;
        }

        // A locked vault cannot tell whether it holds a passkey for this site,
        // so it must not be reported as "no passkey". Say it is locked, then
        // follow the user's fallback setting: blocking the native prompt on
        // every locked sign-in would also lock out their security keys.
        if (dialog.status === 'locked') {
          _showErrorNotification(t('popupVaultLocked'), t('pageVaultLockedMsg'));
          if (rules.passthroughOnNoPasskey !== false) {
            this.postPassthroughResponse('PASSKEY_GET_RESPONSE', requestId, 'Vault is locked');
          } else {
            this.postBlockedResponse('PASSKEY_GET_RESPONSE', requestId, t('pageVaultLockedMsg'));
          }
          return;
        }

        // The background offers only passkeys in allowCredentials, when the
        // RP sends a list: the server accepts no others.
        if (dialog.status === 'none') {
          if (rules.passthroughOnNoPasskey !== false) {
            const allowCredentials = (pk?.allowCredentials as unknown[] | undefined) || [];
            this.postPassthroughResponse(
              'PASSKEY_GET_RESPONSE',
              requestId,
              allowCredentials.length > 0
                ? 'No vault passkey matches allowCredentials'
                : 'No vault passkey for this site'
            );
            return;
          }

          this.postBlockedResponse('PASSKEY_GET_RESPONSE', requestId, t('pageNoPasskeysSite'));
          return;
        }

        if (dialog.outcome === 'passthrough') {
          this.postPassthroughResponse(
            'PASSKEY_GET_RESPONSE',
            requestId,
            'User chose other passkey'
          );
          return;
        }

        if (dialog.outcome === 'cancel') {
          // A conditional (autofill) request is meant to stay open for the
          // life of the page, so dismissing the picker hands it to the
          // browser's own autofill instead of failing it.
          if (payload.mediation === 'conditional') {
            this.postPassthroughResponse(
              'PASSKEY_GET_RESPONSE',
              requestId,
              'Vault picker dismissed'
            );
            return;
          }
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: {
                success: false,
                error: t('commonCancel'),
                name: 'NotAllowedError',
                blockNativeFallback: true,
              },
            },
            '*'
          );
          return;
        }

        userChosePasskey = true;

        // Sign with the passkey the user picked in the dialog. The background
        // knows which one, and signs only for a request the dialog approved.
        const response = await this.sendMessage({
          type: 'GET_PASSKEY',
          payload,
          requestId,
          timestamp: Date.now(),
        });

        if (response.success && response.credential) {
          // No account name here: this notice is in the page's DOM.
          _showPasskeyUsedNotification(rpId);
          void this.captureSiteIcon(rpId);

          // Reconstruct a proper PublicKeyCredential object
          const credential = this.createCredentialFromResponse(
            response.credential as Record<string, unknown>,
            'get'
          );
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: { success: true, credential },
            },
            '*'
          );
        } else {
          _showErrorNotification(
            t('pageSignInFailed'),
            (response.error as string) || t('pageSignInFailed')
          );
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: { ...response, blockNativeFallback: true },
            },
            '*'
          );
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : t('pageSignInFailed');
        _showErrorNotification(t('pageSignInFailed'), msg);
        window.postMessage(
          {
            source: 'PASSKEY_VAULT_CONTENT',
            type: 'PASSKEY_GET_RESPONSE',
            requestId,
            result: {
              success: false,
              error: msg,
              ...(userChosePasskey && { blockNativeFallback: true }),
            },
          },
          '*'
        );
      }
    }
  }

  /** Ask the background to take back the passkey it made for this request. */
  private discardRegistration(requestId: string): void {
    this.sendMessage({ type: 'DISCARD_REGISTRATION', requestId }).catch(() => undefined);
  }

  private rememberPostedRegistration(requestId: string): void {
    const now = Date.now();
    for (const [id, postedAt] of this.postedRegistrations) {
      if (now - postedAt > POSTED_REGISTRATION_MEMORY_MS) this.postedRegistrations.delete(id);
    }
    this.postedRegistrations.set(requestId, now);
  }

  /**
   * Set up communication with background script
   */
  private setupBackgroundCommunication(): void {
    // Listen for messages from background script
    // Nothing here answers, so the channel is not held open: a sender that
    // waits for a reply would otherwise wait until the page unloads.
    chrome.runtime.onMessage.addListener((message) => {
      this.handleBackgroundMessage(message);
    });
  }

  /**
   * Handle messages from background script
   */
  private handleBackgroundMessage(message: { type: string }): void {
    try {
      switch (message.type) {
        case 'UI_ACTIVATION':
          this.showEmergencyUI();
          break;
        case 'WEB_AUTHN_RESPONSE':
          // Handle WebAuthn responses
          break;
        default:
          logger.debug('Unknown background message type:', message.type);
      }
    } catch (error) {
      logger.error('Error handling background message:', error);
    }
  }

  /**
   * Set up activation listeners for the hidden interface
   */
  private setupActivationListeners(): void {
    // Listen for custom activation events
    window.addEventListener('vault-activate', () => {
      console.log('Fenko Vault: Activation event received');
      this.activateEmergencyUI();
    });

    // Listen for keyboard sequences (Konami code)
    let konamiCode: string[] = [];
    const konamiPattern = [
      'ArrowUp',
      'ArrowUp',
      'ArrowDown',
      'ArrowDown',
      'ArrowLeft',
      'ArrowRight',
      'ArrowLeft',
      'ArrowRight',
      'b',
      'a',
    ];

    document.addEventListener('keydown', (event) => {
      konamiCode.push(event.key);
      konamiCode = konamiCode.slice(-konamiPattern.length);

      if (konamiCode.join(',') === konamiPattern.join(',')) {
        logger.info('Konami code activated');
        this.activateEmergencyUI();
      }
    });
  }

  /**
   * Activate emergency UI
   */
  private async activateEmergencyUI(): Promise<void> {
    try {
      const response = await this.sendMessage({
        type: 'ACTIVATE_UI',
        payload: { url: window.location.href },
        requestId: this.generateRequestId(),
        timestamp: Date.now(),
      });

      if (response.success) {
        // Open emergency UI
        this.showEmergencyUI();
      }
    } catch (error) {
      logger.error('Failed to activate emergency UI:', error);
    }
  }

  /**
   * Show emergency UI (placeholder)
   */
  private showEmergencyUI(): void {
    logger.info('Showing emergency UI');

    // Create a simple modal for now (will be enhanced in UI Agent phase)
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #0D1117;
      color: #E6EDF3;
      padding: 20px;
      border: 1px solid rgba(245,166,35,0.35);
      border-radius: 16px;
      z-index: 999999;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      font-family: Arial, sans-serif;
    `;

    modal.innerHTML = `
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#F5A623" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
      <h3>${t('appName')}</h3>
      <p>${t('emergencyActivated')}</p>
      <button onclick="this.parentElement.remove()" style="
        background: #D4920A;
        color: #ffffff;
        border: none;
        padding: 8px 16px;
        border-radius: 10px;
        cursor: pointer;
        margin-top: 10px;
      ">${t('commonClose')}</button>
    `;

    document.body.appendChild(modal);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (modal.parentElement) {
        modal.remove();
      }
    }, 5000);
  }

  /**
   * Store the site's own icon so the vault list can show it later.
   *
   * Only runs for a ceremony whose page is same-site with the RP ID. A Related
   * Origin Request runs on another brand's page (facebook.com authorizing
   * accounts.meta.com), and labelling one brand with another's mark would be
   * worse than no icon at all. Best-effort throughout: a failure here must never
   * affect the ceremony, which has already completed by this point.
   */
  private async captureSiteIcon(rpId: string): Promise<void> {
    const host = window.location.hostname.toLowerCase();
    const id = rpId.toLowerCase();
    if (host !== id && !host.endsWith('.' + id)) {
      return;
    }

    try {
      const status = await this.sendMessage({ type: 'NEEDS_SITE_ICON', payload: { rpId } });
      if (status?.needed !== true) {
        return;
      }

      const icon = await readPageIcon();
      if (!icon) {
        return;
      }

      await this.sendMessage({ type: 'SAVE_SITE_ICON', payload: { rpId, ...icon } });
    } catch (error) {
      logger.debug('Site icon capture skipped', error);
    }
  }

  /**
   * Send message to background script
   */
  private async sendMessage(message: Record<string, unknown>): Promise<Record<string, unknown>> {
    // Promise form works on Chrome MV3 and on Firefox (where `chrome` is aliased
    // to the promise-based `browser`). The callback form would silently never
    // resolve under Firefox's promise-only namespace.
    const response = await chrome.runtime.sendMessage(message);
    return response as Record<string, unknown>;
  }

  private createCredentialFromResponse(
    data: Record<string, unknown>,
    type: 'create' | 'get'
  ): Record<string, unknown> {
    const resp = data.response as Record<string, unknown> | undefined;
    let responseObj;

    if (type === 'create') {
      responseObj = {
        clientDataJSON: resp?.clientDataJSON,
        attestationObject: resp?.attestationObject,
        authenticatorData: resp?.authenticatorData,
        publicKey: resp?.publicKey,
        publicKeyAlgorithm: resp?.publicKeyAlgorithm,
        transports: resp?.transports,
      };
    } else {
      responseObj = {
        clientDataJSON: resp?.clientDataJSON,
        authenticatorData: resp?.authenticatorData,
        signature: resp?.signature,
        userHandle: resp?.userHandle,
      };
    }

    return {
      id: data.id,
      rawId: data.rawId,
      type: data.type,
      response: responseObj,
      authenticatorAttachment: data.authenticatorAttachment,
      clientExtensionResults: data.clientExtensionResults,
    };
  }

  private async getDomainRules(): Promise<DomainRules> {
    const result = await chrome.storage.local.get('domain_rules');
    const partial = (result.domain_rules || {}) as Partial<DomainRules>;
    return {
      mode: partial.mode || 'all',
      domains: Array.isArray(partial.domains) ? partial.domains : [],
      passthroughOnNoPasskey: partial.passthroughOnNoPasskey !== false,
    };
  }

  private shouldInterceptDomain(rpId: string, rules: DomainRules): boolean {
    if (rules.mode === 'disabled') return false;
    if (rules.mode === 'all') return true;

    const domain = rpId.toLowerCase();
    const matches = rules.domains.some((rule) => {
      const normalizedRule = rule.toLowerCase();
      return domain === normalizedRule || domain.endsWith(`.${normalizedRule}`);
    });

    if (rules.mode === 'allowlist') return matches;
    if (rules.mode === 'blocklist') return !matches;
    return true;
  }

  private postPassthroughResponse(type: string, requestId: string, reason: string): void {
    window.postMessage(
      {
        source: 'PASSKEY_VAULT_CONTENT',
        type,
        requestId,
        result: {
          success: false,
          passthrough: true,
          error: reason,
          name: 'NotAllowedError',
        },
      },
      '*'
    );
  }

  private postBlockedResponse(type: string, requestId: string, error: string): void {
    window.postMessage(
      {
        source: 'PASSKEY_VAULT_CONTENT',
        type,
        requestId,
        result: {
          success: false,
          error,
          name: 'NotAllowedError',
          blockNativeFallback: true,
        },
      },
      '*'
    );
  }

  /**
   * Generate a unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleanup when content script is removed
   */
  public destroy(): void {
    if (this.originalCreate && this.originalGet && navigator.credentials) {
      // Restore original WebAuthn methods
      navigator.credentials.create = this.originalCreate;
      navigator.credentials.get = this.originalGet;
    }

    this.isInjected = false;
    logger.info('Content script destroyed');
  }
}

// Initialize the content script
new ContentScript();
