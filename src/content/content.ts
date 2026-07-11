/**
 * Content Script for Fenko Vault
 *
 * This script is injected into web pages to intercept WebAuthn API calls
 * and communicate with the background script.
 */

import { initI18n, t } from '../i18n';
import { logger } from '../utils/logger';

interface PasskeyOption {
  id: string;
  credentialId: string;
  userName: string;
  userDisplayName: string;
  rpId: string;
  createdAt: number;
}

interface DomainRules {
  mode: 'disabled' | 'all' | 'allowlist' | 'blocklist';
  domains: string[];
  passthroughOnNoPasskey?: boolean;
}

type PasskeySelectorResult =
  | { action: 'use'; id: string }
  | { action: 'cancel' }
  | { action: 'passthrough' };

interface WindowWithVault extends Window {
  showPasskeySelector: (options: PasskeyOption[], rpId: string) => Promise<PasskeySelectorResult>;
  showPasskeyCreateConfirm: (rpId: string, userName: string) => Promise<boolean>;
  showPasskeyCreatedNotification: (userName: string, rpId: string) => void;
  showPasskeyUsedNotification: (userName: string, rpId: string) => void;
  showErrorNotification: (title: string, message: string) => void;
}

const vaultWindow = window as unknown as WindowWithVault;
const _showPasskeySelector = vaultWindow.showPasskeySelector;
const _showPasskeyCreateConfirm = vaultWindow.showPasskeyCreateConfirm;
const _showPasskeyCreatedNotification = vaultWindow.showPasskeyCreatedNotification;
const _showPasskeyUsedNotification = vaultWindow.showPasskeyUsedNotification;
const _showErrorNotification = vaultWindow.showErrorNotification;

class ContentScript {
  private isInjected = false;
  private originalCreate?: typeof navigator.credentials.create;
  private originalGet?: typeof navigator.credentials.get;

  constructor() {
    this.initialize();
  }

  /**
   * Initialize the content script
   */
  private async initialize(): Promise<void> {
    try {
      await initI18n();

      // Initialize logger first
      await logger.init();

      logger.info('Content script initializing');

      // Inject WebAuthn interception code
      this.injectScript();

      // Set up communication with background script
      this.setupBackgroundCommunication();

      // Set up page communication
      this.setupPageCommunication();

      // Listen for activation events
      this.setupActivationListeners();

      this.isInjected = true;
      logger.info('Content script initialized successfully');
    } catch (error) {
      logger.error('Content script initialization failed:', error);
    }
  }

  /**
   * Inject WebAuthn API interception script
   */
  private injectScript(): void {
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
   * WebAuthn client enforces). Returns null to reject a cross-origin request.
   *
   * This does not change behaviour for legitimate pages: a real registration
   * already used the true origin, so the stored rpId still resolves.
   */
  private resolveTrustedRpId(payload: Record<string, unknown>): string | null {
    const trueOrigin = window.location.origin;
    let trueHost: string;
    try {
      trueHost = new URL(trueOrigin).hostname;
    } catch {
      return null;
    }
    // Bind the origin that will be written into clientDataJSON to the real one.
    payload.origin = trueOrigin;

    const pk = payload.publicKey as Record<string, unknown> | undefined;
    const pkRp = (pk?.rp as Record<string, string>) || {};
    const requested = (pk?.rpId as string) || pkRp.id || trueHost;

    const host = trueHost.toLowerCase();
    const rpId = requested.toLowerCase();
    if (host === rpId || host.endsWith('.' + rpId)) {
      return requested;
    }
    logger.error('Rejected passkey request: rpId', requested, 'not valid for origin', trueOrigin);
    return null;
  }

  /**
   * Handle messages from the page script
   */
  private async handlePageMessage(message: {
    type: string;
    payload: Record<string, unknown>;
    requestId: string;
  }): Promise<void> {
    const { type, payload, requestId } = message;

    if (type === 'PASSKEY_CREATE_REQUEST') {
      // Create a new passkey
      try {
        const pk = payload.publicKey as Record<string, unknown> | undefined;
        const rpId = this.resolveTrustedRpId(payload);
        if (rpId === null) {
          this.postBlockedResponse('PASSKEY_CREATE_RESPONSE', requestId, t('pagePasskeyError'));
          return;
        }
        const rules = await this.getDomainRules();

        if (!this.shouldInterceptDomain(rpId, rules)) {
          this.postPassthroughResponse(
            'PASSKEY_CREATE_RESPONSE',
            requestId,
            'Domain not intercepted'
          );
          return;
        }

        // SECURITY: require an explicit user gesture before creating a passkey,
        // so a page cannot silently register an attacker-triggered credential.
        const createUser = (pk?.user as Record<string, string>) || {};
        const createUserName = createUser.displayName || createUser.name || t('commonUnknownUser');
        const confirmed = await _showPasskeyCreateConfirm(rpId, createUserName);
        if (!confirmed) {
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

        if (response.success && response.credential) {
          const pkUser = (pk?.user as Record<string, string>) || {};
          const userName = pkUser.displayName || pkUser.name || t('commonUnknownUser');
          _showPasskeyCreatedNotification(userName, rpId);

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
      // Sign in with existing passkey - show selection UI
      try {
        // First, get list of available passkeys for this site
        const pk = payload.publicKey as Record<string, unknown> | undefined;
        const rpId = this.resolveTrustedRpId(payload);
        if (rpId === null) {
          this.postBlockedResponse('PASSKEY_GET_RESPONSE', requestId, t('pagePasskeyError'));
          return;
        }
        const rules = await this.getDomainRules();

        if (!this.shouldInterceptDomain(rpId, rules)) {
          this.postPassthroughResponse('PASSKEY_GET_RESPONSE', requestId, 'Domain not intercepted');
          return;
        }

        const listResponse = await this.sendMessage({
          type: 'LIST_PASSKEYS_FOR_RP',
          payload: { rpId },
          requestId,
          timestamp: Date.now(),
        });

        const passkeys = listResponse.passkeys as Record<string, unknown>[] | undefined;

        // If the RP specified allowCredentials, the server only accepts those
        // specific credential IDs (e.g. it knows the user is "alice" and lists
        // alice's credentials). Suggesting a vault passkey not in that list
        // would just fail at the server, so filter them out before deciding
        // whether to show the picker.
        const allowCredentials = (pk?.allowCredentials as Array<{ id: string }> | undefined) || [];
        const allowedIds = allowCredentials
          .map((c) => c?.id)
          .filter((id): id is string => typeof id === 'string' && id.length > 0);
        const matchingPasskeys =
          allowedIds.length > 0 && passkeys
            ? passkeys.filter((p) => {
                const credId = (p.credentialId || p.id) as string;
                return allowedIds.includes(credId);
              })
            : passkeys;

        if (!listResponse.success || !matchingPasskeys || matchingPasskeys.length === 0) {
          if (rules.passthroughOnNoPasskey !== false) {
            this.postPassthroughResponse(
              'PASSKEY_GET_RESPONSE',
              requestId,
              allowedIds.length > 0
                ? 'No vault passkey matches allowCredentials'
                : 'No vault passkey for this site'
            );
            return;
          }

          this.postBlockedResponse('PASSKEY_GET_RESPONSE', requestId, t('pageNoPasskeysSite'));
          return;
        }

        // Convert to PasskeyOption format for the selector
        const passkeyOptions: PasskeyOption[] = matchingPasskeys.map((pk) => {
          const user = pk.user as Record<string, string> | undefined;
          return {
            id: pk.id as string,
            credentialId: (pk.credentialId || pk.id) as string,
            userName: user?.name || '',
            userDisplayName: user?.displayName || user?.name || t('commonUnknownUser'),
            rpId: pk.rpId as string,
            createdAt: pk.createdAt as number,
          };
        });

        // Show passkey selector UI
        const selectorResult = await _showPasskeySelector(passkeyOptions, rpId);

        if (selectorResult.action === 'passthrough') {
          this.postPassthroughResponse(
            'PASSKEY_GET_RESPONSE',
            requestId,
            'User chose other passkey'
          );
          return;
        }

        if (selectorResult.action === 'cancel') {
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

        const selectedId = selectorResult.id;

        // Get the selected passkey and sign
        const response = await this.sendMessage({
          type: 'GET_PASSKEY',
          payload: {
            ...payload,
            selectedPasskeyId: selectedId,
          },
          requestId,
          timestamp: Date.now(),
        });

        if (response.success && response.credential) {
          // Show success notification
          const selectedPasskey = passkeyOptions.find((pk) => pk.id === selectedId);
          const userName =
            selectedPasskey?.userDisplayName || selectedPasskey?.userName || t('commonUnknownUser');
          _showPasskeyUsedNotification(userName, rpId);

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
            result: { success: false, error: msg },
          },
          '*'
        );
      }
    } else if (type === 'PASSKEY_STORE_REQUEST') {
      // Store passkey after successful creation (non-blocking response)
      try {
        await this.sendMessage({
          type: 'STORE_PASSKEY',
          payload,
          requestId,
          timestamp: Date.now(),
        });
        logger.debug('Passkey stored successfully');
      } catch (error) {
        logger.error('Failed to store passkey:', error);
      }
    }
  }

  /**
   * Set up communication with background script
   */
  private setupBackgroundCommunication(): void {
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message) => {
      this.handleBackgroundMessage(message);
      return true;
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
