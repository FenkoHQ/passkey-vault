/**
 * Content Script for PassKey Vault
 *
 * This script is injected into web pages to intercept WebAuthn API calls
 * and communicate with the background script.
 */

// Note: showPasskeySelector, showPasskeyCreatedNotification, showPasskeyUsedNotification,
// showErrorNotification, and PasskeyOption are provided by passkey-ui.ts (concatenated during build)

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
      console.log('PassKey Vault: Content script initializing');

      // Inject WebAuthn interception code
      this.injectScript();

      // Set up communication with background script
      this.setupBackgroundCommunication();

      // Set up page communication
      this.setupPageCommunication();

      // Listen for activation events
      this.setupActivationListeners();

      this.isInjected = true;
      console.log('PassKey Vault: Content script initialized successfully');
    } catch (error) {
      console.error('PassKey Vault: Content script initialization failed:', error);
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
      console.log('PassKey Vault: Injected webauthn-inject.js');
    } catch (e) {
      console.error('PassKey Vault: Injection failed', e);
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
   * Handle messages from the page script
   */
  private async handlePageMessage(message: any): Promise<void> {
    const { type, payload, requestId } = message;

    if (type === 'PASSKEY_CREATE_REQUEST') {
      // Create a new passkey
      try {
        const response = await this.sendMessage({
          type: 'CREATE_PASSKEY',
          payload,
          requestId,
          timestamp: Date.now(),
        });

        if (response.success && response.credential) {
          // Show success notification
          const userName =
            payload.publicKey?.user?.displayName || payload.publicKey?.user?.name || 'User';
          const rpId =
            payload.publicKey?.rpId ||
            payload.publicKey?.rp?.id ||
            new URL(payload.origin).hostname;
          showPasskeyCreatedNotification(userName, rpId);

          // Reconstruct a proper PublicKeyCredential object
          const credential = this.createCredentialFromResponse(response.credential, 'create');
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
            showErrorNotification('Passkey Error', response.error || 'Failed to create passkey');
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
      } catch (error: any) {
        showErrorNotification('Passkey Error', error.message || 'Failed to create passkey');
        window.postMessage(
          {
            source: 'PASSKEY_VAULT_CONTENT',
            type: 'PASSKEY_CREATE_RESPONSE',
            requestId,
            result: { success: false, error: error.message },
          },
          '*'
        );
      }
    } else if (type === 'PASSKEY_GET_REQUEST') {
      // Sign in with existing passkey - show selection UI
      try {
        // First, get list of available passkeys for this site
        const rpId = payload.publicKey?.rpId || new URL(payload.origin).hostname;
        const listResponse = await this.sendMessage({
          type: 'LIST_PASSKEYS_FOR_RP',
          payload: { rpId },
          requestId,
          timestamp: Date.now(),
        });

        if (!listResponse.success || !listResponse.passkeys || listResponse.passkeys.length === 0) {
          // No passkeys found, return error to trigger fallback
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: {
                success: false,
                error: 'No passkeys found for this site',
                name: 'NotAllowedError',
              },
            },
            '*'
          );
          return;
        }

        // Convert to PasskeyOption format for the selector
        const passkeyOptions: PasskeyOption[] = listResponse.passkeys.map((pk: any) => ({
          id: pk.id,
          credentialId: pk.credentialId || pk.id,
          userName: pk.user?.name || '',
          userDisplayName: pk.user?.displayName || pk.user?.name || 'Unknown User',
          rpId: pk.rpId,
          createdAt: pk.createdAt,
        }));

        // Show passkey selector UI
        const selectedId = await showPasskeySelector(passkeyOptions, rpId);

        if (!selectedId) {
          // User cancelled
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: {
                success: false,
                error: 'User cancelled the operation',
                name: 'NotAllowedError',
              },
            },
            '*'
          );
          return;
        }

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
          const userName = selectedPasskey?.userDisplayName || selectedPasskey?.userName || 'User';
          showPasskeyUsedNotification(userName, rpId);

          // Reconstruct a proper PublicKeyCredential object
          const credential = this.createCredentialFromResponse(response.credential, 'get');
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
          showErrorNotification('Sign In Failed', response.error || 'Failed to use passkey');
          window.postMessage(
            {
              source: 'PASSKEY_VAULT_CONTENT',
              type: 'PASSKEY_GET_RESPONSE',
              requestId,
              result: response,
            },
            '*'
          );
        }
      } catch (error: any) {
        showErrorNotification('Sign In Failed', error.message || 'Failed to use passkey');
        window.postMessage(
          {
            source: 'PASSKEY_VAULT_CONTENT',
            type: 'PASSKEY_GET_RESPONSE',
            requestId,
            result: { success: false, error: error.message },
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
        console.log('PassKey Vault: Passkey stored successfully');
      } catch (error) {
        console.error('PassKey Vault: Failed to store passkey:', error);
      }
    }
  }

  /**
   * Set up communication with background script
   */
  private setupBackgroundCommunication(): void {
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleBackgroundMessage(message, sender, sendResponse);
      return true;
    });
  }

  /**
   * Handle messages from background script
   */
  private handleBackgroundMessage(
    message: any,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: any) => void
  ): void {
    try {
      switch (message.type) {
        case 'UI_ACTIVATION':
          this.showEmergencyUI();
          break;
        case 'WEB_AUTHN_RESPONSE':
          // Handle WebAuthn responses
          break;
        default:
          console.log('PassKey Vault: Unknown background message type:', message.type);
      }
    } catch (error) {
      console.error('PassKey Vault: Error handling background message:', error);
    }
  }

  /**
   * Set up activation listeners for the hidden interface
   */
  private setupActivationListeners(): void {
    // Listen for custom activation events
    window.addEventListener('vault-activate', () => {
      console.log('PassKey Vault: Activation event received');
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
        console.log('PassKey Vault: Konami code activated');
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
      console.error('PassKey Vault: Failed to activate emergency UI:', error);
    }
  }

  /**
   * Show emergency UI (placeholder)
   */
  private showEmergencyUI(): void {
    console.log('PassKey Vault: Showing emergency UI');

    // Create a simple modal for now (will be enhanced in UI Agent phase)
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #2a2a2a;
      color: white;
      padding: 20px;
      border-radius: 8px;
      z-index: 999999;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      font-family: Arial, sans-serif;
    `;

    modal.innerHTML = `
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#4a9eff" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
      <h3>PassKey Vault</h3>
      <p>Emergency access activated</p>
      <button onclick="this.parentElement.remove()" style="
        background: #4a9eff;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        margin-top: 10px;
      ">Close</button>
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
  private async sendMessage(message: any): Promise<any> {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * Create a proper PublicKeyCredential object from the response data
   */
  private createCredentialFromResponse(data: any, type: 'create' | 'get'): any {
    // Create a response object based on type
    let response;

    if (type === 'create') {
      response = {
        clientDataJSON: data.response.clientDataJSON,
        attestationObject: data.response.attestationObject,
      };
    } else {
      response = {
        clientDataJSON: data.response.clientDataJSON,
        authenticatorData: data.response?.authenticatorData,
        signature: data.response?.signature,
        userHandle: data.response?.userHandle,
      };
    }

    // Return a plain object - the page script will convert it to a proper credential
    return {
      id: data.id,
      rawId: data.rawId,
      type: data.type,
      response: response,
      authenticatorAttachment: data?.authenticatorAttachment,
      clientExtensionResults: data?.clientExtensionResults,
    };
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
    console.log('PassKey Vault: Content script destroyed');
  }
}

// Initialize the content script
const contentScript = new ContentScript();
