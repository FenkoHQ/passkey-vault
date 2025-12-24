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
      <svg xmlns="http://www.w3.org/2000/svg" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" image-rendering="optimizeQuality" fill-rule="evenodd" clip-rule="evenodd" viewBox="0 0 512 468.554"><path fill="#fff" fill-rule="nonzero" d="M483.381 151.575H28.619v219.35c0 37.906 31.106 69.009 69.013 69.009h316.736c37.884 0 69.013-31.125 69.013-69.009v-219.35z"/><path fill="#FD5" d="M353.177 122.962l36.214-92.199c.286-.725.621-1.441.999-2.144H284.447l-37.054 94.343h105.784zm62.346-94.33l-37.051 94.33h104.909v-25.33c0-18.947-7.773-36.205-20.295-48.724-12.255-12.258-29.061-19.967-47.563-20.276zM88.36 122.962l36.214-92.199c.287-.725.621-1.441.999-2.144H97.632c-18.963 0-36.218 7.77-48.731 20.283-12.512 12.512-20.282 29.767-20.282 48.73v25.33H88.36zm62.353-94.343l-37.058 94.343h108.681l36.129-91.983c.315-.798.687-1.587 1.116-2.36H150.713z"/><path fill="#212121" fill-rule="nonzero" d="M97.632 0h316.736C468.073 0 512 43.928 512 97.632v273.293c0 53.682-43.95 97.629-97.632 97.629H97.632C43.927 468.554 0 424.629 0 370.925V97.632C0 43.902 43.902 0 97.632 0zm255.545 122.962l36.214-92.199c.286-.725.621-1.441.999-2.144H284.447l-37.054 94.343h105.784zm62.346-94.33l-37.051 94.33h104.909v-25.33c0-37.461-30.413-68.377-67.858-69zM88.36 122.962l36.214-92.199c.287-.725.621-1.441.999-2.144H97.632c-37.929 0-69.013 31.084-69.013 69.013v25.33H88.36zm62.353-94.343l-37.058 94.343h108.681l36.129-91.983c.315-.798.687-1.587 1.116-2.36H150.713zm332.668 122.956H28.619v219.35c0 37.906 31.106 69.009 69.013 69.009h316.736c37.884 0 69.013-31.125 69.013-69.009v-219.35z"/><path fill="#212121" fill-rule="nonzero" d="M195.916 244.816c1.685-13.282 7.845-25.185 16.868-34.209v-.036c10.691-10.708 25.475-17.357 41.71-17.357 16.271 0 31.02 6.649 41.746 17.357l.017.036c10.672 10.673 17.322 25.44 17.322 41.692v25.439h14.387c2.482.054 4.511 2.12 4.511 4.62v92.822c0 2.537-2.065 4.62-4.602 4.62H184.121c-2.537 0-4.602-2.084-4.602-4.62v-92.823c0-2.537 2.065-4.62 4.602-4.62l11.27.001v-25.584c0-2.482.163-4.929.471-7.338h.054zm22.413 32.922h72.33-.018v-25.783c0-9.912-4.077-18.971-10.618-25.494-6.559-6.54-15.582-10.599-25.53-10.599-9.911 0-18.952 4.04-25.493 10.599-6.16 6.161-10.128 14.477-10.563 23.718l-.09-.001-.018 1.667v25.893z"/></svg>
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
