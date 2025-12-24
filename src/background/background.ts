/**
 * Background Service Worker for PassKey Vault
 *
 * This is the main background script that coordinates all agents
 * and handles extension lifecycle events.
 */

// Storage key for passkeys
const PASSKEY_STORAGE_KEY = 'passkeys';

class BackgroundService {
  private agents: Map<string, any>;
  private isInitialized: boolean;

  constructor() {
    this.agents = new Map();
    this.isInitialized = false;
    this.initialize();
  }

  /**
   * Initialize the background service
   */
  private async initialize(): Promise<void> {
    try {
      console.log('PassKey Vault: Background service initializing...');

      // Set up message handlers
      this.setupMessageHandlers();

      // Set up extension lifecycle handlers
      this.setupLifecycleHandlers();

      // Initialize agents (will be done in future phases)
      await this.initializeAgents();

      this.isInitialized = true;
      console.log('PassKey Vault: Background service initialized successfully');
    } catch (error) {
      console.error('PassKey Vault: Background service initialization failed:', error);
    }
  }

  /**
   * Set up message handlers for communication with content scripts
   */
  private setupMessageHandlers(): void {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep the message channel open for async response
    });
  }

  /**
   * Handle incoming messages
   */
  private async handleMessage(
    message: any,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: any) => void
  ): Promise<void> {
    try {
      // Route message to appropriate agent
      const response = await this.routeMessage(message, sender);
      sendResponse(response);
    } catch (error) {
      console.error('Message handling error:', error);
      sendResponse({
        success: false,
        error: error.message,
      });
    }
  }

  /**
   * Route messages to appropriate agents
   */
  private async routeMessage(message: any, sender: chrome.runtime.MessageSender): Promise<any> {
    const { type, payload, requestId } = message;

    switch (type) {
      case 'CREATE_PASSKEY':
        return this.handleCreatePasskey(payload, sender);

      case 'GET_PASSKEY':
        return this.handleGetPasskey(payload, sender);

      case 'STORE_PASSKEY':
        return this.handleStorePasskey(payload, sender);

      case 'RETRIEVE_PASSKEY':
        return this.handleRetrievePasskey(payload, sender);

      case 'LIST_PASSKEYS':
        return this.handleListPasskeys(payload, sender);

      case 'LIST_PASSKEYS_FOR_RP':
        return this.handleListPasskeysForRp(payload, sender);

      case 'DELETE_PASSKEY':
        return this.handleDeletePasskey(payload, sender);

      case 'BACKUP':
        return this.handleBackup(payload, sender);

      case 'RESTORE':
        return this.handleRestore(payload, sender);

      case 'ACTIVATE_UI':
        return this.handleActivateUI(payload, sender);

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  /**
   * Set up extension lifecycle handlers
   */
  private setupLifecycleHandlers(): void {
    // Extension installed
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstalled(details);
    });

    // Extension startup
    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });

    // Extension suspend (for performance optimization)
    chrome.runtime.onSuspend.addListener(() => {
      this.handleSuspend();
    });
  }

  /**
   * Handle extension installation
   */
  private handleInstalled(details: chrome.runtime.InstalledDetails): void {
    console.log('PassKey Vault: Extension installed', details);

    if (details.reason === 'install') {
      // First-time installation
      console.log('PassKey Vault: First-time installation');
      // TODO: Set up initial configuration
    } else if (details.reason === 'update') {
      // Extension update
      console.log('PassKey Vault: Extension updated');
      // TODO: Handle migration if needed
    }
  }

  /**
   * Handle extension startup
   */
  private handleStartup(): void {
    console.log('PassKey Vault: Extension startup');
    // TODO: Reinitialize any state that might have been lost
  }

  /**
   * Handle extension suspend
   */
  private handleSuspend(): void {
    console.log('PassKey Vault: Extension suspending');
    // TODO: Clean up resources before suspension
  }

  /**
   * Initialize all agents (will be implemented in future phases)
   */
  private async initializeAgents(): Promise<void> {
    console.log('PassKey Vault: Initializing agents...');

    // TODO: Initialize agents in correct order
    // this.agents.set('storage', new StorageAgent());
    // this.agents.set('security', new SecurityAgent());
    // this.agents.set('webauthn', new WebAuthnAgent());
    // this.agents.set('backup', new BackupAgent());
    // this.agents.set('ui', new UIAgent());

    console.log('PassKey Vault: Agents initialized (placeholder)');
  }

  // Storage operations

  /**
   * Create a new passkey (generate keys, create attestation)
   */
  private async handleCreatePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey: options, origin } = payload;
      const challenge = options?.challenge;
      const user = options?.user;
      const rpId =
        options?.rpId || options?.rp?.id || (origin ? new URL(origin).hostname : 'localhost');

      console.log('PassKey Vault: Creating passkey for', rpId, 'user:', user?.name);

      // Check if a passkey already exists for this origin
      const existingResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const existingPasskeys: any[] = existingResult[PASSKEY_STORAGE_KEY] || [];
      const existingPasskey = existingPasskeys.find((p) => p.rpId === rpId);

      if (existingPasskey) {
        console.log(
          'PassKey Vault: Passkey already exists for',
          rpId,
          '- returning existing credential'
        );
        // Return the existing credential info so the site knows this credential is already registered
        return {
          success: false,
          error: 'A passkey already exists for this site',
          name: 'InvalidStateError',
          existingCredentialId: existingPasskey.id,
        };
      }

      // Generate credential ID
      const credentialId = this.generateCredentialId();
      const credentialIdBase64 = this.arrayBufferToBase64URL(credentialId.buffer as ArrayBuffer);

      // Generate key pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        true,
        ['sign', 'verify']
      );

      // Export private key for storage
      const privateKeyExport = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const privateKeyBytes = new Uint8Array(privateKeyExport);
      let privateKeyBinary = '';
      for (let i = 0; i < privateKeyBytes.length; i++) {
        privateKeyBinary += String.fromCharCode(privateKeyBytes[i]);
      }
      const privateKeyBase64 = btoa(privateKeyBinary);

      // Export public key in RAW format (65 bytes: 0x04 + x + y)
      const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      const publicKeyBytes = new Uint8Array(publicKeyRaw);
      let publicKeyBinary = '';
      for (let i = 0; i < publicKeyBytes.length; i++) {
        publicKeyBinary += String.fromCharCode(publicKeyBytes[i]);
      }
      const publicKeyBase64 = btoa(publicKeyBinary);

      // Derive PRF key for this credential
      const prfKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const prfKeyBase64 = this.arrayBufferToBase64URL(prfKeyBytes.buffer);

      // Handle PRF extension during registration if requested
      const prfInput = options?.extensions?.prf;
      const prfEvalInput = this.selectPrfEval(prfInput, credentialIdBase64);
      const prfResults = prfEvalInput
        ? await this.computePrfResults(prfKeyBytes.buffer, prfEvalInput)
        : null;
      const extensionsData = prfResults ? this.encodePrfExtension(prfResults) : null;
      const clientExtensionResults = this.buildClientExtensionResults(prfResults);

      // Create clientDataJSON
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge,
        origin: origin,
      };
      const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientData));

      // Create authenticator data with COSE public key
      const authenticatorData = await this.createAuthenticatorDataAsync(
        rpId,
        credentialId,
        publicKeyRaw,
        true,
        0,
        extensionsData
      );

      // Create attestation object (using "none" attestation format)
      const attestationObject = this.createAttestationObjectNone(authenticatorData);

      // Store the passkey
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      passkeys.push({
        id: credentialIdBase64,
        credentialId: credentialIdBase64,
        type: 'public-key',
        rpId,
        origin,
        user: {
          id: user?.id
            ? user.id instanceof ArrayBuffer
              ? this.arrayBufferToBase64URL(user.id)
              : user.id
            : null,
          name: user?.name,
          displayName: user?.displayName,
        },
        privateKey: privateKeyBase64,
        publicKey: publicKeyBase64,
        createdAt: Date.now(),
        counter: 0,
        prfKey: prfKeyBase64,
      });

      await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });

      console.log('PassKey Vault: Created and stored passkey', credentialIdBase64);

      // Convert ArrayBuffers to base64 for safe message passing
      // credentialIdBase64 is already base64url, just convert to regular base64
      const rawIdBase64 = this.base64urlToBase64(credentialIdBase64);
      const clientDataJSONBase64 = this.arrayBufferToBase64(clientDataJSONBytes.buffer);
      const attestationObjectBase64 = this.arrayBufferToBase64(attestationObject);

      // Return the credential object with base64-encoded binary data
      return {
        success: true,
        credential: {
          id: credentialIdBase64,
          rawId: rawIdBase64,
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONBase64,
            attestationObject: attestationObjectBase64,
          },
          authenticatorAttachment: 'cross-platform',
          clientExtensionResults,
        },
      };
    } catch (error) {
      console.error('PassKey Vault: Error creating passkey:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get/Sign with an existing passkey
   */
  private async handleGetPasskey(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    try {
      const { publicKey: options, origin, selectedPasskeyId } = payload;
      const challenge = options?.challenge;
      const rpId = options?.rpId || (origin ? new URL(origin).hostname : 'localhost');

      console.log('PassKey Vault: Getting passkey for', rpId, 'selectedId:', selectedPasskeyId);

      // Get stored passkeys
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      // Filter passkeys for this RP ID
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      if (matchingPasskeys.length === 0) {
        console.log('PassKey Vault: No passkeys found for', rpId);
        return {
          success: false,
          error: 'No passkeys found for this site',
          name: 'NotAllowedError',
        };
      }

      // Use the selected passkey if provided, otherwise use the first one
      let passkey;
      if (selectedPasskeyId) {
        passkey = matchingPasskeys.find((p) => p.id === selectedPasskeyId);
        if (!passkey) {
          console.log('PassKey Vault: Selected passkey not found:', selectedPasskeyId);
          return {
            success: false,
            error: 'Selected passkey not found',
            name: 'NotAllowedError',
          };
        }
      } else {
        passkey = matchingPasskeys[0];
      }

      console.log('PassKey Vault: Using passkey', passkey.id, 'for signing');

      // Validate private key format
      if (!passkey.privateKey || typeof passkey.privateKey !== 'string') {
        throw new Error('Invalid private key format: ' + typeof passkey.privateKey);
      }

      if (passkey.privateKey.length === 0) {
        throw new Error('Private key is empty');
      }

      try {
        // Import the private key
        let privateKeyBinary;
        try {
          privateKeyBinary = atob(passkey.privateKey);
        } catch (atobError) {
          console.error('PassKey Vault: Failed to decode private key (atob error):', atobError);
          console.error(
            'PassKey Vault: Private key value (first 100 chars):',
            passkey.privateKey.substring(0, 100)
          );
          throw new Error('Invalid base64 encoding for private key: ' + atobError.message);
        }

        const privateKeyBytes = new Uint8Array(privateKeyBinary.length);
        for (let i = 0; i < privateKeyBinary.length; i++) {
          privateKeyBytes[i] = privateKeyBinary.charCodeAt(i);
        }

        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBytes.buffer,
          {
            name: 'ECDSA',
            namedCurve: 'P-256',
          },
          true,
          ['sign']
        );

        // Create clientDataJSON
        const clientData = {
          type: 'webauthn.get',
          challenge: challenge,
          origin: origin,
        };
        const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientData));

        // Handle PRF extension if requested
        const prfInput = options?.extensions?.prf;
        const prfEvalInput = this.selectPrfEval(prfInput, passkey.id);
        const prfKeyBuffer = await this.getOrCreatePrfKey(passkey);
        const prfResults = prfEvalInput
          ? await this.computePrfResults(prfKeyBuffer, prfEvalInput)
          : null;
        const extensionsData = prfResults ? this.encodePrfExtension(prfResults) : null;
        const clientExtensionResults = this.buildClientExtensionResults(prfResults);

        // Create authenticator data
        passkey.counter = (passkey.counter || 0) + 1;
        const authenticatorData = await this.createAuthenticatorDataAsync(
          rpId,
          null,
          null,
          false,
          passkey.counter,
          extensionsData
        );

        // Sign the assertion
        const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBytes.buffer);
        const authenticatorDataBytes = new Uint8Array(authenticatorData);
        const signatureBase = new Uint8Array(
          authenticatorDataBytes.length + clientDataHash.byteLength
        );
        signatureBase.set(authenticatorDataBytes, 0);
        signatureBase.set(new Uint8Array(clientDataHash), authenticatorDataBytes.length);

        const signatureP1363 = await crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: 'SHA-256',
          },
          privateKey,
          signatureBase
        );

        // Convert signature from P1363 format to DER format (WebAuthn requirement)
        const signatureDER = this.convertP1363ToDER(signatureP1363);

        // Update counter in storage
        const index = passkeys.findIndex((p) => p.id === passkey.id);
        if (index >= 0) {
          passkeys[index] = passkey;
          await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
        }

        console.log('PassKey Vault: Signed assertion for', passkey.id);

        // Convert ArrayBuffers to base64 for safe message passing
        // passkey.id is already base64url string, convert to regular base64
        const rawIdBase64 = this.base64urlToBase64(passkey.id);
        const clientDataJSONBase64 = this.arrayBufferToBase64(clientDataJSONBytes.buffer);
        const authenticatorDataBase64 = this.arrayBufferToBase64(authenticatorData);
        const signatureBase64 = this.arrayBufferToBase64(signatureDER);
        // Handle user.id - could be base64url string (new format) or ArrayBuffer (old format)
        const userHandleBase64 = passkey.user?.id
          ? typeof passkey.user.id === 'string'
            ? this.base64urlToBase64(passkey.user.id)
            : this.arrayBufferToBase64(passkey.user.id)
          : null;

        // Return the assertion credential with base64-encoded binary data
        return {
          success: true,
          credential: {
            id: passkey.id,
            rawId: rawIdBase64,
            type: 'public-key',
            response: {
              clientDataJSON: clientDataJSONBase64,
              authenticatorData: authenticatorDataBase64,
              signature: signatureBase64,
              userHandle: userHandleBase64,
            },
            authenticatorAttachment: 'cross-platform',
            clientExtensionResults,
          },
        };
      } catch (cryptoError) {
        // Log full error for debugging
        console.error('PassKey Vault: Crypto operation failed:', cryptoError);
        if (cryptoError instanceof DOMException) {
          console.error('PassKey Vault: DOMException name:', cryptoError.name);
          console.error('PassKey Vault: DOMException message:', cryptoError.message);
        }
        throw cryptoError;
      }
    } catch (error) {
      // Better error handling - get proper error message
      let errorMessage = 'Unknown error';
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (error instanceof DOMException) {
        errorMessage = error.message || error.name || 'DOMException';
      } else if (typeof error === 'string') {
        errorMessage = error;
      }

      console.error('PassKey Vault: Error getting passkey:', error);
      console.error('PassKey Vault: Error details:', {
        message: errorMessage,
        name: error?.name,
        type: error?.constructor?.name,
      });

      return { success: false, error: errorMessage };
    }
  }

  /**
   * Generate a random credential ID
   */
  private generateCredentialId(): Uint8Array {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return array;
  }

  /**
   * Convert ArrayBuffer to Base64URL
   */
  private arrayBufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Convert ArrayBuffer to regular Base64
   */
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary);
  }

  /**
   * Convert base64url string to regular base64 string
   * This avoids unnecessary ArrayBuffer conversion
   */
  private base64urlToBase64(base64url: string): string {
    if (!base64url || typeof base64url !== 'string') {
      console.error('base64urlToBase64: Invalid input type', typeof base64url);
      throw new Error('base64urlToBase64 requires a string input');
    }

    // Convert base64url to regular base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const padding = (4 - (base64.length % 4)) % 4;
    if (padding > 0) {
      base64 += '='.repeat(padding);
    }

    return base64;
  }

  /**
   * Convert Base64URL to ArrayBuffer
   * Handles string (base64url), ArrayBuffer, ArrayBufferView, and Uint8Array inputs
   */
  private base64URLToArrayBuffer(base64url: any): ArrayBuffer {
    // Debug logging with full input
    console.log('base64URLToArrayBuffer called with:', {
      inputType: typeof base64url,
      constructor: base64url?.constructor?.name,
      value:
        typeof base64url === 'string'
          ? base64url.substring(0, 50) + (base64url.length > 50 ? '...' : '')
          : '[non-string]',
      length: typeof base64url === 'string' ? base64url.length : 'N/A',
    });

    // If ArrayBuffer, return it
    if (base64url instanceof ArrayBuffer) {
      console.log('base64URLToArrayBuffer: Returning ArrayBuffer directly');
      return base64url;
    }
    // If Uint8Array, return its buffer
    if (base64url instanceof Uint8Array) {
      console.log('base64URLToArrayBuffer: Returning Uint8Array.buffer');
      return base64url.buffer as ArrayBuffer;
    }
    // Handle any other ArrayBufferView (e.g., DataView, Int8Array)
    if (ArrayBuffer.isView(base64url)) {
      console.log('base64URLToArrayBuffer: Returning ArrayBufferView.buffer');
      return base64url.buffer as ArrayBuffer;
    }
    // Support Node Buffer-like objects from JSON serialization { type: 'Buffer', data: number[] }
    if (base64url?.type === 'Buffer' && Array.isArray(base64url.data)) {
      console.log('base64URLToArrayBuffer: Converting Node-like Buffer');
      return new Uint8Array(base64url.data).buffer;
    }
    if (base64url == null) {
      throw new TypeError('Unsupported base64 input type: null/undefined');
    }
    if (typeof base64url !== 'string') {
      console.log('base64URLToArrayBuffer: Converting non-string to string');
      base64url = String(base64url);
    }
    // Validate string length
    if (base64url.length === 0) {
      throw new Error('Empty base64 string provided');
    }

    // Convert base64url string to ArrayBuffer
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');

    console.log('base64URLToArrayBuffer: Conversion details:', {
      originalLength: base64url.length,
      convertedLength: base64.length,
      paddedLength: padded.length,
      paddedPreview: padded.substring(0, 50) + (padded.length > 50 ? '...' : ''),
    });

    try {
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i) & 0xff;
      }
      console.log(
        'base64URLToArrayBuffer: Success, returning ArrayBuffer of',
        bytes.buffer.byteLength,
        'bytes'
      );
      return bytes.buffer;
    } catch (e) {
      console.error('base64URLToArrayBuffer FAILED:', e);
      console.error('DOMException name:', (e as DOMException)?.name);
      console.error('DOMException message:', (e as DOMException)?.message);
      console.error('Full input string:', base64url);
      console.error('Padded string:', padded);
      console.error('Stack:', (e as Error)?.stack);
      throw e;
    }
  }

  private selectPrfEval(prfInput: any, credentialId?: string): any | null {
    if (!prfInput) {
      return null;
    }
    if (prfInput.eval) {
      return prfInput.eval;
    }
    const map = prfInput.evalByCredential;
    if (!map) {
      return null;
    }

    const candidates = new Set<string>();
    if (credentialId) {
      candidates.add(credentialId);
      try {
        candidates.add(this.base64urlToBase64(credentialId));
      } catch {
        /* ignore */
      }
    }

    for (const key of Object.keys(map)) {
      if (candidates.has(key)) {
        return map[key];
      }
      try {
        const decoded = this.base64URLToArrayBuffer(key);
        const asUrl = this.arrayBufferToBase64URL(decoded);
        if (asUrl && candidates.has(asUrl)) {
          return map[key];
        }
      } catch {
        // ignore malformed keys
      }
    }

    return null;
  }

  private async getOrCreatePrfKey(passkey: any): Promise<ArrayBuffer> {
    if (passkey.prfKey) {
      return this.decodeBase64Flexible(passkey.prfKey);
    }

    const privateKeyBytes = this.base64URLToArrayBuffer(passkey.privateKey);
    const derived = await crypto.subtle.digest('SHA-256', privateKeyBytes);
    passkey.prfKey = this.arrayBufferToBase64URL(derived);
    return derived;
  }

  private normalizePrfInput(input: any): ArrayBuffer | null {
    if (!input) {
      return null;
    }

    // Direct buffers
    if (input instanceof ArrayBuffer) {
      return input;
    }
    if (ArrayBuffer.isView(input)) {
      return input.buffer as ArrayBuffer;
    }
    if (input?.type === 'Buffer' && Array.isArray(input.data)) {
      return new Uint8Array(input.data).buffer;
    }
    if (Array.isArray(input)) {
      return new Uint8Array(input).buffer;
    }

    // Only process strings as base64
    if (typeof input === 'string') {
      try {
        return this.base64URLToArrayBuffer(input);
      } catch (e) {
        try {
          return this.decodeBase64Flexible(input);
        } catch (err) {
          console.warn('PassKey Vault: Failed to normalize PRF input string', err);
          return null;
        }
      }
    }

    // Handle objects with numeric keys (serialized Uint8Array)
    if (typeof input === 'object' && input !== null) {
      const keys = Object.keys(input);
      if (keys.length > 0 && keys.every((k) => !isNaN(Number(k)))) {
        // Object with numeric keys - likely serialized typed array
        const maxIndex = Math.max(...keys.map(Number));
        const arr = new Uint8Array(maxIndex + 1);
        for (const key of keys) {
          arr[Number(key)] = input[key];
        }
        return arr.buffer;
      }
    }

    console.warn(
      'PassKey Vault: Unsupported PRF input type',
      typeof input,
      input?.constructor?.name
    );
    return null;
  }

  private async computePrfResults(prfKey: ArrayBuffer, evalInput: any): Promise<any | null> {
    if (!evalInput) {
      return null;
    }
    const results: any = { results: {} };
    const first = this.normalizePrfInput(evalInput.first);
    const second = this.normalizePrfInput(evalInput.second);

    if (first) {
      results.results.first = await this.hmacSha256(prfKey, first);
    }
    if (second) {
      results.results.second = await this.hmacSha256(prfKey, second);
    }

    if (!results.results.first && !results.results.second) {
      return null;
    }

    return results;
  }

  private async hmacSha256(keyBytes: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return crypto.subtle.sign('HMAC', key, data);
  }

  private buildClientExtensionResults(prfResults: any | null): any {
    const baseResults: any = { credProps: { rk: true } };
    if (!prfResults?.results) {
      return baseResults;
    }

    const encoded: any = { results: {} };
    if (prfResults.results.first) {
      encoded.results.first = this.arrayBufferToBase64URL(prfResults.results.first);
    }
    if (prfResults.results.second) {
      encoded.results.second = this.arrayBufferToBase64URL(prfResults.results.second);
    }

    if (encoded.results.first || encoded.results.second) {
      baseResults.prf = encoded;
    }

    return baseResults;
  }

  private encodePrfExtension(prfResults: any | null): Uint8Array | null {
    if (!prfResults?.results) {
      return null;
    }

    const resultEntries: number[] = [];
    let resultCount = 0;

    if (prfResults.results.first) {
      resultEntries.push(...this.encodeTextString('first'));
      resultEntries.push(...this.encodeByteString(new Uint8Array(prfResults.results.first)));
      resultCount++;
    }

    if (prfResults.results.second) {
      resultEntries.push(...this.encodeTextString('second'));
      resultEntries.push(...this.encodeByteString(new Uint8Array(prfResults.results.second)));
      resultCount++;
    }

    if (resultCount === 0) {
      return null;
    }

    const resultsMap = [...this.encodeMapHeader(resultCount), ...resultEntries];
    const prfMap = [...this.encodeMapHeader(1), ...this.encodeTextString('results'), ...resultsMap];
    const extensions = [...this.encodeMapHeader(1), ...this.encodeTextString('prf'), ...prfMap];

    return new Uint8Array(extensions);
  }

  private encodeMapHeader(length: number): number[] {
    if (length < 24) {
      return [0xa0 + length];
    }
    if (length < 256) {
      return [0xb8, length];
    }
    return [0xb9, (length >> 8) & 0xff, length & 0xff];
  }

  private encodeTextString(value: string): number[] {
    const bytes = new TextEncoder().encode(value);
    const header =
      bytes.length < 24
        ? [0x60 + bytes.length]
        : bytes.length < 256
          ? [0x78, bytes.length]
          : [0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff];
    return [...header, ...bytes];
  }

  private encodeByteString(bytes: Uint8Array): number[] {
    if (bytes.length < 24) {
      return [0x40 + bytes.length, ...bytes];
    }
    if (bytes.length < 256) {
      return [0x58, bytes.length, ...bytes];
    }
    return [0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff, ...bytes];
  }

  private decodeBase64Flexible(value: any): ArrayBuffer {
    if (value instanceof ArrayBuffer) {
      return value;
    }
    if (ArrayBuffer.isView(value)) {
      return value.buffer as ArrayBuffer;
    }
    if (value?.type === 'Buffer' && Array.isArray(value.data)) {
      return new Uint8Array(value.data).buffer;
    }

    if (typeof value !== 'string') {
      throw new TypeError('Invalid base64 input type');
    }

    // Try base64url first
    try {
      return this.base64URLToArrayBuffer(value);
    } catch {
      // fall through
    }

    // Try standard base64
    const padded =
      value.length % 4 === 0 ? value : value + '='.repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i) & 0xff;
    }
    return bytes.buffer;
  }

  /**
   * Create authenticator data with proper format
   * Structure: rpIdHash (32) + flags (1) + counter (4) + [attestedCredentialData]
   * attestedCredentialData: aaguid (16) + credIdLen (2) + credentialId + cosePublicKey
   */
  private async createAuthenticatorDataAsync(
    rpId: string,
    credentialId: Uint8Array | null,
    publicKeyRaw: ArrayBuffer | null,
    includeAttestedCredentialData: boolean,
    counter: number = 0,
    extensionsData?: Uint8Array | null
  ): Promise<ArrayBuffer> {
    // RP ID hash (SHA-256)
    const rpIdBytes = new TextEncoder().encode(rpId);
    const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdBytes));

    // Flags: UP (0x01) + UV (0x04) + AT (0x40) + ED (0x80 when extensions present)
    let flagsByte = includeAttestedCredentialData ? 0x45 : 0x05;
    if (extensionsData && extensionsData.length > 0) {
      flagsByte |= 0x80;
    }
    const flags = new Uint8Array([flagsByte]);

    // Counter (4 bytes, big-endian)
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);

    if (includeAttestedCredentialData && credentialId && publicKeyRaw) {
      // AAGUID - 16 bytes of zeros for software authenticator
      const aaguid = new Uint8Array(16);

      // Credential ID length (2 bytes, big-endian)
      const credentialIdLength = new Uint8Array(2);
      new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length, false);

      // Convert raw public key to COSE format
      const cosePublicKey = this.rawPublicKeyToCose(publicKeyRaw);

      // Combine all parts
      const authData = new Uint8Array(
        rpIdHash.length +
          flags.length +
          counterBytes.length +
          aaguid.length +
          credentialIdLength.length +
          credentialId.length +
          cosePublicKey.length +
          (extensionsData?.length || 0)
      );

      let offset = 0;
      authData.set(rpIdHash, offset);
      offset += rpIdHash.length;
      authData.set(flags, offset);
      offset += flags.length;
      authData.set(counterBytes, offset);
      offset += counterBytes.length;
      authData.set(aaguid, offset);
      offset += aaguid.length;
      authData.set(credentialIdLength, offset);
      offset += credentialIdLength.length;
      authData.set(credentialId, offset);
      offset += credentialId.length;
      authData.set(cosePublicKey, offset);
      offset += cosePublicKey.length;
      if (extensionsData && extensionsData.length > 0) {
        authData.set(extensionsData, offset);
      }

      return authData.buffer;
    } else {
      // No attested credential data (for authentication)
      const authData = new Uint8Array(
        rpIdHash.length + flags.length + counterBytes.length + (extensionsData?.length || 0)
      );
      let offset = 0;
      authData.set(rpIdHash, offset);
      offset += rpIdHash.length;
      authData.set(flags, offset);
      offset += flags.length;
      authData.set(counterBytes, offset);
      offset += counterBytes.length;
      if (extensionsData && extensionsData.length > 0) {
        authData.set(extensionsData, offset);
      }

      return authData.buffer;
    }
  }

  /**
   * Convert raw EC P-256 public key to COSE Key format
   * Raw key is 65 bytes: 0x04 + x (32 bytes) + y (32 bytes)
   */
  private rawPublicKeyToCose(rawKey: ArrayBuffer): Uint8Array {
    const raw = new Uint8Array(rawKey);

    // Extract x and y coordinates (skip the 0x04 prefix)
    const x = raw.slice(1, 33);
    const y = raw.slice(33, 65);

    // Build COSE Key structure for EC2 P-256
    // Map with 5 entries:
    // 1 (kty): 2 (EC2)
    // 3 (alg): -7 (ES256)
    // -1 (crv): 1 (P-256)
    // -2 (x): bytes
    // -3 (y): bytes

    const coseKey: number[] = [];

    // Map of 5 items
    coseKey.push(0xa5);

    // Key 1 (kty): Value 2 (EC2)
    coseKey.push(0x01, 0x02);

    // Key 3 (alg): Value -7 (ES256) - negative int: -1-n, so -7 = 0x26
    coseKey.push(0x03, 0x26);

    // Key -1 (crv): Value 1 (P-256) - negative int -1 = 0x20
    coseKey.push(0x20, 0x01);

    // Key -2 (x): bytes(32)
    coseKey.push(0x21, 0x58, 0x20);
    for (let i = 0; i < x.length; i++) {
      coseKey.push(x[i]);
    }

    // Key -3 (y): bytes(32)
    coseKey.push(0x22, 0x58, 0x20);
    for (let i = 0; i < y.length; i++) {
      coseKey.push(y[i]);
    }

    return new Uint8Array(coseKey);
  }

  /**
   * Convert ECDSA signature from IEEE P1363 format to ASN.1 DER format
   * P1363 format: r (32 bytes) || s (32 bytes) = 64 bytes total
   * DER format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
   *
   * WebAuthn requires DER format, but Web Crypto API produces P1363 format
   */
  private convertP1363ToDER(p1363Sig: ArrayBuffer): ArrayBuffer {
    const sig = new Uint8Array(p1363Sig);

    // P1363 format is r || s, each 32 bytes for P-256
    const r = sig.slice(0, 32);
    const s = sig.slice(32, 64);

    // Encode r and s as DER integers
    const rDer = this.encodeDERInteger(r);
    const sDer = this.encodeDERInteger(s);

    // Total length of the SEQUENCE content
    const sequenceLength = rDer.length + sDer.length;

    // Build the final DER structure
    // SEQUENCE tag (0x30) + length + r + s
    let result;
    if (sequenceLength <= 127) {
      result = new Uint8Array(2 + sequenceLength);
      result[0] = 0x30; // SEQUENCE tag
      result[1] = sequenceLength;
      result.set(rDer, 2);
      result.set(sDer, 2 + rDer.length);
    } else {
      // For lengths > 127, use long form (0x81 + 1-byte length)
      result = new Uint8Array(3 + sequenceLength);
      result[0] = 0x30; // SEQUENCE tag
      result[1] = 0x81; // Long form, 1 byte length follows
      result[2] = sequenceLength;
      result.set(rDer, 3);
      result.set(sDer, 3 + rDer.length);
    }

    return result.buffer;
  }

  /**
   * Encode a byte array as a DER INTEGER
   * DER integers must be positive, so prepend 0x00 if high bit is set
   */
  private encodeDERInteger(bytes: Uint8Array): Uint8Array {
    // Remove leading zeros (but keep at least one byte)
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
      start++;
    }
    const trimmed = bytes.slice(start);

    // If high bit is set, prepend 0x00 to indicate positive number
    const needsPadding = (trimmed[0] & 0x80) !== 0;
    const length = trimmed.length + (needsPadding ? 1 : 0);

    const result = new Uint8Array(2 + length); // 0x02 + length byte + data
    result[0] = 0x02; // INTEGER tag
    result[1] = length;
    if (needsPadding) {
      result[2] = 0x00;
      result.set(trimmed, 3);
    } else {
      result.set(trimmed, 2);
    }
    return result;
  }

  /**
   * Create attestation object with proper CBOR encoding (using "none" format)
   * Structure: { "fmt": "none", "attStmt": {}, "authData": bytes }
   */
  private createAttestationObjectNone(authenticatorData: ArrayBuffer): ArrayBuffer {
    const authDataBytes = new Uint8Array(authenticatorData);

    // Build CBOR manually for attestation object
    // Map with 3 entries
    const parts: number[] = [];

    // Map(3)
    parts.push(0xa3);

    // Key "fmt" (text string of length 3)
    parts.push(0x63); // text(3)
    parts.push(0x66, 0x6d, 0x74); // "fmt"

    // Value "none" (text string of length 4)
    parts.push(0x64); // text(4)
    parts.push(0x6e, 0x6f, 0x6e, 0x65); // "none"

    // Key "attStmt" (text string of length 7)
    parts.push(0x67); // text(7)
    parts.push(0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74); // "attStmt"

    // Value {} (empty map)
    parts.push(0xa0); // map(0)

    // Key "authData" (text string of length 8)
    parts.push(0x68); // text(8)
    parts.push(0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61); // "authData"

    // Value: byte string with authData
    // For lengths > 23, use 0x58 (1-byte length) or 0x59 (2-byte length)
    if (authDataBytes.length <= 23) {
      parts.push(0x40 + authDataBytes.length);
    } else if (authDataBytes.length <= 255) {
      parts.push(0x58, authDataBytes.length);
    } else {
      parts.push(0x59, (authDataBytes.length >> 8) & 0xff, authDataBytes.length & 0xff);
    }

    // Combine parts with authData
    const result = new Uint8Array(parts.length + authDataBytes.length);
    result.set(parts, 0);
    result.set(authDataBytes, parts.length);

    return result.buffer;
  }

  /**
   * Store a passkey after successful creation
   */
  private async handleStorePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey, origin, options } = payload;

      // Get existing passkeys
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      // Extract rpId from options or derive from origin
      const rpId = options?.publicKey?.rpId || new URL(origin).hostname;

      // The credential object from native WebAuthn has 'id' as the credential ID
      const credentialId = publicKey?.id || publicKey?.rawId;

      if (credentialId) {
        const existingIndex = passkeys.findIndex((p) => p.credentialId === credentialId);
        const passkeyData = {
          credentialId,
          id: publicKey.id,
          rawId: publicKey.rawId,
          type: publicKey.type,
          response: publicKey.response,
          rpId,
          origin,
          createdAt: Date.now(),
        };

        if (existingIndex >= 0) {
          // Update existing passkey
          passkeys[existingIndex] = passkeyData;
        } else {
          // Add new passkey
          passkeys.push(passkeyData);
        }

        // Save to storage
        await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });

        console.log('PassKey Vault: Stored passkey', credentialId, 'for', rpId);
        return { success: true, message: 'Passkey stored successfully', count: passkeys.length };
      }

      return { success: false, error: 'No credential ID in payload' };
    } catch (error) {
      console.error('PassKey Vault: Error storing passkey:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Retrieve passkeys for authentication
   */
  private async handleRetrievePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey, origin } = payload;
      const rpId = publicKey?.rpId || (origin ? new URL(origin).hostname : null);

      if (!rpId) {
        return { success: false, error: 'No rpId provided' };
      }

      // Get stored passkeys
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      // Filter passkeys for this RP ID
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      console.log('PassKey Vault: Found', matchingPasskeys.length, 'passkeys for', rpId);

      return {
        success: true,
        passkeys: matchingPasskeys,
        count: matchingPasskeys.length,
        rpId,
      };
    } catch (error) {
      console.error('PassKey Vault: Error retrieving passkey:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * List all stored passkeys
   */
  private async handleListPasskeys(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      return {
        success: true,
        passkeys: passkeys.map((p) => ({
          rpId: p.rpId,
          origin: p.origin,
          createdAt: p.createdAt,
          credentialId: p.credentialId?.substring(0, 20) + '...',
        })),
        count: passkeys.length,
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * List passkeys for a specific RP (relying party)
   */
  private async handleListPasskeysForRp(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { rpId } = payload;

      if (!rpId) {
        return { success: false, error: 'No rpId provided' };
      }

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      // Filter passkeys for this RP ID
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      console.log('PassKey Vault: Found', matchingPasskeys.length, 'passkeys for', rpId);

      return {
        success: true,
        passkeys: matchingPasskeys.map((p) => ({
          id: p.id,
          credentialId: p.credentialId || p.id,
          rpId: p.rpId,
          origin: p.origin,
          user: p.user,
          createdAt: p.createdAt,
        })),
        count: matchingPasskeys.length,
        rpId,
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Delete a passkey
   */
  private async handleDeletePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { credentialId } = payload;

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      const filtered = passkeys.filter((p) => p.credentialId !== credentialId);

      if (filtered.length < passkeys.length) {
        await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: filtered });
        return { success: true, message: 'Passkey deleted' };
      }

      return { success: false, error: 'Passkey not found' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  private async handleBackup(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Backup placeholder' };
  }

  private async handleRestore(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Restore placeholder' };
  }

  private async handleActivateUI(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Activate UI placeholder' };
  }
}

// Initialize the background service
const backgroundService = new BackgroundService();
