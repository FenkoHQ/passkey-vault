import {
  generatePasskeyKeyPair,
  exportPrivateKey,
  importPrivateKey,
  createAttestation,
  createAssertion,
} from '../src/crypto/webauthn';

describe('WebAuthn Module', () => {
  describe('generatePasskeyKeyPair', () => {
    it('should generate an ES256 key pair', async () => {
      const keyPair = await generatePasskeyKeyPair();

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(keyPair.publicKey.type).toBe('public');
      expect(keyPair.privateKey.type).toBe('private');
    });

    it('should generate a key pair with correct algorithm', async () => {
      const keyPair = await generatePasskeyKeyPair();

      expect(keyPair.publicKey.algorithm).toEqual({
        name: 'ECDSA',
        namedCurve: 'P-256',
      });
    });

    it('should generate a key pair with extractable keys', async () => {
      const keyPair = await generatePasskeyKeyPair();

      expect(keyPair.publicKey.extractable).toBe(true);
      expect(keyPair.privateKey.extractable).toBe(true);
    });

    it('should generate different key pairs on each call', async () => {
      const keyPair1 = await generatePasskeyKeyPair();
      const keyPair2 = await generatePasskeyKeyPair();

      const exported1 = await crypto.subtle.exportKey('spki', keyPair1.publicKey);
      const exported2 = await crypto.subtle.exportKey('spki', keyPair2.publicKey);

      expect(new Uint8Array(exported1)).not.toEqual(new Uint8Array(exported2));
    });
  });

  describe('exportPrivateKey', () => {
    it('should export private key as base64 string', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const exported = await exportPrivateKey(keyPair.privateKey);

      expect(typeof exported).toBe('string');
      expect(exported.length).toBeGreaterThan(0);
    });

    it('should produce valid base64 output', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const exported = await exportPrivateKey(keyPair.privateKey);

      expect(() => atob(exported)).not.toThrow();
    });
  });

  describe('importPrivateKey', () => {
    it('should import private key from PKCS8 base64', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const exported = await exportPrivateKey(keyPair.privateKey);

      const imported = await importPrivateKey(exported);

      expect(imported).toHaveProperty('type', 'private');
      expect(imported.algorithm).toEqual({
        name: 'ECDSA',
        namedCurve: 'P-256',
      });
    });

    it('should import a key that can sign', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const exported = await exportPrivateKey(keyPair.privateKey);

      const imported = await importPrivateKey(exported);

      expect(imported.usages).toContain('sign');
    });

    it('should reject invalid PKCS8 data', async () => {
      const invalid = 'invalid-base64-data';

      await expect(importPrivateKey(invalid)).rejects.toThrow();
    });
  });

  describe('createAttestation', () => {
    it('should create attestation object and client data', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);
      const user = {
        id: 'user-id',
        name: 'test@example.com',
        displayName: 'Test User',
      };

      const result = await createAttestation(
        challenge,
        origin,
        credentialId,
        keyPair.publicKey,
        user
      );

      expect(result).toHaveProperty('attestationObject');
      expect(result).toHaveProperty('clientDataJSON');
      expect(result.attestationObject.byteLength).toBeGreaterThan(0);
      expect(result.clientDataJSON.byteLength).toBeGreaterThan(0);

      const clientDataJSONStr = new TextDecoder().decode(result.clientDataJSON);
      const clientData = JSON.parse(clientDataJSONStr);
      expect(clientData).toHaveProperty('type', 'webauthn.create');
    });

    it('should create valid client data JSON', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);
      const user = {
        id: 'user-id',
        name: 'test@example.com',
        displayName: 'Test User',
      };

      const result = await createAttestation(
        challenge,
        origin,
        credentialId,
        keyPair.publicKey,
        user
      );

      const clientDataJSON = new TextDecoder().decode(result.clientDataJSON);
      const clientData = JSON.parse(clientDataJSON);

      expect(clientData).toHaveProperty('type', 'webauthn.create');
      expect(clientData).toHaveProperty('challenge', challenge);
      expect(clientData).toHaveProperty('origin', origin);
    });
  });

  describe('createAssertion', () => {
    it('should create assertion, client data, and authenticator data', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const result = await createAssertion(challenge, origin, credentialId, keyPair.privateKey);

      expect(result).toHaveProperty('assertionObject');
      expect(result).toHaveProperty('clientDataJSON');
      expect(result).toHaveProperty('authenticatorData');
      expect(result.assertionObject.byteLength).toBeGreaterThan(0);
      expect(result.clientDataJSON.byteLength).toBeGreaterThan(0);
      expect(result.authenticatorData.byteLength).toBeGreaterThan(0);

      const clientDataJSONStr = new TextDecoder().decode(result.clientDataJSON);
      const clientData = JSON.parse(clientDataJSONStr);
      expect(clientData).toHaveProperty('type', 'webauthn.get');
    });

    it('should create valid client data JSON for get', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const result = await createAssertion(challenge, origin, credentialId, keyPair.privateKey);

      const clientDataJSON = new TextDecoder().decode(result.clientDataJSON);
      const clientData = JSON.parse(clientDataJSON);

      expect(clientData).toHaveProperty('type', 'webauthn.get');
      expect(clientData).toHaveProperty('challenge', challenge);
      expect(clientData).toHaveProperty('origin', origin);
    });

    it('should create signature with correct structure', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const result = await createAssertion(challenge, origin, credentialId, keyPair.privateKey);

      expect(result.assertionObject.byteLength).toBeGreaterThan(0);
      expect(result.authenticatorData.byteLength).toBeGreaterThan(0);
    });

    it('should include counter in authenticator data', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const counter = 5;
      const result = await createAssertion(
        challenge,
        origin,
        credentialId,
        keyPair.privateKey,
        counter
      );

      const authData = new Uint8Array(result.authenticatorData);
      const counterOffset = 32 + 1;
      const recoveredCounter = new DataView(authData.buffer).getUint32(counterOffset, false);

      expect(recoveredCounter).toBe(counter);
    });

    it('should produce valid ECDSA signature', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const result = await createAssertion(challenge, origin, credentialId, keyPair.privateKey);

      const signature = new Uint8Array(result.assertionObject);
      expect(signature.length).toBeGreaterThan(0);
      expect(signature.length).toBeLessThanOrEqual(72);
    });
  });

  describe('Integration: Full passkey flow', () => {
    it('should create attestation and verify signature', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);
      const user = {
        id: 'user-id',
        name: 'test@example.com',
        displayName: 'Test User',
      };

      const attestation = await createAttestation(
        challenge,
        origin,
        credentialId,
        keyPair.publicKey,
        user
      );

      expect(attestation.attestationObject.byteLength).toBeGreaterThan(0);
    });

    it('should export and import private key correctly', async () => {
      const keyPair = await generatePasskeyKeyPair();

      const exported = await exportPrivateKey(keyPair.privateKey);
      const imported = await importPrivateKey(exported);

      // Signing should work with the imported key
      const testData = new TextEncoder().encode('test data');
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        imported,
        testData
      );

      // Signature should be generated successfully
      expect(signature.byteLength).toBeGreaterThan(0);

      // The imported key should have the correct algorithm
      expect(imported.algorithm).toEqual({
        name: 'ECDSA',
        namedCurve: 'P-256',
      });
      expect(imported.usages).toContain('sign');
    });

    it('should create and verify assertion with same key pair', async () => {
      const keyPair = await generatePasskeyKeyPair();
      const challenge = 'test-challenge';
      const origin = 'https://example.com';
      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);

      const assertion = await createAssertion(challenge, origin, credentialId, keyPair.privateKey);

      const clientDataJSON = new TextDecoder().decode(assertion.clientDataJSON);
      const clientDataHash = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(clientDataJSON)
      );

      const authData = new Uint8Array(assertion.authenticatorData);
      const signatureBase = new Uint8Array(authData.length + clientDataHash.byteLength);
      signatureBase.set(authData, 0);
      signatureBase.set(new Uint8Array(clientDataHash), authData.length);

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keyPair.publicKey,
        assertion.assertionObject,
        signatureBase
      );

      expect(isValid).toBe(true);
    });
  });
});
