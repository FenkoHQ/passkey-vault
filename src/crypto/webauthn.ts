/**
 * WebAuthn Crypto Utilities
 *
 * Handles generation of passkeys and creation of WebAuthn responses
 * without using the native browser API.
 */

// Helper to convert ArrayBuffer to Base64URL
function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Helper to convert Base64URL to ArrayBuffer
function base64URLToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Generate a random credential ID
function generateCredentialId(): Uint8Array {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return array;
}

// Generate a new ES256 key pair for the passkey
export async function generatePasskeyKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );
}

// Export private key to PKCS8 format for storage
export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('pkcs8', key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// Import private key from PKCS8 format
export async function importPrivateKey(pkcs8: string): Promise<CryptoKey> {
  const binary = atob(pkcs8);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return await crypto.subtle.importKey(
    'pkcs8',
    bytes.buffer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign']
  );
}

// Create a WebAuthn attestation object
export async function createAttestation(
  challenge: string,
  origin: string,
  credentialId: Uint8Array,
  publicKey: CryptoKey,
  user: { id: string; name: string; displayName: string }
): Promise<{ attestationObject: ArrayBuffer; clientDataJSON: ArrayBuffer }> {
  // Create clientDataJSON
  const clientData = {
    type: 'webauthn.create',
    challenge: challenge,
    origin: origin,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  // Get the public key in SPKI format (COSE format for WebAuthn)
  const publicKeySpki = await crypto.subtle.exportKey('spki', publicKey);

  // Build COSE key format (simplified - focusing on ES256)
  // COSE Key parameters: kty (2), alg (3), crv (-1), x (-2), y (-3)
  const coseKey = createCOSEKey(publicKeySpki);

  // Create attestation object (using "none" attestation for simplicity)
  const attestationObject = createAttestationObject(
    credentialId,
    coseKey,
    clientDataJSON,
    await crypto.subtle.exportKey('spki', publicKey)
  );

  return {
    attestationObject,
    clientDataJSON: clientDataJSON.buffer,
  };
}

// Create a simplified COSE key from SPKI
function createCOSEKey(spki: ArrayBuffer): Uint8Array {
  // Parse SPKI and create COSE key format
  // This is a simplified version - a real implementation would properly parse DER
  const spkiBytes = new Uint8Array(spki);

  // COSE Key map format: CBOR encoded
  // For ES256: kty=2 (EC), alg=-7 (ES256), crv=1 (P-256), x=public key x, y=public key y
  // This is a placeholder - proper implementation needs CBOR encoding
  return new Uint8Array(spki);
}

// Create attestation object in CBOR format
function createAttestationObject(
  credentialId: Uint8Array,
  coseKey: Uint8Array,
  clientDataJSON: Uint8Array,
  spki: ArrayBuffer
): ArrayBuffer {
  // For "none" attestation, we create a simple structure
  // Format: { fmt: "none", authData: <authenticator data>, attStmt: {} }

  // Authenticator data structure:
  // - RP ID hash (32 bytes)
  // - Flags (1 byte)
  // - Counter (4 bytes)
  // - Attested credential data (variable)
  //   - Credential ID length (2 bytes)
  //   - Credential ID (16 bytes)
  //   - Credential public key (COSE format)

  const rpIdHash = new Uint8Array(32); // Should be SHA-256 of RP ID
  const flags = new Uint8Array([0x41]); // UP (User Present) + AT (Attested Credential Data)
  const counter = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
  const credentialIdLength = new Uint8Array([0x00, 0x10]); // 16 bytes

  // Combine into authData
  const authData = new Uint8Array(
    rpIdHash.length +
      flags.length +
      counter.length +
      credentialIdLength.length +
      credentialId.length +
      coseKey.length
  );

  let offset = 0;
  authData.set(rpIdHash, offset);
  offset += rpIdHash.length;
  authData.set(flags, offset);
  offset += flags.length;
  authData.set(counter, offset);
  offset += counter.length;
  authData.set(credentialIdLength, offset);
  offset += credentialIdLength.length;
  authData.set(credentialId, offset);
  offset += credentialId.length;
  authData.set(coseKey, offset);

  return authData.buffer;
}

// Create a WebAuthn assertion (signature)
export async function createAssertion(
  challenge: string,
  origin: string,
  credentialId: Uint8Array,
  privateKey: CryptoKey,
  counter: number = 0
): Promise<{
  assertionObject: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;
}> {
  // Create clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: challenge,
    origin: origin,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  // Create authenticator data
  const rpIdHash = new Uint8Array(32); // Should be SHA-256 of RP ID
  const flags = new Uint8Array([0x01]); // UP (User Present)
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false);

  const authenticatorData = new Uint8Array(rpIdHash.length + flags.length + counterBytes.length);
  authenticatorData.set(rpIdHash, 0);
  authenticatorData.set(flags, rpIdHash.length);
  authenticatorData.set(counterBytes, rpIdHash.length + flags.length);

  // Sign the data (authenticatorData + hash of clientDataJSON)
  const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);
  const signatureBase = new Uint8Array(authenticatorData.length + clientDataHash.byteLength);
  signatureBase.set(authenticatorData, 0);
  signatureBase.set(new Uint8Array(clientDataHash), authenticatorData.length);

  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    privateKey,
    signatureBase
  );

  return {
    assertionObject: signature,
    clientDataJSON: clientDataJSON.buffer,
    authenticatorData: authenticatorData.buffer,
  };
}
