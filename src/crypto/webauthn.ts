/**
 * WebAuthn Crypto Utilities
 *
 * Handles generation of passkeys and creation of WebAuthn responses
 * without using the native browser API.
 */

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
  void user;

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
  const attestationObject = createAttestationObject(credentialId, coseKey);

  return {
    attestationObject,
    clientDataJSON: clientDataJSON.buffer,
  };
}

// Create a simplified COSE key from SPKI
function createCOSEKey(spki: ArrayBuffer): Uint8Array {
  // COSE Key map format: CBOR encoded
  // For ES256: kty=2 (EC), alg=-7 (ES256), crv=1 (P-256), x=public key x, y=public key y
  // This is a placeholder - proper implementation needs CBOR encoding
  return new Uint8Array(spki);
}

// Create attestation object in CBOR format
function createAttestationObject(credentialId: Uint8Array, coseKey: Uint8Array): ArrayBuffer {
  // For "none" attestation, we create a simple structure
  // Format: { fmt: "none", authData: <authenticator data>, attStmt: {} }

  // Authenticator data structure:
  // - RP ID hash (32 bytes)
  // - Flags (1 byte) - bit 6 set for attested credential data
  // - Counter (4 bytes)
  // - Attested credential data (variable)
  //   - Credential ID length (2 bytes)
  //   - Credential ID (16 bytes)
  //   - Credential public key (COSE format)

  const rpIdHash = new Uint8Array(32);
  const flags = new Uint8Array([0x41]);
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, 0, false);

  // Calculate authData length
  const credentialIdLengthBytes = new Uint8Array(2);
  new DataView(credentialIdLengthBytes.buffer).setUint16(0, credentialId.length, false);

  const authDataLength =
    rpIdHash.length +
    flags.length +
    counterBytes.length +
    credentialIdLengthBytes.length +
    credentialId.length +
    coseKey.length;
  const authData = new Uint8Array(authDataLength);

  let offset = 0;
  authData.set(rpIdHash, offset);
  offset += rpIdHash.length;
  authData.set(flags, offset);
  offset += flags.length;
  authData.set(counterBytes, offset);
  offset += counterBytes.length;
  authData.set(credentialIdLengthBytes, offset);
  offset += credentialIdLengthBytes.length;
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
