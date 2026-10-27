/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * The strict verifier is the oracle every conformance test leans on, so it
 * is tested itself, both ways:
 *
 *   - it accepts the WebAuthn Level 3 test vectors (§16), which come from an
 *     independent implementation of the spec;
 *   - it rejects every single-field corruption of a credential the vault
 *     really produced. A check that let any of these through would make the
 *     green conformance suite mean less than it says.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, register } from '../helpers/ceremony';
import { decodeCbor } from '../helpers/cbor-strict';
import { concat, fromHex, sha256 } from '../helpers/bytes';
import {
  partsOf,
  syntheticCredential,
  type CredentialParts,
} from '../helpers/synthetic-credential';
import {
  ConformanceError,
  limitedVerifyClientData,
  verifyAuthentication,
  verifyRegistration,
  type CredentialRecord,
} from '../helpers/rp-verifier';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

/** §16.2 ES256 Credential with No Attestation. */
const NONE_ES256 = {
  credentialId: 'f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4',
  registration: {
    challenge: '00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130',
    clientDataJSON:
      '7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d',
    attestationObject:
      'a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220',
  },
  authentication: {
    challenge: '39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408',
    authenticatorData: 'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000',
    clientDataJSON:
      '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d',
    signature:
      '3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87',
  },
};

async function spkiOf(attestationObject: Uint8Array): Promise<Uint8Array> {
  const authData = (decodeCbor(attestationObject).value as Map<string, Uint8Array>).get(
    'authData'
  )!;
  const idLength = (authData[53] << 8) | authData[54];
  const cose = decodeCbor(authData.subarray(55 + idLength)).value as Map<number, Uint8Array>;
  const key = await crypto.subtle.importKey(
    'raw',
    concat(new Uint8Array([4]), cose.get(-2)!, cose.get(-3)!) as unknown as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  return new Uint8Array(await crypto.subtle.exportKey('spki', key));
}

describe('the verifier accepts the WebAuthn Level 3 test vectors', () => {
  it('§16.2: an ES256 "none" registration and its assertion', async () => {
    const attestationObject = fromHex(NONE_ES256.registration.attestationObject);
    const authData = (decodeCbor(attestationObject).value as Map<string, Uint8Array>).get(
      'authData'
    )!;
    const rawId = fromHex(NONE_ES256.credentialId);
    const registration = syntheticCredential({
      rawId,
      clientDataJSON: fromHex(NONE_ES256.registration.clientDataJSON),
      attestationObject,
      authenticatorData: authData,
      publicKey: await spkiOf(attestationObject),
      publicKeyAlgorithm: -7,
    });

    expect(Array.from(authData.slice(0, 32))).toEqual(Array.from(await sha256('example.org')));
    const record = await verifyRegistration(registration, {
      challenge: fromHex(NONE_ES256.registration.challenge),
      origin: 'https://example.org',
      rpId: 'example.org',
      userId: new Uint8Array([1]),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    });

    const assertion = syntheticCredential({
      rawId,
      clientDataJSON: fromHex(NONE_ES256.authentication.clientDataJSON),
      authenticatorData: fromHex(NONE_ES256.authentication.authenticatorData),
      signature: fromHex(NONE_ES256.authentication.signature),
    });
    await verifyAuthentication(assertion, {
      challenge: fromHex(NONE_ES256.authentication.challenge),
      origin: 'https://example.org',
      rpId: 'example.org',
      record,
      allowCredentials: [rawId],
    });
  });

  it('§16.4 and §16.5: crossOrigin and topOrigin client data', () => {
    const crossOrigin = fromHex(
      '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d713464746d6a36656667227d'
    );
    const topOrigin = fromHex(
      '7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d'
    );

    expect(JSON.parse(new TextDecoder().decode(crossOrigin)).crossOrigin).toBe(true);
    expect(
      limitedVerifyClientData(topOrigin, {
        type: 'webauthn.create',
        challenge: fromHex('4e1f4c6198699e33c14f192153f49d7e0e8e3577d5ac416c5f3adc92a41f27e5'),
        origin: 'https://example.org',
        topOrigin: 'https://example.com',
      })
    ).toBe(true);
    expect(
      limitedVerifyClientData(topOrigin, {
        type: 'webauthn.create',
        challenge: fromHex('4e1f4c6198699e33c14f192153f49d7e0e8e3577d5ac416c5f3adc92a41f27e5'),
        origin: 'https://example.org',
      })
    ).toBe(false);
  });
});

type Mutation = [string, (parts: CredentialParts, record: CredentialRecord) => void];

const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const bytes = (value: string) => new TextEncoder().encode(value);
const editJSON = (parts: CredentialParts, edit: (json: string) => string) => {
  parts.clientDataJSON = bytes(edit(text(parts.clientDataJSON)));
};
const flip = (array: Uint8Array, index: number, mask = 0x01) => {
  const copy = array.slice();
  copy[index < 0 ? copy.length + index : index] ^= mask;
  return copy;
};
/** Rewrite authData both inside the attestation object and as returned by getAuthenticatorData(). */
const editAuthData = (parts: CredentialParts, edit: (authData: Uint8Array) => Uint8Array) => {
  const authData = edit(parts.authenticatorData!);
  parts.authenticatorData = authData;
  // {"fmt": "none", "attStmt": {}, "authData": h'...'} in canonical CBOR.
  const prefix = [
    0xa3,
    0x63,
    ...bytes('fmt'),
    0x64,
    ...bytes('none'),
    0x67,
    ...bytes('attStmt'),
    0xa0,
    0x68,
    ...bytes('authData'),
  ];
  const length =
    authData.length < 256
      ? [0x58, authData.length]
      : [0x59, authData.length >> 8, authData.length & 0xff];
  parts.attestationObject = new Uint8Array([...prefix, ...length, ...authData]);
};

const registrationMutations: Mutation[] = [
  ['clientData type', (p) => editJSON(p, (j) => j.replace('webauthn.create', 'webauthn.get'))],
  [
    'clientData challenge',
    (p) => editJSON(p, (j) => j.replace(/"challenge":"./, '"challenge":"Z')),
  ],
  [
    'clientData origin',
    (p) => editJSON(p, (j) => j.replace('https://example.com', 'https://evil.com')),
  ],
  [
    'clientData without crossOrigin',
    (p) => editJSON(p, (j) => j.replace(',"crossOrigin":false', '')),
  ],
  [
    'clientData crossOrigin true',
    (p) => editJSON(p, (j) => j.replace('"crossOrigin":false', '"crossOrigin":true')),
  ],
  [
    'clientData reordered',
    (p) =>
      editJSON(p, (j) =>
        JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(j)).reverse()))
      ),
  ],
  [
    'clientData with a byte order mark',
    (p) => (p.clientDataJSON = concat(new Uint8Array([0xef, 0xbb, 0xbf]), p.clientDataJSON)),
  ],
  [
    'attestation fmt',
    (p) => (p.attestationObject = bytes(text(p.attestationObject!).replace('none', 'nonf'))),
  ],
  [
    'attestation trailing byte',
    (p) => (p.attestationObject = concat(p.attestationObject!, new Uint8Array([0]))),
  ],
  ['rpIdHash', (p) => editAuthData(p, (a) => flip(a, 0))],
  ['UP clear', (p) => editAuthData(p, (a) => flip(a, 32, 0x01))],
  ['RFU bit set', (p) => editAuthData(p, (a) => flip(a, 32, 0x02))],
  [
    'BS without BE',
    (p) =>
      editAuthData(p, (a) => {
        const c = a.slice();
        c[32] = (c[32] & ~0x08) | 0x10;
        return c;
      }),
  ],
  ['AT clear', (p) => editAuthData(p, (a) => flip(a, 32, 0x40))],
  ['credential ID differs from rawId', (p) => editAuthData(p, (a) => flip(a, 55))],
  [
    'COSE alg not offered',
    (p) =>
      editAuthData(p, (a) => {
        const c = a.slice();
        const i = c.indexOf(0x26, 55 + 16);
        c[i] = 0x24;
        return c;
      }),
  ],
  ['COSE x off the curve', (p) => editAuthData(p, (a) => flip(a, a.length - 40))],
  ['authData trailing byte', (p) => editAuthData(p, (a) => concat(a, new Uint8Array([0])))],
  ['getAuthenticatorData disagrees', (p) => (p.authenticatorData = flip(p.authenticatorData!, 1))],
  ['getPublicKeyAlgorithm disagrees', (p) => (p.publicKeyAlgorithm = -257)],
  ['getPublicKey is another key', (p) => (p.publicKey = flip(p.publicKey!, -1))],
  ['transports unsorted', (p) => (p.transports = ['usb', 'internal'])],
  ['id not the base64url of rawId', (p) => (p.id = 'not-the-raw-id')],
];

const assertionMutations: Mutation[] = [
  ['clientData type', (p) => editJSON(p, (j) => j.replace('webauthn.get', 'webauthn.create'))],
  [
    'clientData origin',
    (p) => editJSON(p, (j) => j.replace('https://example.com', 'https://example.co')),
  ],
  ['signature bit flip', (p) => (p.signature = flip(p.signature!, -1))],
  [
    'signature with a trailing byte',
    (p) => (p.signature = concat(p.signature!, new Uint8Array([0]))),
  ],
  [
    'signature with a non-minimal INTEGER',
    (p) => {
      const s = p.signature!;
      const rLength = s[3];
      p.signature = new Uint8Array([0x30, s[1] + 1, 0x02, rLength + 1, 0x00, ...s.subarray(4)]);
    },
  ],
  ['signature over other data', (p) => editJSON(p, (j) => j.replace('}', ',"extra":1}'))],
  ['rpIdHash', (p) => (p.authenticatorData = flip(p.authenticatorData!, 5))],
  ['UP clear', (p) => (p.authenticatorData = flip(p.authenticatorData!, 32, 0x01))],
  ['AT set', (p) => (p.authenticatorData = flip(p.authenticatorData!, 32, 0x40))],
  ['BE changed', (p) => (p.authenticatorData = flip(p.authenticatorData!, 32, 0x08))],
  [
    'registered as not backup eligible',
    (_p, record) => (record.backupEligible = !record.backupEligible),
  ],
  ['a different registered key', (_p, record) => (record.publicKey = otherKey)],
  ['counter not advanced past the stored one', (_p, record) => (record.signCount = 99)],
  ['another credential', (p) => (p.rawId = flip(p.rawId, 0))],
  ['wrong user handle', (p) => (p.userHandle = new Uint8Array([9, 9, 9]))],
  ['no user handle on a usernameless sign-in', (p) => (p.userHandle = null)],
];

let otherKey: CryptoKey;

beforeAll(async () => {
  otherKey = (
    await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
  ).publicKey;
});

describe('the verifier rejects every single-field corruption', () => {
  let registration: Awaited<ReturnType<typeof register>>;

  beforeEach(async () => {
    registration = await register({ pubKeyCredParams: [{ type: 'public-key', alg: -7 }] });
  });

  const expectation = () => ({
    challenge: new TextEncoder().encode('x'),
    origin: 'https://example.com',
    rpId: 'example.com',
    userId: registration.record.userHandle,
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  });

  it('accepts the unmodified registration', async () => {
    const parts = partsOf(registration.credential);
    const challenge = JSON.parse(text(parts.clientDataJSON)).challenge;

    await verifyRegistration(syntheticCredential(parts), {
      ...expectation(),
      challenge: Uint8Array.from(Buffer.from(challenge, 'base64url')),
    });
  });

  it.each(registrationMutations)('registration: %s', async (_name, mutate) => {
    const parts = partsOf(registration.credential);
    const challenge = Uint8Array.from(
      Buffer.from(JSON.parse(text(parts.clientDataJSON)).challenge, 'base64url')
    );
    mutate(parts, registration.record);

    await expect(
      verifyRegistration(syntheticCredential(parts), { ...expectation(), challenge })
    ).rejects.toBeInstanceOf(ConformanceError);
  });

  it.each(assertionMutations)('assertion: %s', async (_name, mutate) => {
    const { assertion, json } = await authenticate(registration);
    const record: CredentialRecord = { ...registration.record, signCount: 0 };
    const parts = partsOf(assertion);
    mutate(parts, record);

    await expect(
      verifyAuthentication(syntheticCredential(parts), {
        challenge: Uint8Array.from(Buffer.from(json.challenge, 'base64url')),
        origin: 'https://example.com',
        rpId: 'example.com',
        record,
      })
    ).rejects.toBeInstanceOf(ConformanceError);
  });
});
