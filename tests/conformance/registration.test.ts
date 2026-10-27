/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Registration ceremonies (navigator.credentials.create) driven through the
 * real page shim, content script and background, and verified as a relying
 * party would: WebAuthn Level 3 §7.1 by the strict verifier, and again by
 * SimpleWebAuthn. See tests/helpers/harness.ts for how the pieces connect.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { register } from '../helpers/ceremony';
import { b64url, fromB64url, hex, sha256, toBytes } from '../helpers/bytes';
import { decodeCbor } from '../helpers/cbor-strict';
import {
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  parseAuthenticatorData,
} from '../helpers/rp-verifier';
import { creationOptionsFromJSON, random, registrationJSON } from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const VAULT_AAGUID = 'd2717a32985148a89961b264c97a411a';

function authDataOf(credential: any) {
  const issues: string[] = [];
  const parsed = parseAuthenticatorData(
    toBytes(credential.response.getAuthenticatorData()),
    issues
  );
  expect(issues).toEqual([]);
  return parsed!;
}

describe('a registration a strict relying party accepts', () => {
  it('passes §7.1 and SimpleWebAuthn with typical passkey options', async () => {
    const { record, oracle } = await register();

    expect(record.rawId).toHaveLength(16);
    expect(oracle.id).toBe(record.id);
  });

  it('serialises clientDataJSON exactly as §5.8.1.1, crossOrigin included', async () => {
    const { credential, json } = await register();

    expect(new TextDecoder().decode(credential.response.clientDataJSON)).toBe(
      `{"type":"webauthn.create","challenge":"${json.challenge}","origin":"https://example.com","crossOrigin":false}`
    );
  });

  it('wraps authenticator data in canonical "none" attestation', async () => {
    const { credential } = await register();
    const { value } = decodeCbor(toBytes(credential.response.attestationObject));
    const map = value as Map<string, unknown>;

    expect([...map.keys()]).toEqual(['fmt', 'attStmt', 'authData']);
    expect(map.get('fmt')).toBe('none');
    expect((map.get('attStmt') as Map<unknown, unknown>).size).toBe(0);
  });

  it('hashes the RP ID, sets UP, UV and AT, and starts the counter at zero', async () => {
    const { credential } = await register();
    const authData = authDataOf(credential);

    expect(hex(authData.rpIdHash)).toBe(hex(await sha256('example.com')));
    expect(authData.flags & (FLAG_UP | FLAG_UV | FLAG_AT)).toBe(FLAG_UP | FLAG_UV | FLAG_AT);
    expect(authData.signCount).toBe(0);
    expect(authData.extensions).toBeUndefined();
  });

  it('identifies the authenticator model with the Fenko Vault AAGUID', async () => {
    const { record } = await register();

    expect(hex(record.aaguid)).toBe(VAULT_AAGUID);
  });

  it('carries an ES256 P-256 COSE key in canonical order', async () => {
    const { record, credential } = await register();
    const { value } = decodeCbor(record.publicKeyCose);
    const cose = value as Map<number, unknown>;

    expect([...cose.keys()]).toEqual([1, 3, -1, -2, -3]);
    expect(cose.get(1)).toBe(2);
    expect(cose.get(3)).toBe(-7);
    expect(cose.get(-1)).toBe(1);
    expect(credential.response.getPublicKeyAlgorithm()).toBe(-7);
  });

  it('mints a fresh credential ID and key pair every time', async () => {
    const first = await register();
    const second = await register();

    expect(first.record.id).not.toBe(second.record.id);
    expect(hex(first.record.publicKeyCose)).not.toBe(hex(second.record.publicKeyCose));
  });

  it('serialises as RegistrationResponseJSON for the server', async () => {
    const { credential, record } = await register();
    const json = JSON.parse(JSON.stringify(credential));

    expect(Object.keys(json).sort()).toEqual(
      [
        'authenticatorAttachment',
        'clientExtensionResults',
        'id',
        'rawId',
        'response',
        'type',
      ].sort()
    );
    expect(json.rawId).toBe(record.id);
    expect(Object.keys(json.response).sort()).toEqual(
      [
        'attestationObject',
        'authenticatorData',
        'clientDataJSON',
        'publicKey',
        'publicKeyAlgorithm',
        'transports',
      ].sort()
    );
  });
});

describe('RP ID', () => {
  it('defaults to the page host when rp.id is omitted', async () => {
    vault.goto('https://login.example.com/signup');
    const { credential, rpId } = await register({ rp: { name: 'Example' } });

    expect(rpId).toBe('login.example.com');
    expect(hex(authDataOf(credential).rpIdHash)).toBe(hex(await sha256('login.example.com')));
  });

  it('may be a registrable parent of the page host', async () => {
    vault.goto('https://accounts.shop.example.co.uk/register');
    const { credential } = await register({ rp: { name: 'Shop', id: 'example.co.uk' } });

    expect(hex(authDataOf(credential).rpIdHash)).toBe(hex(await sha256('example.co.uk')));
  });

  it('is recorded with the passkey so sign-in finds it', async () => {
    vault.goto('https://www.example.com/');
    const { record } = await register({ rp: { name: 'Example', id: 'example.com' } });
    const [stored] = await vault.passkeys();

    expect(stored.rpId).toBe('example.com');
    expect(stored.credentialId).toBe(record.id);
    expect(stored.origin).toBe('https://www.example.com');
  });
});

describe('BufferSource inputs', () => {
  // Pages pass whatever view their encoder hands them. Only the bytes the
  // view covers may reach clientDataJSON and the stored user handle.
  const challenge = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  const userId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  function backed(bytes: Uint8Array) {
    const backing = new Uint8Array(bytes.length + 10).fill(0xee);
    backing.set(bytes, 5);
    return backing;
  }

  const forms: Array<[string, (bytes: Uint8Array) => BufferSource]> = [
    ['ArrayBuffer', (b) => b.slice().buffer],
    ['Uint8Array', (b) => b.slice()],
    ['Uint8Array subarray', (b) => backed(b).subarray(5, 5 + b.length)],
    ['DataView window', (b) => new DataView(backed(b).buffer, 5, b.length)],
    ['Int8Array', (b) => new Int8Array(b.slice().buffer)],
    ['Uint16Array', (b) => new Uint16Array(b.slice().buffer)],
  ];

  it.each(forms)('takes the challenge and user.id as a %s', async (_name, form) => {
    const json = registrationJSON({ rp: { name: 'Example', id: 'example.com' } });
    const options = creationOptionsFromJSON(json);
    options.challenge = form(challenge);
    options.user.id = form(userId);

    const credential: any = await navigator.credentials.create({ publicKey: options });
    const clientData = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    const [stored] = await vault.passkeys();

    expect(clientData.challenge).toBe(b64url(challenge));
    expect(stored.user.id).toBe(b64url(userId));
  });
});

describe('Advanced ceremony settings', () => {
  async function flagsWith(settings: Record<string, unknown>, sync = false) {
    await vault.send({ type: 'SET_WEBAUTHN_FLAGS', payload: { flags: settings } });
    if (sync) {
      vault.storage.sync_config = {
        enabled: true,
        chainId: 'c'.repeat(32),
        deviceId: 'd',
        deviceName: 'x',
      };
    }
    const { credential, record } = await register();
    return { flags: authDataOf(credential).flags, credential, record };
  }

  it.each([
    [{}, FLAG_BE],
    [{ backupEligible: true, backupState: true }, FLAG_BE | FLAG_BS],
    [{ backupEligible: false, backupState: true }, 0],
    [{ backupEligible: false }, 0],
  ])('backup flags for %j', async (settings, expected) => {
    const { flags } = await flagsWith(settings);

    expect(flags & (FLAG_BE | FLAG_BS)).toBe(expected);
  });

  it('reports a new passkey as backed up once sync is on', async () => {
    const { flags } = await flagsWith({ backupEligible: true, backupState: false }, true);

    expect(flags & (FLAG_BE | FLAG_BS)).toBe(FLAG_BE | FLAG_BS);
  });

  it('clears UV when verification reporting is off', async () => {
    const { flags } = await flagsWith({ userVerification: 'never' });

    expect(flags & FLAG_UV).toBe(0);
    expect(flags & FLAG_UP).toBe(FLAG_UP);
  });

  it('reports the anonymous AAGUID when asked', async () => {
    const { record } = await flagsWith({ aaguid: 'zero' });

    expect(hex(record.aaguid)).toBe('0'.repeat(32));
  });

  it.each([
    ['platform', ['internal']],
    ['cross-platform', []],
  ])('reports %s attachment with transports %j', async (attachment, transports) => {
    const { credential } = await flagsWith({ attachment });

    expect(credential.authenticatorAttachment).toBe(attachment);
    expect(credential.response.getTransports()).toEqual(transports);
  });
});

describe('what reaches the page', () => {
  it('never carries the private key or PRF secret', async () => {
    await register();
    const [stored] = await vault.passkeys();
    const traffic = JSON.stringify(vault.posted.map((message) => message.data));

    expect(traffic).not.toContain(stored.privateKey);
    expect(traffic).not.toContain(stored.prfKey);
  });

  it('gives the page a user handle it can read back on sign-in', async () => {
    const userId = random(64);
    const { record } = await register({
      user: { id: b64url(userId), name: 'max@example.com', displayName: 'Max' },
    });

    expect(hex(record.userHandle)).toBe(hex(userId));
    const [stored] = await vault.passkeys();
    expect(fromB64url(stored.user.id)).toEqual(userId);
  });
});
