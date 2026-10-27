/**
 * PRF salts cross three realms before the background HMACs them: the page
 * shim posts them to the content script, which forwards them with
 * chrome.runtime.sendMessage. Chrome serialises that message as JSON, so the
 * salts must survive a JSON round trip byte for byte, whatever BufferSource
 * the relying party passed.
 */

import { computePrfResults, normalizePrfInput, selectPrfEval } from '../src/background/prf';

// Side-effect import: hooks navigator.credentials and listens for responses.
require('../src/content/webauthn-inject');

const PAGE_SOURCE = 'PASSKEY_VAULT_PAGE';
const CONTENT_SOURCE = 'PASSKEY_VAULT_CONTENT';
const PRF_KEY = new Uint8Array(32).fill(7).buffer;

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

interface SentPrfValues {
  first?: string;
  second?: string;
}

/** Extension inputs as the background sees them. */
interface SentExtensions {
  prf?: { eval?: SentPrfValues; evalByCredential?: Record<string, SentPrfValues> };
  [name: string]: unknown;
}

/** Wait for the shim to post its request, then refuse it so the call settles. */
function captureRequest(): Promise<{ payload: unknown }> {
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (event.data?.source !== PAGE_SOURCE) {
        return;
      }
      window.removeEventListener('message', listener);
      const { requestId } = event.data;
      window.dispatchEvent(
        new MessageEvent('message', {
          data: {
            source: CONTENT_SOURCE,
            requestId,
            result: { success: false, error: 'test', blockNativeFallback: true },
          },
          source: window,
        })
      );
      resolve(event.data);
    };
    window.addEventListener('message', listener);
  });
}

/** What the background receives from the content script on Chrome. */
async function backgroundExtensions(
  extensions: AuthenticationExtensionsClientInputs,
  allowCredentials?: PublicKeyCredentialDescriptor[]
): Promise<SentExtensions> {
  const request = captureRequest();
  await navigator.credentials
    .get({ publicKey: { challenge: new Uint8Array([1]), allowCredentials, extensions } })
    .catch(() => undefined);
  const message = await request;
  return JSON.parse(JSON.stringify(message.payload)).publicKey.extensions;
}

async function hmac(data: Uint8Array<ArrayBuffer>): Promise<number[]> {
  const key = await crypto.subtle.importKey(
    'raw',
    PRF_KEY,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', key, data)));
}

async function prfFirst(extensions: SentExtensions, credentialId?: string) {
  const evalInput = selectPrfEval(extensions.prf, credentialId);
  const results = evalInput ? await computePrfResults(PRF_KEY, evalInput) : null;
  return results?.results.first ? Array.from(new Uint8Array(results.results.first)) : null;
}

describe('PRF inputs across the page → content → background boundary', () => {
  // Built in the page realm: TextEncoder here is Node's, whose buffers fail
  // the page's `instanceof ArrayBuffer`, which a real page never hits.
  const salt = Uint8Array.from(Buffer.from('per-user salt'));

  it('keeps an ArrayBuffer salt through the JSON hop', async () => {
    const extensions = await backgroundExtensions({
      prf: { eval: { first: salt.slice().buffer } },
    });

    expect(extensions.prf.eval.first).toBe(b64url(salt));
    expect(await prfFirst(extensions)).toEqual(await hmac(salt));
  });

  it('sends only the bytes a typed-array view or DataView covers', async () => {
    const backing = new Uint8Array(salt.length + 16).fill(0xee);
    backing.set(salt, 8);
    const extensions = await backgroundExtensions({
      prf: {
        eval: {
          first: backing.subarray(8, 8 + salt.length),
          second: new DataView(backing.buffer, 8, salt.length),
        },
      },
    });

    expect(extensions.prf.eval.first).toBe(b64url(salt));
    expect(extensions.prf.eval.second).toBe(b64url(salt));
    expect(await prfFirst(extensions)).toEqual(await hmac(salt));
  });

  it('serialises every evalByCredential entry', async () => {
    const credentialId = b64url(new Uint8Array([1, 2, 3, 4]));
    // evalByCredential is only valid for credentials named in allowCredentials.
    const extensions = await backgroundExtensions(
      { prf: { evalByCredential: { [credentialId]: { first: salt.slice().buffer } } } },
      [{ type: 'public-key', id: new Uint8Array([1, 2, 3, 4]) }]
    );

    expect(extensions.prf.evalByCredential[credentialId]).toEqual({ first: b64url(salt) });
    expect(await prfFirst(extensions, credentialId)).toEqual(await hmac(salt));
  });

  it('drops the extensions the vault does not implement', async () => {
    const extensions = await backgroundExtensions({
      appid: 'https://example.com/u2f.json',
      largeBlob: { read: true },
    } as AuthenticationExtensionsClientInputs);

    expect(extensions).toEqual({});
  });
});

describe('normalizePrfInput', () => {
  it('reads only the bytes a view covers', () => {
    const backing = new Uint8Array([0xaa, 1, 2, 3, 0xbb]);

    expect(Array.from(new Uint8Array(normalizePrfInput(backing.subarray(1, 4))!))).toEqual([
      1, 2, 3,
    ]);
    expect(
      Array.from(new Uint8Array(normalizePrfInput(new DataView(backing.buffer, 1, 3))!))
    ).toEqual([1, 2, 3]);
  });
});

describe('selectPrfEval', () => {
  const credentialId = b64url(new Uint8Array([0xfb, 0xff, 0x01, 0x02]));
  const generic = { first: 'generic' };
  const perCredential = { first: 'per-credential' };

  it('prefers a matching evalByCredential entry over eval', () => {
    const prf = { eval: generic, evalByCredential: { [credentialId]: perCredential } };

    expect(selectPrfEval(prf, credentialId)).toBe(perCredential);
  });

  it('matches an entry keyed by standard base64', () => {
    const key = Buffer.from([0xfb, 0xff, 0x01, 0x02]).toString('base64');
    const prf = { eval: generic, evalByCredential: { [key]: perCredential } };

    expect(selectPrfEval(prf, credentialId)).toBe(perCredential);
  });

  it('falls back to eval when no entry matches', () => {
    const other = b64url(new Uint8Array([9, 9, 9]));
    const prf = { eval: generic, evalByCredential: { [other]: perCredential } };

    expect(selectPrfEval(prf, credentialId)).toBe(generic);
    expect(selectPrfEval({ eval: generic }, credentialId)).toBe(generic);
  });

  it('returns null with neither a match nor eval', () => {
    const other = b64url(new Uint8Array([9, 9, 9]));

    expect(selectPrfEval({ evalByCredential: { [other]: perCredential } }, credentialId)).toBe(
      null
    );
    expect(selectPrfEval(undefined, credentialId)).toBe(null);
  });
});
