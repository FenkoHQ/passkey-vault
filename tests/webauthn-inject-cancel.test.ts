/**
 * When the page stops waiting for a vault request (the shim's timeout, or
 * the site aborting through options.signal), the shim must tell the content
 * script to cancel. Otherwise its dialog stays up, and a late click creates
 * or signs with a passkey nobody receives.
 */

const nativeGet = navigator.credentials.get as jest.Mock;

// Side-effect import: hooks navigator.credentials and listens for messages.
require('../src/content/webauthn-inject');

const PAGE_SOURCE = 'PASSKEY_VAULT_PAGE';

let posted: Array<{ type: string; requestId: string }>;
const record = (event: MessageEvent) => {
  if (event.data?.source === PAGE_SOURCE) posted.push(event.data);
};

beforeEach(() => {
  posted = [];
  nativeGet.mockReset();
  window.addEventListener('message', record);
});

afterEach(() => {
  window.removeEventListener('message', record);
  jest.useRealTimers();
});

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

// Longer than any timeout the shim allows a ceremony, whatever the RP asks for.
const PAST_ANY_TIMEOUT_MS = 10 * 60 * 1000 + 1;

const createOptions = (signal?: AbortSignal): CredentialCreationOptions => ({
  publicKey: {
    rp: { name: 'Example' },
    user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' },
    challenge: new Uint8Array([9]),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  },
  signal,
});

const getOptions = (signal?: AbortSignal): CredentialRequestOptions => ({
  publicKey: { challenge: new Uint8Array([9]) },
  signal,
});

function cancels() {
  return posted.filter((message) => message.type === 'PASSKEY_CANCEL_REQUEST');
}

describe('webauthn-inject cancellation', () => {
  it('cancels a create in the content script when it times out', async () => {
    jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
    const result = navigator.credentials.create(createOptions());
    const outcome = result.catch((error) => error);

    jest.advanceTimersByTime(PAST_ANY_TIMEOUT_MS);
    jest.useRealTimers();
    await flush();

    const [request] = posted;
    expect(request.type).toBe('PASSKEY_CREATE_REQUEST');
    expect(cancels()).toEqual([expect.objectContaining({ requestId: request.requestId })]);
    expect((await outcome).name).toBe('NotAllowedError');
  });

  it('cancels a get on timeout without opening the native prompt', async () => {
    jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
    const outcome = navigator.credentials.get(getOptions()).catch((error) => error);

    jest.advanceTimersByTime(PAST_ANY_TIMEOUT_MS);
    jest.useRealTimers();
    await flush();

    expect(cancels()).toHaveLength(1);
    expect((await outcome).name).toBe('NotAllowedError');
    expect(nativeGet).not.toHaveBeenCalled();
  });

  it('cancels when the page aborts, rejecting with the abort reason', async () => {
    const controller = new AbortController();
    const outcome = navigator.credentials.get(getOptions(controller.signal)).catch((e) => e);
    await flush();

    controller.abort();
    await flush();

    const [request] = posted;
    expect(cancels()).toEqual([expect.objectContaining({ requestId: request.requestId })]);
    expect((await outcome).name).toBe('AbortError');
    expect(nativeGet).not.toHaveBeenCalled();
  });

  it('does not start a request whose signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();

    const outcome = await navigator.credentials
      .create(createOptions(controller.signal))
      .catch((error) => error);
    await flush();

    expect(outcome.name).toBe('AbortError');
    expect(posted).toEqual([]);
  });
});
