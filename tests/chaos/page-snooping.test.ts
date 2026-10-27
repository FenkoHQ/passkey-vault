/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: a page that watches its own DOM while it asks for a passkey.
 *
 * Page script sees everything in the page's DOM: a MutationObserver gets
 * every node and attribute the moment it lands, and the page can cancel
 * its own request a moment later. The vault's picker used to be page DOM,
 * so any script on a site (an analytics tag, a compromised dependency)
 * could list every account the user holds there without the user ever
 * clicking anything. Hypothesis: with the picker open, nothing the page
 * can read names an account, a credential ID, or how many there are.
 *
 * The real dialog frame is mounted here (jsdom does not load it, so the
 * dialog stays open until the page cancels).
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { outcome } from '../helpers/ceremony';
import { authenticationJSON, requestOptionsFromJSON } from '../helpers/options';

const vault = setupVault('https://bank.example/login', { realDialogFrame: true });

beforeAll(() => vaultReady(vault));

const ACCOUNTS = [
  ['cred-alice-7f3a', 'alice.secret@bank.example', 'Alice Secret'],
  ['cred-bob-91c2', 'bob.hidden@bank.example', 'Bob Hidden'],
  ['cred-carol-0d5e', 'carol.private@bank.example', 'Carol Private'],
];
const SECRETS = ACCOUNTS.flat().concat(['alice', 'bob', 'carol', 'Alice', 'Bob', 'Carol']);

const passkeys = ACCOUNTS.map(([id, name, displayName], index) => ({
  id,
  credentialId: id,
  type: 'public-key',
  rpId: 'bank.example',
  origin: 'https://bank.example',
  user: { id: `dXNlci0${index}`, name, displayName },
  privateKey: 'unused',
  publicKey: 'unused',
  createdAt: index,
  counter: 0,
}));

/** Everything a page-world MutationObserver saw, as text. */
function watchPage(): { seen: string[]; stop(): void } {
  const seen: string[] = [];
  const describe = (node: Node) =>
    node instanceof Element ? node.outerHTML : String(node.textContent ?? '');
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      record.addedNodes.forEach((node) => seen.push(describe(node)));
      if (record.type === 'attributes' && record.target instanceof Element) {
        seen.push(`${record.attributeName}=${record.target.getAttribute(record.attributeName!)}`);
      }
      if (record.type === 'characterData') seen.push(String(record.target.textContent));
    }
  });
  observer.observe(document, {
    subtree: true,
    childList: true,
    attributes: true,
    characterData: true,
  });
  return { seen, stop: () => observer.disconnect() };
}

beforeEach(async () => {
  await vault.reset({ passkeys });
  vault.goto('https://bank.example/login');
});

describe('a page watching its DOM while the picker is open', () => {
  it('sees a frame it cannot look into, and no account', async () => {
    // What the background answers the content script, in the page's process.
    const answers: unknown[] = [];
    const deliver = vault.chrome.deliver.bind(vault.chrome);
    jest.spyOn(vault.chrome, 'deliver').mockImplementation(async (message, sender) => {
      const answer = await deliver(message, sender);
      if (sender.url?.startsWith('https:')) answers.push(answer);
      return answer;
    });
    const watcher = watchPage();
    const controller = new AbortController();
    const signIn = outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'bank.example' })),
        signal: controller.signal,
      })
    );
    await vault.settle();
    watcher.stop();

    // The dialog is up: its host is in the page, closed to the page.
    const hosts = Array.from(document.documentElement.children).filter(
      (element) => element !== document.head && element !== document.body
    );
    expect(hosts).toHaveLength(1);
    expect(hosts[0].shadowRoot).toBeNull();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
    expect(watcher.seen.length).toBeGreaterThan(0);

    const pageCanRead = [
      ...watcher.seen,
      document.documentElement.outerHTML,
      document.documentElement.textContent ?? '',
      ...vault.posted.map((message) => JSON.stringify(message.data)),
    ].join('\n');
    for (const secret of SECRETS) expect(pageCanRead).not.toContain(secret);

    // Not even the content script, in the page's process, was told.
    expect(answers.length).toBeGreaterThan(0);
    for (const secret of SECRETS) expect(JSON.stringify(answers)).not.toContain(secret);
    jest.restoreAllMocks();

    // The page gives up, as an enumerating script would.
    controller.abort();
    const { error } = await signIn;
    await vault.settle();
    expect(error?.name).toBe('AbortError');
    expect(document.documentElement.children).toHaveLength(2);
  });

  it('cannot tell how many passkeys the site has from the frame', async () => {
    const sizes: string[] = [];
    for (const count of [1, 3]) {
      await vault.reset({ passkeys: passkeys.slice(0, count) });
      const controller = new AbortController();
      const signIn = outcome(
        navigator.credentials.get({
          publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'bank.example' })),
          signal: controller.signal,
        })
      );
      await vault.settle();
      const host = document.documentElement.lastElementChild as HTMLElement;
      sizes.push(`${host.outerHTML}|${getComputedStyle(host).cssText}`);
      controller.abort();
      await signIn;
      await vault.settle();
    }

    expect(sizes[0]).toBe(sizes[1]);
  });
});
