/**
 * What the content script puts in the page for the vault's dialogs: the
 * dialog's frame, and the card that offers an autofill sign-in where the
 * dialog opens in a window. Both sit in closed shadow roots, and neither
 * carries anything the page does not already know.
 */

import { mountDialogFrame, supportsFrameDialogs } from '../src/content/vault-dialog-frame';
import { showLauncher } from '../src/content/vault-launcher';
import { trustedClick } from './helpers/trusted-input';

const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;

/** The shadow roots the code under test attaches, closed or not. */
const roots: ShadowRoot[] = [];
const attachShadow = Element.prototype.attachShadow;
beforeAll(() => {
  jest.spyOn(Element.prototype, 'attachShadow').mockImplementation(function (
    this: Element,
    init: ShadowRootInit
  ) {
    const root = attachShadow.call(this, init);
    roots.push(root);
    return root;
  });
});

afterEach(() => {
  roots.length = 0;
  for (const element of Array.from(document.documentElement.children)) {
    if (element !== document.head && element !== document.body) element.remove();
  }
});

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/** jsdom gives a frame in a shadow root no window; stand one in, and return its postMessage. */
function frameWindow(): jest.Mock {
  const postMessage = jest.fn();
  jest
    .spyOn(HTMLIFrameElement.prototype, 'contentWindow', 'get')
    .mockReturnValue({ postMessage } as unknown as Window);
  return postMessage;
}

describe('the dialog frame', () => {
  it('is an extension page in a closed shadow root', () => {
    const frame = mountDialogFrame({ token: 'secret-token', kind: 'get', focus: false });

    const host = document.documentElement.lastElementChild!;
    expect(host.shadowRoot).toBeNull();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
    const iframe = roots[0].querySelector('iframe')!;
    expect(iframe.src).toBe('chrome-extension://test/vault-dialog.html');
    // The token is never in the page's DOM, nor in the frame's URL.
    expect(document.documentElement.outerHTML).not.toContain('secret-token');
    expect(iframe.src).not.toContain('secret-token');
    frame.unmount();
    expect(host.isConnected).toBe(false);
  });

  it('hands the token only to the extension’s origin', () => {
    const post = frameWindow();
    mountDialogFrame({ token: 'secret-token', kind: 'create', focus: false });
    const iframe = roots[0].querySelector('iframe')!;

    iframe.dispatchEvent(new Event('load'));

    expect(post).toHaveBeenCalledWith(
      { type: 'fenko-vault-dialog-token', token: 'secret-token' },
      'chrome-extension://test-extension-id'
    );
  });

  it('counts as gone when it loads a second document', async () => {
    frameWindow();
    const frame = mountDialogFrame({ token: 'secret-token', kind: 'get', focus: false });
    const iframe = roots[0].querySelector('iframe')!;
    let gone = false;
    void frame.gone.then(() => (gone = true));

    iframe.dispatchEvent(new Event('load'));
    iframe.dispatchEvent(new Event('load'));
    await flush();

    expect(gone).toBe(true);
  });

  it('counts as gone when the page removes it', async () => {
    const frame = mountDialogFrame({ token: 'secret-token', kind: 'get', focus: false });
    let gone = false;
    void frame.gone.then(() => (gone = true));

    document.documentElement.lastElementChild!.remove();
    await flush();

    expect(gone).toBe(true);
  });

  it('is the same size whatever it shows', () => {
    mountDialogFrame({ token: 'a', kind: 'get', focus: false });
    const style = roots[0].querySelector('style')!.textContent!;

    expect(style).toContain('min(340px');
    expect(style).toContain('min(372px');
    expect(style).toMatch(/all: initial !important/);
  });
});

describe('where the dialog can be a frame', () => {
  const entry = (globalThis as Record<string, any>).IntersectionObserverEntry;

  afterEach(() => {
    (globalThis as Record<string, any>).IntersectionObserverEntry = entry;
    delete chromeMock.runtime.getManifest;
  });

  const manifest = (resources: string[]) => () => ({
    web_accessible_resources: [{ resources, matches: ['https://*/*'] }],
  });

  it('needs IntersectionObserver v2, to know the frame is visible', () => {
    chromeMock.runtime.getManifest = manifest(['vault-dialog.html']);
    (globalThis as Record<string, any>).IntersectionObserverEntry = class {};
    expect(supportsFrameDialogs()).toBe(false);

    (globalThis as Record<string, any>).IntersectionObserverEntry = class {
      get isVisible() {
        return false;
      }
    };
    expect(supportsFrameDialogs()).toBe(true);
  });

  it('needs a build that lets pages load the dialog page', () => {
    (globalThis as Record<string, any>).IntersectionObserverEntry = class {
      get isVisible() {
        return false;
      }
    };
    chromeMock.runtime.getManifest = manifest(['webauthn-inject.js']);

    expect(supportsFrameDialogs()).toBe(false);
  });
});

describe('the autofill launcher', () => {
  it('names only the site, and answers only the user’s own click', async () => {
    const launcher = showLauncher('example.com', 'light');
    let choice: string | undefined;
    void launcher.choice.then((value) => (choice = value));
    const [open] = Array.from(roots[0].querySelectorAll('button'));

    expect(document.documentElement.lastElementChild!.shadowRoot).toBeNull();
    expect(roots[0].textContent).toContain('example.com');
    open.click();
    await flush();
    expect(choice).toBeUndefined();

    trustedClick(open);
    await flush();
    expect(choice).toBe('open');
    launcher.remove();
  });
});
