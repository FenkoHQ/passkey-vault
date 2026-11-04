/**
 * The vault's notices on a page sit in a closed shadow root and leave the
 * page's own elements alone, and the "signed in" notice names the site,
 * never the account.
 */

import { initI18n } from '../src/i18n';
import { showErrorNotification, showPasskeyUsedNotification } from '../src/content/page-notices';

const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;
chromeMock.storage.local.get.mockResolvedValue({ ui_theme: 'dark', ui_language: 'fa' });

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

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

it('loads the language without touching the page’s <html>', async () => {
  await initI18n({ applyToDocument: false });

  expect(document.documentElement.getAttributeNames()).toEqual([]);
});

it('shows a notice in a closed shadow root, themed without marking the page', async () => {
  showErrorNotification('Sign In Failed', 'Something went wrong');
  await flush();

  const host = document.documentElement.lastElementChild!;
  expect(host.shadowRoot).toBeNull();
  expect(document.documentElement.textContent).not.toContain('Something went wrong');
  expect(roots[0].textContent).toContain('Something went wrong');
  expect(host.getAttribute('data-theme')).toBe('dark');
  expect(document.documentElement.getAttributeNames()).toEqual([]);
});

it('names the site, not the account, after a sign-in', async () => {
  showPasskeyUsedNotification('bank.example');
  await flush();

  expect(roots[roots.length - 1].textContent).toContain('bank.example');
  expect(document.documentElement.querySelectorAll(':scope > div')).toHaveLength(1);
});
