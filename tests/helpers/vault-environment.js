/**
 * jsdom environment that lets a test move the page to another origin.
 *
 * The content script trusts only `window.location` for the caller's origin,
 * so ceremony tests have to run on the relying party's real origin
 * (https://github.com, https://accountscenter.facebook.com, ...). jsdom can
 * change the document URL through `reconfigure()`, which the stock Jest
 * environment keeps private. jsdom also has no `isSecureContext`, which the
 * content script checks, so it is derived from the URL the way browsers do
 * for top-level documents.
 *
 * Use with a docblock at the top of a test file:
 *   @jest-environment ./tests/helpers/vault-environment.js
 */
const { TestEnvironment } = require('jest-environment-jsdom');

const LOOPBACK = /^(localhost|.*\.localhost|127(\.\d{1,3}){3}|\[::1\])$/;

class VaultEnvironment extends TestEnvironment {
  constructor(config, context) {
    super(config, context);
    const dom = this.dom;
    const window = this.global;
    let secureOverride = null;

    window.__setPageUrl = (url) => {
      dom.reconfigure({ url });
      secureOverride = null;
    };
    // Lets a test model a context the URL alone does not describe, such as
    // an insecure iframe on a secure page.
    window.__setSecureContext = (value) => {
      secureOverride = value;
    };
    Object.defineProperty(window, 'isSecureContext', {
      configurable: true,
      get() {
        if (secureOverride !== null) return secureOverride;
        const { protocol, hostname } = window.location;
        return protocol === 'https:' || protocol === 'wss:' || LOOPBACK.test(hostname);
      },
    });
  }
}

module.exports = VaultEnvironment;
