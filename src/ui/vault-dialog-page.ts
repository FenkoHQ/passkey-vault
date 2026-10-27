/**
 * Entry point of vault-dialog.html.
 */

import {
  receiveTokenFromParent,
  startVaultDialog,
  takeTokenFromUrl,
  type ConsentGate,
} from './vault-dialog';

/** Until the clickjacking gate lands: every trusted click counts. */
function openGate(): ConsentGate {
  return { isReady: () => true, onChange: () => undefined, dispose: () => undefined };
}

// A frame on the page gets its token from the content script; a popup
// window the background opened has it in its URL.
const inWindow = window.parent === window;

void startVaultDialog({
  window,
  inWindow,
  token: async () => (inWindow ? takeTokenFromUrl(window) : receiveTokenFromParent(window)),
  send: (message) => chrome.runtime.sendMessage(message),
  createGate: openGate,
});
