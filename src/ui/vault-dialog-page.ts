/**
 * Entry point of vault-dialog.html.
 */

import { receiveTokenFromParent, startVaultDialog, type ConsentGate } from './vault-dialog';

/** Until the clickjacking gate lands: every trusted click counts. */
function openGate(): ConsentGate {
  return { isReady: () => true, onChange: () => undefined, dispose: () => undefined };
}

void startVaultDialog({
  window,
  token: () => receiveTokenFromParent(window),
  send: (message) => chrome.runtime.sendMessage(message),
  createGate: openGate,
});
