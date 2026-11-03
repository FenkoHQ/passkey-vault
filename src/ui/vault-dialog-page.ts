/**
 * Entry point of vault-dialog.html.
 */

import { createFrameGate, createWindowGate } from './consent-gate';
import { receiveTokenFromParent, startVaultDialog, takeTokenFromUrl } from './vault-dialog';

// A frame on the page gets its token from the content script; a popup
// window the background opened has it in its URL.
const inWindow = window.parent === window;

void startVaultDialog({
  window,
  inWindow,
  token: async () => (inWindow ? takeTokenFromUrl(window) : receiveTokenFromParent(window)),
  send: (message) => chrome.runtime.sendMessage(message),
  createGate: (card, context) =>
    context.mode === 'window'
      ? createWindowGate(document, { fits: context.fits })
      : createFrameGate(card, { win: window, reference: context.reference, fits: context.fits }),
});
