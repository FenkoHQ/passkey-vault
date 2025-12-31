import { validateMnemonic } from '../crypto/bip39';

const STORAGE_KEY = 'sync_config';
const MNEMONIC_DISPLAY = 'mnemonic-words';
const CREATE_SUCCESS = 'create-success';
const JOIN_SUCCESS = 'join-success';
const JOIN_LOADING = 'join-loading';

interface SyncConfig {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash: string | null;
}

let currentConfig: SyncConfig | null = null;
let currentMnemonic: string = '';

document.addEventListener('DOMContentLoaded', () => {
  setupModeButtons();
  setupCreateChain();
  setupJoinChain();
  loadExistingConfig();
});

function setupModeButtons(): void {
  const createBtn = document.getElementById('create-mode-btn') as HTMLButtonElement;
  const joinBtn = document.getElementById('join-mode-btn') as HTMLButtonElement;

  if (!createBtn || !joinBtn) return;

  createBtn.addEventListener('click', () => {
    createBtn.classList.add('active');
    joinBtn.classList.remove('active');
    showPanel('create-chain-panel');
  });

  joinBtn.addEventListener('click', () => {
    joinBtn.classList.add('active');
    createBtn.classList.remove('active');
    showPanel('join-chain-panel');
  });
}

function showPanel(panelId: string): void {
  document.querySelectorAll('.panel').forEach((panel) => {
    (panel as HTMLElement).style.display = 'none';
    panel.classList.remove('active');
  });

  const target = document.getElementById(panelId) as HTMLElement;
  if (target) {
    target.style.display = 'block';
    target.classList.add('active');
  }
}

function setupCreateChain(): void {
  const createBtn = document.getElementById('create-chain-btn') as HTMLButtonElement;
  const deviceNameInput = document.getElementById('device-name-create') as HTMLInputElement;
  const copyMnemonicBtn = document.getElementById('copy-mnemonic-btn') as HTMLButtonElement;
  const finishBtn = document.getElementById('finish-create-btn') as HTMLButtonElement;

  if (!createBtn || !deviceNameInput || !copyMnemonicBtn || !finishBtn) return;

  createBtn.addEventListener('click', async () => {
    const deviceName = deviceNameInput.value.trim();
    if (!deviceName) {
      alert('Please enter a device name');
      return;
    }

    try {
      const wordCount = getSelectedWordCount();
      const result = await chrome.runtime.sendMessage({
        type: 'CREATE_SYNC_CHAIN',
        deviceName,
        wordCount,
      });

      if (result.success) {
        currentMnemonic = result.mnemonic;
        displayMnemonic(result.mnemonic);
        showSuccess(CREATE_SUCCESS);
      } else {
        alert(`Failed to create sync chain: ${result.error}`);
      }
    } catch (error) {
      alert(`Error creating sync chain: ${error}`);
    }
  });

  copyMnemonicBtn.addEventListener('click', async () => {
    if (!currentMnemonic) return;

    try {
      await navigator.clipboard.writeText(currentMnemonic);
      copyMnemonicBtn.textContent = 'Copied!';
      setTimeout(() => {
        copyMnemonicBtn.innerHTML =
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"></rect><rect x="3" y="3" width="13" height="13" rx="2"></rect></svg> Copy';
      }, 2000);
    } catch (error) {
      alert('Failed to copy to clipboard');
    }
  });

  finishBtn.addEventListener('click', () => {
    window.location.href = chrome.runtime.getURL('sync-settings.html');
  });
}

function setupJoinChain(): void {
  const joinBtn = document.getElementById('join-chain-btn') as HTMLButtonElement;
  const mnemonicInput = document.getElementById('mnemonic-input') as HTMLTextAreaElement;
  const deviceNameInput = document.getElementById('device-name-join') as HTMLInputElement;
  const scanQrBtn = document.getElementById('scan-qr-btn') as HTMLButtonElement;

  if (!joinBtn || !mnemonicInput || !deviceNameInput) return;

  joinBtn.addEventListener('click', async () => {
    const deviceName = deviceNameInput.value.trim();
    const mnemonic = mnemonicInput.value.trim();

    if (!deviceName) {
      alert('Please enter a device name');
      return;
    }

    if (!mnemonic) {
      alert('Please enter your recovery phrase');
      return;
    }

    if (!validateMnemonic(mnemonic)) {
      alert('Invalid recovery phrase. Please check and try again.');
      return;
    }

    try {
      showLoading(JOIN_LOADING);

      const result = await chrome.runtime.sendMessage({
        type: 'JOIN_SYNC_CHAIN',
        deviceName,
        mnemonic,
      });

      hideLoading(JOIN_LOADING);

      if (result.success) {
        showSuccess(JOIN_SUCCESS);
        setTimeout(() => {
          window.close();
        }, 2000);
      } else {
        alert(`Failed to join sync chain: ${result.error}`);
      }
    } catch (error) {
      hideLoading(JOIN_LOADING);
      alert(`Error joining sync chain: ${error}`);
    }
  });

  scanQrBtn.addEventListener('click', async () => {
    alert(
      'QR code scanning requires camera access. This feature will be available in a future update.'
    );
  });
}

function getSelectedWordCount(): number {
  const wordCountInputs = document.querySelectorAll<HTMLInputElement>('input[name="word-count"]');
  for (const input of wordCountInputs) {
    if (input.checked) {
      return parseInt(input.value);
    }
  }
  return 12;
}

function displayMnemonic(mnemonic: string): void {
  const mnemonicEl = document.getElementById(MNEMONIC_DISPLAY) as HTMLElement;
  const words = mnemonic.split(' ');

  mnemonicEl.innerHTML = words
    .map(
      (word, index) =>
        `<div class="mnemonic-word"><span class="word-number">${index + 1}</span>${word}</div>`
    )
    .join('');
}

function showSuccess(elementId: string): void {
  const successEl = document.getElementById(elementId) as HTMLElement;
  if (!successEl) return;

  const parentPanel = successEl.closest('.panel') as HTMLElement;
  if (parentPanel) {
    const otherContent = parentPanel.querySelectorAll(':scope > *:not(.success-message)');
    otherContent.forEach((el) => {
      (el as HTMLElement).style.display = 'none';
    });
  }

  successEl.style.display = 'block';
}

function showLoading(elementId: string): void {
  const el = document.getElementById(elementId) as HTMLElement;
  if (el) {
    el.style.display = 'block';
  }
}

function hideLoading(elementId: string): void {
  const el = document.getElementById(elementId) as HTMLElement;
  if (el) {
    el.style.display = 'none';
  }
}

async function loadExistingConfig(): Promise<void> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    const config = result[STORAGE_KEY] as SyncConfig | undefined;

    if (config && config.enabled && config.chainId) {
      window.location.href = chrome.runtime.getURL('sync-settings.html');
    }
  } catch (error) {
    console.error('Failed to load sync config:', error);
  }
}
