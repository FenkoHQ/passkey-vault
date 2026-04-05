/**
 * Import Page for PassKey Vault
 *
 * Handles importing passkeys from backup files
 */

(function () {
  'use strict';

  const IMPORT_PASSKEY_STORAGE_KEY = 'passkeys';

  // State
  let parsedData: any = null;
  let newPasskeys: any[] = [];
  let existingIds: Set<string> = new Set();

  // DOM elements
  const dropZone = document.getElementById('drop-zone') as HTMLElement;
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  const chooseFileBtn = document.getElementById('choose-file-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('status') as HTMLElement;
  const previewEl = document.getElementById('preview') as HTMLElement;
  const previewListEl = document.getElementById('preview-list') as HTMLElement;
  const actionsEl = document.getElementById('actions') as HTMLElement;
  const cancelBtn = document.getElementById('cancel-btn') as HTMLButtonElement;
  const importBtn = document.getElementById('import-btn') as HTMLButtonElement;
  const closeLink = document.getElementById('close-link') as HTMLAnchorElement;

  // Initialize
  setupEventListeners();

  function setupEventListeners(): void {
    // File input change
    fileInput.addEventListener('change', handleFileSelect);

    // Drag and drop
    dropZone.addEventListener('dragover', handleDragOver);
    dropZone.addEventListener('dragleave', handleDragLeave);
    dropZone.addEventListener('drop', handleDrop);

    // Buttons
    cancelBtn.addEventListener('click', resetState);
    importBtn.addEventListener('click', performImport);
    chooseFileBtn.addEventListener('click', () => fileInput.click());
    closeLink.addEventListener('click', (e) => {
      e.preventDefault();
      window.close();
    });
  }

  function handleDragOver(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('drag-over');
  }

  function handleDragLeave(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');
  }

  function handleDrop(e: DragEvent): void {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      processFile(files[0]);
    }
  }

  function handleFileSelect(e: Event): void {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) {
      processFile(file);
    }
  }

  async function processFile(file: File): Promise<void> {
    resetState();

    if (!file.name.endsWith('.json') && file.type !== 'application/json') {
      showStatus('Please select a JSON file', 'error');
      return;
    }

    try {
      const text = await file.text();
      const fileData = JSON.parse(text);

      // Check if this is an encrypted backup
      if (fileData.encrypted === true && fileData.data && fileData.iv && fileData.salt) {
        await processEncryptedBackup(fileData);
        return;
      }

      // Unencrypted backup (legacy support)
      await processPlaintextBackup(fileData);
    } catch (error) {
      console.error('Error processing file:', error);
      if (error instanceof SyntaxError) {
        showStatus('Invalid JSON file', 'error');
      } else {
        showStatus('Failed to process file: ' + (error as Error).message, 'error');
      }
    }
  }

  async function processEncryptedBackup(fileData: Record<string, string>): Promise<void> {
    const password = await showImportPasswordPrompt();
    if (password === null) {
      showStatus('Import cancelled', 'info');
      return;
    }

    showStatus('Decrypting...', 'info');

    const response = await chrome.runtime.sendMessage({
      type: 'DECRYPT_BACKUP',
      payload: {
        data: fileData.data,
        iv: fileData.iv,
        salt: fileData.salt,
        password,
      },
    });

    if (!response.success) {
      showStatus('Wrong password or corrupted file', 'error');
      return;
    }

    try {
      const decrypted = JSON.parse(response.data);
      await processPlaintextBackup(decrypted);
    } catch {
      showStatus('Decryption succeeded but file contents are invalid', 'error');
    }
  }

  function showImportPasswordPrompt(): Promise<string | null> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.style.cssText =
        'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999';
      overlay.innerHTML = `
        <div style="background:#222;padding:20px;border-radius:8px;width:300px;max-width:90%">
          <h3 style="margin:0 0 8px;color:#fff;font-size:15px">Enter Backup Password</h3>
          <p style="margin:0 0 12px;color:#999;font-size:13px">This backup is encrypted. Enter the password used when exporting.</p>
          <input type="password" id="import-pw" placeholder="Password" autocomplete="off"
            style="width:100%;padding:8px;border:1px solid #444;background:#1a1a1a;color:#fff;border-radius:4px;font-size:13px;box-sizing:border-box;margin-bottom:8px" />
          <div id="import-pw-error" style="color:#ef4444;font-size:12px;margin-bottom:8px;display:none"></div>
          <div style="display:flex;gap:8px">
            <button id="import-pw-cancel" style="flex:1;padding:8px;border:1px solid #444;background:transparent;color:#ccc;border-radius:4px;cursor:pointer">Cancel</button>
            <button id="import-pw-ok" style="flex:1;padding:8px;border:none;background:#FCD34D;color:#000;border-radius:4px;cursor:pointer;font-weight:600">Decrypt</button>
          </div>
        </div>
      `;
      document.body.appendChild(overlay);

      const pwInput = overlay.querySelector('#import-pw') as HTMLInputElement;
      const okBtn = overlay.querySelector('#import-pw-ok') as HTMLButtonElement;
      const cancelBtn = overlay.querySelector('#import-pw-cancel') as HTMLButtonElement;

      pwInput.focus();

      const cleanup = (result: string | null) => {
        overlay.remove();
        resolve(result);
      };

      okBtn.addEventListener('click', () => {
        const pw = pwInput.value;
        if (!pw) {
          const err = overlay.querySelector('#import-pw-error') as HTMLElement;
          err.textContent = 'Password is required';
          err.style.display = 'block';
          return;
        }
        cleanup(pw);
      });

      cancelBtn.addEventListener('click', () => cleanup(null));
      pwInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') okBtn.click();
      });
    });
  }

  async function processPlaintextBackup(data: Record<string, unknown>): Promise<void> {
    parsedData = data;

    if (!parsedData.passkeys || !Array.isArray(parsedData.passkeys)) {
      showStatus('Invalid file format: missing passkeys array', 'error');
      return;
    }

    const hasPrivateKeys = parsedData.passkeys.some((p: any) => p.privateKey);

    if (!hasPrivateKeys) {
      showStatus(
        'Cannot import: this file does not contain private keys. You need a full backup file.',
        'error'
      );
      return;
    }

    const validPasskeys = parsedData.passkeys.filter((p: any) => {
      return p.id && p.rpId && p.privateKey;
    });

    if (validPasskeys.length === 0) {
      showStatus('No valid passkeys found in file', 'error');
      return;
    }

    const result = await chrome.storage.local.get(IMPORT_PASSKEY_STORAGE_KEY);
    const existingPasskeys: any[] = result[IMPORT_PASSKEY_STORAGE_KEY] || [];
    existingIds = new Set(existingPasskeys.map((p) => p.id));

    newPasskeys = validPasskeys.filter((p: any) => !existingIds.has(p.id));
    const duplicates = validPasskeys.filter((p: any) => existingIds.has(p.id));

    showPreview(validPasskeys, duplicates);

    if (newPasskeys.length === 0) {
      showStatus('All passkeys in this file already exist in your vault', 'info');
      return;
    }

    let message = `Found ${newPasskeys.length} new passkey${newPasskeys.length !== 1 ? 's' : ''} to import`;
    if (duplicates.length > 0) {
      message += ` (${duplicates.length} duplicate${duplicates.length !== 1 ? 's' : ''} will be skipped)`;
    }
    showStatus(message, 'info');

    actionsEl.classList.remove('hidden');
  }

  function showPreview(allPasskeys: any[], duplicates: any[]): void {
    previewListEl.innerHTML = '';

    allPasskeys.forEach((pk) => {
      const isDuplicate = duplicates.some((d) => d.id === pk.id);
      const item = document.createElement('div');
      item.className = 'preview-item';
      item.innerHTML = `
        <div>
          <div class="preview-item-site">${importEscapeHtml(pk.rpId || 'Unknown Site')}</div>
          <div class="preview-item-user">${importEscapeHtml(pk.user?.name || pk.user?.displayName || 'Unknown User')}</div>
        </div>
        <span class="preview-item-status ${isDuplicate ? 'duplicate' : 'new'}">
          ${isDuplicate ? 'Already exists' : 'New'}
        </span>
      `;
      previewListEl.appendChild(item);
    });

    previewEl.classList.add('visible');
  }

  async function performImport(): Promise<void> {
    if (newPasskeys.length === 0) {
      showStatus('No new passkeys to import', 'error');
      return;
    }

    try {
      // Get existing passkeys
      const result = await chrome.storage.local.get(IMPORT_PASSKEY_STORAGE_KEY);
      const existingPasskeys: any[] = result[IMPORT_PASSKEY_STORAGE_KEY] || [];

      // Merge
      const mergedPasskeys = [...existingPasskeys, ...newPasskeys];

      // Save
      await chrome.storage.local.set({ [IMPORT_PASSKEY_STORAGE_KEY]: mergedPasskeys });

      // Show success
      showStatus(
        `Successfully imported ${newPasskeys.length} passkey${newPasskeys.length !== 1 ? 's' : ''}!`,
        'success'
      );

      // Hide action buttons
      actionsEl.classList.add('hidden');

      // Update close link text
      closeLink.textContent = 'Close and return to extension';
    } catch (error) {
      console.error('Error importing passkeys:', error);
      showStatus('Failed to import passkeys: ' + (error as Error).message, 'error');
    }
  }

  function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
    statusEl.textContent = message;
    statusEl.className = 'status ' + type;
  }

  function resetState(): void {
    parsedData = null;
    newPasskeys = [];
    existingIds = new Set();
    statusEl.className = 'status';
    statusEl.textContent = '';
    previewEl.classList.remove('visible');
    previewListEl.innerHTML = '';
    actionsEl.classList.add('hidden');
    fileInput.value = '';
  }

  function importEscapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }
})();
