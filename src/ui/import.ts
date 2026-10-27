/**
 * Import Page for Fenko Vault
 *
 * Takes a file from any of the supported providers — encrypted Fenko backups,
 * CXF, password-manager exports, authenticator-app backups, or a filled-in
 * CSV template — and turns it into vault records.
 */

import { formatCount, initAndLocalize, t } from '../i18n';
import { initTheme } from '../theme';
import {
  acceptedExtensions,
  materialize,
  parseImport,
  passkeyCsvTemplate,
  totpCsvTemplate,
  type MaterializedImport,
} from '../porting';

(function () {
  'use strict';

  const TEMPLATE_MIME = 'text/csv';

  interface ExistingPasskey {
    id: string;
    credentialId?: string;
    rpId?: string;
  }

  // State
  let pending: MaterializedImport | null = null;

  // DOM elements
  const dropZone = document.getElementById('drop-zone') as HTMLElement;
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  const chooseFileBtn = document.getElementById('choose-file-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('status') as HTMLElement;
  const previewEl = document.getElementById('preview') as HTMLElement;
  const previewListEl = document.getElementById('preview-list') as HTMLElement;
  const previewTitleEl = document.getElementById('preview-title') as HTMLElement;
  const actionsEl = document.getElementById('actions') as HTMLElement;
  const cancelBtn = document.getElementById('cancel-btn') as HTMLButtonElement;
  const importBtn = document.getElementById('import-btn') as HTMLButtonElement;
  const closeLink = document.getElementById('close-link') as HTMLAnchorElement;
  const totpTemplateBtn = document.getElementById('totp-template-btn') as HTMLButtonElement;
  const passkeyTemplateBtn = document.getElementById('passkey-template-btn') as HTMLButtonElement;

  // Initialize
  void Promise.all([initAndLocalize(), initTheme()]);
  fileInput.accept = acceptedExtensions().join(',');
  setupEventListeners();

  function setupEventListeners(): void {
    fileInput.addEventListener('change', handleFileSelect);

    dropZone.addEventListener('dragover', handleDragOver);
    dropZone.addEventListener('dragleave', handleDragLeave);
    dropZone.addEventListener('drop', handleDrop);

    cancelBtn.addEventListener('click', resetState);
    importBtn.addEventListener('click', performImport);
    chooseFileBtn.addEventListener('click', () => fileInput.click());
    totpTemplateBtn?.addEventListener('click', () =>
      downloadTemplate('fenko-mfa-template.csv', totpCsvTemplate())
    );
    passkeyTemplateBtn?.addEventListener('click', () =>
      downloadTemplate('fenko-passkey-template.csv', passkeyCsvTemplate())
    );
    closeLink.addEventListener('click', (e) => {
      e.preventDefault();
      window.close();
    });
  }

  function downloadTemplate(fileName: string, content: string): void {
    const url = URL.createObjectURL(new Blob([content], { type: TEMPLATE_MIME }));
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
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
      void processFile(files[0]);
    }
  }

  function handleFileSelect(e: Event): void {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) {
      void processFile(file);
    }
  }

  async function processFile(file: File): Promise<void> {
    resetState();

    try {
      const text = await file.text();
      const encrypted = readEncryptedBackup(text);

      if (encrypted) {
        await processEncryptedBackup(encrypted);
        return;
      }

      await processContent(file.name, text);
    } catch (error) {
      console.error('Error processing file:', error);
      showStatus(t('importFailedProcess', { error: (error as Error).message }), 'error');
    }
  }

  /** Our own password-protected backup, which must be decrypted first. */
  function readEncryptedBackup(text: string): Record<string, string> | null {
    try {
      const data = JSON.parse(text);
      const isEncrypted = data?.encrypted === true && data.data && data.iv && data.salt;
      return isEncrypted ? (data as Record<string, string>) : null;
    } catch {
      return null;
    }
  }

  async function processEncryptedBackup(fileData: Record<string, string>): Promise<void> {
    const password = await showImportPasswordPrompt();
    if (password === null) {
      showStatus(t('importCancelled'), 'info');
      return;
    }

    showStatus(t('importDecrypting'), 'info');

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
      showStatus(t('importWrongPassword'), 'error');
      return;
    }

    await processContent('backup.json', response.data);
  }

  /** Parse, de-duplicate against the vault, then show what would be added. */
  async function processContent(fileName: string, text: string): Promise<void> {
    let parsed;
    try {
      parsed = parseImport(fileName, text);
    } catch (error) {
      showStatus((error as Error).message, 'error');
      return;
    }

    const [passkeyResult, totpResult] = await Promise.all([
      chrome.runtime.sendMessage({ type: 'LIST_PASSKEYS' }),
      chrome.runtime.sendMessage({ type: 'LIST_TOTP_ENTRIES' }),
    ]);
    if (!passkeyResult.success) {
      throw new Error(passkeyResult.error || 'Failed to load vault');
    }

    pending = await materialize(parsed, {
      passkeys: (passkeyResult.passkeys || []) as ExistingPasskey[],
      totpEntries: totpResult.success ? totpResult.entries || [] : [],
    });

    showPreview(pending);
  }

  function showPreview(result: MaterializedImport): void {
    previewListEl.innerHTML = '';
    previewTitleEl.textContent = t('importDetectedFormat', { format: result.formatLabel });

    for (const passkey of result.passkeys) {
      appendPreviewItem(passkey.rpId, passkey.user.name || passkey.user.displayName, 'passkey');
    }
    for (const entry of result.totpEntries) {
      appendPreviewItem(entry.issuer || t('commonUnknownSite'), entry.account, 'mfa');
    }

    for (const repair of result.backupRepairs) {
      appendPreviewItem(repair.rpId, t('importBackupRepairHint'), 'repair');
    }

    const repairs = result.backupRepairs.length;
    const duplicates = result.duplicatePasskeys + result.duplicateTotp - repairs;
    for (let i = 0; i < duplicates; i++) {
      appendPreviewItem(t('importAlreadyExists'), '', 'duplicate');
    }

    previewEl.classList.add('visible');

    const total = result.passkeys.length + result.totpEntries.length;
    if (total === 0 && repairs === 0) {
      showStatus(t('importNothingNew'), 'info');
      reportWarnings(result);
      return;
    }

    let message = t('importFoundEntries', {
      passkeys: result.passkeys.length,
      totp: result.totpEntries.length,
    });
    if (duplicates > 0) {
      message += t('importDuplicatesSkipped', {
        count: duplicates,
        plural: duplicates !== 1 ? 's' : '',
      });
    }
    if (repairs > 0) {
      message += ` ${formatCount('importBackupRepairs', repairs)}`;
    }
    showStatus(message, 'info');
    reportWarnings(result);

    actionsEl.classList.remove('hidden');
  }

  function reportWarnings(result: MaterializedImport): void {
    if (result.warnings.length === 0) return;
    const note = document.createElement('div');
    note.className = 'preview-warnings';
    note.textContent = `${t('importSkippedItems', { count: result.warnings.length })} ${result.warnings.join(' · ')}`;
    previewListEl.appendChild(note);
  }

  function appendPreviewItem(
    title: string,
    subtitle: string,
    kind: 'passkey' | 'mfa' | 'duplicate' | 'repair'
  ): void {
    const labels = {
      passkey: t('importKindPasskey'),
      mfa: t('importKindMfa'),
      duplicate: t('importAlreadyExists'),
      repair: t('importKindRepair'),
    };

    const item = document.createElement('div');
    item.className = 'preview-item';
    item.innerHTML = `
      <div>
        <div class="preview-item-site">${importEscapeHtml(title || t('commonUnknownSite'))}</div>
        <div class="preview-item-user">${importEscapeHtml(subtitle || t('commonUnknownUser'))}</div>
      </div>
      <span class="preview-item-status ${kind === 'duplicate' ? 'duplicate' : 'new'}">
        ${labels[kind]}
      </span>
    `;
    previewListEl.appendChild(item);
  }

  function showImportPasswordPrompt(): Promise<string | null> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.style.cssText =
        'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999';
      overlay.innerHTML = `
        <div style="background:#222;padding:20px;border-radius:8px;width:300px;max-width:90%">
          <h3 style="margin:0 0 8px;color:#fff;font-size:15px">${t('importEnterBackupPassword')}</h3>
          <p style="margin:0 0 12px;color:#999;font-size:13px">${t('importPasswordDesc')}</p>
          <input type="password" id="import-pw" placeholder="${t('commonPassword')}" autocomplete="off"
            style="width:100%;padding:8px;border:1px solid #444;background:#1a1a1a;color:#fff;border-radius:4px;font-size:13px;box-sizing:border-box;margin-bottom:8px" />
          <div id="import-pw-error" style="color:#ef4444;font-size:12px;margin-bottom:8px;display:none"></div>
          <div style="display:flex;gap:8px">
            <button id="import-pw-cancel" style="flex:1;padding:8px;border:1px solid #444;background:transparent;color:#ccc;border-radius:4px;cursor:pointer">${t('commonCancel')}</button>
            <button id="import-pw-ok" style="flex:1;padding:8px;border:none;background:#FCD34D;color:#000;border-radius:4px;cursor:pointer;font-weight:600">${t('importDecrypt')}</button>
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
          err.textContent = t('importPasswordRequired');
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

  async function performImport(): Promise<void> {
    if (
      !pending ||
      pending.passkeys.length + pending.totpEntries.length + pending.backupRepairs.length === 0
    ) {
      showStatus(t('importNoNew'), 'error');
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'IMPORT_VAULT',
        payload: {
          passkeys: pending.passkeys,
          totpEntries: pending.totpEntries,
          backupRepairs: pending.backupRepairs,
        },
      });
      if (!response.success) throw new Error(response.error || 'Import failed');

      let message = t('importSucceeded', {
        passkeys: Number(response.passkeys || 0),
        totp: Number(response.totpEntries || 0),
      });
      const repaired = Number(response.backupRepaired || 0);
      if (repaired > 0) message += ` ${formatCount('importBackupRepaired', repaired)}`;
      showStatus(message, 'success');

      actionsEl.classList.add('hidden');
      closeLink.textContent = t('importCloseReturn');
    } catch (error) {
      console.error('Error importing:', error);
      showStatus(t('importFailed', { error: (error as Error).message }), 'error');
    }
  }

  function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
    statusEl.textContent = message;
    statusEl.className = 'status ' + type;
  }

  function resetState(): void {
    pending = null;
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
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
})();
