import { initAndLocalize, t } from '../i18n';
import { initTheme } from '../theme';

/**
 * Emergency UI Controller for Fenko Vault
 *
 * This module handles the hidden emergency interface that can be activated
 * via specific sequences or triggers.
 */

interface EmergencyUIState {
  isVisible: boolean;
  isAuthenticated: boolean;
  currentTab: 'passkeys' | 'backup' | 'settings';
}

type EmergencyTab = EmergencyUIState['currentTab'];

function isEmergencyTab(value: string | null): value is EmergencyTab {
  return value === 'passkeys' || value === 'backup' || value === 'settings';
}

class EmergencyUIController {
  private state: EmergencyUIState = {
    isVisible: false,
    isAuthenticated: false,
    currentTab: 'passkeys',
  };

  private container: HTMLElement | null = null;

  constructor() {
    this.initialize();
  }

  /**
   * Initialize the emergency UI
   */
  private async initialize(): Promise<void> {
    await Promise.all([initAndLocalize(), initTheme()]);
    console.log('Fenko Vault: Emergency UI initializing');

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setupUI());
    } else {
      this.setupUI();
    }
  }

  /**
   * Set up the UI components
   */
  private setupUI(): void {
    // Create main container
    this.createContainer();

    // Set up tab switching
    this.setupTabs();

    // Set up form handlers
    this.setupForms();

    // Set up keyboard shortcuts
    this.setupKeyboardShortcuts();

    console.log('Fenko Vault: Emergency UI setup complete');
  }

  /**
   * Create the main UI container
   */
  private createContainer(): void {
    this.container = document.createElement('div');
    this.container.id = 'passext-emergency-ui';
    this.container.className = 'passext-hidden';
    this.container.innerHTML = `
      <div class="passext-modal-overlay">
        <div class="passext-modal">
          <div class="passext-header">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>

            <h2>${t('appName')} - ${t('emergencyAccess')}</h2>
            <button class="passext-close" id="passext-close-btn">&times;</button>
          </div>

          <div class="passext-content">
            <div id="passext-login" class="passext-panel">
              <h3>${t('emergencyAuthRequired')}</h3>
              <form id="passext-login-form">
                <label for="passext-master-password">${t('emergencyMasterPassword')}</label>
                <input type="password" id="passext-master-password" required>
                <button type="submit" id="passext-unlock-btn">${t('popupUnlock')}</button>
                <div id="passext-auth-error" class="passext-error"></div>
              </form>
            </div>

            <div id="passext-main" class="passext-panel passext-hidden">
              <div class="passext-tabs">
                <button class="passext-tab active" data-tab="passkeys">${t('emergencyPasskeys')}</button>
                <button class="passext-tab" data-tab="backup">${t('emergencyBackup')}</button>
                <button class="passext-tab" data-tab="settings">${t('emergencySettings')}</button>
              </div>

              <div id="passext-passkeys" class="passext-tab-content">
                <h3>${t('emergencyStoredPasskeys')}</h3>
                <div id="passext-passkey-list" class="passext-list"></div>
                <button id="passext-refresh-btn">${t('commonRefresh')}</button>
              </div>

              <div id="passext-backup" class="passext-tab-content passext-hidden">
                <h3>${t('emergencyBackupRestore')}</h3>
                <div class="passext-backup-actions">
                  <button id="passext-create-backup-btn">${t('emergencyCreateBackup')}</button>
                  <button id="passext-download-backup-btn">${t('emergencyDownloadBackup')}</button>
                  <input type="file" id="passext-backup-file" accept=".json,.backup">
                  <button id="passext-restore-backup-btn">${t('emergencyRestore')}</button>
                </div>
                <div id="passext-backup-status"></div>
              </div>

              <div id="passext-settings" class="passext-tab-content passext-hidden">
                <h3>${t('emergencySecuritySettings')}</h3>
                <form id="passext-settings-form">
                  <label>
                    <input type="checkbox" id="passext-auto-backup"> ${t('emergencyAutoBackup')}
                  </label>
                  <label>
                    <input type="checkbox" id="passext-biometric"> ${t('emergencyBiometric')}
                  </label>
                  <label for="passext-lock-timeout">${t('emergencyLockTimeout')}</label>
                  <input type="number" id="passext-lock-timeout" value="30" min="1" max="1440">
                  <button type="submit" id="passext-save-settings-btn">${t('emergencySaveSettings')}</button>
                  <button type="button" id="passext-change-password-btn">${t('emergencyChangeMaster')}</button>
                  <button type="button" id="passext-emergency-wipe-btn" class="passext-danger">${t('emergencyWipe')}</button>
                </form>
                <div id="passext-settings-status"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Add styles
    this.addStyles();

    // Add to document
    document.body.appendChild(this.container);
  }

  /**
   * Add CSS styles for the emergency UI
   */
  private addStyles(): void {
    const styles = `
      #passext-emergency-ui {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }

      #passext-emergency-ui.passext-hidden {
        display: none;
      }

      .passext-modal-overlay {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        justify-content: center;
        align-items: center;
      }

      .passext-modal {
        background: #0D1117;
        border: 1px solid rgba(245, 166, 35, 0.35);
        border-radius: 18px;
        width: 90%;
        max-width: 500px;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
      }

      .passext-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem;
        border-bottom: 1px solid rgba(209, 217, 224, 0.16);
      }

      .passext-header h2 {
        margin: 0;
        color: #F5A623;
      }

      .passext-close {
        background: none;
        border: none;
        color: #888;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 0;
        width: 30px;
        height: 30px;
      }

      .passext-close:hover {
        color: #fff;
      }

      .passext-content {
        padding: 1rem;
      }

      .passext-panel {
        display: block;
      }

      .passext-panel.passext-hidden {
        display: none;
      }

      .passext-tabs {
        display: flex;
        border-bottom: 1px solid rgba(209, 217, 224, 0.16);
        margin-bottom: 1rem;
      }

      .passext-tab {
        flex: 1;
        padding: 0.75rem;
        background: none;
        border: none;
        color: #888;
        cursor: pointer;
        border-bottom: 2px solid transparent;
      }

      .passext-tab.active {
        color: #F5A623;
        border-bottom-color: #F5A623;
      }

      .passext-tab-content {
        display: block;
      }

      .passext-tab-content.passext-hidden {
        display: none;
      }

      .passext-form-group {
        margin-bottom: 1rem;
      }

      label {
        display: block;
        margin-bottom: 0.5rem;
        color: #ccc;
      }

      input[type="password"],
      input[type="number"] {
        width: 100%;
        padding: 0.5rem;
        border: 1px solid #30363D;
        border-radius: 10px;
        background: #161B22;
        color: #fff;
        box-sizing: border-box;
      }

      input[type="file"] {
        margin: 1rem 0;
      }

      button {
        background: #D4920A;
        color: #fff;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 10px;
        cursor: pointer;
        margin-right: 0.5rem;
        margin-bottom: 0.5rem;
      }

      button:hover {
        background: #357abd;
      }

      button.passext-danger {
        background: #CF222E;
      }

      button.passext-danger:hover {
        background: #ff5252;
      }

      .passext-error {
        color: #F85149;
        margin-top: 0.5rem;
        font-size: 0.875rem;
      }

      .passext-success {
        color: #3FB950;
        margin-top: 0.5rem;
        font-size: 0.875rem;
      }

      .passext-list {
        max-height: 200px;
        overflow-y: auto;
        border: 1px solid #30363D;
        border-radius: 12px;
        padding: 0.5rem;
        margin: 1rem 0;
      }

      .passext-list-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem;
        border-bottom: 1px solid #333;
      }

      .passext-list-item:last-child {
        border-bottom: none;
      }

      h3 {
        color: #F5A623;
        margin-top: 0;
      }
    `;

    const styleElement = document.createElement('style');
    styleElement.textContent = styles;
    document.head.appendChild(styleElement);
  }

  /**
   * Set up tab switching
   */
  private setupTabs(): void {
    if (!this.container) return;

    const tabs = this.container.querySelectorAll('.passext-tab');
    const contents = this.container.querySelectorAll('.passext-tab-content');

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const tabName = tab.getAttribute('data-tab');
        if (!isEmergencyTab(tabName)) {
          return;
        }
        if (!tabName) return;

        // Update active tab
        tabs.forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');

        // Update active content
        contents.forEach((content) => {
          content.classList.add('passext-hidden');
        });

        const activeContent = this.container?.querySelector(`#passext-${tabName}`);
        if (activeContent) {
          activeContent.classList.remove('passext-hidden');
        }

        this.state.currentTab = tabName;
      });
    });
  }

  /**
   * Set up form handlers
   */
  private setupForms(): void {
    if (!this.container) return;

    // Login form
    const loginForm = this.container.querySelector('#passext-login-form') as HTMLFormElement;
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleLogin();
      });
    }

    // Settings form
    const settingsForm = this.container.querySelector('#passext-settings-form') as HTMLFormElement;
    if (settingsForm) {
      settingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleSaveSettings();
      });
    }

    // Close button
    const closeBtn = this.container.querySelector('#passext-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.hide());
    }

    // Other button handlers will be added in future phases
  }

  /**
   * Set up keyboard shortcuts
   */
  private setupKeyboardShortcuts(): void {
    document.addEventListener('keydown', (e) => {
      if (!this.state.isVisible) return;

      // Escape to close
      if (e.key === 'Escape') {
        this.hide();
      }

      // Ctrl+Shift+S for settings
      if (e.ctrlKey && e.shiftKey && e.key === 'S') {
        this.switchToTab('settings');
      }

      // Ctrl+Shift+B for backup
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        this.switchToTab('backup');
      }
    });
  }

  /**
   * Show the emergency UI
   */
  public show(): void {
    if (this.container) {
      this.container.classList.remove('passext-hidden');
      this.state.isVisible = true;
    }
  }

  /**
   * Hide the emergency UI
   */
  public hide(): void {
    if (this.container) {
      this.container.classList.add('passext-hidden');
      this.state.isVisible = false;
      this.state.isAuthenticated = false;

      // Reset to login screen
      const loginPanel = this.container.querySelector('#passext-login');
      const mainPanel = this.container.querySelector('#passext-main');
      if (loginPanel) loginPanel.classList.remove('passext-hidden');
      if (mainPanel) mainPanel.classList.add('passext-hidden');
    }
  }

  /**
   * Switch to a specific tab
   */
  private switchToTab(tabName: string): void {
    if (!this.container || !this.state.isAuthenticated) return;

    const tab = this.container.querySelector(`[data-tab="${tabName}"]`) as HTMLElement;
    if (tab) {
      tab.click();
    }
  }

  /**
   * Handle login (placeholder)
   */
  private async handleLogin(): Promise<void> {
    if (!this.container) return;

    const passwordInput = this.container.querySelector(
      '#passext-master-password'
    ) as HTMLInputElement;
    const errorDiv = this.container.querySelector('#passext-auth-error') as HTMLElement;

    // Placeholder authentication logic
    if (passwordInput && passwordInput.value === 'test') {
      this.state.isAuthenticated = true;

      // Show main interface
      const loginPanel = this.container.querySelector('#passext-login');
      const mainPanel = this.container.querySelector('#passext-main');
      if (loginPanel) loginPanel.classList.add('passext-hidden');
      if (mainPanel) mainPanel.classList.remove('passext-hidden');

      // Clear password
      passwordInput.value = '';
      if (errorDiv) errorDiv.textContent = '';
    } else {
      if (errorDiv) {
        errorDiv.textContent = t('emergencyInvalidPassword');
      }
    }
  }

  /**
   * Handle save settings (placeholder)
   */
  private async handleSaveSettings(): Promise<void> {
    if (!this.container) return;

    const statusDiv = this.container.querySelector('#passext-settings-status') as HTMLElement;
    if (statusDiv) {
      statusDiv.textContent = t('emergencySettingsSaved');
      statusDiv.className = 'passext-success';
    }
  }
}

// Initialize when the script loads
const emergencyUI = new EmergencyUIController();

// Export for testing
export default emergencyUI;
