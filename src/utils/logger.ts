/**
 * Configurable logging utility for PassKey Vault
 *
 * By default, only errors are logged to the console.
 * Enable debug mode in the extension settings to see all logs.
 */

const STORAGE_KEY = 'debug_logging_enabled';

class Logger {
  private debugEnabled: boolean = false;
  private initialized: boolean = false;

  async init(): Promise<void> {
    if (this.initialized) return;

    try {
      const result = await chrome.storage.local.get(STORAGE_KEY);
      this.debugEnabled = result[STORAGE_KEY] === true;
      this.initialized = true;
    } catch {
      // If we can't access storage, default to false
      this.debugEnabled = false;
      this.initialized = true;
    }
  }

  async setDebugEnabled(enabled: boolean): Promise<void> {
    this.debugEnabled = enabled;
    try {
      await chrome.storage.local.set({ [STORAGE_KEY]: enabled });
    } catch (error) {
      console.error('Failed to save debug logging preference:', error);
    }
  }

  isDebugEnabled(): boolean {
    return this.debugEnabled;
  }

  // Always log errors
  error(message: string, ...args: any[]): void {
    console.error(`PassKey Vault: ${message}`, ...args);
  }

  // Only log warnings, info, and debug messages if debug mode is enabled
  warn(message: string, ...args: any[]): void {
    if (this.debugEnabled) {
      console.warn(`PassKey Vault: ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.debugEnabled) {
      console.log(`PassKey Vault: ${message}`, ...args);
    }
  }

  debug(message: string, ...args: any[]): void {
    if (this.debugEnabled) {
      console.debug(`PassKey Vault: ${message}`, ...args);
    }
  }
}

export const logger = new Logger();
