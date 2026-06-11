// Basic Chrome Extension API type definitions for Fenko Vault
// These are minimal definitions to enable TypeScript compilation
// Note: WebAuthn types are provided by TypeScript's DOM lib
/* eslint-disable @typescript-eslint/no-explicit-any */

declare global {
  namespace chrome {
    namespace runtime {
      interface RuntimeStatic {
        sendMessage(message: any, callback?: (response: any) => void): void;
        onMessage: MessageHandlers;
        onInstalled: Event<OnInstalledDetailsType>;
        onStartup: Event<undefined>;
        onSuspend: Event<undefined>;
        id?: string;
        lastError?: { message?: string };
        getURL(path: string): string;
      }

      interface MessageHandlers {
        addListener(
          callback: (
            message: any,
            sender: MessageSender,
            sendResponse: (response?: any) => void
          ) => boolean | void
        ): void;
        // eslint-disable-next-line @typescript-eslint/ban-types
        removeListener(callback: Function): void;
      }

      interface Event<T> {
        addListener(callback: (details: T) => void): void;
      }

      interface OnInstalledDetailsType {
        reason: 'install' | 'update' | 'chrome_update' | 'shared_module_update';
        previousVersion?: string;
      }
    }

    namespace storage {
      interface StorageArea {
        get(keys?: string | string[] | object | null): Promise<object>;
        set(items: object): Promise<void>;
        remove(keys: string | string[]): Promise<void>;
        clear(): Promise<void>;
      }

      interface LocalStorageArea extends StorageArea {}
      interface SyncStorageArea extends StorageArea {}

      interface StorageStatic {
        local: LocalStorageArea;
        sync: SyncStorageArea;
      }
    }

    namespace tabs {
      interface Tab {
        id?: number;
        url?: string;
        title?: string;
      }

      interface TabsStatic {
        query(queryInfo: any, callback?: (tabs: Tab[]) => void): Promise<Tab[]>;
        sendMessage(tabId: number, message: any, callback?: (response: any) => void): void;
        create(createProperties: any, callback?: (tab: Tab) => void): void;
      }
    }

    namespace scripting {
      interface ScriptingStatic {
        executeScript(injection: any, callback?: (results: any[]) => void): Promise<any[]>;
        insertCSS(injection: any, callback?: () => void): Promise<void>;
      }
    }
  }

  // MessageSender for Chrome extension messaging
  interface MessageSender {
    id?: string;
    url?: string;
    tab?: chrome.tabs.Tab;
    frameId?: number;
  }
}

export {};
