// Basic Chrome Extension API type definitions for PassKey Vault
// These are minimal definitions to enable TypeScript compilation

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

  // Extend existing interfaces
  interface Navigator {
    credentials: CredentialsContainer;
  }

  interface CredentialsContainer {
    create(options?: CredentialCreationOptions): Promise<Credential | null>;
    get(options?: CredentialRequestOptions): Promise<Credential | null>;
  }

  interface Credential {
    id: string;
    type: string;
    rawId?: ArrayBuffer;
    response?: any;
    getClientExtensionResults?(): any;
    getType?(): string;
  }

  interface CredentialCreationOptions {
    publicKey?: PublicKeyCredentialCreationOptions;
    signal?: AbortSignal;
  }

  interface CredentialRequestOptions {
    publicKey?: PublicKeyCredentialRequestOptions;
    signal?: AbortSignal;
  }

  interface PublicKeyCredentialCreationOptions {
    rp: PublicKeyCredentialRpEntity;
    user: PublicKeyCredentialUserEntity;
    challenge: ArrayBuffer;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    excludeCredentials?: PublicKeyCredentialDescriptor[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    attestation?: AttestationConveyancePreference;
    extensions?: any;
  }

  interface PublicKeyCredentialRequestOptions {
    challenge: ArrayBuffer;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptor[];
    userVerification?: UserVerificationRequirement;
    extensions?: any;
  }

  interface PublicKeyCredentialRpEntity {
    id: string;
    name: string;
  }

  interface PublicKeyCredentialUserEntity {
    id: string;
    name: string;
    displayName: string;
  }

  interface PublicKeyCredentialParameters {
    type: string;
    alg: number;
  }

  interface PublicKeyCredentialDescriptor {
    type: string;
    id: ArrayBuffer;
    transports?: string[];
  }

  interface AuthenticatorSelectionCriteria {
    authenticatorAttachment?: string;
    requireResidentKey?: boolean;
    residentKey?: string;
    userVerification?: UserVerificationRequirement;
  }

  type AttestationConveyancePreference = 'none' | 'indirect' | 'direct';
  type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

  interface MessageSender {
    id?: string;
    url?: string;
    tab?: chrome.tabs.Tab;
    frameId?: number;
  }
}

export {};
