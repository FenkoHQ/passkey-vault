// Global type definitions for the PassKey Vault extension

export interface PasskeyData {
  id: string;
  name: string;
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  publicKey: string;
  privateKey: string;
  counter: number;
  createdAt: Date;
  lastUsed: Date;
  metadata: PasskeyMetadata;
}

export interface PasskeyMetadata {
  id?: string;
  name?: string;
  rpId?: string;
  deviceType?: string;
  backupEligible?: boolean;
  backupState?: boolean;
  transports?: string[];
  algorithm?: string;
  createdAt?: Date;
  lastUsed?: Date;
}

export interface EncryptedBackup {
  version: string;
  algorithm: string;
  salt: string;
  iv: string;
  data: string;
  checksum: string;
  timestamp: number;
}

export interface ExtensionMessage {
  type: 'STORE_PASSKEY' | 'RETRIEVE_PASSKEY' | 'BACKUP' | 'RESTORE' | 'ACTIVATE_UI';
  payload: any;
  requestId: string;
  timestamp: number;
}

export interface SecurityContext {
  sessionId: string;
  userId?: string;
  permissions: Permission[];
  trustLevel: TrustLevel;
  expiresAt: Date;
}

export interface Permission {
  id: string;
  name: string;
  granted: boolean;
  expiresAt?: Date;
}

export type TrustLevel = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityOperation {
  type: string;
  data: any;
  requiresAuth: boolean;
  timestamp: Date;
}

export interface ActivityEvent {
  type: string;
  source: string;
  timestamp: Date;
  data: any;
  suspicious: boolean;
}

export interface AuditEvent {
  id: string;
  type: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  timestamp: Date;
  data: any;
  userId?: string;
}

export interface BackupFile {
  version: string;
  encrypted: EncryptedBackup;
  metadata: {
    passkeyCount: number;
    createdAt: Date;
    version: string;
  };
}

// WebAuthn related types
export interface CredentialCreationOptions {
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

export interface CredentialRequestOptions {
  challenge: ArrayBuffer;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  extensions?: any;
}

// Storage interfaces
export interface StorageArea {
  get(keys?: string | string[] | object | null): Promise<object>;
  set(items: object): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  clear(): Promise<void>;
}

// Background script context
export interface BackgroundContext {
  storage: StorageArea;
  runtime: typeof chrome.runtime;
  tabs: typeof chrome.tabs;
  scripting: typeof chrome.scripting;
}

// Content script context
export interface ContentContext {
  document: Document;
  window: Window;
  chrome: typeof chrome;
}

// Chrome extension specific types
export interface ChromeMessageSender {
  id?: string;
  url?: string;
  tab?: chrome.tabs.Tab;
  frameId?: number;
}

// Cryptography types
export interface EncryptionKey {
  key: CryptoKey;
  salt: ArrayBuffer;
  iterations: number;
}

export interface KeyDerivationOptions {
  password: string;
  salt: ArrayBuffer;
  iterations: number;
  keyLength: number;
  hash: string;
}
