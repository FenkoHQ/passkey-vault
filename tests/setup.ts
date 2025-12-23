// Jest setup file for test environment

// Polyfill TextEncoder and TextDecoder for jsdom environment
if (typeof TextEncoder === 'undefined') {
  global.TextEncoder = require('util').TextEncoder;
}
if (typeof TextDecoder === 'undefined') {
  global.TextDecoder = require('util').TextDecoder;
}

// Mock Chrome APIs
const mockChrome = {
  runtime: {
    sendMessage: jest.fn(),
    onMessage: {
      addListener: jest.fn(),
      removeListener: jest.fn(),
    },
    getURL: jest.fn((path: string) => `chrome-extension://test/${path}`),
    id: 'test-extension-id',
  },
  storage: {
    local: {
      get: jest.fn(),
      set: jest.fn(),
      remove: jest.fn(),
      clear: jest.fn(),
    },
    sync: {
      get: jest.fn(),
      set: jest.fn(),
      remove: jest.fn(),
      clear: jest.fn(),
    },
  },
  tabs: {
    query: jest.fn(),
    sendMessage: jest.fn(),
    create: jest.fn(),
  },
  scripting: {
    executeScript: jest.fn(),
    insertCSS: jest.fn(),
  },
};

// Extend global window with chrome mock
Object.defineProperty(window, 'chrome', {
  value: mockChrome,
  writable: true,
});

// Mock WebAuthn API
const mockNavigator = {
  credentials: {
    create: jest.fn(),
    get: jest.fn(),
  },
};

Object.defineProperty(global, 'navigator', {
  value: mockNavigator,
  writable: true,
});

// Use real crypto API from Node.js for testing
const nodeCrypto = require('crypto').webcrypto;

Object.defineProperty(global, 'crypto', {
  value: nodeCrypto,
  writable: true,
});

// Setup global test utilities
global.createMockPasskey = () => ({
  id: 'test-passkey-id',
  name: 'Test Passkey',
  rpId: 'example.com',
  rpName: 'Example Site',
  userId: 'test-user-id',
  userName: 'test@example.com',
  publicKey: 'test-public-key',
  privateKey: 'test-private-key',
  counter: 0,
  createdAt: new Date(),
  lastUsed: new Date(),
  metadata: {
    deviceType: 'platform',
    backupEligible: true,
    backupState: true,
    transports: ['internal'],
    algorithm: 'ES256',
  },
});

global.createMockCredential = () => ({
  id: 'test-credential-id',
  rawId: new Uint8Array([1, 2, 3]),
  response: {
    attestationObject: new Uint8Array([4, 5, 6]),
    clientDataJSON: JSON.stringify({
      type: 'webauthn.create',
      challenge: 'test-challenge',
      origin: 'https://example.com',
    }),
  },
  getClientExtensionResults: () => ({}),
  getType: () => 'public-key' as PublicKeyCredentialType,
});

// Configure test timeout
jest.setTimeout(10000);

// Mock console methods in tests to reduce noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Export mocks for use in tests
export { mockChrome, mockNavigator };
