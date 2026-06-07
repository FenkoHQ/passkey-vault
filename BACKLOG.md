# Passkey Vault — Backlog

## Phase 1: Harden (done)

- [x] Core WebAuthn interception and signing
- [x] Nostr-based sync with BIP-39 seed phrase
- [x] Integrate SecureStorage — encrypt private keys at rest with master password
- [x] Session lock with auto-timeout (30min default)
- [x] Split `background.ts` into modules (cbor, prf, base64)
- [x] Replace `any` types with proper interfaces in core modules
- [x] Remove dead code (StorageAgent, unused types, crypto barrel)
- [x] Consolidate duplicated base64 utilities
- [x] Fix silent error swallowing in catch blocks
- [x] Password-protect export files (AES-256-GCM, password required on import)
- [x] TOTP / HOTP store (RFC 6238 / 4226) with otpauth:// import, live codes, clipboard copy
- [x] TOTP entries included in encrypted backup and Nostr sync bundle

## Phase 2: Complete

- [x] Firefox MV3 migration
- [x] Sync UX — connection status indicator, retry logic, auto-refresh
- [ ] Finish emergency UI (Konami code activates, but the interface is a stub)
- [ ] Domain allowlist/blocklist for WebAuthn interception
- [ ] Improve test coverage (sync service, message handlers, UI)

## Phase 3: Differentiate

- [ ] Biometric unlock (use a hardware key to unlock the vault)
- [ ] Passkey sharing via encrypted link
- [ ] Discoverable credentials (resident keys)
- [ ] Browser-native credential provider API (Chrome 127+)
- [ ] Audit log — which sites used which passkeys, when

## Phase 4: Ecosystem

- [ ] Mobile companion app or PWA joining Nostr sync chain
- [ ] CLI tool for headless passkey operations (CI/CD, testing)
- [ ] Safari extension
- [ ] Self-hosted relay option for sync
