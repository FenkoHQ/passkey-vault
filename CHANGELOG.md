# Changelog

All notable changes to Passkey Vault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.9.2] - 2026-06-30

A Firefox fix that makes the extension actually work there, and a clearer store
name.

### Fixed

- **Firefox now works.** The extension talked to the browser through promise-style
  `chrome.*` calls, which only return promises on Chrome. On Firefox those calls
  returned nothing, so the vault never loaded and passkey sign-in hung. Firefox now
  uses its promise-based `browser` API, so storage reads and the WebAuthn flow work.
- **Firefox manifest:** dropped a background `type: module` declaration that older
  supported Firefox versions reject, and stopped emitting the unsupported
  `version_name` key.

### Changed

- **Clearer name.** The extension is now listed as **Fenko Vault | Passkey and MFA
  Manager** in both stores.

## [0.9.1] - 2026-06-14

A fix for sync being hard to reach, plus a Firefox store requirement.

### Fixed

- **Sync is reachable again.** Settings → Sync pointed you to the popup to set
  it up, but the popup had no sync entry — a dead end. There's now a **Set up
  sync** button in Settings → Sync, and the popup's top-bar icon opens sync
  settings directly.

### Changed

- **Firefox:** the manifest now declares its data collection (none) — newly
  required by addons.mozilla.org. Fenko Vault is offline and end-to-end
  encrypted, so it reports collecting no data.

## [0.9.0] - 2026-06-08

The big one: Passkey Vault is now a 2FA authenticator too, everything lives in
one vault, and you can lock it behind a PIN.

### Added

- **TOTP / 2FA authenticator** (RFC 6238 / RFC 4226). Time-based and
  counter-based codes are generated locally, refresh once per second, and copy
  to the clipboard on click. SHA-1/256/512, 6–8 digits, custom periods.
- **Add codes three ways** — paste an `otpauth://` URI, paste a QR screenshot
  (Ctrl/⌘+V), or upload a QR image. Decoded on-device with jsQR; no camera and
  no new permissions.
- **Unified vault** — passkeys and 2FA codes share one searchable list with
  per-type filters (show/hide each), and every entry expands to show its
  details (issuer, account, algorithm, digits, period/counter, added date).
- **Master PIN** — set an optional 4–12 digit PIN that encrypts the vault at
  rest (AES-GCM) and gates the popup behind a lock screen. Set, change, or
  remove it from Settings → Security, lock on demand from the popup, or let it
  auto-lock after a timeout.
- **No-recovery warning** — a dismissable banner (popup) and a sidebar notice
  (settings) make clear that sync is end-to-end encrypted, the servers never
  see your keys, and there is no recovery if you lose every device and backup.

### Changed

- Backups now include TOTP entries alongside passkeys; the encrypted Nostr sync
  bundle carries 2FA codes too (end-to-end encrypted, count only on the wire).
- Reworked the popup chrome: grouped lock + settings buttons, counts folded
  into the search placeholder ("Search in N passkeys and M codes"), and the
  footer pinned to the bottom.
- Consistent "Del" buttons across passkey and 2FA rows.
- README screenshots are now dark-theme, native-ratio captures.

### Fixed

- HOTP codes are generated through the counter path instead of being derived as
  TOTP (the counter was previously ignored).
- Several state panels (2FA view, "no results", the lock screen PIN field) that
  could linger or render over the wrong screen now hide correctly.

## [0.8.1] - 2026 (prior release)

- Chrome Web Store listing assets and copy.

## [0.8.0] - 2026 (prior release)

- Assigned a Passkey Vault AAGUID to attested credentials.

## [0.7.0] - prior release

- Native browser/OS passkey fallback passthrough for sites without a stored
  passkey, with interception controls (disabled / all-sites / allowlist).

Older releases are listed on the
[GitHub releases page](https://github.com/FenkoHQ/passkey-vault/releases).

[0.9.0]: https://github.com/FenkoHQ/passkey-vault/releases/tag/v0.9.0
[0.8.1]: https://github.com/FenkoHQ/passkey-vault/releases/tag/v0.8.1
[0.8.0]: https://github.com/FenkoHQ/passkey-vault/releases/tag/v0.8.0
[0.7.0]: https://github.com/FenkoHQ/passkey-vault/releases/tag/v0.7.0
