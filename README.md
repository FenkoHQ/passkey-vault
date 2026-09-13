# Fenko Vault

Intercepts WebAuthn API calls and stores passkeys locally, bypassing the browser's native passkey UI. Available as a browser extension for Chromium browsers and Firefox, and as an Android passkey provider app.

## Download

| Platform | Get it | Status |
| --- | --- | --- |
| <img src="https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png" width="16" alt=""/> **Chrome** · <img src="https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png" width="16" alt=""/> **Edge** · <img src="https://raw.githubusercontent.com/alrra/browser-logos/main/src/brave/brave_24x24.png" width="16" alt=""/> **Brave** · <img src="https://raw.githubusercontent.com/alrra/browser-logos/main/src/opera/opera_24x24.png" width="16" alt=""/> **Opera** | [Chrome Web Store](https://chromewebstore.google.com/detail/passkey-vault/lopekoolgoijpmaidblgfgelbkfkgmod) | Available |
| <img src="https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png" width="16" alt=""/> **Firefox** | [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/fenko-vault/) | Available |
| <img src="https://cdn.simpleicons.org/android/3DDC84" width="16" alt=""/> **Android** | [Google Play](https://play.google.com/store/apps/details?id=nz.fenko.passkeyvault) | Available |

> Found a bug? [Open an issue](https://github.com/FenkoHQ/passkey-vault/issues).

---

## Screenshots

<table>
  <tr>
    <td align="center" valign="top" width="33%">
      <img src="docs/readme/vault.png" width="240" alt="Passkeys and 2FA codes in one searchable vault"/>
    </td>
    <td align="center" valign="top" width="33%">
      <img src="docs/readme/totp.png" width="240" alt="Expandable details for every entry"/>
    </td>
    <td align="center" valign="top" width="33%">
      <img src="docs/readme/search.png" width="240" alt="Search across passkeys and 2FA codes at once"/>
    </td>
  </tr>
  <tr>
    <td align="center"><sub><b>One searchable vault</b></sub></td>
    <td align="center"><sub><b>Details on every entry</b></sub></td>
    <td align="center"><sub><b>Find anything fast</b></sub></td>
  </tr>
  <tr>
    <td align="center" valign="top">
      <img src="docs/readme/add-code.png" width="240" alt="Add a 2FA code by otpauth URI, pasted QR, or uploaded image"/>
    </td>
    <td align="center" valign="top">
      <img src="docs/readme/lock.png" width="240" alt="Lock the vault behind a PIN"/>
    </td>
    <td></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Add codes by URI or QR image</b></sub></td>
    <td align="center"><sub><b>Lock behind a PIN</b></sub></td>
    <td></td>
  </tr>
</table>

---

## Features

- **WebAuthn interception** — captures `navigator.credentials.create()` and `navigator.credentials.get()` before the browser handles them
- **Local storage** — passkeys stay in browser local storage, no external server
- **TOTP / 2FA codes** — built-in RFC 6238 / 4226 authenticator with live codes, clipboard copy, and `otpauth://` import (paste a URI, paste a QR screenshot, or upload a QR image — decoded locally, no camera)
- **Unified vault** — passkeys and 2FA codes share one searchable list with per-type filters; each entry expands to show its details
- **Vault lock** — optional 4–12 digit master PIN encrypts the vault at rest and locks the popup; set, change, or remove it any time
- **Backup & import** — export all passkeys (including private keys) and TOTP entries as a JSON file, import on another device
- **Move in from anywhere** — import passkeys and MFA seeds from CXF, Bitwarden, Proton Pass, Dashlane, 1Password, KeePassXC, LastPass, Keeper, Google Authenticator, Aegis, 2FAS, andOTP, FreeOTP+, Raivo and Ente Auth; export back out as CXF, `otpauth://` or CSV — Options → Import & Export ([details](docs/porting/README.md))
- **Cross-device sync** — optional Nostr-based sync chain using a BIP-39 seed phrase; passkeys and 2FA codes sync end-to-end encrypted
- **Emergency access** — standalone recovery page for vault management without the extension popup
- **Chrome, Firefox & Android** — one codebase; browser extension plus a native Android passkey provider

---

## Installation

### Chrome, Edge, Brave, Opera

[Install from the Chrome Web Store](https://chromewebstore.google.com/detail/passkey-vault/lopekoolgoijpmaidblgfgelbkfkgmod). The same listing covers all Chromium-based browsers.

### Firefox

[Install from Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/fenko-vault/).

### Android

[Install from Google Play](https://play.google.com/store/apps/details?id=nz.fenko.passkeyvault), then enable Fenko Vault under **Settings → Passwords & accounts → Passkeys** as a credential provider.

Prefer sideloading? A signed APK ships with each [GitHub release](https://github.com/FenkoHQ/passkey-vault/releases). Note the APK and the Play build are signed with different keys, so a device can't upgrade between them — pick one.

### Build from source

Requires Node.js 18+.

```bash
git clone https://github.com/FenkoHQ/passkey-vault.git
cd passkey-vault
npm install

npm run build          # Chrome
npm run build:firefox  # Firefox
npm run build:all      # Both
```

**Load in Chrome:**

1. Open `chrome://extensions/`
2. Enable Developer mode
3. Click "Load unpacked" → select `dist/`

**Load in Firefox:**

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `dist-firefox/manifest.json`

---

## How it works

1. A content script injects into every page and overrides the native WebAuthn API
2. On `credentials.create()`, the background script generates an ECDSA P-256 key pair, creates a valid attestation response, and stores the passkey
3. On `credentials.get()`, it signs the challenge with the stored private key using proper CBOR encoding
4. The popup reads directly from `chrome.storage.local` — no background message passing for display
5. TOTP codes are derived locally from each entry's secret using HMAC-SHA1/256/512; the popup caches the current code and refreshes it once per second while the vault is open
6. With a master PIN set, the vault is also written as an AES-GCM encrypted copy and the popup gates behind a lock screen; removing the PIN drops the encrypted copy

---

## How sync works

Cross-device sync is optional and off by default. When you enable it, your devices exchange end-to-end encrypted messages over public [Nostr](https://github.com/nostr-protocol/nips) relays — there is no Fenko account, no server that holds your vault, and nothing a relay operator can read.

**Setup.** Enabling sync generates a BIP-39 seed phrase (the "sync chain"). You type that phrase into your other devices; every device holding the phrase is on the chain. The phrase never leaves your devices.

**Key derivation.** From the seed, each device derives two things with PBKDF2 (100k iterations, SHA-256): an AES-256-GCM key for encrypting sync payloads, and a secp256k1 keypair for signing Nostr events. Different chains derive different keys.

**Transport.** Sync messages are standard Nostr events (NIP-01): kind `30078` (application data) with a `d` tag of `pksync-<chainId>`, signed with BIP340 Schnorr signatures. The event content is AES-GCM ciphertext. A relay — or anyone watching one — sees ciphertext, the chain tag, and event timing. Passkey IDs, relying-party domains, device names, and counts of what you store are all inside the encrypted payload.

**What gets synced.** Passkeys (including private keys — that's the point of sync) and TOTP entries. Merging is additive: a device adds entries it doesn't have and updates ones with a newer creation time. Sync never deletes local data.

**Receiving.** Devices verify each event's Schnorr signature and ID hash before decrypting, ignore replayed event IDs, and discard anything that doesn't decrypt with the chain key.

**Relays.** Events are published to all configured relays and subscriptions run on all of them, so two devices sync if they share at least one working relay. The defaults:

| Relay | Operator |
| --- | --- |
| `wss://vaultsync.fenko.nz` | Fenko (us) — runs [nosflare](https://github.com/Spl0itable/nosflare), accepts only kind 30078 sync events |
| `wss://relay.damus.io` | Damus |
| `wss://nos.lol` | nos.lol |
| `wss://relay.nostr.band` | nostr.band |

You can add or remove relays in the extension options. On restricted networks, whitelisting `vaultsync.fenko.nz` (WebSocket, port 443) is enough for sync to work.

---

## Project structure

```
src/
├── background/         # Service worker / background script
├── content/            # Content script + WebAuthn injection
├── crypto/             # BIP-39, ECDSA, AES-GCM, secure storage
├── porting/            # Import/export for other providers' formats (CXF, CSV, vendor JSON)
├── sync/               # Nostr-based sync service
├── ui/                 # popup, options, import, sync-setup, sync-settings, emergency
├── manifest.json       # Chrome MV3
└── manifest.firefox.json
```

---

## Security

- Passkeys and TOTP secrets live in `chrome.storage.local`. Setting a master PIN adds an AES-GCM encrypted copy and a lock screen, but a raw copy is kept for display — treat the profile as sensitive regardless
- Export files contain private keys and TOTP secrets — treat them like passwords. The CXF, otpauth:// and CSV exports are plaintext because the receiving app expects that; delete them once imported. The popup's password-protected backup is the one to keep
- Sync payloads are end-to-end encrypted; relays never see plaintext (see [How sync works](#how-sync-works))
- Anyone who obtains your sync seed phrase can join your chain and receive your vault — protect it like the vault itself
- This is a research/developer tool, not a production credential manager

---

## License

MIT
