# Fenko Vault for iOS

Native iOS app + **AutoFill credential provider extension** that serves passkeys
(and shows 2FA codes) system-wide, the iOS counterpart to the Android provider.
Same vault model and WebAuthn wire format, so passkeys sync and verify identically
across web, Android, and iOS.

> **Status: compiles + crypto verified; not yet device-tested.** Both targets build
> clean on Xcode 26.4 / iOS 26 SDK (simulator, unsigned). The WebAuthn crypto is
> verified by a cross-platform test: our keys round-trip a full sign/verify, and a
> named-curve PKCS8 key (the canonical WebCrypto/Java format) imports to the correct
> public key. What's left is signing config + running the provider on a real device.
> See [Known gaps](#known-gaps).

## Architecture

```
ios/
├── project.yml                  XcodeGen spec — the .xcodeproj is generated, not committed
├── Shared/                      compiled into BOTH targets
│   ├── WebAuthn.swift           COSE key, authData, attestation, ES256, PKCS8 <-> raw P-256
│   ├── VaultStore.swift         App Group store + ASCredentialIdentityStore registration
│   ├── PasskeyRecord.swift      vault model (matches the browser/Android JSON shape)
│   ├── TOTP.swift               RFC 6238 codes
│   └── Base64.swift
├── App/                         host app (SwiftUI): onboarding, list, backup import
└── CredentialProvider/          ASCredentialProviderExtension (iOS 17+ passkey provider)
```

- **App ↔ extension data sharing:** App Group `group.nz.fenko.passkeyvault`
  (separate processes, so this replaces Android's in-process SharedPreferences).
- **Crypto:** CryptoKit `P256` (ES256). Private keys use the canonical **PKCS8
  base64** encoding the other platforms use; CryptoKit has no PKCS8 API, so
  `WebAuthn.swift` carries a small PKCS8 ↔ raw-scalar shim.
- **AAGUID** matches the Android provider so attestations look identical.

## Apple-side prerequisites (one-time)

1. **Apple Developer Program** membership ($99/yr).
2. App IDs in the Developer portal:
   - `nz.fenko.passkeyvault` — capabilities: App Groups, AutoFill Credential Provider.
   - `nz.fenko.passkeyvault.CredentialProvider` — capability: App Groups.
3. **App Group** `group.nz.fenko.passkeyvault` enabled on both App IDs.
4. App record in **App Store Connect** (for TestFlight).
5. **App Store Connect API key** (Users and Access → Integrations → App Store
   Connect API). Note the Key ID, Issuer ID, and download the `.p8` once.

## Build locally (on a Mac)

```bash
brew install xcodegen
cd ios
DEVELOPMENT_TEAM=YOURTEAMID xcodegen generate
open FenkoVault.xcodeproj
# select your team on both targets if needed, run on a device (iOS 17+)
```

Enable it on the device: **Settings → General → AutoFill & Passwords → Fenko
Vault**. Import a vault backup (the extension's exported JSON) from the app's
import button to populate passkeys, then test a passkey sign-in in Safari/an app.

## Ship to TestFlight (CI)

Pushing a tag `ios-v0.1.0` runs `.github/workflows/ios-testflight.yml` on a macOS
runner: XcodeGen → archive → export → upload. Set these repo secrets first:

| Secret | What |
| --- | --- |
| `APPLE_TEAM_ID` | 10-char Developer Team ID |
| `ASC_KEY_ID` | App Store Connect API key ID |
| `ASC_ISSUER_ID` | API key issuer ID |
| `ASC_KEY_P8_BASE64` | `base64 -i AuthKey_XXXX.p8` |

Then: `git tag ios-v0.1.0 && git push origin ios-v0.1.0`. After upload, add
testers in App Store Connect → TestFlight.

## Known gaps

Verified already: full build of both targets (Xcode 26.4), the `ASPasskey*`
provider API signatures, and the PKCS8 import/sign path (cross-platform test).
Still to do:

- **On-device functional test** — run the provider on a real iOS 17+ device:
  enable it in Settings, import a backup, and complete an actual passkey
  registration + sign-in. The simulator can't exercise system AutoFill.
- **`prepareCredentialList` UI** — currently auto-selects the first matching
  passkey. A real picker (list multiple candidates) is nicer.
- **App icon / launch screen** — placeholder; add real assets.
- **Sync** — the app imports backups but does not yet run the Nostr sync client
  the extension/Android app use. Future work.
- **No code reuse from the web UI** — this is a native SwiftUI app, by design
  (the chosen "native AutoFill provider" approach), unlike the WebView Android app.
```
