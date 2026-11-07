# Fenko Vault for iOS

Native SwiftUI vault for iOS 17 and later. Development preview; not ready for
production accounts or App Store distribution.

The app stores passkeys and authenticator entries in an encrypted vault unlocked
with Face ID, Touch ID, or the device passcode. It provides encrypted backups,
TOTP and HOTP codes, QR setup, and encrypted sync with other Fenko Vault devices.
The AutoFill extension creates and uses passkeys in Safari and supported apps.

## Build on a Mac

Install Xcode with the iOS SDK and XcodeGen, then generate the project:

```bash
brew install xcodegen
cd ios
xcodegen generate
open FenkoVault.xcodeproj
```

Select an iPhone simulator to try the app. For a signed device build, select your
Apple Developer team for the app and credential provider targets. Both targets
need the shared App Group and Keychain Sharing capabilities, plus AutoFill
Credential Provider support.

The app uses native Swift code for its interface, vault, and sync. No web app
bundle build is needed. A small local WebKit page is used only to migrate data
from the previous iOS app.

## Test with a free Apple account

A separate target supports standalone vault testing on an iPhone:

```bash
cd ios
xcodegen generate --spec project-devsync.yml
open FenkoVaultSync.xcodeproj
```

Select your Personal Team and connected iPhone in Xcode, then run the app.
This target has its own vault and does not provide system passkey AutoFill.

Full AutoFill testing, TestFlight, and App Store distribution require a paid
Apple Developer Program membership.

## Backups and upgrades

Before upgrading, export an encrypted backup and keep its password separately.
Keep that backup until you have checked your entries in the new app.

On first unlock, the native app migrates data from the previous iOS app into its
encrypted vault. If migration cannot finish, retain the existing installation
and backup. Do not uninstall it to troubleshoot an upgrade.

In Settings, use **Export encrypted backup** to save a backup or **Import backup**
to restore one. Backups contain credentials; keep the sync recovery phrase
separately to reconnect devices to the same chain.

## Validation still required

Before release, verify upgrades on an existing installation, real-device passkey
creation and sign-in, camera setup, clipboard expiry, backup recovery, and sync
with the browser extensions and Android. Signing, store assets, and distribution
setup also remain required.
