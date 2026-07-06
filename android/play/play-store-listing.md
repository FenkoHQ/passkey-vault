# Google Play — manual submission pack (Fenko Vault)

**The listing is live:** <https://play.google.com/store/apps/details?id=nz.fenko.passkeyvault>

Everything needed to create the Play Console listing for `nz.fenko.passkeyvault`
by hand. Copy fields straight into the console; asset paths are relative to the
repo root.

---

## 1. App bundle (.aab)

Play needs a **signed** `.aab`. The bundle is built from `android/build-aab.sh`;
the signing step needs the upload-key password, so run it yourself:

```bash
env ANDROID_KEYSTORE_PASSWORD='<your keystore password>' \
    VERSION_CODE=902 \
    ./android/build-aab.sh
# -> android/dist/fenko-vault-0.9.2.aab
```

- `versionName` is read from `package.json` (currently **0.9.2**).
- `versionCode` **902** — must strictly increase on every future upload.
- Signing key: `android/signing/passkey-vault.jks`, alias `passkey-vault`. On the
  **first** upload, enroll this as your **upload key** under Play App Signing
  (Google then holds the distribution key). Note: this key differs in role from
  the GitHub-Releases APK, which is self-signed with the same file — a device can
  hold one or the other, not upgrade between them.

> The bundle built this session includes the in-app dialog / import / file-export
> fixes that are still uncommitted in the working tree. Commit those before
> building the upload AAB if you want the shipped bundle to match git.

---

## 2. Store listing — text

### App name (max 30 chars)
```
Fenko Vault: Passkey & 2FA
```
(The full "Fenko Vault | Passkey and MFA Manager" is 37 chars and won't fit Play's
30-char title limit.)

### Short description (max 80 chars)
```
Passkeys and 2FA codes, on your device. Encrypted sync, no cloud account.
```

### Full description (max 4000 chars)
```
Fenko Vault keeps your passkeys and two-factor codes in one place, on your device. Sign in without passwords, get your 2FA codes where your passkeys already live, and sync across your devices with no cloud account.

Sync is end-to-end encrypted, so your keys move between your devices without anyone else seeing them — not even us. Nothing leaves your device unless you choose to back it up or sync it.

Highlights:

- A system passkey provider: create and use passkeys in the apps and browsers that support them
- A built-in authenticator: time-based 2FA codes with a live countdown and one-tap copy
- Add a code by pasting its link or scanning a QR — read on your device
- End-to-end encrypted sync across your devices, with no account to create
- Unlock with your fingerprint, face, or screen lock; optional auto-lock
- Encrypted backups you export and restore yourself
- Everything lives on your device — nothing is uploaded unless you back up or sync

Fenko Vault is built for people who want their passkeys and 2FA codes to stay private and portable. Because everything lives on your device, keep an offline backup: there is no recovery if you lose every device and every backup.
```

---

## 3. Categorization & contact

| Field | Value |
|---|---|
| App category | Tools |
| Tags | passkey, authenticator, 2FA, password manager, security |
| Email | security@fenko.nz |
| Website | https://fenko.nz |
| Privacy policy | https://fenko.nz/privacy-policy |

---

## 4. Graphics (all present, sizes verified)

| Asset | Spec | File |
|---|---|---|
| App icon | 512×512 PNG | `android/play/icon-512.png` |
| Feature graphic | 1024×500 PNG | `android/play/feature-graphic.png` |
| Phone screenshot 1 | 1080×2400 | `android/play/screenshots/01-vault.png` |
| Phone screenshot 2 | 1080×2400 | `android/play/screenshots/02-add.png` |
| Phone screenshot 3 | 1080×2400 | `android/play/screenshots/03-sync.png` |
| Phone screenshot 4 | 1080×2400 | `android/play/screenshots/04-tools.png` |
| Phone screenshot 5 | 1080×2400 | `android/play/screenshots/05-tools-security.png` |

Play requires 2–8 phone screenshots; five are provided.

---

## 5. Data safety form

- **Does your app collect or share any user data?** No.
- Data stays on the device. Optional sync sends only end-to-end encrypted bundles
  through relays the user chooses; Fenko runs no server that can read them.
- No analytics, no advertising, no tracking, no third-party data sharing.
- **Data encrypted in transit:** Yes (sync is E2E encrypted).
- **Users can request data deletion:** Not applicable — there is no account and no
  server-side data; the user controls all data on-device.

## 6. Content rating questionnaire

- Category: Utility / Productivity / Communication → **Tools**.
- No violence, sexual content, profanity, gambling, or user-generated content.
- No data shared with third parties.
- Expected rating: **Everyone / PEGI 3**.

## 7. App access

- All functionality is available without an account or login. The vault unlocks
  with the device biometric/screen lock. Note this under "All functionality is
  available without special access" (no test credentials needed).

---

## 8. "What's new" (release notes for this version)

```
First Play Store release of Fenko Vault for Android: a passkey provider and 2FA
authenticator that keeps everything on your device, with optional end-to-end
encrypted sync and encrypted backups.
```
