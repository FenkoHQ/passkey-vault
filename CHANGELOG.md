# Changelog

All notable changes to Passkey Vault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **Advanced settings for the WebAuthn ceremony.** Everything the vault used to
  assert as a constant is now a setting: user verification, the backup flags
  (BE/BS), the signature counter, the AAGUID, and the reported attachment. The
  card shows the exact flag byte each combination produces, for registration and
  for sign-in.

  Defaults reproduce 0.9.6 byte for byte, so a vault that never opens the page
  signs exactly as before. What the settings are for:

  - **User verification** — the vault has no verification step, so reporting UV
    is a claim it cannot back up. Leaving it on is what makes Google and other
    passwordless sign-ins work; turning it off is honest and makes those sites
    ask for a password. Real verification is still [#5](https://github.com/FenkoHQ/passkey-vault/issues/5).
  - **Backup flags** — a synced credential is what BE/BS were added to describe,
    but sites read them in different ways, so they are off until you say so.
  - **Signature counter** — every device keeps its own counter, which looks like
    a cloned authenticator to a site that checks. Sending zero is what platform
    passkey providers do.
  - **AAGUID** — keep the Fenko Vault identity so sites show the vault by name
    and icon, or go all-zero and stay anonymous.

## [0.9.6] - 2026-08-06

### Fixed

- **Sign-in broke on every site that requires user verification.** 0.9.5 cleared
  the UV bit in authenticator data, so Google and anyone else asking for
  `userVerification` treated the assertion as a 2-Step-Verification-only
  security key and fell back to asking for a password. The bit is set again and
  existing credentials work as before.

  It is still a claim the extension cannot back up — a click in the consent card
  is user presence, not verification — and it stays that way until there is a
  real ceremony to derive it from. That work needs a mandatory vault PIN and is
  tracked in [#5](https://github.com/FenkoHQ/passkey-vault/issues/5) for 1.x.
  Android is unaffected: it gates signing on the device lock screen and reports
  what actually happened.

## [0.9.5] - 2026-08-05

A security release covering the findings from a full-codebase review. The vault
now actually encrypts what it said it encrypted, the lock actually locks, and
the Android provider stops vouching for callers it never checked.

**Cross-site passkeys still work.** 0.9.3 broke Meta/Facebook sign-in by
rejecting any cross-site `rpId`, and 0.9.4 fixed it with Related Origin
Requests. Nothing here narrows that path: the new secure-origin check runs
before the same-site test and only rejects plain `http:` pages, the
`/.well-known/webauthn` lookup is untouched, and `https://*/*` host permissions
are retained so the background can still fetch it. The Related Origin Requests
test suite passes unchanged.

### Security

- **Android: any installed app could mint assertions for any site.** The
  provider derived the signing origin as `https://<rpId>` whenever
  `CallingAppInfo.getOrigin()` was null, which is every non-browser caller. It
  now derives `android:apk-key-hash:<sha256(signing cert)>` from the caller's
  own certificate, so a relying party's asset links decide whether that app is
  allowed. A caller-supplied `clientDataHash` is honoured only for callers the
  platform has confirmed as privileged.
- **Silent assertions from a compromised page.** The consent dialogs live in the
  page's DOM, so any script on the site could hide them and synthesise a click,
  producing signed assertions with no user present. Every dialog handler now
  ignores untrusted events.
- **A web page could write to the vault.** `PASSKEY_STORE_REQUEST` was relayed
  from the page without any origin validation, letting any site plant entries
  under another site's `rpId` or overwrite a real credential's private key. The
  relay and the background handler are both gone.
- **The PIN did not encrypt anything.** Private keys and TOTP seeds were written
  to cleartext storage on every save, alongside the encrypted copy. The
  encrypted store is now the only copy once a PIN is set, and existing vaults
  are migrated on first unlock (see below).
- **The lock did not lock.** A locked vault still signed assertions and emitted
  TOTP codes by falling back to the cleartext copy. Credential and TOTP
  operations are now refused until the vault is unlocked, and the popup reads
  through the background worker instead of raw storage.
- **Both providers claimed the user was verified when nobody was.** The UV flag
  was hardcoded on every ceremony. The extension no longer sets it, and Android
  sets it only when the device lock screen actually verified the user.
- **`http:` pages could run ceremonies.** WebAuthn is secure-context only, but
  the content script accepted direct page messages on plain HTTP, exposing PRF
  output that never reaches the relying party and so cannot be caught by any
  server-side origin check. Insecure origins are now rejected, and the Chrome
  manifest matches `https` plus localhost rather than `<all_urls>`.
- **Stored XSS in the mobile vault.** An imported backup could put markup in a
  passkey's `counter` and reach the native bridge, which hands out every private
  key and TOTP seed. The value is coerced to a number, imported records are
  normalised, and both WebViews now ship a Content-Security-Policy.
- **Release workflow leaked its Chrome Web Store token.** The access token
  derived from the refresh token was interpolated into `run:` blocks, and the
  runner prints those verbatim; only registered secrets get masked. It is now
  registered with `::add-mask::`.

### Added

- **A feedback link, in the extension popup and settings sidebar and in the
  mobile app's header and Tools tab.** It opens a short form in your browser.
  Nothing is collected automatically and the form asks for no account. If a
  website ever refuses one of your passkeys, that is the single most useful
  thing you can tell us.

### Breaking

- **Sites that require user verification will refuse the extension.** The
  extension used to claim the user had been verified on every ceremony, which
  was untrue: it has no verification step. It no longer sets that flag, so a
  relying party configured with `userVerification: "required"` will now reject
  the assertion instead of accepting a false one. Sites that ask for user
  verification as preferred, which is most of them, are unaffected. Restoring
  compatibility means adding a real per-assertion prompt, not restating the
  claim.
- **A locked vault no longer signs anything.** With a PIN set, sign-in, TOTP
  codes and vault listings all fail until you unlock in the popup, including
  after the 30-minute auto-lock. Previously the lock only hid the UI while the
  vault kept serving credentials from the cleartext copy.
- **PIN'd vaults must export a backup once, after upgrading.** Changes to the
  vault (adding or deleting a passkey or 2FA code, importing, resetting,
  changing the PIN) are refused until you export an encrypted backup from the
  popup, which the popup prompts for. **Signing in keeps working throughout.**
  This exists because the upgrade is one-way: the first unlock deletes the
  cleartext copies, and 0.9.4 treats those as authoritative, so unlocking on the
  older build would overwrite the encrypted store with an empty one and destroy
  the vault. The backup is your route back to 0.9.4, via its import page. Vaults
  with no PIN are unaffected, since nothing is deleted for them.
- **Chrome no longer runs on plain `http://` pages**, other than `localhost` and
  `127.0.0.1`. WebAuthn is secure-context only and browsers never offered it
  there. `host_permissions` narrows from `*://*/*` to `https://*/*`. Firefox was
  already scoped this way.
- **Android prompts for the device lock screen on every passkey use.** There is
  no way to opt out, since the alternative is signing while claiming a
  verification that never happened.
- **Sync starts only once the vault is unlocked**, for vaults with a PIN. The
  chain seed now lives in the encrypted store, so after a browser restart sync
  stays down until you unlock. It resumes automatically on unlock.
- **Removing your PIN writes the vault back out unencrypted**, which is the
  pre-PIN layout and what makes the vault readable again without a PIN.
- Android credentials created by another app now record that app's signing
  identity as their origin instead of a fabricated `https://<rpId>`. Existing
  records keep the value they were stored with.
- The internal `STORE_PASSKEY` message and its `PASSKEY_STORE_REQUEST` page
  relay are gone. No shipped code sent either.

### Changed

- **Existing vaults migrate on first unlock.** Vaults with a PIN set before this
  release keep a cleartext copy that the encrypted store may never have seen.
  The first unlock merges those records in, keeping whichever is newer, then
  deletes the cleartext keys. Nothing is lost, and the cleanup runs once.
- **Android asks for your lock screen before signing**, using whichever method
  the device has: fingerprint, face, PIN or pattern. Devices with no lock screen
  at all still work, and report the user as unverified rather than pretending.
- **Removing your PIN restores the unencrypted layout**, so the vault stays
  readable exactly as it was before the PIN was set.

## [0.9.4] - 2026-07-15

A hotfix for cross-origin passkeys that broke in 0.9.3.

### Fixed

- **Facebook (and other cross-site) passkeys work again.** The 0.9.3 hardening
  pass rejected any request where the `rpId` was not same-site with the page,
  which broke RPs that deliberately use a cross-site RP ID — most visibly Meta,
  whose Facebook passkeys use the `accounts.meta.com` RP ID on
  `accountscenter.facebook.com`. The vault now implements WebAuthn Related
  Origin Requests: when the RP ID is not same-site, it consults the RP's
  `/.well-known/webauthn` file and honours the origins the RP itself authorizes
  (subject to the spec's five-label cap). The same-origin anti-forgery
  protection from 0.9.3 is unchanged — the allowlist is served from the RP ID's
  own HTTPS origin, which only the RP controls.

## [0.9.3] - 2026-07-13

A security hardening pass and an easier way to get the vault onto your other
devices.

### Security

- **Cross-origin passkey forgery fixed.** The content script now binds the
  request origin to `window.location.origin` and checks the `rpId` against the
  registrable suffix, closing an account-takeover path.
- **No more silent passkey creation.** Creating a passkey now shows a confirm
  dialog.
- **PRF secret is no longer exposed.** It was being embedded in the
  server-visible `authenticatorData`; it now stays local.
- **XSS hardening.** Quote-safe `escapeHtml` and an escaped `device.id`.
- **Storage data-loss fixes.** Sync merges, popup deletes, and imports now keep
  the encrypted store consistent (reconcile-on-unlock), imports restore TOTP and
  validate before clearing, and changing the master PIN is now atomic.
- **Cross-device sync now derives a shared key.** The PBKDF2 salt is derived
  deterministically from the chain ID instead of being random per device.

### Added

- **Get the vault on your other devices.** The sync Devices tab now links to the
  Chrome, Firefox, and Android listings so you can install and join the chain
  from another device.

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
