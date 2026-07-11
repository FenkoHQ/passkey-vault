# Fenko Vault AAGUID

## Value

```
d2717a32-9851-48a8-9961-b264c97a411a
```

Byte form (16 bytes, big-endian, as embedded in attested credential data):

```
d2 71 7a 32 98 51 48 a8 99 61 b2 64 c9 7a 41 1a
```

This is a randomly generated UUID version 4 (version nibble `4` in the third
group, RFC 4122 variant nibble `9` in the fourth group). It identifies the
**authenticator model** ("Fenko Vault"), not any user or credential — every
Fenko Vault install reports the same value, exactly like 1Password, Bitwarden,
and iCloud Keychain report theirs.

## Where it is defined (single source of truth per platform)

The same 16 bytes are used byte-for-byte on every platform. If this value ever
changes it MUST be changed in all three places together.

| Platform | File | Symbol |
|----------|------|--------|
| Web extension | `src/background/cbor.ts` | `PASSKEY_VAULT_AAGUID` |
| Android | `android/app/src/main/java/nz/fenko/passkeyvault/WebAuthnNative.java` | `AAGUID` |
| iOS | `ios/Shared/WebAuthn.swift` | `aaguid` |

Verify consistency:

```sh
grep -rn '0xd2, 0x71, 0x7a, 0x32' src android/app ios
```

## Why it is non-zero

The AAGUID is emitted in attested credential data during registration. With
`none` attestation, a strict reading of the WebAuthn privacy model expects the
client to zero the AAGUID so relying parties cannot fingerprint the
authenticator model without asking for attestation.

Fenko Vault intentionally reports a real, stable AAGUID instead, so that
consumer relying parties (Google, GitHub, etc.) display **"Fenko Vault"** and
the Fenko icon in their passkey lists. This is the same trade-off every major
passkey manager makes, and it is what the community AAGUID registry below
exists to support.

Trade-off, stated plainly: a stable AAGUID reveals to a relying party that the
user's authenticator is Fenko Vault. It is a *model* identifier shared by all
users, so it does not deanonymize an individual. If a future deployment needs
to hide the authenticator brand, zero the AAGUID in the three files above (and
drop the registry entry).

## Registry submission (makes RPs render the brand)

Relying parties resolve the AAGUID to a name and icon via the community
registry consumed by Chrome and others:

> https://github.com/passkeydeveloper/passkey-authenticator-aaguids

To register (or update) the Fenko Vault entry:

1. Fork that repository.
2. Merge the entry in [`registry-entry.json`](./registry-entry.json) into the
   repository's `aaguid.json` (a single object keyed by AAGUID; append the
   `d2717a32-…` key with its `name`/`icon_dark`/`icon_light`).
3. Keep `combined_aaguid.json` / `aaguid.csv` in sync if the repo's tooling
   does not regenerate them.
4. Open a pull request (the repo requires a complete GitHub profile with an
   organization name and contact info for vendor verification).

Registry rule: icons MUST be base64-encoded **SVG** data URIs, square, and pure
vector (no embedded PNG/JPG).

The icon is the Fenko Vault fox-shield logo ([`vault-icon.svg`](./vault-icon.svg)):
a fennec fox forming a keyhole on an amber shield. It was vectorized from the
raster brand logo (`docs/brand/fenko-vault-logo.png`, which has no vector
master) by color-separating the amber shield and navy fox and tracing each with
potrace, then centering the portrait art in a square `1260×1260` viewBox. The
amber shield is its own background, so a single icon reads on both light and
dark RP backgrounds — `icon_light` and `icon_dark` are identical.

`registry-entry.json` embeds it. To regenerate after a logo change, re-run the
color-separate → potrace → combine steps and then `scratchpad/gen-aaguid-entry.js`.

(The previous lock-box icon `icon.png` is deprecated and must not be used.)

## Status

- [x] Proper value: valid random UUIDv4, unique to Fenko Vault.
- [x] Verified: byte-identical across web, Android, and iOS.
- [x] Documented: this file, referenced from each platform's source.
- [ ] Registered: PR to `passkey-authenticator-aaguids` not yet opened
      (entry prepared in `registry-entry.json`).
