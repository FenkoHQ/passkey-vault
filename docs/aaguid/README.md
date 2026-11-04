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

## FIDO Metadata Service entry (makes RPs render the brand)

Relying parties and browsers resolve an AAGUID to a display name and icon
through the FIDO Alliance Metadata Service (MDS). Fenko Vault is listed there
as a FIDO2 non-CTAP passkey provider: `none` attestation, ES256 only,
software key protection. The statement submitted on 2026-11-04 is
[`mds-statement.json`](./mds-statement.json).

The older community registry (`passkeydeveloper/passkey-authenticator-aaguids`)
stopped accepting submissions on 2026-11-01, empties its lists on 2027-01-06
and is archived on 2027-07-06. Fenko Vault's entry there is not migrated
automatically; the MDS entry replaces it.

### Updating the entry

1. Sign in at <https://mymds.fidoalliance.org/metadata-management> with the
   Fenko vendor account.
2. Open the Fenko Vault statement, or **Add New** → **Sample FIDO2 Non-CTAP**
   for a fresh one.
3. Paste [`mds-statement.json`](./mds-statement.json). Only these fields are
   ours to change; leave the rest as the sample sets them:
   `authenticationAlgorithms`, `aaguid`, `friendlyNames`, `description`,
   `providerLogoLight`, `providerLogoDark`. Do not add `cxConfigURL`.
4. **Analyze**, then save and submit for publication.

Field limits from the Metadata Statement spec v3.1.1: `description` is
English ASCII, 200 characters max; each `friendlyNames` entry 63 characters
max.

### Icon

MDS requires the SVG Tiny Portable/Secure profile: root element declares
`version="1.2"` and `baseProfile="tiny-ps"`, first child is a `<title>` holding
the English friendly name, square viewBox, pure vector, no comments, scripts or
raster. [`vault-icon-tiny-ps.svg`](./vault-icon-tiny-ps.svg) is that form of
the fox-shield logo and is what the statement embeds as a base64 data URL in
both `providerLogoLight` and `providerLogoDark`. The amber shield is its own
background, so one file serves light and dark.

[`vault-icon.svg`](./vault-icon.svg) is the plain source SVG, vectorized from
the raster brand logo (`docs/brand/fenko-vault-logo.png`, which has no vector
master) by color-separating the amber shield and navy fox and tracing each
with potrace. After a logo change: regenerate `vault-icon.svg`, re-wrap it in
the Tiny PS envelope above, base64-encode it into both logo fields, and
resubmit.

(The previous lock-box icon `icon.png` is deprecated and must not be used.)

## Status

- [x] Proper value: valid random UUIDv4, unique to Fenko Vault.
- [x] Verified: byte-identical across web, Android, and iOS.
- [x] Documented: this file, referenced from each platform's source.
- [x] Submitted to FIDO MDS on 2026-11-04 (awaiting publication).
