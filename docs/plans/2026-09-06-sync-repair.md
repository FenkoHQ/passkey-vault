# Sync repair

Prioritise working sync over compatibility with older Android clients. Preserve
stored credentials, private keys, recovery phrases and backup decryption. Android
clients must update together; no vault reset or new recovery phrase is required.
An old random-salt client cannot exchange events with the repaired clients.

## Implemented

- Both clients derive transport keys from the recovery phrase and chain ID.
  The saved legacy salt is ignored, rather than rewriting the vault.
- Use Schnorr `verifyAsync`. The synchronous verifier lacked configured hashes
  and rejected valid signatures with the installed noble-secp256k1 3.0.0.
- Include TOTP-only and empty vaults in broadcasts and responses.
- Share record merge rules. Preserve maximum passkey/HOTP counters; keep explicit
  deletion records indefinitely. Absence from a snapshot never means deletion.
  Explicit restore advances beyond the known deletion revision, including when
  the deleting device's clock is ahead.
- Publish version 3 bundles with optional `deletions` inside the ciphertext.
  Readers still accept legacy arrays and version 2 objects.
- Store one addressable relay snapshot per device: kind 30078,
  `d=pksync-{chainId}-{deviceId}`, `h={chainId}`. Subscribe by author and `h`
  without a one-hour cutoff. Keep legacy `d=pksync-{chainId}` subscriptions and
  request/response messages. Older clients still need upgrading for reliable
  signature verification and deletion handling.
- Coalesce queued messages by type. Retry until a relay acknowledges the event;
  retain newer changes when an older acknowledgement arrives. Re-publish the
  persisted vault and request peers on reconnect and heartbeat. This reconstructs
  pending snapshots after a process restart without storing plaintext outboxes.
- Update browser publish status only after acknowledgement of the current vault.
  Relay acceptance does not prove every peer has received the update.
- Serialize browser mutations and incoming merges. Failed merges remain retryable.
- Merge native Android snapshots instead of replacing them. Carry deletion history
  through the existing bridge's sync configuration; refresh after native saves
  and activity resume. Keep the explicit local wipe path separate from sync deletes.
- Explain cross-device deletion in the confirmation dialogs.

Relay retention still depends on the relay. Keep encrypted backups. The protocol
uses NIP-01's addressable-event and indexed-tag rules:
https://github.com/nostr-protocol/nips/blob/master/01.md

## Validation

- `npm test -- --runInBand`: existing Jest tests plus the sync regression runner.
- `npm run test:sync`: real bundled browser/mobile code, WebCrypto encryption and
  Schnorr signatures, isolated storage and simulated relay delivery. Covers
  bidirectional passkeys/TOTP, counters, deletes, restore, delayed catch-up,
  rejected/tampered events, coalescing and retry after storage failure.
- `bash android/test-sync.sh`: real native store against in-memory preferences on
  the JVM. Tests stale saves, counters, deletion, restore and PRF preservation.
- Browser/mobile typechecking; Chrome/Firefox builds; Android Java compilation;
  Android and Safari-targeted web bundles.

This is local validation, not a published release or real-device acceptance test.
No connected Android device was available. CI now includes mobile typechecking
and the Android native regression test.

## iOS follow-up, blocked

The shared web bundle receives the sync fixes above. The iOS native snapshot store
still replaces records, and its bridge only loads the native snapshot at startup.
`ios/Tests/main.swift` and `bash ios/test-sync.sh` capture the required behaviour,
including preservation of unknown passkey fields such as PRF material. They have
not been run: SSH to the configured Mac returned `No route to host`. Swift/Xcode
are unavailable on the local Linux machine. Native fixes remain pending that
regression run, following the project's test-before-fix rule.

Before TestFlight: repair the native store/refresh path, run the regression on a
Mac, update the existing Xcode 16 upload workflow to a supported iOS SDK, and
exercise registration/sign-in and multi-device sync on an iPhone. No TestFlight
upload, app-store release or standalone desktop implementation was performed.
