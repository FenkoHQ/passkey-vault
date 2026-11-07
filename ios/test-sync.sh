#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/vault-ios-sync-test.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
SHARED=("$ROOT"/ios/Shared/*.swift)
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/main.swift" -o "$OUT/test-sync"
"$OUT/test-sync" "$ROOT/tests/sync/merge-fixtures.json"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/StorageRegression/main.swift" -o "$OUT/test-storage"
"$OUT/test-storage"
node "$ROOT/ios/Tests/Credentials/interop.mjs" create "$OUT"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/Credentials/main.swift" -o "$OUT/test-credentials"
"$OUT/test-credentials" "$OUT"
node "$ROOT/ios/Tests/Credentials/interop.mjs" verify "$OUT"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/App/NativeVaultModel.swift" \
  "$ROOT/ios/Tests/Session/main.swift" -o "$OUT/test-session"
"$OUT/test-session"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/SyncStorage/main.swift" -o "$OUT/test-sync-storage"
"$OUT/test-sync-storage"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/OTP/main.swift" -o "$OUT/test-otp"
"$OUT/test-otp"
xcrun swiftc "${SHARED[@]}" "$ROOT/ios/Tests/Recovery/main.swift" -o "$OUT/test-recovery"
"$OUT/test-recovery"
