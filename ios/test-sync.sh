#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/vault-ios-sync-test.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
xcrun swiftc "$ROOT/ios/Shared/Base64.swift" \
  "$ROOT/ios/Shared/PasskeyRecord.swift" \
  "$ROOT/ios/Shared/VaultStore.swift" \
  "$ROOT/ios/Tests/main.swift" -o "$OUT/test-sync"
"$OUT/test-sync"
