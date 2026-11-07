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
