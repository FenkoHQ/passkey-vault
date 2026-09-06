#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_ROOT="${ANDROID_HOME:-/opt/android-sdk}"
PLATFORM="${ANDROID_PLATFORM:-$SDK_ROOT/platforms/android-35/android.jar}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/vault-sync-test.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
JSON_LIB="${JSON_JAR:-$HOME/.m2/repository/org/json/json/20250517/json-20250517.jar}"
if [ ! -f "$JSON_LIB" ]; then
  JSON_LIB="$OUT/json.jar"
  curl --fail --silent --show-error --location \
    https://repo.maven.apache.org/maven2/org/json/json/20250517/json-20250517.jar \
    --output "$JSON_LIB"
fi
printf '%s  %s\n' 3ea61b2a06e31edf1c91134fe9106b0ebb16628be169f3db75bc7a2b06b45796 "$JSON_LIB" | sha256sum --check --status

javac -cp "$PLATFORM:$JSON_LIB" -d "$OUT" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/ProviderVaultStore.java" \
  "$ROOT/android/test/VaultSyncSelfTest.java"
java -cp "$OUT:$JSON_LIB:$PLATFORM" nz.fenko.passkeyvault.VaultSyncSelfTest "$ROOT/tests/sync/merge-fixtures.json"
