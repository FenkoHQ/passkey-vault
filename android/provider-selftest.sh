#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$ANDROID_HOME/build-tools/35.0.0}"
PLATFORM="${ANDROID_PLATFORM:-$ANDROID_HOME/platforms/android-35/android.jar}"
DEVICE="${ANDROID_SERIAL:-}"
OUT="${TMPDIR:-/tmp}/fenko-vault-provider-selftest"

ADB=(adb)
if [ -n "$DEVICE" ]; then
  ADB=(adb -s "$DEVICE")
fi

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex"

if [ ! -f "$ROOT/android/build/generated/nz/fenko/passkeyvault/R.java" ]; then
  "$ROOT/android/build-android.sh" >/dev/null
fi

javac --release 8 \
  -cp "$PLATFORM" \
  -d "$OUT/classes" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/MainActivity.java" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/ProviderVaultStore.java" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/WebAuthnNative.java" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/PasskeyCredentialProviderService.java" \
  "$ROOT/android/app/src/main/java/nz/fenko/passkeyvault/CredentialActionActivity.java" \
  "$ROOT/android/build/generated/nz/fenko/passkeyvault/R.java" \
  "$ROOT/android/test/FenkoVaultProviderSelfTest.java"

jar cf "$OUT/provider-selftest.jar" -C "$OUT/classes" .
"$BUILD_TOOLS/d8" --lib "$PLATFORM" --output "$OUT/dex" "$OUT/provider-selftest.jar"
jar cf "$OUT/provider-selftest-dex.jar" -C "$OUT/dex" .

"${ADB[@]}" push "$OUT/provider-selftest-dex.jar" /data/local/tmp/fenko-vault-provider-selftest.jar >/dev/null
"${ADB[@]}" shell CLASSPATH=/data/local/tmp/fenko-vault-provider-selftest.jar \
  app_process /system/bin nz.fenko.passkeyvault.FenkoVaultProviderSelfTest
