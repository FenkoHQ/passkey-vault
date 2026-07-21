#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$ANDROID_HOME/build-tools/36.0.0}"
PLATFORM="${ANDROID_PLATFORM:-$ANDROID_HOME/platforms/android-36/android.jar}"
APP_ID="nz.fenko.passkeyvault"
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-$(node -p "require('$ROOT/package.json').version")}"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

OUT="$ROOT/android/build"
ASSETS="$OUT/assets"
CLASSES="$OUT/classes"
DEX="$OUT/dex"
GEN="$OUT/generated"
COMPILED="$OUT/compiled"
DIST="$ROOT/android/dist"
KEY_DIR="$ROOT/android/signing"
KEYSTORE="$KEY_DIR/passkey-vault.jks"
KS_PASS="${ANDROID_KEYSTORE_PASSWORD:-android}"

rm -rf "$OUT" "$DIST"
mkdir -p "$ASSETS" "$CLASSES" "$DEX" "$GEN" "$COMPILED" "$DIST" "$KEY_DIR"

"$ROOT/node_modules/.bin/esbuild" "$ROOT/android/web/src/app.ts" \
  --bundle \
  --format=iife \
  --target=chrome110 \
  --define:__APP_VERSION__="\"$VERSION_NAME\"" \
  --outfile="$ASSETS/app.js" \
  --log-level=warning

cp "$ROOT/android/web/src/index.html" "$ASSETS/index.html"
cp "$ROOT/android/web/src/styles.css" "$ASSETS/styles.css"
cp -r "$ROOT/android/web/src/fonts" "$ASSETS/fonts"
cp "$ROOT/android/web/src/icon.png" "$ASSETS/icon.png"
cp "$ROOT/node_modules/jsqr/dist/jsQR.js" "$ASSETS/jsQR.js"

"$AAPT2" compile --dir "$ROOT/android/app/src/main/res" -o "$COMPILED"
"$AAPT2" link \
  -o "$OUT/passkey-vault-unsigned.apk" \
  -I "$PLATFORM" \
  --auto-add-overlay \
  --manifest "$ROOT/android/app/src/main/AndroidManifest.xml" \
  --java "$GEN" \
  --min-sdk-version 29 \
  --target-sdk-version 36 \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  -A "$ASSETS" \
  -R "$COMPILED"/*.flat

find "$ROOT/android/app/src/main/java" "$GEN" -name '*.java' > "$OUT/sources.list"
javac --release 8 -cp "$PLATFORM" -d "$CLASSES" @"$OUT/sources.list"

jar cf "$OUT/classes.jar" -C "$CLASSES" .
"$D8" --lib "$PLATFORM" --output "$DEX" "$OUT/classes.jar"
cp "$OUT/passkey-vault-unsigned.apk" "$OUT/passkey-vault-with-dex.apk"
(cd "$DEX" && zip -q -r "$OUT/passkey-vault-with-dex.apk" classes.dex)

"$ZIPALIGN" -f -p 4 "$OUT/passkey-vault-with-dex.apk" "$OUT/passkey-vault-aligned.apk"

if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair \
    -keystore "$KEYSTORE" \
    -storepass "$KS_PASS" \
    -keypass "$KS_PASS" \
    -alias passkey-vault \
    -keyalg RSA \
    -keysize 3072 \
    -validity 10000 \
    -dname "CN=Fenko Vault Android Dev,O=Fenko,L=Auckland,C=NZ" >/dev/null
fi

"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias passkey-vault \
  --ks-pass "pass:$KS_PASS" \
  --key-pass "pass:$KS_PASS" \
  --out "$DIST/passkey-vault-android-signed.apk" \
  "$OUT/passkey-vault-aligned.apk"

"$APKSIGNER" verify --print-certs "$DIST/passkey-vault-android-signed.apk"
echo "$DIST/passkey-vault-android-signed.apk"
