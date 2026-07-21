#!/usr/bin/env bash
set -euo pipefail

# Builds a signed Android App Bundle (.aab) for Google Play upload.
# Mirrors build-android.sh but links resources in protobuf format and
# packages them with bundletool instead of producing a flat APK.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$ANDROID_HOME/build-tools/36.0.0}"
PLATFORM="${ANDROID_PLATFORM:-$ANDROID_HOME/platforms/android-36/android.jar}"
APP_ID="nz.fenko.passkeyvault"
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-$(node -p "require('$ROOT/package.json').version")}"

BUNDLETOOL_VERSION="${BUNDLETOOL_VERSION:-1.17.2}"
BUNDLETOOL="${BUNDLETOOL_JAR:-$ROOT/android/bundletool.jar}"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"

OUT="$ROOT/android/build-aab"
ASSETS="$OUT/assets"
CLASSES="$OUT/classes"
DEX="$OUT/dex"
GEN="$OUT/generated"
COMPILED="$OUT/compiled"
MODULE="$OUT/module"
DIST="$ROOT/android/dist"
KEY_DIR="$ROOT/android/signing"
KEYSTORE="$KEY_DIR/passkey-vault.jks"
KS_PASS="${ANDROID_KEYSTORE_PASSWORD:-android}"

rm -rf "$OUT"
mkdir -p "$ASSETS" "$CLASSES" "$DEX" "$GEN" "$COMPILED" "$MODULE" "$DIST" "$KEY_DIR"

if [ ! -f "$BUNDLETOOL" ]; then
  echo "Downloading bundletool $BUNDLETOOL_VERSION ..."
  curl -fsSL -o "$BUNDLETOOL" \
    "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar"
fi

# 1. Bundle the web app and copy static assets.
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

# 2. Compile + link resources in PROTO format (required by the bundle format).
"$AAPT2" compile --dir "$ROOT/android/app/src/main/res" -o "$COMPILED"
"$AAPT2" link \
  --proto-format \
  -o "$OUT/base-proto.apk" \
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

# 3. Compile Java to a single dex.
find "$ROOT/android/app/src/main/java" "$GEN" -name '*.java' > "$OUT/sources.list"
javac --release 8 -cp "$PLATFORM" -d "$CLASSES" @"$OUT/sources.list"
jar cf "$OUT/classes.jar" -C "$CLASSES" .
"$D8" --lib "$PLATFORM" --output "$DEX" "$OUT/classes.jar"

# 4. Re-arrange the proto APK into the base module layout bundletool expects.
unzip -q -o "$OUT/base-proto.apk" -d "$OUT/proto-extract"
mkdir -p "$MODULE/manifest" "$MODULE/dex"
cp "$OUT/proto-extract/AndroidManifest.xml" "$MODULE/manifest/AndroidManifest.xml"
cp "$OUT/proto-extract/resources.pb" "$MODULE/resources.pb"
[ -d "$OUT/proto-extract/res" ] && cp -r "$OUT/proto-extract/res" "$MODULE/res"
[ -d "$OUT/proto-extract/assets" ] && cp -r "$OUT/proto-extract/assets" "$MODULE/assets"
cp "$DEX/classes.dex" "$MODULE/dex/classes.dex"

(cd "$MODULE" && zip -q -r -X "$OUT/base.zip" .)

# 5. Build the bundle.
java -jar "$BUNDLETOOL" build-bundle \
  --modules="$OUT/base.zip" \
  --output="$OUT/app.aab"

# 6. Sign the bundle with the (upload) key. AABs use JAR signing, not apksigner.
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

jarsigner \
  -keystore "$KEYSTORE" \
  -storepass "$KS_PASS" \
  -keypass "$KS_PASS" \
  -sigalg SHA256withRSA \
  -digestalg SHA-256 \
  -signedjar "$DIST/fenko-vault-${VERSION_NAME}.aab" \
  "$OUT/app.aab" \
  passkey-vault

jarsigner -verify "$DIST/fenko-vault-${VERSION_NAME}.aab" >/dev/null
echo "$DIST/fenko-vault-${VERSION_NAME}.aab"
