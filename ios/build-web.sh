#!/usr/bin/env bash
# Bundles the shared web app (android/web/src/app.ts — same sync/UI engine the
# Android app and browser extensions use) into the iOS app's resources, so iOS
# reuses the identical, proven sync client inside a WKWebView.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/android/web/src"
OUT="$ROOT/ios/web"
VERSION_NAME="${VERSION_NAME:-0.1.0}"

rm -rf "$OUT"
mkdir -p "$OUT/fonts"

"$ROOT/node_modules/.bin/esbuild" "$SRC/app.ts" \
  --bundle \
  --format=iife \
  --target=safari16 \
  --define:__APP_VERSION__="\"$VERSION_NAME\"" \
  --outfile="$OUT/app.js" \
  --log-level=warning

cp "$SRC/index.html" "$OUT/index.html"
cp "$SRC/styles.css" "$OUT/styles.css"
cp -r "$SRC/fonts/." "$OUT/fonts/"
cp "$SRC/icon.png" "$OUT/icon.png"
cp "$ROOT/node_modules/jsqr/dist/jsQR.js" "$OUT/jsQR.js"

echo "Wrote iOS web bundle to $OUT"
ls -la "$OUT"
