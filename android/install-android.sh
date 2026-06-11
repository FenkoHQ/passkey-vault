#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/android/build-android.sh"
adb install -r "$ROOT/android/dist/passkey-vault-android-signed.apk"

