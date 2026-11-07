#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/vault-relay.XXXXXX")"
RELAY_PID=""
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && [ -f "$OUT/relay.log" ]; then cat "$OUT/relay.log"; fi
  if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
  rm -rf "$OUT"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' -keyout "$OUT/key.pem" -out "$OUT/cert.pem" >/dev/null 2>&1
openssl x509 -in "$OUT/cert.pem" -outform der -out "$OUT/cert.der"
cd "$ROOT"
node ios/Sync/local-relay.mjs "$OUT/cert.pem" "$OUT/key.pem" "$OUT/ready" >"$OUT/relay.log" 2>&1 &
RELAY_PID=$!
for _ in {1..100}; do
  if [ -s "$OUT/ready" ]; then break; fi
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then cat "$OUT/relay.log"; exit 1; fi
  sleep 0.1
done
test -s "$OUT/ready"
SYNC_TEST_RELAY="$(cat "$OUT/ready")" SYNC_TEST_CERT="$OUT/cert.der" \
  swift test --package-path ios/Sync
