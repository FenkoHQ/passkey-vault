#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PROJECT="${1:?Xcode project name is required}"
DESTINATION="$ROOT/$PROJECT/project.xcworkspace/xcshareddata/swiftpm"
mkdir -p "$DESTINATION"
cp "$ROOT/Sync/Package.resolved" "$DESTINATION/Package.resolved"
