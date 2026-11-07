#!/usr/bin/env bash
set -euo pipefail

archive_path="${1:?Provide an Xcode archive path}"
app_path="$archive_path/Products/Applications/FenkoVault.app"
provider_path="$app_path/PlugIns/CredentialProvider.appex"
plist_buddy=/usr/libexec/PlistBuddy

# Inspect the delivered bundles, since source manifests alone do not prove packaging.
for bundle_path in "$app_path" "$provider_path"; do
  manifest_path="$bundle_path/PrivacyInfo.xcprivacy"
  plutil -lint "$manifest_path"
  category=$("$plist_buddy" -c 'Print NSPrivacyAccessedAPITypes:0:NSPrivacyAccessedAPIType' "$manifest_path")
  reason=$("$plist_buddy" -c 'Print NSPrivacyAccessedAPITypes:0:NSPrivacyAccessedAPITypeReasons:0' "$manifest_path")
  test "$category" = NSPrivacyAccessedAPICategoryUserDefaults
  test "$reason" = 1C8F.1
  "$plist_buddy" -c 'Print NSFaceIDUsageDescription' "$bundle_path/Info.plist" >/dev/null
done

icon=$("$plist_buddy" -c 'Print CFBundleIcons:CFBundlePrimaryIcon:CFBundleIconName' "$app_path/Info.plist")
test "$icon" = AppIcon
for version_key in CFBundleShortVersionString CFBundleVersion; do
  app_version=$("$plist_buddy" -c "Print $version_key" "$app_path/Info.plist")
  provider_version=$("$plist_buddy" -c "Print $version_key" "$provider_path/Info.plist")
  test "$app_version" = "$provider_version"
done
echo 'Native archive metadata: PASS'
