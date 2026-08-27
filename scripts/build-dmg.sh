#!/usr/bin/env bash
# Build Marty Verifier macOS DMG.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "Building Marty Verifier..."

# The Tauri hook always rebuilds and obfuscates the UI before Rust embeds it.
pnpm --dir ui tauri build

APP_PATH="target/release/bundle/macos/Marty Verifier.app"
VERSION="$(node -p "JSON.parse(require('fs').readFileSync('src-tauri/tauri.conf.json', 'utf8')).version")"
ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; fi
DMG_PATH="target/release/bundle/Marty_Verifier_${VERSION}_${ARCH}.dmg"

if [ ! -d "$APP_PATH" ]; then
    echo "Build failed: $APP_PATH was not created" >&2
    exit 1
fi

hdiutil create -volname "Marty Verifier" \
    -srcfolder "$APP_PATH" \
    -ov -format UDZO \
    "$DMG_PATH"

echo "Build complete"
echo "App: $APP_PATH"
echo "DMG: $DMG_PATH"
echo "Size: $(du -h "$DMG_PATH" | cut -f1)"
