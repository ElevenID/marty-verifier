#!/bin/bash
# Build script for Marty Verifier macOS DMG
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "🔧 Building Marty Verifier..."

# Build UI if dist doesn't exist
if [ ! -d "ui/dist" ]; then
    echo "📦 Building UI..."
    cd ui && npm run build && cd ..
fi

# Build Tauri app
echo "🦀 Building Rust app..."
cargo tauri build

# Create DMG from .app
APP_PATH="target/release/bundle/macos/Marty Verifier.app"
DMG_PATH="target/release/bundle/Marty_Verifier_0.1.0_aarch64.dmg"

if [ -d "$APP_PATH" ]; then
    echo "💿 Creating DMG..."
    hdiutil create -volname "Marty Verifier" \
        -srcfolder "$APP_PATH" \
        -ov -format UDZO \
        "$DMG_PATH"
    
    echo ""
    echo "✅ Build complete!"
    echo "   App:  $APP_PATH"
    echo "   DMG:  $DMG_PATH"
    echo "   Size: $(du -h "$DMG_PATH" | cut -f1)"
else
    echo "❌ Build failed: .app not found"
    exit 1
fi
