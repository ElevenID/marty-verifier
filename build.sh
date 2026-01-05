#!/bin/bash
# Build script for Marty Verifier
# Usage: ./build.sh [simple|complex|dev]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo not found. Install from https://rustup.rs"
        exit 1
    fi
    
    if ! command -v node &> /dev/null; then
        print_error "Node.js not found. Install from https://nodejs.org"
        exit 1
    fi
    
    if ! command -v pnpm &> /dev/null; then
        print_warning "pnpm not found. Installing..."
        npm install -g pnpm
    fi
    
    print_status "Prerequisites OK"
}

# Install dependencies
install_deps() {
    print_status "Installing UI dependencies..."
    cd ui
    pnpm install
    cd ..
}

# Build for Simple Kiosk (camera only)
build_simple() {
    print_status "Building for Simple Kiosk (camera only)..."
    
    export CARGO_FEATURES="iaca,oid4vp"
    
    cd ui
    pnpm tauri build -- --features "$CARGO_FEATURES"
    cd ..
    
    print_status "Simple Kiosk build complete!"
}

# Build for Complex Kiosk (full features)
build_complex() {
    print_status "Building for Complex Kiosk (full features)..."
    
    export CARGO_FEATURES="iaca,csca,oid4vp,sd-jwt,biometrics,reporting,nfc,ble"
    
    cd ui
    pnpm tauri build -- --features "$CARGO_FEATURES"
    cd ..
    
    print_status "Complex Kiosk build complete!"
}

# Development build
build_dev() {
    print_status "Starting development server..."
    
    cd ui
    pnpm tauri dev
    cd ..
}

# Apply code obfuscation to built UI
apply_obfuscation() {
    print_status "Applying JavaScript obfuscation..."
    
    cd ui
    pnpm run obfuscate
    cd ..
    
    print_status "Obfuscation complete!"
}

# Main
main() {
    local BUILD_TYPE="${1:-dev}"
    
    check_prerequisites
    install_deps
    
    case "$BUILD_TYPE" in
        simple)
            build_simple
            apply_obfuscation
            ;;
        complex)
            build_complex
            apply_obfuscation
            ;;
        dev)
            build_dev
            ;;
        *)
            print_error "Unknown build type: $BUILD_TYPE"
            echo "Usage: $0 [simple|complex|dev]"
            exit 1
            ;;
    esac
}

main "$@"
