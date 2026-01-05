#!/bin/bash
#
# Agentic Development Test Loop for Marty Verifier
# 
# This script provides a live development environment for AI-assisted coding:
# - Vite dev server with hot reload
# - Playwright E2E tests that can be triggered on demand
# - JSON output for programmatic parsing of test results
#
# Usage:
#   ./scripts/test-watch.sh        # Start dev server + watch mode
#   ./scripts/test-watch.sh headed # Start with visible browser
#   ./scripts/test-watch.sh ui     # Start Playwright UI mode
#
# Workflow for Agents:
#   1. Agent modifies code
#   2. Vite hot-reloads the changes
#   3. Agent triggers test run: pnpm test:e2e
#   4. Agent reads test-results/playwright-results.json
#   5. Agent identifies failures and fixes code
#   6. Repeat until all tests pass

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UI_DIR="$PROJECT_ROOT/ui"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

cleanup() {
    print_info "Cleaning up..."
    if [ -n "$DEV_PID" ]; then
        kill $DEV_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

cd "$UI_DIR"

# Ensure dependencies are installed
if [ ! -d "node_modules" ]; then
    print_info "Installing dependencies..."
    pnpm install
fi

# Ensure Playwright browsers are installed
if ! pnpm playwright --version &>/dev/null; then
    print_info "Installing Playwright browsers..."
    pnpm playwright:install
fi

# Create test results directory
mkdir -p test-results

MODE="${1:-watch}"

case "$MODE" in
    "headed")
        print_info "Starting Playwright in headed mode..."
        print_info "Dev server will start automatically via playwright.config.ts"
        pnpm test:e2e:headed
        ;;
    "ui")
        print_info "Starting Playwright UI mode..."
        print_info "This opens an interactive browser for running tests"
        pnpm test:e2e:ui
        ;;
    "watch")
        print_info "Starting development server for agentic testing..."
        print_info ""
        print_info "Agentic Workflow Commands:"
        print_info "  pnpm test:e2e       - Run all E2E tests"
        print_info "  pnpm test:unit      - Run all unit tests"
        print_info "  pnpm test:all       - Run unit + E2E tests"
        print_info ""
        print_info "Test Results (JSON for parsing):"
        print_info "  ui/test-results/playwright-results.json"
        print_info "  ui/test-results/vitest-results.json"
        print_info ""
        
        # Start dev server in background
        pnpm dev &
        DEV_PID=$!
        
        print_success "Dev server started (PID: $DEV_PID)"
        print_info "Waiting for server to be ready..."
        
        # Wait for server to be ready
        until curl -s http://localhost:5173 >/dev/null 2>&1; do
            sleep 1
        done
        
        print_success "Dev server ready at http://localhost:5173"
        print_info ""
        print_info "Ready for agentic development!"
        print_info "Press Ctrl+C to stop."
        print_info ""
        
        # Keep the script running
        wait $DEV_PID
        ;;
    *)
        print_warn "Unknown mode: $MODE"
        echo "Usage: $0 [watch|headed|ui]"
        exit 1
        ;;
esac
