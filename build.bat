@echo off
REM Build script for Marty Verifier (Windows)
REM Usage: build.bat [simple|complex|dev]

setlocal enabledelayedexpansion

set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=dev

echo [BUILD] Marty Verifier - %BUILD_TYPE% build

REM Check prerequisites
where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust/Cargo not found. Install from https://rustup.rs
    exit /b 1
)

where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org
    exit /b 1
)

where pnpm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARN] pnpm not found. Installing...
    npm install -g pnpm
)

echo [BUILD] Prerequisites OK

REM Install dependencies
echo [BUILD] Installing UI dependencies...
cd ui
call pnpm install
cd ..

if "%BUILD_TYPE%"=="simple" goto build_simple
if "%BUILD_TYPE%"=="complex" goto build_complex
if "%BUILD_TYPE%"=="dev" goto build_dev
goto unknown

:build_simple
echo [BUILD] Building for Simple Kiosk (camera only)...
set CARGO_FEATURES=iaca,oid4vp
cd ui
call pnpm tauri build -- --features "%CARGO_FEATURES%"
call pnpm run obfuscate
cd ..
echo [BUILD] Simple Kiosk build complete!
goto end

:build_complex
echo [BUILD] Building for Complex Kiosk (full features)...
set CARGO_FEATURES=iaca,csca,oid4vp,sd-jwt,biometrics,reporting,nfc,ble
cd ui
call pnpm tauri build -- --features "%CARGO_FEATURES%"
call pnpm run obfuscate
cd ..
echo [BUILD] Complex Kiosk build complete!
goto end

:build_dev
echo [BUILD] Starting development server...
cd ui
call pnpm tauri dev
cd ..
goto end

:unknown
echo [ERROR] Unknown build type: %BUILD_TYPE%
echo Usage: build.bat [simple^|complex^|dev]
exit /b 1

:end
endlocal
