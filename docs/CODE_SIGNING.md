# Code Signing Setup for marty-verifier

This document provides step-by-step instructions for setting up code signing certificates for the marty-verifier desktop application.

## Overview

The marty-verifier Tauri application requires code signing for:
- **macOS**: Required for distribution and notarization
- **Windows**: Required for SmartScreen reputation and user trust
- **Linux**: Optional (currently not configured)

## Table of Contents

1. [macOS Code Signing](#macos-code-signing)
2. [Windows Code Signing](#windows-code-signing)
3. [Tauri Updater Signing](#tauri-updater-signing)
4. [GitHub Secrets Setup](#github-secrets-setup)

---

## macOS Code Signing

### Prerequisites

- Apple Developer Account ($99/year)
- macOS computer with Xcode or Xcode Command Line Tools installed

### Step 1: Create Apple Developer Certificate

1. **Log in to Apple Developer Portal**:
   - Visit [developer.apple.com](https://developer.apple.com)
   - Go to Certificates, Identifiers & Profiles

2. **Create a Developer ID Application Certificate**:
   - Click the "+" button to create a new certificate
   - Select "Developer ID Application" (for distribution outside Mac App Store)
   - Follow the Certificate Signing Request (CSR) process:
     ```bash
     # Open Keychain Access on macOS
     # Go to: Keychain Access > Certificate Assistant > Request a Certificate from a Certificate Authority
     # Enter your email and name
     # Select "Saved to disk"
     # This creates a .certSigningRequest file
     ```
   - Upload the CSR file to Apple Developer Portal
   - Download the certificate (.cer file)

3. **Install Certificate**:
   - Double-click the downloaded .cer file
   - It will be added to your macOS Keychain

### Step 2: Export Certificate for GitHub Actions

1. **Export as P12**:
   ```bash
   # Open Keychain Access
   # Find your "Developer ID Application" certificate
   # Right-click → Export
   # Choose format: Personal Information Exchange (.p12)
   # Set a strong password (you'll need this for GitHub Secrets)
   # Save as: certificate.p12
   ```

2. **Encode Certificate**:
   ```bash
   # Base64 encode the certificate for GitHub Secrets
   base64 -i certificate.p12 -o certificate_base64.txt
   
   # Display the encoded content (copy this for GitHub Secrets)
   cat certificate_base64.txt
   ```

3. **Get Team ID**:
   - Visit [developer.apple.com/account](https://developer.apple.com/account)
   - Your Team ID is displayed in the top-right corner
   - Format: 10-character alphanumeric string (e.g., `ABC1234567`)

### Step 3: Apple ID App-Specific Password

Required for notarization:

1. **Generate App-Specific Password**:
   - Visit [appleid.apple.com](https://appleid.apple.com)
   - Go to "Sign-In and Security"
   - Select "App-Specific Passwords"
   - Click "+" to generate a new password
   - Label it "marty-verifier GitHub Actions"
   - Copy the generated password (format: `xxxx-xxxx-xxxx-xxxx`)

### macOS GitHub Secrets Summary

Add these secrets to your GitHub repository:

| Secret Name | Value | Example |
|------------|-------|---------|
| `APPLE_CERTIFICATE_P12` | Base64-encoded .p12 file | `MIIJ...` (very long string) |
| `APPLE_CERTIFICATE_PASSWORD` | Password you set when exporting P12 | `MySecurePassword123!` |
| `APPLE_TEAM_ID` | Your Apple Developer Team ID | `ABC1234567` |
| `APPLE_ID` | Your Apple ID email | `developer@example.com` |
| `APPLE_PASSWORD` | App-specific password | `xxxx-xxxx-xxxx-xxxx` |
| `APPLE_SIGNING_IDENTITY` | Certificate common name | `Developer ID Application: Your Name (ABC1234567)` |

**Finding APPLE_SIGNING_IDENTITY**:
```bash
# List all signing identities in your keychain
security find-identity -v -p codesigning

# Look for: "Developer ID Application: Your Name (TEAM_ID)"
# Copy the entire string including parentheses
```

---

## Windows Code Signing

### Prerequisites

- Code signing certificate from a trusted Certificate Authority (CA)
- Common CAs: DigiCert, Sectigo, GlobalSign
- Approximate cost: $200-$500/year

### Step 1: Obtain a Code Signing Certificate

**Option A: Standard Code Signing Certificate**

1. **Purchase from CA**:
   - Choose "Code Signing Certificate" or "EV Code Signing Certificate"
   - EV (Extended Validation) provides immediate SmartScreen reputation
   - Complete identity verification process (can take days/weeks)

2. **Generate CSR** (if required by CA):
   ```powershell
   # On Windows, use certreq or CA's tool to generate CSR
   # Follow your CA's specific instructions
   ```

3. **Download Certificate**:
   - CA will provide a .pfx or .p12 file
   - Or provide instructions to export from Windows Certificate Store

**Option B: Use Existing Certificate**

If you already have a certificate in Windows Certificate Store:

```powershell
# Export from Windows Certificate Store
# 1. Open "Manage User Certificates" (certmgr.msc)
# 2. Navigate to Personal > Certificates
# 3. Find your code signing certificate
# 4. Right-click → All Tasks → Export
# 5. Choose "Yes, export the private key"
# 6. Select "Personal Information Exchange (.pfx)"
# 7. Set a password
# 8. Save as certificate.pfx
```

### Step 2: Prepare Certificate for GitHub Actions

```powershell
# Base64 encode the PFX file
certutil -encode certificate.pfx certificate_base64.txt

# Display the encoded content (copy for GitHub Secrets)
type certificate_base64.txt
```

### Windows GitHub Secrets Summary

Add these secrets to your GitHub repository:

| Secret Name | Value | Example |
|------------|-------|---------|
| `WINDOWS_CERTIFICATE_PFX` | Base64-encoded .pfx file | `MIIJ...` (long string) |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password for the PFX file | `MySecurePassword123!` |

---

## Tauri Updater Signing

The Tauri updater uses a separate signing key for update manifest verification (different from code signing).

### Generate Updater Keys

```bash
# Install Tauri CLI (if not already installed)
cargo install tauri-cli

# Generate updater key pair
cargo tauri signer generate --write-keys

# This creates two files:
# - myapp.key (private key) - KEEP SECRET
# - myapp.key.pub (public key) - embed in app
```

### Configure Keys

1. **Private Key (for CI/CD)**:
   ```bash
   # Read the private key
   cat myapp.key
   
   # Copy the entire content for TAURI_SIGNING_PRIVATE_KEY secret
   ```

2. **Public Key (for app)**:
   - Open `src-tauri/tauri.conf.json`
   - Add the public key to the updater configuration:
   ```json
   {
     "plugins": {
       "updater": {
         "pubkey": "YOUR_PUBLIC_KEY_HERE",
         "endpoints": [
           "https://github.com/{{owner}}/{{repo}}/releases/latest/download/latest.json"
         ]
       }
     }
   }
   ```

### Tauri GitHub Secrets Summary

| Secret Name | Value | Source |
|------------|-------|--------|
| `TAURI_SIGNING_PRIVATE_KEY` | Content of `myapp.key` | Generated by `cargo tauri signer generate` |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password for private key (if set) | Optional, leave empty if no password |

---

## GitHub Secrets Setup

### Adding Secrets to GitHub Repository

1. **Navigate to Repository Settings**:
   - Go to your GitHub repository
   - Click "Settings" tab
   - Select "Secrets and variables" → "Actions"

2. **Add Each Secret**:
   - Click "New repository secret"
   - Enter the secret name (exactly as shown above)
   - Paste the secret value
   - Click "Add secret"

3. **Verify Secrets**:
   - You should see all secrets listed (values are hidden)
   - Names must match exactly what the workflows expect

### Complete Secrets Checklist

- [ ] `APPLE_CERTIFICATE_P12` - Base64 encoded macOS certificate
- [ ] `APPLE_CERTIFICATE_PASSWORD` - Certificate password
- [ ] `APPLE_TEAM_ID` - Apple Developer Team ID
- [ ] `APPLE_ID` - Apple ID email
- [ ] `APPLE_PASSWORD` - App-specific password
- [ ] `APPLE_SIGNING_IDENTITY` - Certificate common name
- [ ] `WINDOWS_CERTIFICATE_PFX` - Base64 encoded Windows certificate
- [ ] `WINDOWS_CERTIFICATE_PASSWORD` - Certificate password
- [ ] `TAURI_SIGNING_PRIVATE_KEY` - Tauri updater private key
- [ ] `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` - Updater key password (optional)

---

## Testing the Setup

### Test Without Secrets (Development)

The workflows will run but skip code signing if secrets are not configured:

```bash
# Trigger a test build
git tag v0.1.0-rc.1
git push origin v0.1.0-rc.1
```

Check GitHub Actions logs for warnings about missing certificates.

### Test With Secrets (Production)

After adding all secrets:

1. Create a test RC tag:
   ```bash
   git tag v0.1.0-rc.2
   git push origin v0.1.0-rc.2
   ```

2. Monitor GitHub Actions workflow
3. Verify that code signing succeeds
4. Download the built artifacts
5. Test signature verification:

   **macOS**:
   ```bash
   # Check code signature
   codesign -dvvv Marty-Verifier.app
   
   # Verify notarization
   spctl -a -vvv -t install Marty-Verifier.app
   ```

   **Windows**:
   ```powershell
   # Check signature
   Get-AuthenticodeSignature Marty-Verifier-Setup.exe | Format-List
   ```

---

## Troubleshooting

### macOS: "Certificate not found in keychain"

- Ensure certificate is properly imported in GitHub Actions
- Check that `APPLE_SIGNING_IDENTITY` matches exactly
- Verify base64 encoding is correct (no extra whitespace)

### Windows: "Invalid PFX file"

- Verify password is correct
- Ensure certificate includes private key
- Check base64 encoding

### Tauri Updater: "Invalid signature"

- Verify public key in `tauri.conf.json` matches private key
- Ensure private key is complete (no truncation)
- Check that workflows are signing the update manifests

### General: Workflow Runs but Skips Signing

- Check workflow logs for "Warning: CERTIFICATE not set"
- Verify secret names match exactly (case-sensitive)
- Ensure secrets are added to the correct repository

---

## Security Best Practices

1. **Never commit certificates or keys to git**
   - Add `*.p12`, `*.pfx`, `*.key` to `.gitignore`

2. **Rotate certificates before expiration**
   - Set calendar reminders 30 days before expiration
   - Update GitHub Secrets with new certificates

3. **Limit access to secrets**
   - Only repository admins should have secret access
   - Use separate certificates for different projects

4. **Use strong passwords**
   - Minimum 16 characters
   - Mix of letters, numbers, symbols

5. **Monitor certificate usage**
   - Review GitHub Actions logs for suspicious activity
   - Revoke and replace if compromised

---

## Additional Resources

- [Tauri Code Signing Guide](https://tauri.app/v1/guides/distribution/sign-macos)
- [Apple Developer Documentation](https://developer.apple.com/support/code-signing/)
- [Microsoft Code Signing Guide](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
- [Tauri Updater Documentation](https://tauri.app/v1/guides/distribution/updater/)

---

## Support

If you encounter issues with code signing setup:

1. Check workflow logs in GitHub Actions
2. Review this documentation
3. Search [Tauri Discussions](https://github.com/tauri-apps/tauri/discussions)
4. Open an issue in the repository
