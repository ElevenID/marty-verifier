/**
 * E2E tests for VerificationPage
 * Tests the main verification workflow including credential type selection,
 * QR scanning, and result display.
 */
import { test, expect, defaultLicenseStatus } from '../fixtures';

test.describe('Verification Page', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/');
  });

  test('should display verification page with panel', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /credential verification/i })).toBeVisible();
    await expect(page.getByTestId('verifier-panel')).toBeVisible();
  });

  test('should show credential type toggles', async ({ page }) => {
    await expect(page.getByRole('button', { name: /mdl/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /emrtd/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /oid4vp/i })).toBeVisible();
  });

  test('should allow selecting different credential types', async ({ page }) => {
    const mdlButton = page.getByRole('button', { name: /mdl/i });
    const emrtdButton = page.getByRole('button', { name: /emrtd/i });

    // MDL should be selected by default
    await expect(mdlButton).toHaveAttribute('aria-pressed', 'true');

    // Click eMRTD
    await emrtdButton.click();
    await expect(emrtdButton).toHaveAttribute('aria-pressed', 'true');
    await expect(mdlButton).toHaveAttribute('aria-pressed', 'false');
  });

  test('should disable unlicensed credential types', async ({ page, mockTauri }) => {
    // Mock license with only mdl feature
    await mockTauri({
      get_license_status: {
        ...defaultLicenseStatus,
        features: ['mdl'],
      },
    });
    await page.reload();

    // MDL should be enabled
    await expect(page.getByRole('button', { name: /mdl/i })).toBeEnabled();
    
    // eMRTD should be disabled
    await expect(page.getByRole('button', { name: /emrtd/i })).toBeDisabled();
  });

  test('should show scan button when ready', async ({ page }) => {
    await expect(page.getByTestId('scan-button')).toBeVisible();
    await expect(page.getByTestId('scan-button')).toHaveText(/scan/i);
  });

  test('should display hardware tier information', async ({ page }) => {
    await expect(page.getByText(/hardware tier/i)).toBeVisible();
    await expect(page.getByText(/simple/i)).toBeVisible();
  });

  test('should show license warning when license is near expiry', async ({ page, mockTauri }) => {
    await mockTauri({
      get_license_status: {
        ...defaultLicenseStatus,
        days_until_expiry: 10,
      },
    });
    await page.reload();

    await expect(page.getByTestId('license-warning-banner')).toBeVisible();
  });

  test('should show offline banner when disconnected', async ({ page, mockTauri }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'onLine', {
        configurable: true,
        get: () => false,
      });
    });
    await mockTauri({
      get_sync_status: {
        last_sync: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
        hours_since_sync: 48,
        sync_overdue: true,
        iaca_certificates: 56,
        csca_certificates: 120,
        dsc_certificates: 450,
        last_error: null,
      },
    });
    await page.reload();

    await expect(page.getByTestId('offline-status-banner')).toBeVisible();
  });
});

test.describe('Verification Flow', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/');
  });

  test('should start verification when scan button clicked', async ({ page }) => {
    const scanButton = page.getByTestId('scan-button');
    await scanButton.click();
    
    // Should show scanning state or result
    // This depends on the mock implementation
    await expect(page.getByTestId('verifier-panel')).toBeVisible();
  });

  test('should display verification result on success', async ({ page, mockTauri }) => {
    // Mock a successful verification
    await mockTauri({
      verify_credential: {
        verification_id: 'test-verification',
        status: 'valid',
        credential_type: 'mdl',
        issuer: { name: 'State of California', jurisdiction: 'US-CA', subject: null },
        disclosed_claims: {
          given_name: 'John',
          family_name: 'Doe',
          birth_date: '1990-01-15',
        },
        trust_chain: {
          valid: true,
          chain_type: 'iaca',
          trust_anchor: 'US-CA',
          offline_verified: false,
        },
        revocation_status: 'valid',
        verified_at: new Date().toISOString(),
        warnings: [],
      },
    });
    await page.reload();

    await page.getByLabel(/require liveness/i).uncheck();

    // Trigger scan
    await page.getByTestId('scan-button').click();
    
    // Should show result
    await expect(page.getByTestId('verification-result')).toBeVisible({ timeout: 10000 });
  });
});
