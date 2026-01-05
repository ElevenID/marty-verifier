/**
 * E2E tests for LicensePage
 * Tests license status display, validation, and installation.
 */
import { test, expect, defaultLicenseStatus } from '../fixtures';

test.describe('License Page', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/license');
  });

  test('should display license management heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /license management/i })).toBeVisible();
  });

  test('should show current license status when valid', async ({ page }) => {
    await expect(page.getByText(/license active/i)).toBeVisible();
    await expect(page.getByText(/test-org/i)).toBeVisible();
  });

  test('should display licensed features', async ({ page }) => {
    await expect(page.getByText(/licensed features/i)).toBeVisible();
    await expect(page.getByText('mdl')).toBeVisible();
    await expect(page.getByText('oid4vp')).toBeVisible();
  });

  test('should show expiration date and days remaining', async ({ page }) => {
    await expect(page.getByText(/expires/i)).toBeVisible();
    await expect(page.getByText(/30 days/i)).toBeVisible();
  });

  test('should display hardware binding status', async ({ page }) => {
    await expect(page.getByText(/hardware binding/i)).toBeVisible();
    await expect(page.getByText(/disabled/i)).toBeVisible();
  });

  test('should show verification count', async ({ page }) => {
    await expect(page.getByText(/verification limit/i)).toBeVisible();
    await expect(page.getByText(/5 \/ 1000/i)).toBeVisible();
  });
});

test.describe('License Status Variations', () => {
  test('should show invalid license state', async ({ page, mockTauri }) => {
    await mockTauri({
      get_license_status: {
        ...defaultLicenseStatus,
        valid: false,
        features: [],
      },
    });
    await page.goto('/#/license');

    await expect(page.getByText(/no valid license/i)).toBeVisible();
  });

  test('should show grace period warning', async ({ page, mockTauri }) => {
    await mockTauri({
      get_license_status: {
        ...defaultLicenseStatus,
        valid: true,
        grace_period_active: true,
        grace_period_days: 5,
        expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        days_until_expiry: -1,
      },
    });
    await page.goto('/#/license');

    const banner = page.getByTestId('license-warning-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toHaveText(/grace period/i);
    await expect(banner).toHaveText(/5 days remaining/i);
  });

  test('should show expiration warning when less than 30 days', async ({ page, mockTauri }) => {
    await mockTauri({
      get_license_status: {
        ...defaultLicenseStatus,
        days_until_expiry: 15,
      },
    });
    await page.goto('/#/license');

    const banner = page.getByTestId('license-warning-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toHaveText(/15 days/i);
  });
});

test.describe('License Installation', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/license');
  });

  test('should display license input field', async ({ page }) => {
    await expect(page.getByTestId('license-input')).toBeVisible();
    await expect(page.getByLabel(/license key/i)).toBeVisible();
  });

  test('should have install button', async ({ page }) => {
    await expect(page.getByTestId('license-submit')).toBeVisible();
    await expect(page.getByTestId('license-submit')).toHaveText(/validate & install/i);
  });

  test('should show error for empty input', async ({ page }) => {
    await page.getByTestId('license-submit').click();
    await expect(page.getByText(/please enter a license key/i)).toBeVisible();
  });

  test('should validate and install license', async ({ page, mockTauri }) => {
    // Enter license
    const validJwt = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test.signature';
    await page.getByLabel(/license key/i).fill(validJwt);
    await page.getByTestId('license-submit').click();

    await expect(page.getByText(/license validated and installed successfully/i)).toBeVisible();
  });

  test('should show error for invalid license', async ({ page, mockTauri }) => {
    // Mock validation failure
    await mockTauri({
      validate_license: { __error: 'Invalid signature' },
    });
    await page.reload();

    await page.getByLabel(/license key/i).fill('invalid-jwt');
    await page.getByTestId('license-submit').click();

    await expect(page.getByText(/invalid signature/i)).toBeVisible();
  });
});
