/**
 * E2E tests for SyncPage
 * Tests trust anchor synchronization status and actions.
 */
import { test, expect, defaultSyncStatus } from '../fixtures';

test.describe('Sync Page', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/sync');
  });

  test('should display sync page heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /trust store sync/i })).toBeVisible();
  });

  test('should show online status', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Online' })).toBeVisible();
  });

  test('should display certificate counts', async ({ page }) => {
    const iaca = page.getByText(/iaca certificates/i);
    await expect(iaca).toBeVisible();
    await expect(iaca.locator('..').getByRole('heading', { name: '56' })).toBeVisible();

    const csca = page.getByText(/csca certificates/i);
    await expect(csca).toBeVisible();
    await expect(csca.locator('..').getByRole('heading', { name: '120' })).toBeVisible();

    const dsc = page.getByText(/dsc certificates/i);
    await expect(dsc).toBeVisible();
    await expect(dsc.locator('..').getByRole('heading', { name: '450' })).toBeVisible();

    const openBadge = page.getByText(/open badge keys/i);
    await expect(openBadge).toBeVisible();
    await expect(openBadge.locator('..').getByRole('heading', { name: '18' })).toBeVisible();
  });

  test('should show last sync time', async ({ page }) => {
    await expect(page.getByText('Last Sync:', { exact: true })).toBeVisible();
    await expect(page.getByText('Time Since Sync:', { exact: true })).toBeVisible();
  });

  test('should have sync actions', async ({ page }) => {
    await expect(page.getByRole('button', { name: /sync from cloud/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /import from usb/i })).toBeVisible();
  });
});

test.describe('Sync Status Variations', () => {
  test('should show offline status', async ({ page, mockTauri }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'onLine', {
        configurable: true,
        get: () => false,
      });
    });
    await mockTauri();
    await page.goto('/#/sync');

    await expect(page.getByText(/offline mode/i)).toBeVisible();
    
    // Cloud sync should be disabled when offline
    await expect(page.getByRole('button', { name: /sync from cloud/i })).toBeDisabled();
    
    // USB import should still be enabled
    await expect(page.getByRole('button', { name: /import from usb/i })).toBeEnabled();
  });

  test('should show sync overdue warning', async ({ page, mockTauri }) => {
    await mockTauri({
      get_sync_status: {
        ...defaultSyncStatus,
        sync_overdue: true,
        hours_since_sync: 96,
      },
    });
    await page.goto('/#/sync');

    await expect(page.getByText(/sync overdue/i)).toBeVisible();
  });

  test('should show last error if present', async ({ page, mockTauri }) => {
    await mockTauri({
      get_sync_status: {
        ...defaultSyncStatus,
        last_error: 'Network timeout',
      },
    });
    await page.goto('/#/sync');

    await expect(page.getByText(/last error/i)).toBeVisible();
    await expect(page.getByText(/network timeout/i)).toBeVisible();
  });

  test('should show never synced state', async ({ page, mockTauri }) => {
    await mockTauri({
      get_sync_status: {
        last_sync: null,
        hours_since_sync: null,
        sync_overdue: true,
        iaca_certificates: 0,
        csca_certificates: 0,
        dsc_certificates: 0,
        open_badge_keys: 0,
        open_badge_last_sync: null,
        open_badge_hours_since_sync: null,
        open_badge_sync_overdue: true,
        crl_cache_age_hours: null,
        sync_in_progress: false,
        last_error: null,
      },
    });
    await page.goto('/#/sync');

    await expect(page.getByText('Last Sync:', { exact: true }).locator('..')).toContainText('Never');
    await expect(page.getByText('Open Badge Trust Last Sync:', { exact: true }).locator('..')).toContainText('Never');
    await expect(page.getByText(/iaca certificates/i).locator('..').getByRole('heading', { name: '0' })).toBeVisible();
    await expect(page.getByText(/csca certificates/i).locator('..').getByRole('heading', { name: '0' })).toBeVisible();
    await expect(page.getByText(/dsc certificates/i).locator('..').getByRole('heading', { name: '0' })).toBeVisible();
    await expect(page.getByText(/open badge keys/i).locator('..').getByRole('heading', { name: '0' })).toBeVisible();
  });
});

test.describe('Sync Actions', () => {
  test('should trigger cloud sync', async ({ page, mockTauri }) => {
    await mockTauri({
      sync_trust_anchors: {
        success: true,
        iaca_updated: 5,
        csca_updated: 10,
        dsc_updated: 25,
        open_badge_keys_updated: 2,
        duration_seconds: 3.5,
      },
    });
    await page.goto('/#/sync');

    const syncButton = page.getByRole('button', { name: /sync from cloud/i });
    await expect(syncButton).toBeEnabled();
    await syncButton.click();

    await expect(page.getByText(/sync completed/i)).toBeVisible();
    await expect(page.getByText(/5 iaca/i)).toBeVisible();
  });

  test('should handle sync failure', async ({ page, mockTauri }) => {
    await mockTauri({
      sync_trust_anchors: {
        success: false,
        error: 'Connection refused',
        iaca_updated: 0,
        csca_updated: 0,
        dsc_updated: 0,
        open_badge_keys_updated: 0,
        duration_seconds: 0.1,
      },
    });
    await page.goto('/#/sync');

    const syncButton = page.getByRole('button', { name: /sync from cloud/i });
    await expect(syncButton).toBeEnabled();
    await syncButton.click();

    await expect(page.getByText(/connection refused/i)).toBeVisible();
  });

  test('should show USB import button', async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/sync');
    const usbButton = page.getByRole('button', { name: /import from usb/i });
    await expect(usbButton).toBeVisible();
    await expect(usbButton).toBeEnabled();
  });
});
