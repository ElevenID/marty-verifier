/**
 * E2E tests for SettingsPage
 * Tests configuration display and modification.
 */
import { test, expect } from '../fixtures';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/settings');
  });

  test('should display settings heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /settings/i })).toBeVisible();
  });

  test('should show hardware info section', async ({ page }) => {
    await expect(page.getByText(/hardware tier/i)).toBeVisible();
    await expect(page.getByText(/simple/i)).toBeVisible();
    await expect(page.getByText(/camera/i)).toBeVisible();
  });

  test('should display UI settings', async ({ page }) => {
    await expect(page.getByText(/user interface/i)).toBeVisible();
    await expect(page.getByLabel(/theme/i)).toBeVisible();
    await expect(page.getByLabel(/kiosk mode/i)).toBeVisible();
  });

  test('should display sync settings', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /sync/i })).toBeVisible();
    await expect(page.getByLabel(/sync interval/i)).toBeVisible();
    await expect(page.getByLabel(/max offline hours/i)).toBeVisible();
  });

  test('should display reporting settings', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /reporting/i })).toBeVisible();
    await expect(page.getByLabel(/enable reporting/i)).toBeVisible();
    await expect(page.getByLabel(/local only/i)).toBeVisible();
  });

  test('should display retention settings', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /data retention/i })).toBeVisible();
    await expect(page.getByLabel(/verification events/i)).toBeVisible();
    await expect(page.getByLabel(/audit log/i)).toBeVisible();
    await expect(page.getByLabel(/encrypt pii/i)).toBeVisible();
  });

  test('should have save button', async ({ page }) => {
    await expect(page.getByTestId('settings-save')).toBeVisible();
    await expect(page.getByTestId('settings-save')).toHaveText(/save settings/i);
  });
});

test.describe('Settings Modification', () => {
  test.beforeEach(async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/settings');
  });

  test('should toggle kiosk mode', async ({ page }) => {
    const kioskSwitch = page.getByLabel(/kiosk mode/i);
    await expect(kioskSwitch).not.toBeChecked();
    
    await kioskSwitch.click();
    await expect(kioskSwitch).toBeChecked();
  });

  test('should change theme', async ({ page }) => {
    const themeSelect = page.getByRole('combobox', { name: /theme/i });
    await themeSelect.click();
    await page.getByRole('option', { name: /dark/i }).click();
    
    await expect(themeSelect).toHaveText(/dark/i);
  });

  test('should modify sync interval', async ({ page }) => {
    const syncInterval = page.getByLabel(/sync interval/i);
    await syncInterval.clear();
    await syncInterval.fill('48');
    
    await expect(syncInterval).toHaveValue('48');
  });

  test('should toggle local only reporting', async ({ page }) => {
    const localOnlySwitch = page.getByLabel(/local only/i);
    await localOnlySwitch.click();
    
    await expect(localOnlySwitch).toBeChecked();
  });

  test('should save settings successfully', async ({ page, mockTauri }) => {
    // Make a change
    await page.getByLabel(/kiosk mode/i).click();
    
    // Save
    await page.getByTestId('settings-save').click();

    await expect(page.getByText(/settings saved successfully/i)).toBeVisible();
  });

  test('should show error on save failure', async ({ page, mockTauri }) => {
    await mockTauri({
      update_config: { __error: 'Permission denied' },
    });
    await page.reload();

    await page.getByTestId('settings-save').click();

    await expect(page.getByText(/permission denied/i)).toBeVisible();
  });
});

test.describe('Settings Navigation', () => {
  test('should navigate from settings to verification', async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/settings');

    await page.locator('[data-testid="nav-verify"]:visible').click();
    
    await expect(page).toHaveURL(/#\/?$/);
    await expect(page.getByRole('heading', { name: /credential verification/i })).toBeVisible();
  });

  test('should navigate from settings to license', async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/settings');

    await page.locator('[data-testid="nav-license"]:visible').click();
    
    await expect(page).toHaveURL(/#\/license$/);
  });

  test('should navigate from settings to sync', async ({ page, mockTauri }) => {
    await mockTauri();
    await page.goto('/#/settings');

    await page.locator('[data-testid="nav-trust-anchors"]:visible').click();
    
    await expect(page).toHaveURL(/#\/sync$/);
  });
});
