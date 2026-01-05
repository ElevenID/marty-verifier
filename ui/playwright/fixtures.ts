/**
 * Playwright test fixtures for Marty Verifier E2E tests.
 * Provides Tauri IPC mocking and page object helpers.
 */
import { test as base, expect, Page } from '@playwright/test';

// Types for Tauri mock state
export interface LicenseStatus {
  valid: boolean;
  org_id: string | null;
  features: string[];
  expires_at: string | null;
  days_until_expiry: number | null;
  grace_period_active: boolean;
  grace_period_days: number | null;
  hardware_bound: boolean;
  deployment_mode: string | null;
  max_verifications_total: number | null;
  verifications_total: number;
  verifications_remaining: number | null;
  update_channels: string[];
}

export interface SyncStatus {
  last_sync: string | null;
  hours_since_sync: number | null;
  sync_overdue: boolean;
  iaca_certificates: number;
  csca_certificates: number;
  dsc_certificates: number;
  open_badge_keys: number;
  open_badge_last_sync: string | null;
  open_badge_hours_since_sync: number | null;
  open_badge_sync_overdue: boolean;
  crl_cache_age_hours: number | null;
  sync_in_progress: boolean;
  last_error: string | null;
}

export interface HardwareCapabilities {
  has_camera: boolean;
  has_nfc: boolean;
  has_ble: boolean;
  has_tpm: boolean;
  has_biometric_sensor: boolean;
  has_usb_scanner: boolean;
}

// Default mock values
export const defaultLicenseStatus: LicenseStatus = {
  valid: true,
  org_id: 'test-org',
  features: ['mdl', 'oid4vp', 'emrtd'],
  expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  days_until_expiry: 30,
  grace_period_active: false,
  grace_period_days: null,
  hardware_bound: false,
  deployment_mode: 'development',
  max_verifications_total: 1000,
  verifications_total: 5,
  verifications_remaining: 995,
  update_channels: ['stable'],
};

export const defaultSyncStatus: SyncStatus = {
  last_sync: new Date().toISOString(),
  hours_since_sync: 1,
  sync_overdue: false,
  iaca_certificates: 56,
  csca_certificates: 120,
  dsc_certificates: 450,
  open_badge_keys: 18,
  open_badge_last_sync: new Date().toISOString(),
  open_badge_hours_since_sync: 1,
  open_badge_sync_overdue: false,
  crl_cache_age_hours: 2,
  sync_in_progress: false,
  last_error: null,
};

export const defaultHardwareCapabilities: HardwareCapabilities = {
  has_camera: true,
  has_nfc: false,
  has_ble: false,
  has_tpm: false,
  has_biometric_sensor: false,
  has_usb_scanner: false,
};

// Mock command responses
export interface MockCommands {
  get_license_status?: LicenseStatus;
  get_sync_status?: SyncStatus;
  get_hardware_tier?: string;
  detect_hardware?: HardwareCapabilities;
  get_config?: object;
  [key: string]: unknown;
}

// Extended test fixture with Tauri mocking
export interface TestFixtures {
  mockTauri: (commands?: MockCommands) => Promise<void>;
}

/**
 * Inject Tauri mock into page before navigation
 */
async function injectTauriMock(page: Page, commands: MockCommands = {}) {
  const mockCommands = {
    get_license_status: defaultLicenseStatus,
    get_sync_status: defaultSyncStatus,
    get_hardware_tier: 'simple',
    detect_hardware: defaultHardwareCapabilities,
    get_config: {
      update_config: {
        enabled: false,
        base_url: '',
        public_key: '',
        default_channel: 'stable',
      },
      sync_config: {
        sync_interval_hours: 24,
        max_offline_hours: 72,
        enable_usb_import: true,
        open_badge_keys_url: null,
      },
      reporting_config: {
        enabled: true,
        local_only: false,
        batch_interval_minutes: 15,
      },
      ui_config: {
        theme: 'light',
        kiosk_mode: false,
        show_offline_banner: true,
      },
      retention: {
        verification_events_days: 30,
        audit_log_days: 90,
        encrypt_pii: true,
      },
      open_badge_trust: {
        policy: 'fail_closed',
        stale_warning_hours: 24,
        stale_critical_hours: 48,
      },
    },
    ...commands,
  };

  await page.addInitScript((cmds) => {
    // Create Tauri mock
    const mockInvoke = (command: string, args?: unknown) => {
      console.log(`[Tauri Mock] invoke: ${command}`, args);
      if (command in cmds) {
        const handler = cmds[command as keyof typeof cmds];
        if (
          handler &&
          typeof handler === 'object' &&
          '__error' in handler
        ) {
          const message = (handler as { __error?: string }).__error;
          return Promise.reject(new Error(message ?? 'Mock command error'));
        }
        if (typeof handler === 'function') {
          try {
            return Promise.resolve(handler(args));
          } catch (error) {
            return Promise.reject(error);
          }
        }
        return Promise.resolve(handler);
      }
      console.warn(`[Tauri Mock] Unmocked command: ${command}`);
      return Promise.resolve(null);
    };

    // Set up window.__TAURI_INTERNALS__
    (window as any).__TAURI_INTERNALS__ = {
      invoke: mockInvoke,
      convertFileSrc: (src: string) => src,
      transformCallback: () => {},
      metadata: {
        currentWindow: { label: 'main' },
        currentWebviewWindow: { label: 'main' },
      },
    };

    // Also mock the module imports
    (window as any).__TAURI_MOCK_COMMANDS__ = cmds;
  }, mockCommands);
}

// Extended test with fixtures
export const test = base.extend<TestFixtures>({
  mockTauri: async ({ page }, use) => {
    const mock = async (commands: MockCommands = {}) => {
      await injectTauriMock(page, commands);
    };
    await use(mock);
  },
});

export { expect };
