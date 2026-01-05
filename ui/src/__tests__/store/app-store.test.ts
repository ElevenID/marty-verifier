/**
 * Unit tests for Zustand app store
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mockTauriCommands } from '../../test/setup';

describe('AppStore', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  describe('Initial State', () => {
    it('should have correct initial state', async () => {
      const { useAppStore } = await import('@/store/app-store');
      const state = useAppStore.getState();

      expect(state.license).toBeNull();
      expect(state.sync).toBeNull();
      expect(state.hardwareTier).toBeNull();
      expect(state.hardwareCapabilities).toBeNull();
      expect(state.isOnline).toBe(false);
      expect(state.lastVerification).toBeNull();
      expect(state.verificationInProgress).toBe(false);
    });
  });

  describe('Actions', () => {
    it('should set online status', async () => {
      const { useAppStore } = await import('@/store/app-store');

      useAppStore.getState().setOnlineStatus(true);
      expect(useAppStore.getState().isOnline).toBe(true);

      useAppStore.getState().setOnlineStatus(false);
      expect(useAppStore.getState().isOnline).toBe(false);
    });

    it('should set verification in progress', async () => {
      const { useAppStore } = await import('@/store/app-store');

      useAppStore.getState().setVerificationInProgress(true);
      expect(useAppStore.getState().verificationInProgress).toBe(true);

      useAppStore.getState().setVerificationInProgress(false);
      expect(useAppStore.getState().verificationInProgress).toBe(false);
    });

    it('should set last verification result', async () => {
      const { useAppStore } = await import('@/store/app-store');
      const mockResult = {
        verification_id: 'test-id',
        status: 'valid' as const,
        credential_type: 'mdl',
        issuer: { name: 'Test DMV', jurisdiction: 'US-CA', subject: null },
        disclosed_claims: { given_name: 'John' },
        trust_chain: { valid: true, chain_type: 'iaca', trust_anchor: 'US-CA', offline_verified: false },
        revocation_status: 'valid' as const,
        verified_at: '2025-12-19T10:00:00Z',
        warnings: [],
      };

      useAppStore.getState().setLastVerification(mockResult);
      expect(useAppStore.getState().lastVerification).toEqual(mockResult);
    });
  });

  describe('Async Actions', () => {
    it('should load license status from Tauri', async () => {
      const mockLicense = {
        valid: true,
        org_id: 'tauri-org',
        features: ['mdl'],
        expires_at: '2025-12-31T00:00:00Z',
        days_until_expiry: 30,
        grace_period_active: false,
        grace_period_days: null,
        hardware_bound: false,
        deployment_mode: 'development',
        max_verifications_total: 500,
        verifications_total: 0,
        verifications_remaining: 500,
        update_channels: ['dev'],
      };

      mockTauriCommands({
        get_license_status: mockLicense,
      });

      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().loadLicenseStatus();

      const state = useAppStore.getState();
      expect(state.license).toEqual(mockLicense);
      expect(state.licenseLoading).toBe(false);
      expect(state.licenseError).toBeNull();
    });

    it('should handle license loading error', async () => {
      mockTauriCommands({
        get_license_status: { __error: 'License expired' },
      });

      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().loadLicenseStatus();

      const state = useAppStore.getState();
      expect(state.license).toBeNull();
      expect(state.licenseLoading).toBe(false);
      expect(state.licenseError).toBeTruthy();
    });

    it('should load sync status from Tauri', async () => {
      const mockSync = {
        last_sync: '2025-12-19T10:00:00Z',
        hours_since_sync: 2,
        sync_overdue: false,
        iaca_certificates: 50,
        csca_certificates: 100,
        dsc_certificates: 400,
        open_badge_keys: 10,
        open_badge_last_sync: '2025-12-19T10:30:00Z',
        open_badge_hours_since_sync: 1.5,
        open_badge_sync_overdue: false,
        crl_cache_age_hours: null,
        sync_in_progress: false,
        last_error: null,
      };

      mockTauriCommands({
        get_sync_status: mockSync,
      });

      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().loadSyncStatus();

      const state = useAppStore.getState();
      expect(state.sync).toEqual(mockSync);
      expect(state.syncLoading).toBe(false);
    });

    it('should initialize all state', async () => {
      const mockLicense = {
        valid: true,
        org_id: 'test-org',
        features: ['mdl'],
        expires_at: '2025-12-31T00:00:00Z',
        days_until_expiry: 30,
        grace_period_active: false,
        grace_period_days: null,
        hardware_bound: false,
        deployment_mode: 'development',
        max_verifications_total: 500,
        verifications_total: 0,
        verifications_remaining: 500,
        update_channels: ['dev'],
      };

      const mockSync = {
        last_sync: '2025-12-19T10:00:00Z',
        hours_since_sync: 1,
        sync_overdue: false,
        iaca_certificates: 25,
        csca_certificates: 50,
        dsc_certificates: 200,
        open_badge_keys: 6,
        open_badge_last_sync: '2025-12-19T10:30:00Z',
        open_badge_hours_since_sync: 0.5,
        open_badge_sync_overdue: false,
        crl_cache_age_hours: null,
        sync_in_progress: false,
        last_error: null,
      };

      mockTauriCommands({
        get_license_status: mockLicense,
        get_sync_status: mockSync,
        get_hardware_tier: 'Complex',
        detect_hardware: {
          has_camera: true,
          has_nfc: true,
          has_ble: false,
          has_biometric: true,
          has_tpm: false,
        },
      });

      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().initialize();

      const state = useAppStore.getState();
      expect(state.license).toEqual(mockLicense);
      expect(state.sync).toEqual(mockSync);
      expect(state.hardwareTier).toBe('Complex');
      expect(state.hardwareCapabilities?.has_camera).toBe(true);
    });
  });
});
