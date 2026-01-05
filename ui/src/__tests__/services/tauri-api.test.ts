/**
 * Unit tests for Tauri API service
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mockTauriCommands } from '../../test/setup';

describe('Tauri API', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  describe('License API', () => {
    it('should get license status', async () => {
      const mockLicense = {
        valid: true,
        org_id: 'test-org',
        features: ['mdl', 'oid4vp'],
        expires_at: '2025-12-31T00:00:00Z',
        days_until_expiry: 30,
        grace_period_active: false,
        grace_period_days: null,
        hardware_bound: true,
        deployment_mode: 'production',
        max_verifications_total: 1000,
        verifications_total: 50,
        verifications_remaining: 950,
        update_channels: ['stable'],
      };

      mockTauriCommands({
        get_license_status: mockLicense,
      });

      const { getLicenseStatus } = await import('@/services/tauri-api');
      const result = await getLicenseStatus();

      expect(result).toEqual(mockLicense);
      expect(result.valid).toBe(true);
      expect(result.org_id).toBe('test-org');
    });

    it('should validate license', async () => {
      const mockResponse = {
        valid: true,
        org_id: 'new-org',
        features: ['mdl'],
        expires_at: '2025-12-31T00:00:00Z',
        days_until_expiry: 60,
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
        validate_license: mockResponse,
      });

      const { validateLicense } = await import('@/services/tauri-api');
      const result = await validateLicense('license-jwt-token');

      expect(result.valid).toBe(true);
      expect(result.org_id).toBe('new-org');
    });

    it('should get licensed features', async () => {
      mockTauriCommands({
        get_licensed_features: ['mdl', 'oid4vp', 'sd-jwt'],
      });

      const { getLicensedFeatures } = await import('@/services/tauri-api');
      const result = await getLicensedFeatures();

      expect(result).toEqual(['mdl', 'oid4vp', 'sd-jwt']);
    });
  });

  describe('Verification API', () => {
    it('should verify credential', async () => {
      const mockResult = {
        verification_id: 'ver-123',
        status: 'valid',
        credential_type: 'mdl',
        issuer: { name: 'State DMV', jurisdiction: 'US-CA', subject: null },
        disclosed_claims: { given_name: 'John', family_name: 'Doe' },
        trust_chain: { valid: true, chain_type: 'iaca', trust_anchor: 'US-CA', offline_verified: false },
        revocation_status: 'valid',
        verified_at: '2025-12-19T10:00:00Z',
        warnings: [],
      };

      mockTauriCommands({
        verify_credential: mockResult,
      });

      const { verifyCredential } = await import('@/services/tauri-api');
      const result = await verifyCredential({
        credential_type: 'mdl',
        credential_data: 'base64-encoded-data',
      });

      expect(result.status).toBe('valid');
      expect(result.verification_id).toBe('ver-123');
    });

    it('should get verification history', async () => {
      const mockHistory = [
        { id: '1', credential_type: 'mdl', status: 'valid', verified_at: '2025-12-19T10:00:00Z', jurisdiction: 'US-CA', synced: true },
        { id: '2', credential_type: 'oid4vp', status: 'invalid', verified_at: '2025-12-19T09:00:00Z', jurisdiction: null, synced: false },
      ];

      mockTauriCommands({
        get_verification_history: mockHistory,
      });

      const { getVerificationHistory } = await import('@/services/tauri-api');
      const result = await getVerificationHistory(10);

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe('1');
    });
  });

  describe('Sync API', () => {
    it('should get sync status', async () => {
      const mockStatus = {
        last_sync: '2025-12-19T08:00:00Z',
        hours_since_sync: 2.5,
        iaca_certificates: 50,
        csca_certificates: 100,
        dsc_certificates: 500,
        open_badge_keys: 12,
        open_badge_last_sync: '2025-12-19T08:30:00Z',
        open_badge_hours_since_sync: 2.0,
        open_badge_sync_overdue: false,
        crl_cache_age_hours: 12,
        sync_overdue: false,
        sync_in_progress: false,
        last_error: null,
      };

      mockTauriCommands({
        get_sync_status: mockStatus,
      });

      const { getSyncStatus } = await import('@/services/tauri-api');
      const result = await getSyncStatus();

      expect(result.iaca_certificates).toBe(50);
      expect(result.sync_overdue).toBe(false);
    });

    it('should trigger sync', async () => {
      const mockResult = {
        success: true,
        iaca_updated: 5,
        csca_updated: 2,
        dsc_updated: 10,
        open_badge_keys_updated: 3,
        crl_updated: true,
        duration_seconds: 3.5,
        error: null,
      };

      mockTauriCommands({
        sync_trust_anchors: mockResult,
      });

      const { syncTrustAnchors } = await import('@/services/tauri-api');
      const result = await syncTrustAnchors(true);

      expect(result.success).toBe(true);
      expect(result.iaca_updated).toBe(5);
    });
  });

  describe('Hardware API', () => {
    it('should detect hardware capabilities', async () => {
      const mockCaps = {
        has_camera: true,
        has_nfc: true,
        has_ble: false,
        has_tpm: true,
        has_biometric_sensor: false,
        has_usb_scanner: true,
      };

      mockTauriCommands({
        detect_hardware: mockCaps,
      });

      const { detectHardware } = await import('@/services/tauri-api');
      const result = await detectHardware();

      expect(result.has_camera).toBe(true);
      expect(result.has_nfc).toBe(true);
      expect(result.has_ble).toBe(false);
    });

    it('should get hardware tier', async () => {
      mockTauriCommands({
        get_hardware_tier: 'complex',
      });

      const { getHardwareTier } = await import('@/services/tauri-api');
      const result = await getHardwareTier();

      expect(result).toBe('complex');
    });
  });

  describe('Storage API', () => {
    it('should get offline queue status', async () => {
      const mockStatus = {
        pending_events: 25,
        oldest_event: '2025-12-18T10:00:00Z',
        data_size_bytes: 50000,
        last_sync_attempt: '2025-12-19T08:00:00Z',
        last_successful_sync: '2025-12-19T08:00:00Z',
      };

      mockTauriCommands({
        get_offline_queue_status: mockStatus,
      });

      const { getOfflineQueueStatus } = await import('@/services/tauri-api');
      const result = await getOfflineQueueStatus();

      expect(result.pending_events).toBe(25);
      expect(result.data_size_bytes).toBe(50000);
    });

    it('should clear verification history', async () => {
      mockTauriCommands({
        clear_verification_history: 50,
      });

      const { clearVerificationHistory } = await import('@/services/tauri-api');
      const result = await clearVerificationHistory(30);

      expect(result).toBe(50);
    });
  });

  describe('Update API', () => {
    it('should check for updates', async () => {
      const mockUpdate = {
        version: '0.2.0',
        current_version: '0.1.0',
        notes: 'Bug fixes',
        pub_date: 1734600000,
        channel: 'stable',
      };

      mockTauriCommands({
        check_for_updates: mockUpdate,
      });

      const { checkForUpdates } = await import('@/services/tauri-api');
      const result = await checkForUpdates();

      expect(result).toEqual(mockUpdate);
    });

    it('should pass channel when checking for updates', async () => {
      mockTauriCommands({
        check_for_updates: ({ channel }: { channel?: string }) => {
          return { channel };
        },
      });

      const { checkForUpdates } = await import('@/services/tauri-api');
      const result = await checkForUpdates('beta');

      expect(result).toEqual({ channel: 'beta' });
    });

    it('should download and install updates', async () => {
      mockTauriCommands({
        download_and_install_update: true,
      });

      const { downloadAndInstallUpdate } = await import('@/services/tauri-api');
      const result = await downloadAndInstallUpdate();

      expect(result).toBe(true);
    });
  });
});
