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

      expect(state.sync).toBeNull();
      expect(state.hardwareTier).toBeNull();
      expect(state.hardwareCapabilities).toBeNull();
      expect(state.isOnline).toBe(false);
      expect(state.networkTransition).toBeNull();
      expect(state.networkError).toBeNull();
      expect(state.lastVerification).toBeNull();
      expect(state.verificationInProgress).toBe(false);
    });
  });

  describe('Actions', () => {
    it('should set online status', async () => {
      mockTauriCommands({
        get_offline_queue_status: { pending_events: 0 },
        set_network_status: ({ online }: { online: boolean }) => ({
          online,
          flushed_events: 0,
          pending_events: 0,
          reporting_error: null,
        }),
      });
      const { useAppStore } = await import('@/store/app-store');

      await useAppStore.getState().setOnlineStatus(true);
      expect(useAppStore.getState().isOnline).toBe(true);
      expect(useAppStore.getState().networkTransition?.online).toBe(true);

      await useAppStore.getState().setOnlineStatus(false);
      expect(useAppStore.getState().isOnline).toBe(false);
    });

    it('keeps operator offline mode across host events and displays acknowledged queue results', async () => {
      const calls: boolean[] = [];
      let pending = 1;
      mockTauriCommands({
        set_network_status: ({ online }: { online: boolean }) => {
          calls.push(online);
          const flushed = online ? pending : 0;
          if (online) pending = 0;
          return { online, flushed_events: flushed, pending_events: pending, reporting_error: null };
        },
        get_offline_queue_status: () => ({ pending_events: pending }),
      });
      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().setOfflineMode(true);
      await useAppStore.getState().setOnlineStatus(true);
      expect(calls).toEqual([false, false]);
      expect(useAppStore.getState().isOnline).toBe(false);
      expect(useAppStore.getState().hostOnline).toBe(true);
      expect(useAppStore.getState().queue?.pending_events).toBe(1);
      await useAppStore.getState().setOfflineMode(false);
      expect(calls).toEqual([false, false, true]);
      expect(useAppStore.getState().networkTransition?.flushed_events).toBe(1);
      expect(useAppStore.getState().queue?.pending_events).toBe(0);
    });

    it('preserves last confirmed state when a native mode change fails', async () => {
      mockTauriCommands({ set_network_status: { __error: 'native unavailable' } });
      const { useAppStore } = await import('@/store/app-store');
      await useAppStore.getState().setOnlineStatus(true);
      expect(useAppStore.getState().hostOnline).toBe(true);
      expect(useAppStore.getState().isOnline).toBe(false);
      expect(useAppStore.getState().networkError).toBe('native unavailable');
      expect(useAppStore.getState().networkBusy).toBe(false);
    });

    it('acknowledges an applied offline mode when queue observation fails and clears stale counts', async () => {
      mockTauriCommands({
        set_network_status: {
          online: false, flushed_events: 0, pending_events: null,
          reporting_error: 'Audit queue status unavailable: storage unavailable',
        },
        get_offline_queue_status: { __error: 'storage unavailable' },
      });
      const { useAppStore } = await import('@/store/app-store');
      useAppStore.setState({ isOnline: true, hostOnline: true, queue: {
        pending_events: 7, oldest_event: null, data_size_bytes: 70,
        last_sync_attempt: null, last_successful_sync: null, last_error: null,
      } });
      await useAppStore.getState().setOfflineMode(true);
      expect(useAppStore.getState().isOnline).toBe(false);
      expect(useAppStore.getState().networkTransition?.pending_events).toBeNull();
      expect(useAppStore.getState().queue).toBeNull();
      expect(useAppStore.getState().networkError).toContain('Audit queue status unavailable');
      expect(useAppStore.getState().networkBusy).toBe(false);
      mockTauriCommands({
        set_network_status: { online: true, flushed_events: 2, pending_events: 0, reporting_error: null },
        get_offline_queue_status: { pending_events: 0 },
      });
      await useAppStore.getState().setOfflineMode(false);
      expect(useAppStore.getState().isOnline).toBe(true);
      expect(useAppStore.getState().queue?.pending_events).toBe(0);
      expect(useAppStore.getState().networkError).toBeNull();
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
      expect(state.sync).toEqual(mockSync);
      expect(state.hardwareTier).toBe('Complex');
      expect(state.hardwareCapabilities?.has_camera).toBe(true);
    });
  });
});
