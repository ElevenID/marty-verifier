import { create } from 'zustand';
import {
  SyncStatus,
  HardwareTier,
  HardwareCapabilities,
  VerificationResult,
  NetworkTransitionResult,
  OfflineQueueStatus,
  getOfflineQueueStatus,
  getSyncStatus,
  getHardwareTier,
  detectHardware,
  setNetworkStatus,
} from '@/services/tauri-api';

interface AppState {
  // Sync state
  sync: SyncStatus | null;
  syncLoading: boolean;
  syncError: string | null;

  // Hardware state
  hardwareTier: HardwareTier | null;
  hardwareCapabilities: HardwareCapabilities | null;

  // Online status
  isOnline: boolean;
  hostOnline: boolean;
  offlineMode: boolean;
  networkBusy: boolean;
  queue: OfflineQueueStatus | null;
  networkTransition: NetworkTransitionResult | null;
  networkError: string | null;

  // Verification state
  lastVerification: VerificationResult | null;
  verificationInProgress: boolean;

  // Actions
  loadSyncStatus: () => Promise<void>;
  loadHardwareInfo: () => Promise<void>;
  setOnlineStatus: (online: boolean) => Promise<void>;
  setOfflineMode: (offline: boolean) => Promise<void>;
  refreshQueue: () => Promise<void>;
  applyNetworkMode: () => Promise<void>;
  setLastVerification: (result: VerificationResult | null) => void;
  setVerificationInProgress: (inProgress: boolean) => void;
  initialize: () => Promise<void>;
}

let networkUpdates: Promise<void> = Promise.resolve();
let networkRequests = 0;

export const useAppStore = create<AppState>((set, get) => ({
  // Initial state
  sync: null,
  syncLoading: false,
  syncError: null,

  hardwareTier: null,
  hardwareCapabilities: null,

  isOnline: false,
  hostOnline: false,
  offlineMode: false,
  networkBusy: false,
  queue: null,
  networkTransition: null,
  networkError: null,

  lastVerification: null,
  verificationInProgress: false,

  // Actions
  loadSyncStatus: async () => {
    set({ syncLoading: true, syncError: null });
    try {
      const sync = await getSyncStatus();
      set({ sync, syncLoading: false });
    } catch (error) {
      set({
        syncError: error instanceof Error ? error.message : 'Failed to load sync status',
        syncLoading: false,
      });
    }
  },

  loadHardwareInfo: async () => {
    try {
      const [tier, capabilities] = await Promise.all([
        getHardwareTier(),
        detectHardware(),
      ]);
      set({ hardwareTier: tier, hardwareCapabilities: capabilities });
    } catch (error) {
      console.error('Failed to detect hardware:', error);
    }
  },

  setOnlineStatus: async (online: boolean) => {
    set({ hostOnline: online });
    await get().applyNetworkMode();
  },

  setOfflineMode: async (offline: boolean) => {
    set({ offlineMode: offline });
    await get().applyNetworkMode();
  },

  refreshQueue: async () => {
    try {
      set({ queue: await getOfflineQueueStatus() });
    } catch (error) {
      set({ networkError: error instanceof Error ? error.message : 'Failed to read audit queue' });
    }
  },

  applyNetworkMode: async () => {
    const online = get().hostOnline && !get().offlineMode;
    const request = ++networkRequests;
    set({ networkBusy: true, networkError: null });
    // Serialize host events and operator requests so native state cannot finish out of order.
    networkUpdates = networkUpdates.then(async () => {
      try {
        const transition = await setNetworkStatus(online);
        set({ isOnline: transition.online, networkTransition: transition,
          networkError: transition.reporting_error });
        await get().refreshQueue();
      } catch (error) {
        set({ networkTransition: null,
          networkError: error instanceof Error ? error.message : 'Failed to update network status' });
      } finally {
        if (request === networkRequests) set({ networkBusy: false });
      }
    });
    await networkUpdates;
  },

  setLastVerification: (result: VerificationResult | null) => {
    set({ lastVerification: result });
  },

  setVerificationInProgress: (inProgress: boolean) => {
    set({ verificationInProgress: inProgress });
  },

  initialize: async () => {
    const { loadSyncStatus, loadHardwareInfo } = get();
    await Promise.all([
      loadSyncStatus(),
      loadHardwareInfo(),
    ]);
  },
}));
