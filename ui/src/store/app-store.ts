import { create } from 'zustand';
import {
  SyncStatus,
  HardwareTier,
  HardwareCapabilities,
  VerificationResult,
  NetworkTransitionResult,
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
  networkTransition: NetworkTransitionResult | null;
  networkError: string | null;

  // Verification state
  lastVerification: VerificationResult | null;
  verificationInProgress: boolean;

  // Actions
  loadSyncStatus: () => Promise<void>;
  loadHardwareInfo: () => Promise<void>;
  setOnlineStatus: (online: boolean) => Promise<void>;
  setLastVerification: (result: VerificationResult | null) => void;
  setVerificationInProgress: (inProgress: boolean) => void;
  initialize: () => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => ({
  // Initial state
  sync: null,
  syncLoading: false,
  syncError: null,

  hardwareTier: null,
  hardwareCapabilities: null,

  isOnline: false,
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
    set({ isOnline: online });
    try {
      const transition = await setNetworkStatus(online);
      set({
        networkTransition: transition,
        networkError: transition.reporting_error,
      });
    } catch (error) {
      set({
        networkTransition: null,
        networkError: error instanceof Error ? error.message : 'Failed to update network status',
      });
    }
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
