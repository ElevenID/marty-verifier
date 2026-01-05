import { create } from 'zustand';
import {
  LicenseStatus,
  SyncStatus,
  HardwareTier,
  HardwareCapabilities,
  VerificationResult,
  getLicenseStatus,
  getSyncStatus,
  getHardwareTier,
  detectHardware,
} from '@/services/tauri-api';

interface AppState {
  // License state
  license: LicenseStatus | null;
  licenseLoading: boolean;
  licenseError: string | null;

  // Sync state
  sync: SyncStatus | null;
  syncLoading: boolean;
  syncError: string | null;

  // Hardware state
  hardwareTier: HardwareTier | null;
  hardwareCapabilities: HardwareCapabilities | null;

  // Online status
  isOnline: boolean;

  // Verification state
  lastVerification: VerificationResult | null;
  verificationInProgress: boolean;

  // Actions
  loadLicenseStatus: () => Promise<void>;
  loadSyncStatus: () => Promise<void>;
  loadHardwareInfo: () => Promise<void>;
  setOnlineStatus: (online: boolean) => void;
  setLastVerification: (result: VerificationResult | null) => void;
  setVerificationInProgress: (inProgress: boolean) => void;
  initialize: () => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => ({
  // Initial state
  license: null,
  licenseLoading: false,
  licenseError: null,

  sync: null,
  syncLoading: false,
  syncError: null,

  hardwareTier: null,
  hardwareCapabilities: null,

  isOnline: false,

  lastVerification: null,
  verificationInProgress: false,

  // Actions
  loadLicenseStatus: async () => {
    set({ licenseLoading: true, licenseError: null });
    try {
      const license = await getLicenseStatus();
      set({ license, licenseLoading: false });
    } catch (error) {
      set({
        licenseError: error instanceof Error ? error.message : 'Failed to load license',
        licenseLoading: false,
      });
    }
  },

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

  setOnlineStatus: (online: boolean) => {
    set({ isOnline: online });
  },

  setLastVerification: (result: VerificationResult | null) => {
    set({ lastVerification: result });
  },

  setVerificationInProgress: (inProgress: boolean) => {
    set({ verificationInProgress: inProgress });
  },

  initialize: async () => {
    const { loadLicenseStatus, loadSyncStatus, loadHardwareInfo } = get();
    await Promise.all([
      loadLicenseStatus(),
      loadSyncStatus(),
      loadHardwareInfo(),
    ]);
  },
}));
