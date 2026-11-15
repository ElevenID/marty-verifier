import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import SettingsPage from '@/pages/SettingsPage';
import type { AppConfig } from '@/services/tauri-api';

const { getConfig, updateConfig } = vi.hoisted(() => ({
  getConfig: vi.fn(),
  updateConfig: vi.fn(),
}));

vi.mock('@/services/tauri-api', () => ({ getConfig, updateConfig }));
vi.mock('@/store', () => ({
  useAppStore: () => ({ hardwareTier: null, hardwareCapabilities: null }),
}));

const config: AppConfig = {
  data_dir: 'test-data',
  liveness_retention: {
    default_audit_clip_ttl_seconds: 60,
    max_audit_clip_ttl_seconds: 120,
    encrypt_temp_media: true,
  },
  sync_config: {
    aamva_dts_url: null,
    icao_pkd_url: null,
    open_badge_keys_url: null,
    sync_interval_hours: 24,
    enable_usb_import: false,
    max_offline_hours: 72,
  },
  reporting_config: {
    enabled: false,
    api_endpoint: null,
    batch_upload_endpoint: null,
    local_only: true,
    batch_interval_minutes: 15,
    max_queue_size: 100,
  },
  update_config: {
    enabled: false,
    base_url: 'https://updates.example.test',
    public_key: 'synthetic-public-key',
    default_channel: 'stable',
  },
  ui_config: {
    hardware_tier_override: null,
    kiosk_mode: false,
    show_offline_banner: true,
    theme: 'system',
    language: 'en',
  },
  retention: {
    verification_events_days: 30,
    audit_log_days: 90,
    encrypt_pii: true,
    redacted_fields: [],
  },
  open_badge_trust: {
    policy: 'fail_closed',
    stale_warning_hours: 24,
    stale_critical_hours: 72,
  },
};

describe('SettingsPage configuration failures', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    updateConfig.mockResolvedValue(undefined);
  });

  afterEach(cleanup);

  it.each([
    [new Error('Configuration could not be read'), 'Configuration could not be read'],
    ['Native settings unavailable', 'Native settings unavailable'],
    [undefined, 'Failed to load config'],
  ])('shows a completed load failure and a recovery action', async (failure, message) => {
    getConfig.mockRejectedValueOnce(failure);

    render(<SettingsPage />);

    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.queryByText('Loading settings...')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry loading settings' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Save Settings' })).not.toBeInTheDocument();
    expect(updateConfig).not.toHaveBeenCalled();
  });

  it('retries loading, clears the old error and preserves native save behavior after recovery', async () => {
    let resolveRetry!: (value: AppConfig) => void;
    getConfig.mockRejectedValueOnce(new Error('Temporary read failure'));
    getConfig.mockReturnValueOnce(new Promise<AppConfig>((resolve) => { resolveRetry = resolve; }));

    render(<SettingsPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Temporary read failure');
    fireEvent.click(screen.getByRole('button', { name: 'Retry loading settings' }));

    expect(getConfig).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Loading settings...')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Settings' })).not.toBeInTheDocument();

    await act(async () => { resolveRetry(config); });
    expect(screen.getByLabelText('Max Offline Hours')).toHaveValue(72);
    fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));
    expect(updateConfig).toHaveBeenCalledWith(config);
    expect(await screen.findByText('Settings saved successfully')).toBeInTheDocument();
    expect(screen.queryByText('Temporary read failure')).not.toBeInTheDocument();
  });

  it('keeps a second failed read visible and retryable without inventing defaults', async () => {
    getConfig.mockRejectedValueOnce('First native error');
    getConfig.mockRejectedValueOnce('Second native error');

    render(<SettingsPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('First native error');
    fireEvent.click(screen.getByRole('button', { name: 'Retry loading settings' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Second native error');
    expect(screen.getByRole('button', { name: 'Retry loading settings' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Save Settings' })).not.toBeInTheDocument();
    expect(updateConfig).not.toHaveBeenCalled();
  });
});
