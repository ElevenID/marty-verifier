import { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Stack,
  Alert,
  TextField,
} from '@mui/material';
import { Save as SaveIcon } from '@mui/icons-material';
import { getConfig, updateConfig, AppConfig } from '@/services/tauri-api';
import { useAppStore } from '@/store';

export default function SettingsPage() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const { hardwareTier, hardwareCapabilities } = useAppStore();

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const cfg = await getConfig();
      setConfig(cfg);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load config');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!config) return;

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      await updateConfig(config);
      setSuccess('Settings saved successfully');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  if (loading || !config) {
    return (
      <Container maxWidth="md">
        <Typography>Loading settings...</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="md">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Settings
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Configure the Marty Verifier application.
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {/* Hardware Info */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Hardware
          </Typography>
          <Stack spacing={1}>
            <Typography variant="body2">
              <strong>Hardware Tier:</strong> {hardwareTier ?? 'Unknown'}
            </Typography>
            {hardwareCapabilities && (
              <>
                <Typography variant="body2">
                  <strong>Camera:</strong> {hardwareCapabilities.has_camera ? 'Yes' : 'No'}
                </Typography>
                <Typography variant="body2">
                  <strong>NFC:</strong> {hardwareCapabilities.has_nfc ? 'Yes' : 'No'}
                </Typography>
                <Typography variant="body2">
                  <strong>BLE:</strong> {hardwareCapabilities.has_ble ? 'Yes' : 'No'}
                </Typography>
                <Typography variant="body2">
                  <strong>TPM:</strong> {hardwareCapabilities.has_tpm ? 'Yes' : 'No'}
                </Typography>
              </>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* UI Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            User Interface
          </Typography>
          <Stack spacing={2}>
            <FormControl fullWidth>
              <InputLabel id="theme-select-label">Theme</InputLabel>
              <Select
                id="theme-select"
                labelId="theme-select-label"
                value={config.ui_config.theme}
                label="Theme"
                onChange={(e) =>
                  setConfig({
                    ...config,
                    ui_config: { ...config.ui_config, theme: e.target.value },
                  })
                }
              >
                <MenuItem value="light">Light</MenuItem>
                <MenuItem value="dark">Dark</MenuItem>
                <MenuItem value="system">System</MenuItem>
              </Select>
            </FormControl>

            <FormControlLabel
              control={
                <Switch
                  checked={config.ui_config.kiosk_mode}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      ui_config: { ...config.ui_config, kiosk_mode: e.target.checked },
                    })
                  }
                />
              }
              label="Kiosk Mode (fullscreen, no exit)"
            />

            <FormControlLabel
              control={
                <Switch
                  checked={config.ui_config.show_offline_banner}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      ui_config: { ...config.ui_config, show_offline_banner: e.target.checked },
                    })
                  }
                />
              }
              label="Show Offline Status Banner"
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Sync Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Sync
          </Typography>
          <Stack spacing={2}>
            <TextField
              fullWidth
              label="Sync Interval (hours)"
              type="number"
              value={config.sync_config.sync_interval_hours}
              onChange={(e) =>
                setConfig({
                  ...config,
                  sync_config: {
                    ...config.sync_config,
                    sync_interval_hours: parseInt(e.target.value) || 24,
                  },
                })
              }
            />

            <TextField
              fullWidth
              label="Max Offline Hours"
              type="number"
              value={config.sync_config.max_offline_hours}
              onChange={(e) =>
                setConfig({
                  ...config,
                  sync_config: {
                    ...config.sync_config,
                    max_offline_hours: parseInt(e.target.value) || 72,
                  },
                })
              }
            />

            <FormControlLabel
              control={
                <Switch
                  checked={config.sync_config.enable_usb_import}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      sync_config: {
                        ...config.sync_config,
                        enable_usb_import: e.target.checked,
                      },
                    })
                  }
                />
              }
              label="Enable USB Import"
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Reporting Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Reporting
          </Typography>
          <Stack spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={config.reporting_config.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      reporting_config: {
                        ...config.reporting_config,
                        enabled: e.target.checked,
                      },
                    })
                  }
                />
              }
              label="Enable Reporting"
            />

            <FormControlLabel
              control={
                <Switch
                  checked={config.reporting_config.local_only}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      reporting_config: {
                        ...config.reporting_config,
                        local_only: e.target.checked,
                      },
                    })
                  }
                />
              }
              label="Local Only (no remote reporting)"
            />

            <TextField
              fullWidth
              label="Batch Upload Interval (minutes)"
              type="number"
              value={config.reporting_config.batch_interval_minutes}
              onChange={(e) =>
                setConfig({
                  ...config,
                  reporting_config: {
                    ...config.reporting_config,
                    batch_interval_minutes: parseInt(e.target.value) || 15,
                  },
                })
              }
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Update Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Updates
          </Typography>
          <Stack spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={config.update_config.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      update_config: {
                        ...config.update_config,
                        enabled: e.target.checked,
                      },
                    })
                  }
                />
              }
              label="Enable Updates"
            />

            <TextField
              fullWidth
              label="Update Base URL"
              placeholder="https://updates.example.com"
              value={config.update_config.base_url}
              onChange={(e) =>
                setConfig({
                  ...config,
                  update_config: {
                    ...config.update_config,
                    base_url: e.target.value,
                  },
                })
              }
            />

            <TextField
              fullWidth
              label="Default Channel"
              placeholder="stable"
              value={config.update_config.default_channel}
              onChange={(e) =>
                setConfig({
                  ...config,
                  update_config: {
                    ...config.update_config,
                    default_channel: e.target.value,
                  },
                })
              }
            />

            <TextField
              fullWidth
              label="Update Public Key"
              placeholder="minisign public key"
              value={config.update_config.public_key}
              onChange={(e) =>
                setConfig({
                  ...config,
                  update_config: {
                    ...config.update_config,
                    public_key: e.target.value,
                  },
                })
              }
              multiline
              minRows={3}
            />
          </Stack>
        </CardContent>
      </Card>

      {/* Retention Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Data Retention
          </Typography>
          <Stack spacing={2}>
            <TextField
              fullWidth
              label="Verification Events (days)"
              type="number"
              value={config.retention.verification_events_days}
              onChange={(e) =>
                setConfig({
                  ...config,
                  retention: {
                    ...config.retention,
                    verification_events_days: parseInt(e.target.value) || 30,
                  },
                })
              }
            />

            <TextField
              fullWidth
              label="Audit Log (days)"
              type="number"
              value={config.retention.audit_log_days}
              onChange={(e) =>
                setConfig({
                  ...config,
                  retention: {
                    ...config.retention,
                    audit_log_days: parseInt(e.target.value) || 90,
                  },
                })
              }
            />

            <FormControlLabel
              control={
                <Switch
                  checked={config.retention.encrypt_pii}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      retention: {
                        ...config.retention,
                        encrypt_pii: e.target.checked,
                      },
                    })
                  }
                />
              }
              label="Encrypt PII at Rest"
            />
          </Stack>
        </CardContent>
      </Card>

      <Button
        data-testid="settings-save"
        variant="contained"
        size="large"
        startIcon={<SaveIcon />}
        onClick={handleSave}
        disabled={saving}
        fullWidth
      >
        {saving ? 'Saving...' : 'Save Settings'}
      </Button>
    </Container>
  );
}
