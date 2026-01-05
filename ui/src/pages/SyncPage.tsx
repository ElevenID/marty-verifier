import { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Button,
  Stack,
  Alert,
  LinearProgress,
  Chip,
  Grid,
  Divider,
} from '@mui/material';
import {
  Sync as SyncIcon,
  CloudDone as CloudIcon,
  CloudOff as OfflineIcon,
  Usb as UsbIcon,
  Security as CertIcon,
} from '@mui/icons-material';
import {
  syncTrustAnchors,
  importTrustAnchorsUsb,
  getConfig,
  SyncResult,
  UsbImportResult,
} from '@/services/tauri-api';
import { useAppStore } from '@/store';

export default function SyncPage() {
  const [syncing, setSyncing] = useState(false);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<SyncResult | UsbImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openBadgePolicy, setOpenBadgePolicy] = useState<string | null>(null);
  const { sync, loadSyncStatus, isOnline } = useAppStore();

  useEffect(() => {
    getConfig()
      .then((config) => setOpenBadgePolicy(config.open_badge_trust.policy))
      .catch(() => setOpenBadgePolicy(null));
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setError(null);
    setResult(null);

    try {
      const syncResult = await syncTrustAnchors(true);
      setResult(syncResult);
      if (!syncResult.success && syncResult.error) {
        setError(syncResult.error);
      }
      await loadSyncStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleUsbImport = async () => {
    // TODO: Open file picker via Tauri dialog
    // For now, use a hardcoded path for demonstration
    const path = '/Volumes/USB/trust_anchors.json';

    setImporting(true);
    setError(null);
    setResult(null);

    try {
      const importResult = await importTrustAnchorsUsb(path);
      setResult(importResult);
      if (!importResult.success && importResult.error) {
        setError(importResult.error);
      }
      await loadSyncStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'USB import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Trust Store Sync
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Manage trust anchors and Open Badge verification keys for credential verification.
        </Typography>
      </Box>

      {/* Sync Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            {isOnline ? (
              <CloudIcon color="success" sx={{ fontSize: 32 }} />
            ) : (
              <OfflineIcon color="warning" sx={{ fontSize: 32 }} />
            )}
            <Typography variant="h6">
              {isOnline ? 'Online' : 'Offline Mode'}
            </Typography>
            {sync?.sync_overdue && (
              <Chip label="Sync Overdue" color="warning" size="small" />
            )}
            {sync?.open_badge_sync_overdue && (
              <Chip label="Open Badge Trust Overdue" color="warning" size="small" />
            )}
          </Box>

          {sync && (
            <Grid container spacing={2}>
              <Grid item xs={12} sm={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <CertIcon color="primary" sx={{ fontSize: 40 }} />
                  <Typography variant="h4">{sync.iaca_certificates}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    IACA Certificates
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} sm={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <CertIcon color="secondary" sx={{ fontSize: 40 }} />
                  <Typography variant="h4">{sync.csca_certificates}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    CSCA Certificates
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} sm={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <CertIcon color="action" sx={{ fontSize: 40 }} />
                  <Typography variant="h4">{sync.dsc_certificates}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    DSC Certificates
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} sm={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <CertIcon color="info" sx={{ fontSize: 40 }} />
                  <Typography variant="h4">{sync.open_badge_keys}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Open Badge Keys
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          )}

          <Divider sx={{ my: 2 }} />

          <Stack spacing={1}>
            <Typography variant="body2">
              <strong>Last Sync:</strong>{' '}
              {sync?.last_sync
                ? new Date(sync.last_sync).toLocaleString()
                : 'Never'}
            </Typography>
            {sync?.hours_since_sync !== null && (
              <Typography variant="body2">
                <strong>Time Since Sync:</strong> {sync?.hours_since_sync?.toFixed(1)} hours
              </Typography>
            )}
            <Typography variant="body2">
              <strong>Open Badge Policy:</strong>{' '}
              {openBadgePolicy ? openBadgePolicy.replace('_', ' ') : 'unknown'}
            </Typography>
            <Typography variant="body2">
              <strong>Open Badge Trust Last Sync:</strong>{' '}
              {sync?.open_badge_last_sync
                ? new Date(sync.open_badge_last_sync).toLocaleString()
                : 'Never'}
            </Typography>
            {sync?.open_badge_hours_since_sync !== null && (
              <Typography variant="body2">
                <strong>Open Badge Trust Age:</strong>{' '}
                {sync?.open_badge_hours_since_sync?.toFixed(1)} hours
              </Typography>
            )}
            {sync?.last_error && (
              <Alert severity="error" sx={{ mt: 1 }}>
                Last Error: {sync.last_error}
              </Alert>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* Actions */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Sync Actions
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {result && 'iaca_updated' in result && (
            <Alert severity={result.success ? 'success' : 'warning'} sx={{ mb: 2 }}>
              Sync completed: {result.iaca_updated} IACA, {result.csca_updated} CSCA,{' '}
              {result.dsc_updated} DSC, {result.open_badge_keys_updated} Open Badge keys updated in{' '}
              {result.duration_seconds.toFixed(1)}s
            </Alert>
          )}

          {result && 'certificates_imported' in result && (
            <Alert severity={result.success ? 'success' : 'warning'} sx={{ mb: 2 }}>
              USB Import: {result.certificates_imported} certificates,{' '}
              {result.open_badge_keys_imported} Open Badge keys imported
              {result.package_version && ` (version ${result.package_version})`}
            </Alert>
          )}

          {(syncing || importing) && <LinearProgress sx={{ mb: 2 }} />}

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <Button
              variant="contained"
              startIcon={<SyncIcon />}
              onClick={handleSync}
              disabled={syncing || importing || !isOnline}
              fullWidth
            >
              {syncing ? 'Syncing...' : 'Sync from Cloud'}
            </Button>

            <Button
              variant="outlined"
              startIcon={<UsbIcon />}
              onClick={handleUsbImport}
              disabled={syncing || importing}
              fullWidth
            >
              {importing ? 'Importing...' : 'Import from USB'}
            </Button>
          </Stack>

          {!isOnline && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              Cloud sync requires network connection. Use USB import for air-gapped environments.
            </Typography>
          )}
        </CardContent>
      </Card>
    </Container>
  );
}
