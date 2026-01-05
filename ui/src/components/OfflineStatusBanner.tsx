import { Alert, Collapse } from '@mui/material';
import { WifiOff as OfflineIcon } from '@mui/icons-material';
import { useAppStore } from '@/store';

export default function OfflineStatusBanner() {
  const { isOnline, sync } = useAppStore();

  const showBanner = !isOnline && sync?.sync_overdue;

  return (
    <Collapse in={showBanner}>
      <Alert
        data-testid="offline-status-banner"
        severity="warning"
        icon={<OfflineIcon />}
        sx={{ mb: 2 }}
      >
        Operating offline. Trust anchors are {sync?.hours_since_sync?.toFixed(1) ?? '?'} hours old.
        Connect to sync for the latest certificates.
      </Alert>
    </Collapse>
  );
}
