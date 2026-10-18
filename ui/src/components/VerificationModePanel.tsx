import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material';
import { useAppStore } from '@/store';

/** Operator controls for the actual native verification/reporting state. */
export default function VerificationModePanel() {
  const { isOnline, hostOnline, offlineMode, networkBusy, networkError, queue,
    networkTransition, setOfflineMode, refreshQueue } = useAppStore();
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }} data-testid="verification-mode-panel">
      <Stack direction="row" spacing={2} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle1" data-testid="verification-mode-status">
            Verification mode: {networkBusy ? 'updating…' : isOnline ? 'Online' : 'Offline'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Host connectivity: {hostOnline ? 'available' : 'unavailable'}.
            {offlineMode ? ' Offline mode is selected for this session; host networking is unchanged.' : ' Verification follows host connectivity.'}
          </Typography>
        </Box>
        <Button variant="outlined" data-testid="verification-offline" disabled={networkBusy || offlineMode}
          onClick={() => void setOfflineMode(true)}>Use offline mode</Button>
        <Button variant="contained" data-testid="verification-online" disabled={networkBusy || !hostOnline}
          onClick={() => void setOfflineMode(false)}>Go online and send audit</Button>
        <Button data-testid="audit-queue-refresh" disabled={networkBusy}
          onClick={() => void refreshQueue()}>Refresh audit queue</Button>
      </Stack>
      <Typography sx={{ mt: 1 }} data-testid="audit-queue-status">
        Pending audit events: {queue?.pending_events ?? 'not yet read'}
        {networkTransition && ` · Last mode change: ${networkTransition.flushed_events} acknowledged, ${networkTransition.pending_events} remaining`}
      </Typography>
      {networkError && <Alert severity="error" sx={{ mt: 1 }}>{networkError}</Alert>}
    </Paper>
  );
}
