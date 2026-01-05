import { Alert, Collapse, Button } from '@mui/material';
import { Warning as WarningIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '@/store';

export default function LicenseWarningBanner() {
  const navigate = useNavigate();
  const { license } = useAppStore();

  // Show warning if license expires in less than 30 days or grace period is active
  const showWarning = license && (
    (license.days_until_expiry !== null && license.days_until_expiry < 30) ||
    license.grace_period_active
  );

  if (!showWarning || !license) {
    return null;
  }

  const message = license.grace_period_active
    ? `License expired. Grace period: ${license.grace_period_days} days remaining.`
    : `License expires in ${license.days_until_expiry} days.`;

  return (
    <Collapse in={showWarning}>
      <Alert
        data-testid="license-warning-banner"
        severity={license.grace_period_active ? 'error' : 'warning'}
        icon={<WarningIcon />}
        sx={{ mb: 2 }}
        action={
          <Button color="inherit" size="small" onClick={() => navigate('/license')}>
            View License
          </Button>
        }
      >
        {message}
      </Alert>
    </Collapse>
  );
}
