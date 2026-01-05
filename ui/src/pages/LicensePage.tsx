import { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Button,
  TextField,
  Stack,
  Alert,
  Chip,
  CircularProgress,
} from '@mui/material';
import {
  CheckCircle as ValidIcon,
  Error as InvalidIcon,
  Upload as UploadIcon,
} from '@mui/icons-material';
import { validateLicense } from '@/services/tauri-api';
import { useAppStore } from '@/store';

export default function LicensePage() {
  const [licenseInput, setLicenseInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const { license, loadLicenseStatus } = useAppStore();

  const handleValidate = async () => {
    if (!licenseInput.trim()) {
      setError('Please enter a license key');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      await validateLicense(licenseInput.trim());
      setSuccess('License validated and installed successfully');
      setLicenseInput('');
      await loadLicenseStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'License validation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          License Management
        </Typography>
        <Typography variant="body1" color="text.secondary">
          View and manage your Marty Verifier license.
        </Typography>
      </Box>

      {/* Current License Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            {license?.valid ? (
              <ValidIcon color="success" sx={{ fontSize: 32 }} />
            ) : (
              <InvalidIcon color="error" sx={{ fontSize: 32 }} />
            )}
            <Typography variant="h6">
              {license?.valid ? 'License Active' : 'No Valid License'}
            </Typography>
          </Box>

          {license && (
            <Stack spacing={2}>
              {license.org_id && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Organization
                  </Typography>
                  <Typography variant="body1">{license.org_id}</Typography>
                </Box>
              )}

              {license.expires_at && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Expires
                  </Typography>
                  <Typography variant="body1">
                    {new Date(license.expires_at).toLocaleDateString()}
                    {license.days_until_expiry !== null && (
                      <Chip
                        label={`${license.days_until_expiry} days`}
                        size="small"
                        color={license.days_until_expiry < 30 ? 'warning' : 'success'}
                        sx={{ ml: 1 }}
                      />
                    )}
                  </Typography>
                </Box>
              )}

              {license.grace_period_active && (
                <Alert severity="error">
                  License expired. Grace period: {license.grace_period_days} days remaining.
                </Alert>
              )}

              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Licensed Features
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {license.features.map((feature) => (
                    <Chip key={feature} label={feature} size="small" />
                  ))}
                </Box>
              </Box>

              {license.deployment_mode && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Deployment Mode
                  </Typography>
                  <Typography variant="body1">{license.deployment_mode}</Typography>
                </Box>
              )}

              {license.max_verifications_total !== null && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Verification Limit
                  </Typography>
                  <Typography variant="body1">
                    {license.verifications_total} / {license.max_verifications_total}
                    {license.verifications_remaining !== null && (
                      <Chip
                        label={`${license.verifications_remaining} remaining`}
                        size="small"
                        color={license.verifications_remaining < 100 ? 'warning' : 'success'}
                        sx={{ ml: 1 }}
                      />
                    )}
                  </Typography>
                </Box>
              )}

              {license.max_verifications_total === null && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Verification Limit
                  </Typography>
                  <Typography variant="body1">
                    Unlimited ({license.verifications_total} used)
                  </Typography>
                </Box>
              )}

              {license.update_channels.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Update Channels
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {license.update_channels.map((channel) => (
                      <Chip key={channel} label={channel} size="small" />
                    ))}
                  </Box>
                </Box>
              )}

              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Hardware Binding
                </Typography>
                <Typography variant="body1">
                  {license.hardware_bound ? 'Enabled' : 'Disabled'}
                </Typography>
              </Box>
            </Stack>
          )}
        </CardContent>
      </Card>

      {/* License Input */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Install License
          </Typography>

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

          <TextField
            data-testid="license-input"
            fullWidth
            multiline
            rows={4}
            label="License Key (JWT)"
            placeholder="Paste your license key here..."
            value={licenseInput}
            onChange={(e) => setLicenseInput(e.target.value)}
            sx={{ mb: 2 }}
          />

          <Button
            data-testid="license-submit"
            variant="contained"
            startIcon={loading ? <CircularProgress size={20} /> : <UploadIcon />}
            onClick={handleValidate}
            disabled={loading}
            fullWidth
          >
            {loading ? 'Validating...' : 'Validate & Install'}
          </Button>
        </CardContent>
      </Card>
    </Container>
  );
}
