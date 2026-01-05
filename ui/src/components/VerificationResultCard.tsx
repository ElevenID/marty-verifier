import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  Divider,
  Alert,
  Stack,
} from '@mui/material';
import {
  CheckCircle as ValidIcon,
  Cancel as InvalidIcon,
  Warning as WarningIcon,
  Schedule as PendingIcon,
  VerifiedUser as TrustIcon,
  RemoveRedEye as EyeIcon,
  Face6 as FaceIcon,
} from '@mui/icons-material';
import { VerificationResult } from '@/services/tauri-api';

interface VerificationResultCardProps {
  result: VerificationResult;
}

const statusConfig = {
  valid: { color: 'success' as const, icon: <ValidIcon />, label: 'Valid' },
  invalid: { color: 'error' as const, icon: <InvalidIcon />, label: 'Invalid' },
  failed: { color: 'error' as const, icon: <InvalidIcon />, label: 'Failed' },
  expired: { color: 'warning' as const, icon: <WarningIcon />, label: 'Expired' },
  revoked: { color: 'error' as const, icon: <InvalidIcon />, label: 'Revoked' },
  pending: { color: 'info' as const, icon: <PendingIcon />, label: 'Pending' },
};

export default function VerificationResultCard({ result }: VerificationResultCardProps) {
  const config = statusConfig[result.status] ?? statusConfig.failed;

  return (
    <Card
      data-testid="verification-result"
      role="region"
      aria-label="Verification result"
      sx={{
        borderLeft: 6,
        borderColor: `${config.color}.main`,
      }}
    >
      <CardContent>
        <Stack spacing={2}>
          {/* Status Header */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: '50%',
                bgcolor: `${config.color}.light`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: `${config.color}.main`,
              }}
            >
              {config.icon}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="h5" fontWeight="bold">
                {config.label}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {result.credential_type.toUpperCase()} Credential
              </Typography>
            </Box>
            <Chip
              label={result.trust_chain.offline_verified ? 'Offline' : 'Online'}
              size="small"
              color={result.trust_chain.offline_verified ? 'warning' : 'success'}
              variant="outlined"
            />
          </Box>

          <Divider />

          {/* Issuer Info */}
          {result.issuer && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary">
                Issuer
              </Typography>
              <Typography variant="body1">
                {result.issuer.name ?? 'Unknown'}
                {result.issuer.jurisdiction && ` (${result.issuer.jurisdiction})`}
              </Typography>
            </Box>
          )}

          {/* Trust Chain */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrustIcon color={result.trust_chain.valid ? 'success' : 'error'} />
            <Typography variant="body2">
              Trust Chain: {result.trust_chain.chain_type.toUpperCase()}
              {result.trust_chain.trust_anchor && ` (${result.trust_chain.trust_anchor})`}
            </Typography>
          </Box>

          {/* Disclosed Claims */}
          {Object.keys(result.disclosed_claims).length > 0 && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Disclosed Claims
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {Object.entries(result.disclosed_claims).map(([key, value]) => (
                  <Chip
                    key={key}
                    label={`${key}: ${typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}`}
                    size="small"
                    variant="outlined"
                  />
                ))}
              </Box>
            </Box>
          )}

          {/* eMRTD Details */}
          {result.emrtd_details && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Passport Verification Details
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip
                  label={`DSC Chain: ${result.emrtd_details.dsc_chain_status}`}
                  color={
                    result.emrtd_details.dsc_chain_status.toLowerCase() === 'valid'
                      ? 'success'
                      : 'warning'
                  }
                  variant="outlined"
                />
                <Chip
                  label={`SOD Signature: ${result.emrtd_details.sod_signature_status}`}
                  color={
                    result.emrtd_details.sod_signature_status.toLowerCase() === 'valid'
                      ? 'success'
                      : 'warning'
                  }
                  variant="outlined"
                />
                <Chip
                  label={`DG Hashes: ${result.emrtd_details.dg_hash_status}`}
                  color={
                    result.emrtd_details.dg_hash_status.toLowerCase() === 'valid'
                      ? 'success'
                      : 'warning'
                  }
                  variant="outlined"
                />
              </Stack>
              {result.emrtd_details.errors.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  {result.emrtd_details.errors.map((err, idx) => (
                    <Alert key={idx} severity="error" sx={{ mb: 1 }}>
                      {err}
                    </Alert>
                  ))}
                </Box>
              )}
            </Box>
          )}

          {/* DTC Details */}
          {result.dtc_details && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                DTC Verification Checks
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {result.dtc_details.checks.map((check) => (
                  <Chip
                    key={check.check_name}
                    label={`${check.check_name}: ${check.passed ? 'Passed' : 'Failed'}${
                      check.error_code ? ` (${check.error_code})` : ''
                    }`}
                    color={check.passed ? 'success' : 'error'}
                    variant="outlined"
                    title={check.details}
                  />
                ))}
              </Stack>
              {result.dtc_details.errors && result.dtc_details.errors.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  {result.dtc_details.errors.map((err, idx) => {
                    const code = result.dtc_details?.error_codes?.[idx];
                    return (
                      <Alert key={idx} severity="error" sx={{ mb: 0.5 }}>
                        {code ? `[${code}] ${err}` : err}
                      </Alert>
                    );
                  })}
                </Box>
              )}
            </Box>
          )}

          {/* Open Badge Details */}
          {result.open_badge_details && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Open Badge Details (v{result.open_badge_details.version})
              </Typography>
              {result.open_badge_details.errors.length > 0 && (
                <Box sx={{ mb: 1 }}>
                  {result.open_badge_details.errors.map((err, idx) => {
                    const code = result.open_badge_details?.error_codes?.[idx];
                    return (
                      <Alert key={idx} severity="error" sx={{ mb: 0.5 }}>
                        {code ? `[${code}] ${err}` : err}
                      </Alert>
                    );
                  })}
                </Box>
              )}
              {result.open_badge_details.warnings.length > 0 && (
                <Box>
                  {result.open_badge_details.warnings.map((warn, idx) => (
                    <Alert key={idx} severity="warning" sx={{ mb: 0.5 }}>
                      {warn}
                    </Alert>
                  ))}
                </Box>
              )}
            </Box>
          )}

          {/* Warnings */}
          {result.warnings.length > 0 && (
            <Box>
              {result.warnings.map((warning, index) => (
                <Alert key={index} severity="warning" sx={{ mb: 1 }}>
                  {warning}
                </Alert>
              ))}
            </Box>
          )}

          {/* Liveness */}
          {result.liveness && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Liveness
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
                <EyeIcon color={result.liveness.passed ? 'success' : 'error'} />
                <Typography variant="body2">
                  {result.liveness.passed ? 'Passed' : 'Failed'} (score:{' '}
                  {result.liveness.fused_score.toFixed(2)})
                </Typography>
                {result.liveness.mode_used && (
                  <Chip
                    label={`Mode: ${result.liveness.mode_used}`}
                    size="small"
                    variant="outlined"
                    color="info"
                  />
                )}
              </Stack>
              {result.liveness.errors && result.liveness.errors.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  {result.liveness.errors.map((err, idx) => (
                    <Alert key={idx} severity="error" sx={{ mb: 0.5 }}>
                      {err}
                    </Alert>
                  ))}
                </Box>
              )}
            </Box>
          )}

          {/* Face match */}
          {result.face_match && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Face Match
              </Typography>
              <Stack direction="row" spacing={1} alignItems="center">
                <FaceIcon color={result.face_match.verified ? 'success' : 'error'} />
                <Typography variant="body2">
                  {result.face_match.verified ? 'Matched' : 'No Match'} (score:{' '}
                  {result.face_match.similarity.toFixed(2)} /{' '}
                  {result.face_match.threshold.toFixed(2)}) via {result.face_match.provider}
                </Typography>
              </Stack>
            </Box>
          )}

          {/* Metadata */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
            <Typography variant="caption" color="text.secondary">
              ID: {result.verification_id.slice(0, 8)}...
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {new Date(result.verified_at).toLocaleString()}
            </Typography>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}
