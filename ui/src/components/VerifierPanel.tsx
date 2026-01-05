import { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Alert,
  Chip,
  Stack,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Checkbox,
  FormControlLabel,
  TextField,
  Divider,
  RadioGroup,
  Radio,
  FormLabel,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  QrCodeScanner as ScanIcon,
} from '@mui/icons-material';
import {
  verifyCredential,
  VerificationResult,
  VerifyRequest,
  issueLivenessChallenge,
  LivenessChallenge,
  LivenessMode,
} from '@/services/tauri-api';
import { useAppStore } from '@/store';
import VerificationResultCard from './VerificationResultCard';

interface VerifierPanelProps {
  credentialType?: string;
  onVerificationComplete?: (result: VerificationResult) => void;
}

export default function VerifierPanel({
  credentialType = 'mdl',
  onVerificationComplete,
}: VerifierPanelProps) {
  const [selectedType, setSelectedType] = useState(credentialType);
  const [useNfc, setUseNfc] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [credentialData, setCredentialData] = useState('');
  const [requireLiveness, setRequireLiveness] = useState(true);
  const [accessibilityMode, setAccessibilityMode] = useState(false);
  const [retainAuditClip, setRetainAuditClip] = useState(true);
  const [auditClipTtlSeconds, setAuditClipTtlSeconds] = useState(30);
  const [preferredMode, setPreferredMode] = useState<LivenessMode>('on_device');
  const [allowNetworkFallback, setAllowNetworkFallback] = useState(true);
  const [challenge, setChallenge] = useState<LivenessChallenge | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [stepDeadline, setStepDeadline] = useState<number | null>(null);
  const [stepRemainingMs, setStepRemainingMs] = useState<number>(0);
  const [challengeExpiresAt, setChallengeExpiresAt] = useState<number | null>(null);
  const [performFaceMatch, setPerformFaceMatch] = useState(false);
  const [referenceImage, setReferenceImage] = useState('');
  const [probeImage, setProbeImage] = useState('');
  const [faceThreshold, setFaceThreshold] = useState(0.75);
  const [sessionId] = useState<string>(() => crypto.randomUUID());
  const { setLastVerification, setVerificationInProgress, license } = useAppStore();

  const handleScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    setResult(null);
    setChallenge(null);

    try {
      // TODO: Implement actual QR scanning via Tauri plugin
      // For now, simulate with mock data
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Use provided data or mock placeholder
      const payload = credentialData || 'mock_credential_qr_data';

      let activeChallenge: LivenessChallenge | undefined;
      if (requireLiveness) {
        activeChallenge = await issueLivenessChallenge({
          session_id: sessionId,
          preferred_mode: preferredMode,
          allow_network_fallback: allowNetworkFallback,
          accessibility_mode: accessibilityMode,
          ttl_seconds: 60,
        });
        setChallenge(activeChallenge);
        setActiveStepIndex(0);
        const firstStep = activeChallenge.steps[0];
        setStepDeadline(Date.now() + (firstStep.time_limit_ms ?? 5000));
        setChallengeExpiresAt(Date.parse(activeChallenge.expires_at));
      }

      setScanning(false);
      setVerifying(false);
      setVerificationInProgress(false);

      // For liveness flows, wait for the user to complete steps before submitting verification
      if (requireLiveness) {
        return;
      }

      const request: VerifyRequest = {
        credential_type: selectedType,
        credential_data: payload,
        use_nfc: selectedType === 'emrtd' ? useNfc : undefined,
        liveness_challenge: activeChallenge,
        require_liveness: requireLiveness,
        preferred_liveness_mode: preferredMode,
        allow_network_fallback: allowNetworkFallback,
        accessibility_mode: accessibilityMode,
        retain_audit_clip: retainAuditClip,
        audit_clip_ttl_seconds: auditClipTtlSeconds,
        session_id: sessionId,
        perform_face_match: performFaceMatch,
        reference_image: performFaceMatch ? referenceImage : undefined,
        probe_image: performFaceMatch ? probeImage : undefined,
        face_threshold: performFaceMatch ? faceThreshold : undefined,
        policy: {
          required_claims: ['given_name', 'family_name'],
          allow_expired_grace: false,
        },
      };

      const verificationResult = await verifyCredential(request);
      setResult(verificationResult);
      setLastVerification(verificationResult);
      onVerificationComplete?.(verificationResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setScanning(false);
      setVerifying(false);
      setVerificationInProgress(false);
    }
  }, [
    selectedType,
    useNfc,
    onVerificationComplete,
    setLastVerification,
    setVerificationInProgress,
    credentialData,
    requireLiveness,
    preferredMode,
    allowNetworkFallback,
    accessibilityMode,
    retainAuditClip,
    auditClipTtlSeconds,
    sessionId,
  ]);

  const allStepsCompleted = challenge ? activeStepIndex >= challenge.steps.length : false;

  const advanceStep = useCallback(() => {
    if (!challenge) return;
    const nextIndex = activeStepIndex + 1;
    if (nextIndex >= challenge.steps.length) {
      setActiveStepIndex(challenge.steps.length);
      setStepDeadline(null);
      setStepRemainingMs(0);
      return;
    }
    setActiveStepIndex(nextIndex);
    const nextStep = challenge.steps[nextIndex];
    setStepDeadline(Date.now() + (nextStep.time_limit_ms ?? 5000));
  }, [activeStepIndex, challenge]);

  useEffect(() => {
    if (!stepDeadline) return;
    const id = window.setInterval(() => {
      setStepRemainingMs(Math.max(0, stepDeadline - Date.now()));
    }, 200);
    return () => window.clearInterval(id);
  }, [stepDeadline]);

  useEffect(() => {
    if (!challengeExpiresAt) return;
    const id = window.setInterval(() => {
      // Trigger re-render for expiry display
      setChallengeExpiresAt((current) => current);
    }, 1000);
    return () => window.clearInterval(id);
  }, [challengeExpiresAt]);

  const handleSubmitVerification = useCallback(async () => {
    if (requireLiveness && !challenge) {
      setError('Issue a liveness challenge first.');
      return;
    }

    setVerifying(true);
    setVerificationInProgress(true);
    setError(null);

    try {
      const payload = credentialData || 'mock_credential_qr_data';
      const request: VerifyRequest = {
        credential_type: selectedType,
        credential_data: payload,
        use_nfc: selectedType === 'emrtd' ? useNfc : undefined,
        liveness_challenge: challenge ?? undefined,
        require_liveness: requireLiveness,
        preferred_liveness_mode: preferredMode,
        allow_network_fallback: allowNetworkFallback,
        accessibility_mode: accessibilityMode,
        retain_audit_clip: retainAuditClip,
        audit_clip_ttl_seconds: auditClipTtlSeconds,
        session_id: sessionId,
        policy: {
          required_claims: ['given_name', 'family_name'],
          allow_expired_grace: false,
        },
      };

      const verificationResult = await verifyCredential(request);
      setResult(verificationResult);
      setLastVerification(verificationResult);
      onVerificationComplete?.(verificationResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setVerifying(false);
      setVerificationInProgress(false);
    }
  }, [
    accessibilityMode,
    allowNetworkFallback,
    auditClipTtlSeconds,
    challenge,
    credentialData,
    onVerificationComplete,
    preferredMode,
    performFaceMatch,
    referenceImage,
    probeImage,
    faceThreshold,
    requireLiveness,
    retainAuditClip,
    selectedType,
    sessionId,
    setLastVerification,
    setVerificationInProgress,
    useNfc,
  ]);

  const handleReset = () => {
    setResult(null);
    setError(null);
    setChallenge(null);
    setActiveStepIndex(-1);
    setStepDeadline(null);
    setStepRemainingMs(0);
    setChallengeExpiresAt(null);
  };

  // Check if credential type is licensed
  const isLicensed = license?.features.some(
    (f) => f === '*' || f === selectedType || selectedType.startsWith(f)
  );

  if (!isLicensed) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error">
            {selectedType.toUpperCase()} verification is not licensed.
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (result) {
    return (
      <Box>
        <VerificationResultCard result={result} />
        <Button
          variant="outlined"
          fullWidth
          onClick={handleReset}
          sx={{ mt: 2 }}
        >
          Verify Another Credential
        </Button>
      </Box>
    );
  }

  return (
    <Card data-testid="verifier-panel">
      <CardContent>
        <Stack spacing={3} alignItems="center">
          <Typography variant="h5">
            {selectedType.toUpperCase()} Verification
          </Typography>

          <FormControl fullWidth>
            <InputLabel id="credential-type-label">Credential Type</InputLabel>
            <Select
              labelId="credential-type-label"
              value={selectedType}
              label="Credential Type"
              onChange={(e) => setSelectedType(e.target.value)}
              data-testid="credential-type-select"
            >
              <MenuItem value="mdl">mDL</MenuItem>
              <MenuItem value="emrtd">eMRTD (Passport)</MenuItem>
              <MenuItem value="oid4vp">OID4VP</MenuItem>
              <MenuItem value="sd-jwt">SD-JWT</MenuItem>
              <MenuItem value="dtc">DTC</MenuItem>
              <MenuItem value="open-badge">Open Badge</MenuItem>
            </Select>
          </FormControl>

          {selectedType === 'emrtd' && (
            <FormControlLabel
              control={
                <Checkbox
                  checked={useNfc}
                  onChange={(e) => setUseNfc(e.target.checked)}
                  data-testid="use-nfc-checkbox"
                />
              }
              label="Use NFC reader (if available)"
            />
          )}

          <FormControlLabel
            control={
              <Checkbox
                checked={requireLiveness}
                onChange={(e) => setRequireLiveness(e.target.checked)}
                data-testid="require-liveness-checkbox"
              />
            }
            label="Require liveness (PAD/ASVspoof)"
          />

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ width: '100%' }}>
            <FormControl component="fieldset" fullWidth>
              <FormLabel component="legend">Liveness Mode</FormLabel>
              <RadioGroup
                row
                value={preferredMode}
                onChange={(e) => setPreferredMode(e.target.value as LivenessMode)}
              >
                <FormControlLabel value="on_device" control={<Radio />} label="On-device" />
                <FormControlLabel value="network" control={<Radio />} label="Network" />
              </RadioGroup>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={allowNetworkFallback}
                    onChange={(e) => setAllowNetworkFallback(e.target.checked)}
                  />
                }
                label="Allow fallback to other mode"
              />
            </FormControl>

            <Stack spacing={1} flex={1}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={accessibilityMode}
                    onChange={(e) => setAccessibilityMode(e.target.checked)}
                  />
                }
                label="Accessibility mode (pose/blink only)"
              />
              <FormControlLabel
                control={
                  <Checkbox
                    checked={retainAuditClip}
                    onChange={(e) => setRetainAuditClip(e.target.checked)}
                  />
                }
                label="Retain short audit clip"
              />
              <TextField
                type="number"
                label="Audit clip TTL (seconds)"
                value={auditClipTtlSeconds}
                onChange={(e) => setAuditClipTtlSeconds(Number(e.target.value) || 0)}
                inputProps={{ min: 5, max: 300 }}
              />
            </Stack>
          </Stack>

          <Divider flexItem />

          <FormControlLabel
            control={
              <Checkbox
                checked={performFaceMatch}
                onChange={(e) => setPerformFaceMatch(e.target.checked)}
              />
            }
            label="Perform face match (placeholder scores)"
          />

          {performFaceMatch && (
            <Stack spacing={2} sx={{ width: '100%' }}>
              <TextField
                label="Reference image (base64)"
                value={referenceImage}
                onChange={(e) => setReferenceImage(e.target.value)}
                fullWidth
                multiline
                minRows={2}
              />
              <TextField
                label="Probe image (base64)"
                value={probeImage}
                onChange={(e) => setProbeImage(e.target.value)}
                fullWidth
                multiline
                minRows={2}
              />
              <TextField
                type="number"
                label="Face match threshold"
                value={faceThreshold}
                onChange={(e) => setFaceThreshold(Number(e.target.value) || 0)}
                inputProps={{ step: 0.01, min: 0, max: 1 }}
              />
            </Stack>
          )}

          <TextField
            label="Credential Data (JSON, base64, or QR contents)"
            placeholder={
              selectedType === 'emrtd'
                ? '{"sod_base64":"...","data_groups":{"DG1":"..."},"country":"USA"}'
                : selectedType === 'dtc'
                ? '{"passport_number":"P1234567","issuing_authority":"USA","dtc_type":4}'
                : selectedType === 'open-badge'
                ? '{"credential":{"@context":"https://purl.imsglobal.org/spec/ob/v3p0/context.json"}}'
                : 'Paste credential payload'
            }
            value={credentialData}
            onChange={(e) => setCredentialData(e.target.value)}
            fullWidth
            multiline
            minRows={3}
            data-testid="credential-data-input"
          />

          <Chip
            label={credentialType}
            color="primary"
            variant="outlined"
          />

          {challenge && (
            <Card variant="outlined" sx={{ width: '100%' }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Liveness Challenge
                </Typography>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Session: {sessionId} · Challenge ID: {challenge.challenge_id} · Mode:{' '}
                  {challenge.preferred_mode} · Expires in:{' '}
                  {challengeExpiresAt
                    ? `${Math.max(0, Math.round((challengeExpiresAt - Date.now()) / 1000))}s`
                    : 'n/a'}
                </Typography>
                <Divider sx={{ my: 1 }} />
                <List dense>
                  {challenge.steps.map((step, idx) => (
                    <ListItem key={step.step_id}>
                      <ListItemText
                        primary={`Step ${idx + 1}: ${step.prompt ?? step.step_type}`}
                        secondary={`Time limit: ${step.time_limit_ms ?? 5000} ms`}
                      />
                    </ListItem>
                  ))}
                </List>
                <Divider sx={{ my: 1 }} />
                {activeStepIndex >= 0 && activeStepIndex < challenge.steps.length && (
                  <Stack spacing={1}>
                    <Typography variant="body2" color="text.secondary">
                      Current step ({activeStepIndex + 1}/{challenge.steps.length}):{' '}
                      {challenge.steps[activeStepIndex].prompt ??
                        challenge.steps[activeStepIndex].step_type}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Time remaining: {Math.max(0, Math.round(stepRemainingMs / 1000))}s
                    </Typography>
                    <Button
                      variant="outlined"
                      onClick={advanceStep}
                      disabled={verifying}
                      data-testid="advance-step-button"
                    >
                      Mark Step Complete
                    </Button>
                  </Stack>
                )}
                {allStepsCompleted && (
                  <Alert severity="success" sx={{ mt: 1 }}>
                    Liveness steps complete. Submit verification to continue.
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}

          {error && (
            <Alert severity="error" sx={{ width: '100%' }}>
              {error}
            </Alert>
          )}

          <Box
            sx={{
              width: 200,
              height: 200,
              border: '2px dashed',
              borderColor: scanning ? 'primary.main' : 'grey.400',
              borderRadius: 2,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: scanning ? 'action.hover' : 'transparent',
            }}
          >
            {scanning || verifying ? (
              <CircularProgress />
            ) : (
              <ScanIcon sx={{ fontSize: 64, color: 'grey.400' }} />
            )}
          </Box>

          <Typography variant="body2" color="text.secondary" textAlign="center">
            {scanning
              ? 'Scanning QR code...'
              : verifying
              ? 'Verifying credential...'
              : requireLiveness && challenge
              ? 'Complete the liveness steps, then submit verification'
              : 'Position the credential QR code in the camera view'}
          </Typography>

          <Button
            data-testid="scan-button"
            variant="contained"
            size="large"
            startIcon={<ScanIcon />}
            onClick={handleScan}
            disabled={scanning || verifying}
            fullWidth
          >
            {scanning ? 'Scanning...' : verifying ? 'Verifying...' : 'Start Scan'}
          </Button>

          {requireLiveness && challenge && (
            <Button
              variant="contained"
              color="secondary"
              onClick={handleSubmitVerification}
              disabled={verifying || !allStepsCompleted}
              fullWidth
            >
              Submit Verification
            </Button>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}
