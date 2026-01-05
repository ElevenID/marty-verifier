import { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import {
  Badge as MdlIcon,
  Flight as EmrtdIcon,
  Fingerprint as OidIcon,
  TravelExplore as DtcIcon,
  WorkspacePremium as OpenBadgeIcon,
} from '@mui/icons-material';
import { VerifierPanel } from '@/components';
import { useAppStore } from '@/store';

const credentialTypes = [
  { value: 'mdl', label: 'mDL', icon: <MdlIcon /> },
  { value: 'emrtd', label: 'eMRTD', icon: <EmrtdIcon /> },
  { value: 'oid4vp', label: 'OID4VP', icon: <OidIcon /> },
  { value: 'dtc', label: 'DTC', icon: <DtcIcon /> },
  { value: 'open-badge', label: 'Open Badge', icon: <OpenBadgeIcon /> },
];

export default function VerificationPage() {
  const [credentialType, setCredentialType] = useState('mdl');
  const { license, hardwareTier } = useAppStore();

  const handleTypeChange = (
    _event: React.MouseEvent<HTMLElement>,
    newType: string | null
  ) => {
    if (newType !== null) {
      setCredentialType(newType);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Credential Verification
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Scan and verify digital credentials. Hardware tier: {hardwareTier ?? 'detecting...'}
        </Typography>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Credential Type
        </Typography>
        <ToggleButtonGroup
          value={credentialType}
          exclusive
          onChange={handleTypeChange}
          aria-label="credential type"
          fullWidth
        >
          {credentialTypes.map((type) => {
            const isLicensed = license?.features.some(
              (f) => f === '*' || f === type.value || type.value.startsWith(f)
            );
            return (
              <ToggleButton
                key={type.value}
                value={type.value}
                disabled={!isLicensed}
                aria-label={type.label}
              >
                {type.icon}
                <Box sx={{ ml: 1 }}>{type.label}</Box>
              </ToggleButton>
            );
          })}
        </ToggleButtonGroup>
      </Box>

      <VerifierPanel credentialType={credentialType} />
    </Container>
  );
}
