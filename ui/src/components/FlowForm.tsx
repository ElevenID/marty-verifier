/**
 * Flow Form Component
 * 
 * Form for creating and editing flows
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormControlLabel,
  FormLabel,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  TextField,
  Alert,
} from '@mui/material';
import { useFlowStore, Flow, CreateFlowRequest, UpdateFlowRequest } from '@/store/flow-store';

interface FlowFormProps {
  flow?: Flow | null;
  onClose: (saved: boolean) => void;
}

export const FlowForm: React.FC<FlowFormProps> = ({ flow, onClose }) => {
  const { createFlow, updateFlow } = useFlowStore();

  const [formData, setFormData] = useState({
    name: flow?.name || '',
    description: flow?.description || '',
    flow_type: flow?.flow_type || ('pre_authorized_code' as Flow['flow_type']),
    trust_profile_id: flow?.trust_profile_id || '',
    credential_template_id: flow?.credential_template_id || '',
    application_template_id: flow?.application_template_id || '',
    presentation_policy_id: flow?.presentation_policy_id || '',
    deployment_profile_ids: flow?.deployment_profile_ids.join(', ') || '',
    approval_strategy: flow?.approval_strategy || ('auto' as Flow['approval_strategy']),
    enabled: flow?.enabled ?? true,
  });

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async () => {
    setError(null);
    setLoading(true);

    try {
      // Validate required fields
      if (!formData.name.trim()) {
        throw new Error('Name is required');
      }

      // Parse deployment profile IDs
      const deploymentProfileIds = formData.deployment_profile_ids
        .split(',')
        .map(id => id.trim())
        .filter(id => id.length > 0);

      if (flow) {
        // Update existing flow
        const updateRequest: UpdateFlowRequest = {
          name: formData.name,
          description: formData.description || undefined,
          trust_profile_id: formData.trust_profile_id || undefined,
          credential_template_id: formData.credential_template_id || undefined,
          application_template_id: formData.application_template_id || undefined,
          presentation_policy_id: formData.presentation_policy_id || undefined,
          deployment_profile_ids: deploymentProfileIds.length > 0 ? deploymentProfileIds : undefined,
          approval_strategy: formData.approval_strategy,
          enabled: formData.enabled,
        };

        await updateFlow(flow.id, updateRequest);
      } else {
        // Create new flow
        const createRequest: CreateFlowRequest = {
          name: formData.name,
          flow_type: formData.flow_type,
          description: formData.description || undefined,
          trust_profile_id: formData.trust_profile_id || undefined,
          credential_template_id: formData.credential_template_id || undefined,
          application_template_id: formData.application_template_id || undefined,
          presentation_policy_id: formData.presentation_policy_id || undefined,
          deployment_profile_ids: deploymentProfileIds.length > 0 ? deploymentProfileIds : undefined,
          approval_strategy: formData.approval_strategy,
          enabled: formData.enabled,
        };

        await createFlow(createRequest);
      }

      onClose(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save flow');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="form" onSubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
      <Stack spacing={3} mt={2}>
        {error && <Alert severity="error">{error}</Alert>}

        <TextField
          label="Name"
          required
          fullWidth
          value={formData.name}
          onChange={(e) => handleChange('name', e.target.value)}
        />

        <TextField
          label="Description"
          fullWidth
          multiline
          rows={3}
          value={formData.description}
          onChange={(e) => handleChange('description', e.target.value)}
        />

        <FormControl fullWidth required disabled={!!flow}>
          <InputLabel>Flow Type</InputLabel>
          <Select
            value={formData.flow_type}
            label="Flow Type"
            onChange={(e) => handleChange('flow_type', e.target.value)}
          >
            <MenuItem value="pre_authorized_code">Pre-Authorized Code</MenuItem>
            <MenuItem value="authorization_code">Authorization Code</MenuItem>
            <MenuItem value="oid4vp">OpenID4VP</MenuItem>
            <MenuItem value="mdl_issuance">mDL Issuance</MenuItem>
            <MenuItem value="mdl_presentation">mDL Presentation</MenuItem>
            <MenuItem value="application_based">Application-Based</MenuItem>
          </Select>
        </FormControl>

        <FormControl fullWidth>
          <InputLabel>Approval Strategy</InputLabel>
          <Select
            value={formData.approval_strategy}
            label="Approval Strategy"
            onChange={(e) => handleChange('approval_strategy', e.target.value)}
          >
            <MenuItem value="auto">Auto</MenuItem>
            <MenuItem value="manual">Manual</MenuItem>
            <MenuItem value="rules_based">Rules-Based</MenuItem>
            <MenuItem value="external">External</MenuItem>
          </Select>
        </FormControl>

        <TextField
          label="Trust Profile ID"
          fullWidth
          value={formData.trust_profile_id}
          onChange={(e) => handleChange('trust_profile_id', e.target.value)}
          helperText="Optional: ID of the trust profile to use"
        />

        <TextField
          label="Credential Template ID"
          fullWidth
          value={formData.credential_template_id}
          onChange={(e) => handleChange('credential_template_id', e.target.value)}
          helperText="Optional: ID of the credential template (for issuance flows)"
        />

        <TextField
          label="Application Template ID"
          fullWidth
          value={formData.application_template_id}
          onChange={(e) => handleChange('application_template_id', e.target.value)}
          helperText="Optional: ID of the application template (mutually exclusive with credential template)"
        />

        <TextField
          label="Presentation Policy ID"
          fullWidth
          value={formData.presentation_policy_id}
          onChange={(e) => handleChange('presentation_policy_id', e.target.value)}
          helperText="Optional: ID of the presentation policy (for verification flows)"
        />

        <TextField
          label="Deployment Profile IDs"
          fullWidth
          value={formData.deployment_profile_ids}
          onChange={(e) => handleChange('deployment_profile_ids', e.target.value)}
          helperText="Optional: Comma-separated list of deployment profile IDs"
        />

        <FormControlLabel
          control={
            <Switch
              checked={formData.enabled}
              onChange={(e) => handleChange('enabled', e.target.checked)}
            />
          }
          label="Enabled"
        />

        <Stack direction="row" spacing={2} justifyContent="flex-end">
          <Button onClick={() => onClose(false)} disabled={loading}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={loading}
          >
            {loading ? 'Saving...' : flow ? 'Update' : 'Create'}
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
};
