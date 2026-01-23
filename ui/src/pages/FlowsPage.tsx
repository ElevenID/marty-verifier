/**
 * Flows Page - Flow Management Component
 * 
 * Provides CRUD operations for flows with execution monitoring
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  Grid,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Stack,
  TextField,
  Typography,
  Alert,
  Tab,
  Tabs,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useFlowStore, Flow, FlowExecution } from '@/store/flow-store';
import { FlowForm } from '@/components/FlowForm';
import { FlowExecutionList } from '@/components/FlowExecutionList';

export const FlowsPage: React.FC = () => {
  const {
    flows,
    selectedFlow,
    flowsLoading,
    flowsError,
    executions,
    executionsLoading,
    loadFlows,
    loadFlow,
    loadExecutions,
    deleteFlow,
    setSelectedFlow,
    startExecution,
  } = useFlowStore();

  const [tabValue, setTabValue] = useState(0);
  const [formOpen, setFormOpen] = useState(false);
  const [editingFlow, setEditingFlow] = useState<Flow | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [flowToDelete, setFlowToDelete] = useState<Flow | null>(null);

  // Load flows on mount
  useEffect(() => {
    loadFlows();
  }, [loadFlows]);

  // Load executions when flow selected
  useEffect(() => {
    if (selectedFlow) {
      loadExecutions(selectedFlow.id);
    }
  }, [selectedFlow, loadExecutions]);

  const handleSelectFlow = (flow: Flow) => {
    setSelectedFlow(flow);
  };

  const handleCreateFlow = () => {
    setEditingFlow(null);
    setFormOpen(true);
  };

  const handleEditFlow = (flow: Flow) => {
    setEditingFlow(flow);
    setFormOpen(true);
  };

  const handleDeleteFlow = (flow: Flow) => {
    setFlowToDelete(flow);
    setDeleteConfirmOpen(true);
  };

  const confirmDelete = async () => {
    if (flowToDelete) {
      await deleteFlow(flowToDelete.id);
      setDeleteConfirmOpen(false);
      setFlowToDelete(null);
      if (selectedFlow?.id === flowToDelete.id) {
        setSelectedFlow(null);
      }
    }
  };

  const handleStartExecution = async (flow: Flow) => {
    try {
      await startExecution(flow.id);
    } catch (error) {
      console.error('Failed to start execution:', error);
    }
  };

  const handleFormClose = (saved: boolean) => {
    setFormOpen(false);
    setEditingFlow(null);
    if (saved) {
      loadFlows();
    }
  };

  const getFlowTypeLabel = (flowType: Flow['flow_type']): string => {
    const labels: Record<Flow['flow_type'], string> = {
      pre_authorized_code: 'Pre-Authorized Code',
      authorization_code: 'Authorization Code',
      oid4vp: 'OpenID4VP',
      mdl_issuance: 'mDL Issuance',
      mdl_presentation: 'mDL Presentation',
      application_based: 'Application-Based',
    };
    return labels[flowType] || flowType;
  };

  const getFlowTypeColor = (flowType: Flow['flow_type']): 'primary' | 'secondary' | 'info' | 'success' => {
    const colors: Record<Flow['flow_type'], 'primary' | 'secondary' | 'info' | 'success'> = {
      pre_authorized_code: 'primary',
      authorization_code: 'primary',
      oid4vp: 'info',
      mdl_issuance: 'secondary',
      mdl_presentation: 'info',
      application_based: 'success',
    };
    return colors[flowType] || 'primary';
  };

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Flow Management</Typography>
        <Stack direction="row" spacing={2}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => loadFlows()}
            disabled={flowsLoading}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreateFlow}
          >
            Create Flow
          </Button>
        </Stack>
      </Stack>

      {flowsError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {flowsError}
        </Alert>
      )}

      <Grid container spacing={3} sx={{ flexGrow: 1, overflow: 'hidden' }}>
        {/* Flow List */}
        <Grid item xs={12} md={4} sx={{ height: '100%', overflow: 'auto' }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Flows ({flows.length})
              </Typography>
              <Divider sx={{ mb: 2 }} />
              
              {flowsLoading ? (
                <Box display="flex" justifyContent="center" py={4}>
                  <CircularProgress />
                </Box>
              ) : (
                <List>
                  {flows.map((flow) => (
                    <ListItem
                      key={flow.id}
                      button
                      selected={selectedFlow?.id === flow.id}
                      onClick={() => handleSelectFlow(flow)}
                      secondaryAction={
                        <Stack direction="row" spacing={1}>
                          <IconButton
                            edge="end"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleStartExecution(flow);
                            }}
                            disabled={!flow.enabled}
                          >
                            <PlayIcon />
                          </IconButton>
                          <IconButton
                            edge="end"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleEditFlow(flow);
                            }}
                          >
                            <EditIcon />
                          </IconButton>
                          <IconButton
                            edge="end"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteFlow(flow);
                            }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Stack>
                      }
                    >
                      <ListItemText
                        primary={
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Typography variant="body1">{flow.name}</Typography>
                            {!flow.enabled && <Chip label="Disabled" size="small" />}
                          </Stack>
                        }
                        secondary={
                          <Stack direction="row" spacing={1} mt={0.5}>
                            <Chip
                              label={getFlowTypeLabel(flow.flow_type)}
                              size="small"
                              color={getFlowTypeColor(flow.flow_type)}
                            />
                            <Chip
                              label={flow.approval_strategy.toUpperCase()}
                              size="small"
                              variant="outlined"
                            />
                          </Stack>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Flow Details */}
        <Grid item xs={12} md={8} sx={{ height: '100%', overflow: 'auto' }}>
          {selectedFlow ? (
            <Card>
              <CardContent>
                <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h5">{selectedFlow.name}</Typography>
                  <Stack direction="row" spacing={1}>
                    <Chip
                      label={getFlowTypeLabel(selectedFlow.flow_type)}
                      color={getFlowTypeColor(selectedFlow.flow_type)}
                    />
                    <Chip
                      label={selectedFlow.enabled ? 'Enabled' : 'Disabled'}
                      color={selectedFlow.enabled ? 'success' : 'default'}
                    />
                  </Stack>
                </Stack>

                {selectedFlow.description && (
                  <Typography variant="body2" color="text.secondary" mb={2}>
                    {selectedFlow.description}
                  </Typography>
                )}

                <Divider sx={{ my: 2 }} />

                <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 2 }}>
                  <Tab label="Configuration" />
                  <Tab label="Executions" />
                </Tabs>

                {tabValue === 0 && (
                  <Stack spacing={3}>
                    {/* Configuration Details */}
                    <Box>
                      <Typography variant="subtitle2" gutterBottom>
                        Approval Strategy
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {selectedFlow.approval_strategy}
                      </Typography>
                    </Box>

                    {selectedFlow.trust_profile_id && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Trust Profile
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {selectedFlow.trust_profile_id}
                        </Typography>
                      </Box>
                    )}

                    {selectedFlow.credential_template_id && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Credential Template
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {selectedFlow.credential_template_id}
                        </Typography>
                      </Box>
                    )}

                    {selectedFlow.presentation_policy_id && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Presentation Policy
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {selectedFlow.presentation_policy_id}
                        </Typography>
                      </Box>
                    )}

                    {selectedFlow.deployment_profile_ids.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Deployment Profiles
                        </Typography>
                        <Stack direction="row" spacing={1} flexWrap="wrap">
                          {selectedFlow.deployment_profile_ids.map((id) => (
                            <Chip key={id} label={id} size="small" />
                          ))}
                        </Stack>
                      </Box>
                    )}

                    {Object.keys(selectedFlow.hooks).length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>
                          Hooks
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {Object.keys(selectedFlow.hooks).join(', ')}
                        </Typography>
                      </Box>
                    )}
                  </Stack>
                )}

                {tabValue === 1 && (
                  <FlowExecutionList
                    executions={executions}
                    loading={executionsLoading}
                    flowId={selectedFlow.id}
                  />
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent>
                <Typography variant="body1" color="text.secondary" textAlign="center" py={8}>
                  Select a flow to view details
                </Typography>
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>

      {/* Flow Form Dialog */}
      <Dialog open={formOpen} onClose={() => handleFormClose(false)} maxWidth="md" fullWidth>
        <DialogTitle>{editingFlow ? 'Edit Flow' : 'Create Flow'}</DialogTitle>
        <DialogContent>
          <FlowForm flow={editingFlow} onClose={handleFormClose} />
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete flow "{flowToDelete?.name}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>Cancel</Button>
          <Button onClick={confirmDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
