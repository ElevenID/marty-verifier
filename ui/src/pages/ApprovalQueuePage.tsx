/**
 * Approval Queue Page
 * 
 * Shows executions awaiting manual approval with approve/reject actions
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardActions,
  Chip,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  IconButton,
  Stack,
  TextField,
  Typography,
  Alert,
} from '@mui/material';
import {
  CheckCircle as ApproveIcon,
  Cancel as RejectIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useFlowStore, FlowExecution } from '@/store/flow-store';

export const ApprovalQueuePage: React.FC = () => {
  const {
    approvalQueue,
    approvalQueueLoading,
    approvalQueueError,
    loadApprovalQueue,
    approveExecution,
    rejectExecution,
  } = useFlowStore();

  const [selectedExecution, setSelectedExecution] = useState<FlowExecution | null>(null);
  const [actionType, setActionType] = useState<'approve' | 'reject' | null>(null);
  const [actionDialogOpen, setActionDialogOpen] = useState(false);
  const [actionReason, setActionReason] = useState('');
  const [actionActor, setActionActor] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Load approval queue on mount and poll every 30 seconds
  useEffect(() => {
    loadApprovalQueue();
    const interval = setInterval(() => {
      loadApprovalQueue();
    }, 30000);
    return () => clearInterval(interval);
  }, [loadApprovalQueue]);

  const handleApprove = (execution: FlowExecution) => {
    setSelectedExecution(execution);
    setActionType('approve');
    setActionReason('');
    setActionActor('');
    setActionError(null);
    setActionDialogOpen(true);
  };

  const handleReject = (execution: FlowExecution) => {
    setSelectedExecution(execution);
    setActionType('reject');
    setActionReason('');
    setActionActor('');
    setActionError(null);
    setActionDialogOpen(true);
  };

  const handleActionSubmit = async () => {
    if (!selectedExecution || !actionType) return;

    if (!actionActor.trim()) {
      setActionError('Approver/Rejector ID is required');
      return;
    }

    setActionLoading(true);
    setActionError(null);

    try {
      if (actionType === 'approve') {
        await approveExecution(
          selectedExecution.flow_id,
          selectedExecution.id,
          actionActor,
          actionReason || undefined
        );
      } else {
        await rejectExecution(
          selectedExecution.flow_id,
          selectedExecution.id,
          actionActor,
          actionReason || undefined
        );
      }
      setActionDialogOpen(false);
      setSelectedExecution(null);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : `Failed to ${actionType}`);
    } finally {
      setActionLoading(false);
    }
  };

  const formatTimestamp = (timestamp?: string): string => {
    if (!timestamp) return '-';
    return new Date(timestamp).toLocaleString();
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Approval Queue</Typography>
        <Stack direction="row" spacing={2} alignItems="center">
          <Chip
            label={`${approvalQueue.length} Pending`}
            color={approvalQueue.length > 0 ? 'warning' : 'default'}
          />
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => loadApprovalQueue()}
            disabled={approvalQueueLoading}
          >
            Refresh
          </Button>
        </Stack>
      </Stack>

      {approvalQueueError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {approvalQueueError}
        </Alert>
      )}

      {/* Loading State */}
      {approvalQueueLoading && approvalQueue.length === 0 && (
        <Box display="flex" justifyContent="center" py={8}>
          <CircularProgress />
        </Box>
      )}

      {/* Empty State */}
      {!approvalQueueLoading && approvalQueue.length === 0 && (
        <Card>
          <CardContent>
            <Typography variant="body1" color="text.secondary" textAlign="center" py={8}>
              No executions awaiting approval
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Approval Queue Grid */}
      {approvalQueue.length > 0 && (
        <Grid container spacing={3}>
          {approvalQueue.map((execution) => (
            <Grid item xs={12} md={6} lg={4} key={execution.id}>
              <Card elevation={2}>
                <CardContent>
                  <Stack spacing={2}>
                    <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                      <Typography variant="h6">
                        Flow Execution
                      </Typography>
                      <Chip
                        label="AWAITING APPROVAL"
                        color="warning"
                        size="small"
                      />
                    </Stack>

                    <Box>
                      <Typography variant="caption" color="text.secondary" display="block">
                        Execution ID
                      </Typography>
                      <Typography variant="body2" fontFamily="monospace" noWrap>
                        {execution.id}
                      </Typography>
                    </Box>

                    <Box>
                      <Typography variant="caption" color="text.secondary" display="block">
                        Flow ID
                      </Typography>
                      <Typography variant="body2" fontFamily="monospace" noWrap>
                        {execution.flow_id}
                      </Typography>
                    </Box>

                    {execution.current_step && (
                      <Box>
                        <Typography variant="caption" color="text.secondary" display="block">
                          Current Step
                        </Typography>
                        <Typography variant="body2">
                          {execution.current_step} (Step {execution.current_step_index + 1})
                        </Typography>
                      </Box>
                    )}

                    <Box>
                      <Typography variant="caption" color="text.secondary" display="block">
                        Started
                      </Typography>
                      <Typography variant="body2">
                        {formatTimestamp(execution.started_at)}
                      </Typography>
                    </Box>

                    {Object.keys(execution.context_data).length > 0 && (
                      <Box>
                        <Typography variant="caption" color="text.secondary" display="block">
                          Context
                        </Typography>
                        <Box
                          component="pre"
                          sx={{
                            p: 1,
                            bgcolor: 'grey.100',
                            borderRadius: 1,
                            overflow: 'auto',
                            fontSize: '0.75rem',
                            maxHeight: '100px',
                          }}
                        >
                          {JSON.stringify(execution.context_data, null, 2)}
                        </Box>
                      </Box>
                    )}
                  </Stack>
                </CardContent>
                <CardActions>
                  <Button
                    size="small"
                    color="success"
                    startIcon={<ApproveIcon />}
                    onClick={() => handleApprove(execution)}
                  >
                    Approve
                  </Button>
                  <Button
                    size="small"
                    color="error"
                    startIcon={<RejectIcon />}
                    onClick={() => handleReject(execution)}
                  >
                    Reject
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Action Dialog */}
      <Dialog
        open={actionDialogOpen}
        onClose={() => !actionLoading && setActionDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {actionType === 'approve' ? 'Approve' : 'Reject'} Execution
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} mt={1}>
            {actionError && <Alert severity="error">{actionError}</Alert>}

            {selectedExecution && (
              <Box>
                <Typography variant="caption" color="text.secondary" display="block">
                  Execution ID
                </Typography>
                <Typography variant="body2" fontFamily="monospace">
                  {selectedExecution.id}
                </Typography>
              </Box>
            )}

            <TextField
              label={actionType === 'approve' ? 'Approved By' : 'Rejected By'}
              required
              fullWidth
              value={actionActor}
              onChange={(e) => setActionActor(e.target.value)}
              helperText="Your user ID or name"
              disabled={actionLoading}
            />

            <TextField
              label="Reason"
              fullWidth
              multiline
              rows={3}
              value={actionReason}
              onChange={(e) => setActionReason(e.target.value)}
              helperText={actionType === 'reject' ? 'Required for rejection' : 'Optional'}
              disabled={actionLoading}
              required={actionType === 'reject'}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setActionDialogOpen(false)} disabled={actionLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleActionSubmit}
            variant="contained"
            color={actionType === 'approve' ? 'success' : 'error'}
            disabled={actionLoading}
          >
            {actionLoading
              ? 'Processing...'
              : actionType === 'approve'
              ? 'Approve'
              : 'Reject'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
