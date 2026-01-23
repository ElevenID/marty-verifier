/**
 * Flow Execution List Component
 * 
 * Displays execution history with status indicators
 */

import React from 'react';
import {
  Box,
  Chip,
  CircularProgress,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
} from '@mui/material';
import {
  Visibility as ViewIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  HourglassEmpty as PendingIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import { FlowExecution } from '@/store/flow-store';
import { FlowStepVisualizer } from './FlowStepVisualizer';
import { useState } from 'react';

interface FlowExecutionListProps {
  executions: FlowExecution[];
  loading: boolean;
  flowId: string;
}

export const FlowExecutionList: React.FC<FlowExecutionListProps> = ({
  executions,
  loading,
  flowId,
}) => {
  const [selectedExecution, setSelectedExecution] = useState<FlowExecution | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const handleViewExecution = (execution: FlowExecution) => {
    setSelectedExecution(execution);
    setDetailsOpen(true);
  };

  const getStatusColor = (status: FlowExecution['status']): 'default' | 'primary' | 'warning' | 'success' | 'error' => {
    const colors: Record<FlowExecution['status'], 'default' | 'primary' | 'warning' | 'success' | 'error'> = {
      created: 'default',
      running: 'primary',
      awaiting_approval: 'warning',
      approved: 'primary',
      rejected: 'error',
      completed: 'success',
      failed: 'error',
      cancelled: 'default',
    };
    return colors[status] || 'default';
  };

  const getStatusIcon = (status: FlowExecution['status']) => {
    const icons: Record<FlowExecution['status'], React.ReactNode> = {
      created: <PendingIcon fontSize="small" />,
      running: <CircularProgress size={16} />,
      awaiting_approval: <PendingIcon fontSize="small" />,
      approved: <SuccessIcon fontSize="small" />,
      rejected: <ErrorIcon fontSize="small" />,
      completed: <SuccessIcon fontSize="small" />,
      failed: <ErrorIcon fontSize="small" />,
      cancelled: <CancelIcon fontSize="small" />,
    };
    return icons[status];
  };

  const formatTimestamp = (timestamp?: string): string => {
    if (!timestamp) return '-';
    return new Date(timestamp).toLocaleString();
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={4}>
        <CircularProgress />
      </Box>
    );
  }

  if (executions.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary" textAlign="center" py={4}>
        No executions yet
      </Typography>
    );
  }

  return (
    <>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Status</TableCell>
              <TableCell>Started</TableCell>
              <TableCell>Completed</TableCell>
              <TableCell>Current Step</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {executions.map((execution) => (
              <TableRow key={execution.id} hover>
                <TableCell>
                  <Chip
                    icon={getStatusIcon(execution.status)}
                    label={execution.status.toUpperCase().replace('_', ' ')}
                    color={getStatusColor(execution.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{formatTimestamp(execution.started_at)}</TableCell>
                <TableCell>{formatTimestamp(execution.completed_at)}</TableCell>
                <TableCell>
                  {execution.current_step || '-'}
                  {execution.current_step && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      Step {execution.current_step_index + 1}
                    </Typography>
                  )}
                </TableCell>
                <TableCell align="right">
                  <IconButton
                    size="small"
                    onClick={() => handleViewExecution(execution)}
                  >
                    <ViewIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Execution Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Execution Details</DialogTitle>
        <DialogContent>
          {selectedExecution && (
            <Stack spacing={3}>
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Status
                </Typography>
                <Chip
                  icon={getStatusIcon(selectedExecution.status)}
                  label={selectedExecution.status.toUpperCase().replace('_', ' ')}
                  color={getStatusColor(selectedExecution.status)}
                />
              </Box>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Execution ID
                </Typography>
                <Typography variant="body2" color="text.secondary" fontFamily="monospace">
                  {selectedExecution.id}
                </Typography>
              </Box>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Timeline
                </Typography>
                <Stack spacing={1}>
                  <Typography variant="body2">
                    Created: {formatTimestamp(selectedExecution.created_at)}
                  </Typography>
                  {selectedExecution.started_at && (
                    <Typography variant="body2">
                      Started: {formatTimestamp(selectedExecution.started_at)}
                    </Typography>
                  )}
                  {selectedExecution.completed_at && (
                    <Typography variant="body2">
                      Completed: {formatTimestamp(selectedExecution.completed_at)}
                    </Typography>
                  )}
                </Stack>
              </Box>

              {selectedExecution.error && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom color="error">
                    Error
                  </Typography>
                  <Typography variant="body2" color="error" fontFamily="monospace">
                    {selectedExecution.error}
                  </Typography>
                </Box>
              )}

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Progress
                </Typography>
                <FlowStepVisualizer execution={selectedExecution} />
              </Box>

              {Object.keys(selectedExecution.step_results).length > 0 && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Step Results
                  </Typography>
                  <Box
                    component="pre"
                    sx={{
                      p: 2,
                      bgcolor: 'grey.100',
                      borderRadius: 1,
                      overflow: 'auto',
                      fontSize: '0.875rem',
                    }}
                  >
                    {JSON.stringify(selectedExecution.step_results, null, 2)}
                  </Box>
                </Box>
              )}
            </Stack>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
};
