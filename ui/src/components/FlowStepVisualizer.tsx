/**
 * Flow Step Visualizer Component
 * 
 * Shows execution progress through flow steps
 */

import React from 'react';
import {
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Typography,
  Box,
} from '@mui/material';
import { FlowExecution } from '@/store/flow-store';

interface FlowStepVisualizerProps {
  execution: FlowExecution;
}

// Define standard flow steps based on backend FLOW_STEPS
const FLOW_STEPS_CONFIG: Record<string, string[]> = {
  pre_authorized_code: [
    'validate_pre_auth_code',
    'verify_holder',
    'prepare_credential',
    'sign_credential',
    'deliver_credential',
  ],
  authorization_code: [
    'authorize',
    'token_exchange',
    'verify_holder',
    'prepare_credential',
    'sign_credential',
    'deliver_credential',
  ],
  oid4vp: [
    'request_presentation',
    'verify_presentation',
    'validate_claims',
    'return_result',
  ],
  mdl_issuance: [
    'verify_identity',
    'prepare_mdl',
    'sign_mdl',
    'deliver_mdl',
  ],
  mdl_presentation: [
    'request_mdl',
    'verify_mdl',
    'validate_binding',
    'return_result',
  ],
  application_based: [
    'submit_application',
    'verify_evidence',
    'approval_decision',
    'prepare_credential',
    'sign_credential',
    'deliver_credential',
  ],
};

export const FlowStepVisualizer: React.FC<FlowStepVisualizerProps> = ({ execution }) => {
  // Try to determine steps from execution context or use generic steps
  const flowType = execution.metadata?.flow_type;
  const steps = flowType && FLOW_STEPS_CONFIG[flowType]
    ? FLOW_STEPS_CONFIG[flowType]
    : Object.keys(execution.step_results);

  // If no steps detected, show current step info
  if (steps.length === 0) {
    return (
      <Box>
        {execution.current_step ? (
          <Typography variant="body2">
            Currently at: {execution.current_step} (Step {execution.current_step_index + 1})
          </Typography>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No step information available
          </Typography>
        )}
      </Box>
    );
  }

  const activeStep = execution.current_step_index;

  return (
    <Stepper activeStep={activeStep} orientation="vertical">
      {steps.map((step, index) => {
        const stepResult = execution.step_results[step];
        const isCompleted = index < activeStep || execution.status === 'completed';
        const isCurrent = index === activeStep;
        const isFailed = execution.status === 'failed' && isCurrent;

        return (
          <Step key={step} completed={isCompleted}>
            <StepLabel
              error={isFailed}
              optional={
                isCurrent && execution.status === 'awaiting_approval' ? (
                  <Typography variant="caption" color="warning.main">
                    Awaiting Approval
                  </Typography>
                ) : null
              }
            >
              {step.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
            </StepLabel>
            {stepResult && (
              <StepContent>
                <Typography variant="body2" color="text.secondary">
                  {typeof stepResult === 'object' 
                    ? JSON.stringify(stepResult, null, 2)
                    : String(stepResult)}
                </Typography>
              </StepContent>
            )}
          </Step>
        );
      })}
    </Stepper>
  );
};
