import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { FlowsPage } from '@/pages/FlowsPage';
import { useFlowStore } from '@/store/flow-store';

// Mock the store
vi.mock('@/store/flow-store');

const mockFlows = [
  {
    id: 'flow-1',
    name: 'Pre-Boarding Flow',
    description: 'Pre-boarding clearance flow',
    flow_type: 'application_based' as const,
    trust_profile_id: 'tp-1',
    credential_template_id: 'ct-1',
    presentation_policy_id: 'pp-1',
    deployment_profile_ids: ['dp-1', 'dp-2'],
    approval_strategy: 'manual' as const,
    enabled: true,
    hooks: {},
    metadata: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    version: 1,
  },
  {
    id: 'flow-2',
    name: 'Age Verification',
    description: 'Age check flow',
    flow_type: 'oid4vp' as const,
    presentation_policy_id: 'pp-2',
    deployment_profile_ids: [],
    approval_strategy: 'auto' as const,
    enabled: false,
    hooks: {},
    metadata: {},
    created_at: '2026-01-02T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z',
    version: 1,
  },
];

const mockExecutions = [
  {
    id: 'exec-1',
    flow_id: 'flow-1',
    status: 'completed' as const,
    current_step: 'deliver_credential',
    current_step_index: 5,
    step_results: { submit_application: { status: 'ok' } },
    context_data: {},
    started_at: '2026-01-10T10:00:00Z',
    completed_at: '2026-01-10T10:05:00Z',
    metadata: {},
    created_at: '2026-01-10T10:00:00Z',
    updated_at: '2026-01-10T10:05:00Z',
    version: 1,
  },
];

describe('FlowsPage', () => {
  const mockLoadFlows = vi.fn();
  const mockLoadFlow = vi.fn();
  const mockLoadExecutions = vi.fn();
  const mockDeleteFlow = vi.fn();
  const mockSetSelectedFlow = vi.fn();
  const mockStartExecution = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    // Setup mock store
    (useFlowStore as any).mockReturnValue({
      flows: mockFlows,
      selectedFlow: null,
      flowsLoading: false,
      flowsError: null,
      executions: [],
      executionsLoading: false,
      loadFlows: mockLoadFlows,
      loadFlow: mockLoadFlow,
      loadExecutions: mockLoadExecutions,
      deleteFlow: mockDeleteFlow,
      setSelectedFlow: mockSetSelectedFlow,
      startExecution: mockStartExecution,
    });
  });

  it('should render flow list', async () => {
    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    // Wait for flows to load
    await waitFor(() => {
      expect(mockLoadFlows).toHaveBeenCalled();
    });

    // Check that flows are displayed
    expect(screen.getByText('Pre-Boarding Flow')).toBeInTheDocument();
    expect(screen.getByText('Age Verification')).toBeInTheDocument();
  });

  it('should display flow type and approval strategy chips', async () => {
    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    // Check for flow type chips
    expect(screen.getByText('Application-Based')).toBeInTheDocument();
    expect(screen.getByText('OpenID4VP')).toBeInTheDocument();

    // Check for approval strategy chips
    expect(screen.getByText('MANUAL')).toBeInTheDocument();
    expect(screen.getByText('AUTO')).toBeInTheDocument();
  });

  it('should show disabled badge for disabled flows', async () => {
    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    expect(screen.getByText('Disabled')).toBeInTheDocument();
  });

  it('should select flow and load executions on click', async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    const flowItem = screen.getByText('Pre-Boarding Flow').closest('[role="button"]');
    expect(flowItem).not.toBeNull();

    await user.click(flowItem!);

    expect(mockSetSelectedFlow).toHaveBeenCalledWith(mockFlows[0]);
  });

  it('should open create dialog when Create Flow button clicked', async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    const createButton = screen.getByRole('button', { name: /create flow/i });
    await user.click(createButton);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Create Flow' })).toBeInTheDocument();
  });

  it('should show confirmation dialog before deleting flow', async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    const deleteButton = screen.getByRole('button', { name: /delete pre-boarding flow/i });
    await user.click(deleteButton);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Confirm Delete' })).toBeInTheDocument();
  });

  it('should start execution when play button clicked', async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    const playButton = screen.getByRole('button', {
      name: /start execution for pre-boarding flow/i,
    });
    await user.click(playButton);

    expect(mockStartExecution).toHaveBeenCalledWith('flow-1');
  });

  it('should display error message when loading fails', async () => {
    (useFlowStore as any).mockReturnValue({
      flows: [],
      selectedFlow: null,
      flowsLoading: false,
      flowsError: 'Failed to load flows',
      executions: [],
      executionsLoading: false,
      loadFlows: mockLoadFlows,
      loadFlow: mockLoadFlow,
      loadExecutions: mockLoadExecutions,
      deleteFlow: mockDeleteFlow,
      setSelectedFlow: mockSetSelectedFlow,
      startExecution: mockStartExecution,
    });

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    expect(screen.getByText('Failed to load flows')).toBeInTheDocument();
  });

  it('should show loading state', async () => {
    (useFlowStore as any).mockReturnValue({
      flows: [],
      selectedFlow: null,
      flowsLoading: true,
      flowsError: null,
      executions: [],
      executionsLoading: false,
      loadFlows: mockLoadFlows,
      loadFlow: mockLoadFlow,
      loadExecutions: mockLoadExecutions,
      deleteFlow: mockDeleteFlow,
      setSelectedFlow: mockSetSelectedFlow,
      startExecution: mockStartExecution,
    });

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('should display flow details when flow selected', async () => {
    (useFlowStore as any).mockReturnValue({
      flows: mockFlows,
      selectedFlow: mockFlows[0],
      flowsLoading: false,
      flowsError: null,
      executions: mockExecutions,
      executionsLoading: false,
      loadFlows: mockLoadFlows,
      loadFlow: mockLoadFlow,
      loadExecutions: mockLoadExecutions,
      deleteFlow: mockDeleteFlow,
      setSelectedFlow: mockSetSelectedFlow,
      startExecution: mockStartExecution,
    });

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    // Check flow details are displayed
    expect(screen.getByRole('heading', { name: 'Pre-Boarding Flow' })).toBeInTheDocument();
    expect(screen.getByText('Pre-boarding clearance flow')).toBeInTheDocument();
    expect(screen.getByText('manual')).toBeInTheDocument();
  });

  it('should switch between Configuration and Executions tabs', async () => {
    const user = userEvent.setup();

    (useFlowStore as any).mockReturnValue({
      flows: mockFlows,
      selectedFlow: mockFlows[0],
      flowsLoading: false,
      flowsError: null,
      executions: mockExecutions,
      executionsLoading: false,
      loadFlows: mockLoadFlows,
      loadFlow: mockLoadFlow,
      loadExecutions: mockLoadExecutions,
      deleteFlow: mockDeleteFlow,
      setSelectedFlow: mockSetSelectedFlow,
      startExecution: mockStartExecution,
    });

    render(
      <BrowserRouter>
        <FlowsPage />
      </BrowserRouter>
    );

    // Should default to Configuration tab
    expect(screen.getByText('Approval Strategy')).toBeInTheDocument();

    // Click Executions tab
    const executionsTab = screen.getByRole('tab', { name: /executions/i });
    await user.click(executionsTab);

    // Should now show executions
    await waitFor(() => {
      // Executions list would be rendered
      expect(screen.queryByText('Approval Strategy')).not.toBeInTheDocument();
    });
  });
});
