import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApprovalQueuePage } from '@/pages/ApprovalQueuePage';
import { useFlowStore } from '@/store/flow-store';
import type { Flow, FlowExecution } from '@/store/flow-store';

const fetchMock = vi.fn<typeof fetch>();

function flow(id: string): Flow {
  return {
    id,
    name: id,
    flow_type: 'application_based',
    deployment_profile_ids: [],
    approval_strategy: 'manual',
    enabled: true,
    hooks: {},
    metadata: {},
    created_at: '2026-11-14T12:00:00Z',
    updated_at: '2026-11-14T12:00:00Z',
    version: 1,
  };
}

function execution(id: string, flowId: string, status: FlowExecution['status'] = 'awaiting_approval'): FlowExecution {
  return {
    id,
    flow_id: flowId,
    status,
    current_step_index: 0,
    step_results: {},
    context_data: {},
    metadata: {},
    created_at: '2026-11-14T12:00:00Z',
    updated_at: '2026-11-14T12:00:00Z',
    version: 1,
  };
}

describe('ApprovalQueuePage complete queue loading', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    useFlowStore.setState(useFlowStore.getInitialState(), true);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it.each([403, 500])('rejects a partial queue after a child HTTP %s and recovers on refresh', async (status) => {
    fetchMock
      .mockResolvedValueOnce(Response.json([flow('flow-a'), flow('flow-b')]))
      .mockResolvedValueOnce(Response.json([execution('pending-a', 'flow-a')]))
      .mockResolvedValueOnce(new Response('', { status }));

    render(<ApprovalQueuePage />);

    expect(await screen.findByRole('alert')).toHaveTextContent('complete approval queue');
    expect(screen.queryByText('pending-a')).not.toBeInTheDocument();
    expect(screen.queryByText(/\d+ Pending/)).not.toBeInTheDocument();
    expect(screen.queryByText('No executions awaiting approval')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled();
    expect(useFlowStore.getState().approvalQueue).toEqual([]);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/identity/flows',
      '/api/v1/identity/flows/flow-a/executions',
      '/api/v1/identity/flows/flow-b/executions',
    ]);

    fetchMock
      .mockResolvedValueOnce(Response.json([flow('flow-a'), flow('flow-b')]))
      .mockResolvedValueOnce(Response.json([execution('pending-a', 'flow-a')]))
      .mockResolvedValueOnce(Response.json([
        execution('pending-b', 'flow-b'),
        execution('already-approved', 'flow-b', 'approved'),
      ]));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(await screen.findByText('pending-b')).toBeInTheDocument();
    expect(screen.getByText('pending-a')).toBeInTheDocument();
    expect(screen.getByText('2 Pending')).toBeInTheDocument();
    expect(screen.queryByText('already-approved')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(useFlowStore.getState().approvalQueueError).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(6);
  });

  it('removes the previous complete queue when a refresh cannot load every flow', async () => {
    fetchMock
      .mockResolvedValueOnce(Response.json([flow('flow-a')]))
      .mockResolvedValueOnce(Response.json([execution('previous-pending', 'flow-a')]));
    render(<ApprovalQueuePage />);
    expect(await screen.findByText('previous-pending')).toBeInTheDocument();

    fetchMock
      .mockResolvedValueOnce(Response.json([flow('flow-a'), flow('flow-b')]))
      .mockResolvedValueOnce(Response.json([execution('previous-pending', 'flow-a')]))
      .mockResolvedValueOnce(new Response('', { status: 503 }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('complete approval queue');
    expect(screen.queryByText('previous-pending')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(useFlowStore.getState().approvalQueue).toEqual([]);
  });

  it('shows a flow-list failure without claiming an empty queue', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 503 }));
    render(<ApprovalQueuePage />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load flows');
    expect(screen.queryByText('No executions awaiting approval')).not.toBeInTheDocument();
    expect(screen.queryByText('0 Pending')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('reports an empty queue only after a successful complete load', async () => {
    fetchMock.mockResolvedValueOnce(Response.json([]));
    render(<ApprovalQueuePage />);

    expect(await screen.findByText('No executions awaiting approval')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled());
    expect(screen.getByText('0 Pending')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
