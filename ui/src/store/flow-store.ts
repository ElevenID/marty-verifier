import { create } from 'zustand';

// Type definitions matching backend API
export interface Flow {
  id: string;
  name: string;
  description?: string;
  flow_type: 'pre_authorized_code' | 'authorization_code' | 'oid4vp' | 'mdl_issuance' | 'mdl_presentation' | 'application_based';
  trust_profile_id?: string;
  credential_template_id?: string;
  application_template_id?: string;
  presentation_policy_id?: string;
  deployment_profile_ids: string[];
  approval_strategy: 'auto' | 'manual' | 'rules_based' | 'external';
  enabled: boolean;
  hooks: Record<string, any[]>;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface FlowExecution {
  id: string;
  flow_id: string;
  status: 'created' | 'running' | 'awaiting_approval' | 'approved' | 'rejected' | 'completed' | 'failed' | 'cancelled';
  current_step?: string;
  current_step_index: number;
  step_results: Record<string, any>;
  context_data: Record<string, any>;
  started_at?: string;
  completed_at?: string;
  error?: string;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface CreateFlowRequest {
  name: string;
  flow_type: Flow['flow_type'];
  description?: string;
  trust_profile_id?: string;
  credential_template_id?: string;
  application_template_id?: string;
  presentation_policy_id?: string;
  deployment_profile_ids?: string[];
  approval_strategy?: Flow['approval_strategy'];
  enabled?: boolean;
  hooks?: Record<string, any[]>;
  metadata?: Record<string, any>;
}

export interface UpdateFlowRequest {
  name?: string;
  description?: string;
  trust_profile_id?: string;
  credential_template_id?: string;
  application_template_id?: string;
  presentation_policy_id?: string;
  deployment_profile_ids?: string[];
  approval_strategy?: Flow['approval_strategy'];
  enabled?: boolean;
  hooks?: Record<string, any[]>;
  metadata?: Record<string, any>;
}

interface FlowState {
  // Flows state
  flows: Flow[];
  selectedFlow: Flow | null;
  flowsLoading: boolean;
  flowsError: string | null;

  // Executions state
  executions: FlowExecution[];
  selectedExecution: FlowExecution | null;
  executionsLoading: boolean;
  executionsError: string | null;

  // Approval queue state
  approvalQueue: FlowExecution[];
  approvalQueueLoading: boolean;
  approvalQueueError: string | null;

  // Actions - Flow CRUD
  loadFlows: (flowType?: Flow['flow_type'], enabled?: boolean) => Promise<void>;
  loadFlow: (flowId: string) => Promise<void>;
  createFlow: (request: CreateFlowRequest) => Promise<Flow>;
  updateFlow: (flowId: string, request: UpdateFlowRequest) => Promise<Flow>;
  deleteFlow: (flowId: string) => Promise<void>;
  setSelectedFlow: (flow: Flow | null) => void;

  // Actions - Execution management
  loadExecutions: (flowId: string) => Promise<void>;
  loadExecution: (flowId: string, executionId: string) => Promise<void>;
  startExecution: (flowId: string, context?: Record<string, any>) => Promise<FlowExecution>;
  cancelExecution: (flowId: string, executionId: string, reason?: string) => Promise<void>;
  setSelectedExecution: (execution: FlowExecution | null) => void;

  // Actions - Approval management
  loadApprovalQueue: () => Promise<void>;
  approveExecution: (flowId: string, executionId: string, approvedBy: string, reason?: string) => Promise<void>;
  rejectExecution: (flowId: string, executionId: string, rejectedBy: string, reason?: string) => Promise<void>;
}

const API_BASE = '/api/v1/identity';

export const useFlowStore = create<FlowState>((set, get) => ({
  // Initial state
  flows: [],
  selectedFlow: null,
  flowsLoading: false,
  flowsError: null,

  executions: [],
  selectedExecution: null,
  executionsLoading: false,
  executionsError: null,

  approvalQueue: [],
  approvalQueueLoading: false,
  approvalQueueError: null,

  // Flow CRUD actions
  loadFlows: async (flowType?: Flow['flow_type'], enabled?: boolean) => {
    set({ flowsLoading: true, flowsError: null });
    try {
      const params = new URLSearchParams();
      if (flowType) params.append('flow_type', flowType);
      if (enabled !== undefined) params.append('enabled', String(enabled));

      const response = await fetch(`${API_BASE}/flows?${params}`);
      if (!response.ok) throw new Error('Failed to load flows');
      
      const flows = await response.json();
      set({ flows, flowsLoading: false });
    } catch (error) {
      set({
        flowsError: error instanceof Error ? error.message : 'Failed to load flows',
        flowsLoading: false,
      });
    }
  },

  loadFlow: async (flowId: string) => {
    set({ flowsLoading: true, flowsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}`);
      if (!response.ok) throw new Error('Failed to load flow');
      
      const flow = await response.json();
      set({ selectedFlow: flow, flowsLoading: false });
    } catch (error) {
      set({
        flowsError: error instanceof Error ? error.message : 'Failed to load flow',
        flowsLoading: false,
      });
    }
  },

  createFlow: async (request: CreateFlowRequest) => {
    set({ flowsLoading: true, flowsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      if (!response.ok) throw new Error('Failed to create flow');
      
      const flow = await response.json();
      set(state => ({
        flows: [...state.flows, flow],
        selectedFlow: flow,
        flowsLoading: false,
      }));
      return flow;
    } catch (error) {
      set({
        flowsError: error instanceof Error ? error.message : 'Failed to create flow',
        flowsLoading: false,
      });
      throw error;
    }
  },

  updateFlow: async (flowId: string, request: UpdateFlowRequest) => {
    set({ flowsLoading: true, flowsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      if (!response.ok) throw new Error('Failed to update flow');
      
      const flow = await response.json();
      set(state => ({
        flows: state.flows.map(f => f.id === flowId ? flow : f),
        selectedFlow: state.selectedFlow?.id === flowId ? flow : state.selectedFlow,
        flowsLoading: false,
      }));
      return flow;
    } catch (error) {
      set({
        flowsError: error instanceof Error ? error.message : 'Failed to update flow',
        flowsLoading: false,
      });
      throw error;
    }
  },

  deleteFlow: async (flowId: string) => {
    set({ flowsLoading: true, flowsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error('Failed to delete flow');
      
      set(state => ({
        flows: state.flows.filter(f => f.id !== flowId),
        selectedFlow: state.selectedFlow?.id === flowId ? null : state.selectedFlow,
        flowsLoading: false,
      }));
    } catch (error) {
      set({
        flowsError: error instanceof Error ? error.message : 'Failed to delete flow',
        flowsLoading: false,
      });
      throw error;
    }
  },

  setSelectedFlow: (flow: Flow | null) => {
    set({ selectedFlow: flow });
  },

  // Execution management actions
  loadExecutions: async (flowId: string) => {
    set({ executionsLoading: true, executionsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions`);
      if (!response.ok) throw new Error('Failed to load executions');
      
      const executions = await response.json();
      set({ executions, executionsLoading: false });
    } catch (error) {
      set({
        executionsError: error instanceof Error ? error.message : 'Failed to load executions',
        executionsLoading: false,
      });
    }
  },

  loadExecution: async (flowId: string, executionId: string) => {
    set({ executionsLoading: true, executionsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions/${executionId}`);
      if (!response.ok) throw new Error('Failed to load execution');
      
      const execution = await response.json();
      set({ selectedExecution: execution, executionsLoading: false });
    } catch (error) {
      set({
        executionsError: error instanceof Error ? error.message : 'Failed to load execution',
        executionsLoading: false,
      });
    }
  },

  startExecution: async (flowId: string, context?: Record<string, any>) => {
    set({ executionsLoading: true, executionsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: context || {} }),
      });
      if (!response.ok) throw new Error('Failed to start execution');
      
      const execution = await response.json();
      set(state => ({
        executions: [execution, ...state.executions],
        selectedExecution: execution,
        executionsLoading: false,
      }));
      return execution;
    } catch (error) {
      set({
        executionsError: error instanceof Error ? error.message : 'Failed to start execution',
        executionsLoading: false,
      });
      throw error;
    }
  },

  cancelExecution: async (flowId: string, executionId: string, reason?: string) => {
    set({ executionsLoading: true, executionsError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions/${executionId}/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason }),
      });
      if (!response.ok) throw new Error('Failed to cancel execution');
      
      // Reload executions
      await get().loadExecutions(flowId);
    } catch (error) {
      set({
        executionsError: error instanceof Error ? error.message : 'Failed to cancel execution',
        executionsLoading: false,
      });
      throw error;
    }
  },

  setSelectedExecution: (execution: FlowExecution | null) => {
    set({ selectedExecution: execution });
  },

  // Approval management actions
  loadApprovalQueue: async () => {
    set({ approvalQueueLoading: true, approvalQueueError: null });
    try {
      // Query all flows for executions with awaiting_approval status
      const response = await fetch(`${API_BASE}/flows`);
      if (!response.ok) throw new Error('Failed to load flows');
      
      const flows: Flow[] = await response.json();
      const allExecutions: FlowExecution[] = [];
      
      // Load executions for each flow
      for (const flow of flows) {
        const execResponse = await fetch(`${API_BASE}/flows/${flow.id}/executions`);
        if (execResponse.ok) {
          const execs = await execResponse.json();
          allExecutions.push(...execs);
        }
      }
      
      // Filter for awaiting_approval status
      const approvalQueue = allExecutions.filter(e => e.status === 'awaiting_approval');
      set({ approvalQueue, approvalQueueLoading: false });
    } catch (error) {
      set({
        approvalQueueError: error instanceof Error ? error.message : 'Failed to load approval queue',
        approvalQueueLoading: false,
      });
    }
  },

  approveExecution: async (flowId: string, executionId: string, approvedBy: string, reason?: string) => {
    set({ approvalQueueLoading: true, approvalQueueError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions/${executionId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: approvedBy, reason }),
      });
      if (!response.ok) throw new Error('Failed to approve execution');
      
      // Reload approval queue
      await get().loadApprovalQueue();
    } catch (error) {
      set({
        approvalQueueError: error instanceof Error ? error.message : 'Failed to approve execution',
        approvalQueueLoading: false,
      });
      throw error;
    }
  },

  rejectExecution: async (flowId: string, executionId: string, rejectedBy: string, reason?: string) => {
    set({ approvalQueueLoading: true, approvalQueueError: null });
    try {
      const response = await fetch(`${API_BASE}/flows/${flowId}/executions/${executionId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rejected_by: rejectedBy, reason }),
      });
      if (!response.ok) throw new Error('Failed to reject execution');
      
      // Reload approval queue
      await get().loadApprovalQueue();
    } catch (error) {
      set({
        approvalQueueError: error instanceof Error ? error.message : 'Failed to reject execution',
        approvalQueueLoading: false,
      });
      throw error;
    }
  },
}));
