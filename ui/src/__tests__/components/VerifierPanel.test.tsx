import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import VerifierPanel from '@/components/VerifierPanel';
import type { IssueLivenessChallengeRequest, LivenessChallenge, VerificationResult, VerifyRequest } from '@/services/tauri-api';

const { verify, issueChallenge, setLastVerification, setVerificationInProgress } = vi.hoisted(() => ({
  verify: vi.fn(),
  issueChallenge: vi.fn(),
  setLastVerification: vi.fn(),
  setVerificationInProgress: vi.fn(),
}));

vi.mock('@/services/tauri-api', () => ({
  verifyCredential: verify,
  issueLivenessChallenge: issueChallenge,
}));
vi.mock('@/store', () => ({
  useAppStore: () => ({ setLastVerification, setVerificationInProgress }),
}));
vi.mock('@/components/VerificationResultCard', () => ({
  default: ({ result }: { result: VerificationResult }) => <div role="status">{result.status}</div>,
}));

const payload = '{"credential":{"id":"test-credential"}}';
const result: VerificationResult = {
  verification_id: 'test-verification',
  status: 'invalid',
  credential_type: 'open-badge',
  issuer: null,
  disclosed_claims: {},
  trust_chain: { valid: false, chain_type: 'iaca', trust_anchor: null, offline_verified: false },
  revocation_status: 'unknown',
  verified_at: '2026-11-14T12:00:00Z',
  warnings: [],
};

function enterPayload(value = payload) {
  fireEvent.change(screen.getByTestId('credential-data-input'), { target: { value } });
}

function disableLiveness() {
  fireEvent.click(screen.getByRole('checkbox', { name: /require liveness/i }));
}

describe('VerifierPanel request admission', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    verify.mockResolvedValue(result);
    issueChallenge.mockImplementation(async (request: IssueLivenessChallengeRequest): Promise<LivenessChallenge> => ({
      challenge_id: 'challenge-1',
      session_id: request.session_id ?? 'test-session',
      nonce: 'test-nonce',
      issued_at: new Date().toISOString(),
      signature: 'synthetic-test-signature',
      allow_network_fallback: true,
      accessibility_mode: false,
      preferred_mode: 'on_device',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      steps: [{ step_id: 'step-1', step_type: 'blink', time_limit_ms: 5000, prompt: 'Blink' }],
    }));
  });

  afterEach(cleanup);

  it.each(['', ' \n\t '])('rejects empty input without requesting a challenge or inventing credential data', (empty) => {
    render(<VerifierPanel />);
    enterPayload(empty);
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Enter credential data before starting verification.');
    expect(issueChallenge).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
    expect(screen.queryByText(/camera view|scanning qr/i)).not.toBeInTheDocument();
  });

  it('submits provided data immediately without an inline policy and preserves the native result', async () => {
    let resolveVerification!: (value: VerificationResult) => void;
    verify.mockReturnValueOnce(new Promise<VerificationResult>((resolve) => { resolveVerification = resolve; }));
    const completed = vi.fn();
    render(<VerifierPanel credentialType="open-badge" onVerificationComplete={completed} />);
    enterPayload();
    disableLiveness();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));

    expect(verify).toHaveBeenCalledTimes(1);
    const request = verify.mock.calls[0][0] as VerifyRequest;
    expect(request).toMatchObject({ credential_type: 'open-badge', credential_data: payload, require_liveness: false });
    expect(request).not.toHaveProperty('policy');
    expect(request.liveness_challenge).toBeUndefined();
    expect(issueChallenge).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Verifying...' })).toBeDisabled();
    expect(setVerificationInProgress).toHaveBeenLastCalledWith(true);

    await act(async () => { resolveVerification(result); });
    expect(screen.getByRole('status')).toHaveTextContent('invalid');
    expect(completed).toHaveBeenCalledWith(result);
    expect(setLastVerification).toHaveBeenCalledWith(result);
    expect(setVerificationInProgress).toHaveBeenLastCalledWith(false);
  });

  it('uses the same policy-free request boundary after the liveness challenge', async () => {
    render(<VerifierPanel credentialType="open-badge" />);
    enterPayload();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));
    await screen.findByText('Liveness Challenge');
    expect(verify).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Submit Verification' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Mark Step Complete' }));
    fireEvent.click(screen.getByRole('button', { name: 'Submit Verification' }));

    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    const request = verify.mock.calls[0][0] as VerifyRequest;
    expect(request).toMatchObject({ credential_data: payload, require_liveness: true, liveness_challenge: { challenge_id: 'challenge-1' } });
    expect(request).not.toHaveProperty('policy');
  });

  it('rejects input cleared after challenge preparation instead of submitting mock data', async () => {
    render(<VerifierPanel />);
    enterPayload();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));
    await screen.findByText('Liveness Challenge');
    fireEvent.click(screen.getByRole('button', { name: 'Mark Step Complete' }));
    enterPayload('  ');
    fireEvent.click(screen.getByRole('button', { name: 'Submit Verification' }));

    expect(screen.getByText('Enter credential data before starting verification.')).toBeInTheDocument();
    expect(verify).not.toHaveBeenCalled();
  });

  it('rejects a challenge with no steps before exposing it as ready for submission', async () => {
    issueChallenge.mockResolvedValueOnce({ challenge_id: 'empty-challenge', steps: [] });
    render(<VerifierPanel />);
    enterPayload();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('The liveness challenge did not include any steps.');
    expect(screen.queryByText('Liveness Challenge')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Submit Verification' })).not.toBeInTheDocument();
    expect(verify).not.toHaveBeenCalled();
    expect(setVerificationInProgress).toHaveBeenLastCalledWith(false);
  });

  it('does not retain an earlier challenge when liveness is disabled for the next request', async () => {
    render(<VerifierPanel />);
    enterPayload();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));
    await screen.findByText('Liveness Challenge');
    disableLiveness();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));

    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    expect(verify.mock.calls[0][0]).toMatchObject({ require_liveness: false, liveness_challenge: undefined });
  });

  it('preserves a supplied OID4VP request and nonce', async () => {
    const oid4vp = '{"vp_token":"signed-vp-token","nonce":"request-nonce"}';
    render(<VerifierPanel credentialType="oid4vp" />);
    enterPayload(oid4vp);
    disableLiveness();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    expect(verify.mock.calls[0][0]).toMatchObject({ credential_type: 'oid4vp', credential_data: oid4vp });
  });

  it('shows a missing governed policy error without producing a verification result', async () => {
    verify.mockRejectedValueOnce(new Error('Active presentation policy is not configured'));
    render(<VerifierPanel />);
    enterPayload();
    disableLiveness();
    fireEvent.click(screen.getByRole('button', { name: 'Start Verification' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Active presentation policy is not configured');
    expect(setLastVerification).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Start Verification' })).toBeEnabled();
    expect(setVerificationInProgress).toHaveBeenLastCalledWith(false);
  });
});
