/**
 * Unit tests for VerificationResultCard component
 */
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import VerificationResultCard from '@/components/VerificationResultCard';
import { VerificationResult } from '@/services/tauri-api';

const createMockResult = (overrides: Partial<VerificationResult> = {}): VerificationResult => ({
  verification_id: 'test-id-123',
  status: 'valid',
  credential_type: 'mdl',
  issuer: {
    name: 'State DMV',
    jurisdiction: 'US-CA',
    subject: null,
  },
  disclosed_claims: {
    given_name: 'John',
    family_name: 'Doe',
    birth_date: '1990-01-15',
  },
  trust_chain: {
    valid: true,
    chain_type: 'iaca',
    trust_anchor: 'US-CA',
    offline_verified: false,
  },
  revocation_status: 'valid',
  verified_at: '2025-12-19T10:00:00Z',
  warnings: [],
  ...overrides,
});

describe('VerificationResultCard', () => {
  it('should render valid status', () => {
    const result = createMockResult({ status: 'valid' });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText('Valid')).toBeInTheDocument();
  });

  it('should render invalid status', () => {
    const result = createMockResult({ status: 'invalid' });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText('Invalid')).toBeInTheDocument();
  });

  it('should render credential type', () => {
    const result = createMockResult({ credential_type: 'mdl' });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText(/mdl/i)).toBeInTheDocument();
  });

  it('should render issuer information when available', () => {
    const result = createMockResult({
      issuer: { name: 'California DMV', jurisdiction: 'US-CA', subject: null },
    });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText(/California DMV/)).toBeInTheDocument();
  });

  it('should render warnings when present', () => {
    const result = createMockResult({
      warnings: ['Verified with cached trust anchors', 'CRL data may be outdated'],
    });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText(/Verified with cached trust anchors/)).toBeInTheDocument();
  });

  it('should render trust chain status', () => {
    const result = createMockResult({
      trust_chain: { valid: true, chain_type: 'iaca', trust_anchor: 'US-CA', offline_verified: false },
    });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText(/Trust Chain/i)).toBeInTheDocument();
  });

  it('should render offline verified indicator when applicable', () => {
    const result = createMockResult({
      trust_chain: { valid: true, chain_type: 'iaca', trust_anchor: 'US-CA', offline_verified: true },
    });
    render(<VerificationResultCard result={result} />);
    
    expect(screen.getByText(/offline/i)).toBeInTheDocument();
  });

  it('renders explicit DTC check outcomes without calling unresolved checks failed', () => {
    const result = createMockResult({
      credential_type: 'dtc',
      dtc_details: {
        checks: [
          { check_name: 'Signature', outcome: 'PASSED', passed: true },
          { check_name: 'TrustChain', outcome: 'FAILED', passed: false },
          {
            check_name: 'RevocationStatus',
            outcome: 'NOT_PERFORMED',
            passed: false,
            error_code: 'E810',
          },
          {
            check_name: 'StatusEvidence',
            outcome: 'ERROR',
            passed: false,
            details: 'Status evidence was malformed',
          },
        ],
        errors: [],
        error_codes: [],
      },
    });

    render(<VerificationResultCard result={result} />);

    expect(screen.getByText('Signature: Passed')).toBeInTheDocument();
    expect(screen.getByText('TrustChain: Failed')).toBeInTheDocument();

    const notPerformed = screen.getByText('RevocationStatus: Not performed (E810)');
    expect(notPerformed).toBeInTheDocument();
    expect(notPerformed.closest('.MuiChip-root')).toHaveClass('MuiChip-colorDefault');

    const error = screen.getByText('StatusEvidence: Error');
    expect(error).toBeInTheDocument();
    expect(error.closest('.MuiChip-root')).toHaveClass('MuiChip-colorWarning');
    expect(error.closest('.MuiChip-root')).toHaveAttribute(
      'title',
      'Status evidence was malformed'
    );
  });
});
