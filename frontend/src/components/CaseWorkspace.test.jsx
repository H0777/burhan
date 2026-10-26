import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { CaseWorkspace } from './CaseWorkspace'
import { apiV2Client } from '../api/client'

vi.mock('../api/client', () => ({
  apiV2Client: {
    listCases: vi.fn(),
    getCase: vi.fn(),
    createCase: vi.fn(),
    transitionCase: vi.fn(),
    uploadCaseEvidence: vi.fn(),
    verifyEvidenceV3: vi.fn(),
  },
  // Pure helpers re-implemented from the real module for badge mapping tests.
  mapAnchorState: (status) => {
    const s = String(status || '').toUpperCase()
    if (s === 'PENDING') return 'pending'
    if (s === 'SUBMITTED') return 'submitted'
    if (s === 'ANCHORED') return 'anchored'
    if (s === 'FAILED' || s === 'DEAD') return 'failed'
    return 'unavailable'
  },
  mapVerificationOutcome: (result) => {
    if (!result || result.legacyGone || result.status === 410) {
      return { state: 'legacy', onChain: false, reasons: [] }
    }
    if (String(result.provenance_status || '').toLowerCase() === 'demo') {
      return { state: 'demo', onChain: false, reasons: [] }
    }
    const status = String(result.status || '').toLowerCase()
    if (status === 'verified' || status === 'invalid' || status === 'unavailable') {
      return { state: status, onChain: status === 'verified' && !result.http_only, reasons: [] }
    }
    return { state: 'unavailable', onChain: false, reasons: [] }
  },
}))

describe('CaseWorkspace Component & Four-Eyes Governance (T16)', () => {
  const mockCases = [
    {
      id: 'case_1',
      case_number: 'CASE-2026-001',
      institution_id: 'inst_cbi',
      title: 'Suspicious Structuring Account 1244',
      description: 'Smurfing velocity pattern flagged by AI Engine',
      severity: 'HIGH',
      status: 'AWAITING_APPROVAL',
      assigned_to_sub: 'operator-1',
      version: 2,
      created_at: '2026-10-23T10:00:00Z',
      updated_at: '2026-10-23T10:30:00Z',
    },
    {
      id: 'case_2',
      case_number: 'CASE-2026-002',
      institution_id: 'inst_cbi',
      title: 'PEP Cross-Border High Value Outflow',
      description: 'Threshold exceeded (>15M IQD)',
      severity: 'CRITICAL',
      status: 'OPEN',
      assigned_to_sub: 'auditor-2',
      version: 1,
      created_at: '2026-10-23T11:00:00Z',
      updated_at: '2026-10-23T11:00:00Z',
    },
  ]

  const mockCaseDetail1 = {
    case: mockCases[0],
    events: [
      {
        id: 'ce_1',
        case_id: 'case_1',
        institution_id: 'inst_cbi',
        event_type: 'create',
        actor_sub: 'operator-1',
        payload: { from_status: 'NONE', to_status: 'OPEN' },
        created_at: '2026-10-23T10:00:00Z',
      },
      {
        id: 'ce_2',
        case_id: 'case_1',
        institution_id: 'inst_cbi',
        event_type: 'request_approval',
        actor_sub: 'operator-1',
        payload: {
          from_status: 'IN_REVIEW',
          to_status: 'AWAITING_APPROVAL',
          reason: 'Investigation finalized with forensic hash',
        },
        created_at: '2026-10-23T10:30:00Z',
      },
    ],
    evidence_count: 2,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    apiV2Client.listCases.mockResolvedValue({ items: mockCases, total: 2 })
    apiV2Client.getCase.mockResolvedValue(mockCaseDetail1)
  })

  it('renders case list and displays selected case details', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="AUDITOR" account="0x123" />)

    await waitFor(() => {
      expect(apiV2Client.listCases).toHaveBeenCalled()
    })

    await waitFor(() => {
      expect(screen.getByText('2 files')).toBeDefined()
    })

    expect(screen.getAllByText('Suspicious Structuring Account 1244').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('CASE-2026-001').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('PEP Cross-Border High Value Outflow')).toBeDefined()
  })

  it('enforces Four-Eyes principle: prohibits self-approval when current persona is the requester', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="OPERATOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText(/Self-approval is strictly forbidden/i)).toBeDefined()
    })

    // Approve button should be disabled for the requester
    const approveBtn = screen.getByRole('button', { name: /Approve Resolution/i })
    expect(approveBtn.disabled).toBe(true)
  })

  it('allows approval when switching to an independent auditor persona', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="AUDITOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText(/Self-approval is strictly forbidden/i)).toBeDefined()
    })

    // Switch persona to auditor-2
    const personaSelect = screen.getByLabelText(/Active Persona/i)
    fireEvent.change(personaSelect, { target: { value: 'auditor-2' } })

    // Four-Eyes self-approval warning should vanish
    await waitFor(() => {
      expect(screen.queryByText(/Self-approval is strictly forbidden/i)).toBeNull()
    })

    const approveBtn = screen.getByRole('button', { name: /Approve Resolution/i })
    expect(approveBtn.disabled).toBe(false)

    apiV2Client.transitionCase.mockResolvedValue({
      ...mockCases[0],
      status: 'RESOLVED',
      version: 3,
    })

    fireEvent.click(approveBtn)

    await waitFor(() => {
      expect(apiV2Client.transitionCase).toHaveBeenCalledWith(
        'case_1',
        expect.objectContaining({
          action: 'approve_resolution',
          expected_version: 2,
        })
      )
    })
  })

  it('handles optimistic locking 409 conflict gracefully', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="AUDITOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText(/Self-approval is strictly forbidden/i)).toBeDefined()
    })

    // Switch persona to auditor-2
    const personaSelect = screen.getByLabelText(/Active Persona/i)
    fireEvent.change(personaSelect, { target: { value: 'auditor-2' } })

    await waitFor(() => {
      expect(screen.queryByText(/Self-approval is strictly forbidden/i)).toBeNull()
    })

    const approveBtn = screen.getByRole('button', { name: /Approve Resolution/i })
    apiV2Client.transitionCase.mockRejectedValue(
      new Error('Case version conflict: expected 2, but found 3')
    )

    fireEvent.click(approveBtn)

    await waitFor(() => {
      expect(screen.getByText(/Case version conflict/i)).toBeDefined()
    })
  })

  it('displays read-only notice for REGULATOR role and disables transitions', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="REGULATOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText(/Self-approval is strictly forbidden/i)).toBeDefined()
    })

    // Switch persona to cbi-regulator
    const personaSelect = screen.getByLabelText(/Active Persona/i)
    fireEvent.change(personaSelect, { target: { value: 'cbi-regulator' } })

    await waitFor(() => {
      expect(
        screen.getByText(/Regulator read-only access: Write transitions are prohibited/i)
      ).toBeDefined()
    })

    const approveBtn = screen.getByRole('button', { name: /Approve Resolution/i })
    expect(approveBtn.disabled).toBe(true)
  })

  // ------------------------------------------------------------------
  // R13 — UI state distinctions
  // ------------------------------------------------------------------

  it('upload is HTTP-only: anchor badge shows pending/submitted without a blockchain-success claim', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="OPERATOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText('2 files')).toBeDefined()
    })

    const fileInput = screen.getByTestId('evidence-file-input')
    apiV2Client.uploadCaseEvidence.mockResolvedValue({ id: 'ev_9', anchor_status: 'SUBMITTED' })
    fireEvent.change(fileInput, { target: { files: [new File(['x'], 'a.pdf')] } })

    await waitFor(() => {
      expect(screen.getByTestId('anchor-state-badge')).toBeDefined()
    })
    expect(screen.getByTestId('anchor-state-badge').textContent).toContain('submitted')
    // SUBMITTED is not final: no on-chain success wording.
    expect(screen.getByTestId('anchor-state-badge').textContent).toMatch(/not blockchain-anchored/i)
  })

  it('anchored badge carries the on-chain wording only for ANCHORED state', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="OPERATOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText('2 files')).toBeDefined()
    })

    apiV2Client.uploadCaseEvidence.mockResolvedValue({ id: 'ev_10', anchor_status: 'ANCHORED' })
    fireEvent.change(screen.getByTestId('evidence-file-input'), {
      target: { files: [new File(['x'], 'b.pdf')] },
    })

    await waitFor(() => {
      expect(screen.getByTestId('anchor-state-badge').textContent).toContain('anchored')
    })
    expect(screen.getByTestId('anchor-state-badge').textContent).not.toMatch(/not blockchain-anchored/i)
  })

  it('verification badge distinguishes verified/invalid/unavailable and demo', async () => {
    render(<CaseWorkspace t={{}} isRtl={false} userRole="AUDITOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByText('2 files')).toBeDefined()
    })

    apiV2Client.verifyEvidenceV3.mockResolvedValue({
      status: 'verified',
      provenance_status: 'official',
      reasons: [],
    })
    fireEvent.click(screen.getByTestId('verify-evidence-button'))
    await waitFor(() => {
      expect(screen.getByTestId('verification-state-badge').textContent).toContain('verified')
    })

    apiV2Client.verifyEvidenceV3.mockResolvedValue({
      status: 'verified',
      provenance_status: 'demo',
      reasons: [],
    })
    fireEvent.click(screen.getByTestId('verify-evidence-button'))
    await waitFor(() => {
      expect(screen.getByTestId('verification-state-badge').textContent).toContain('demo')
    })

    apiV2Client.verifyEvidenceV3.mockResolvedValue({
      status: 'unavailable',
      provenance_status: 'official',
      reasons: ['snapshot_reorged'],
    })
    fireEvent.click(screen.getByTestId('verify-evidence-button'))
    await waitFor(() => {
      expect(screen.getByTestId('verification-state-badge').textContent).toContain('unavailable')
    })
  })

  it('410 legacy V2 response renders a clear V3 transition banner, never an auto-accepted legacy entry', async () => {
    const legacyError = new Error('API Error [410]: V2 evidence verify retired; use /api/v3/evidence/verify')
    legacyError.status = 410
    legacyError.legacyGone = true
    legacyError.body = { detail: 'V2 retired', v3: '/api/v3/evidence/verify' }
    apiV2Client.listCases.mockRejectedValue(legacyError)

    render(<CaseWorkspace t={{}} isRtl={false} userRole="AUDITOR" account="0x123" />)

    await waitFor(() => {
      expect(screen.getByTestId('legacy-410-banner')).toBeDefined()
    })
    expect(screen.getByTestId('legacy-410-banner').textContent).toContain('/api/v3/evidence/verify')
    expect(screen.getByTestId('legacy-410-banner').textContent).toMatch(/NOT auto-accepted/i)
    // The generic error banner must not double-render the failure:
    expect(screen.queryByText(/Failed to load cases/i)).toBeNull()
  })
})
