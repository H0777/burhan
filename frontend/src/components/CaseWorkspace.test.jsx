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
})
