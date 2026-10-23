import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { RoleManagement } from './RoleManagement'
import * as governanceHook from '../hooks/useGovernance'

describe('RoleManagement Component & MultiSig Governance (T09)', () => {
  const mockProposals = [
    {
      id: 1,
      proposalType: 1,
      proposalTypeName: 'POLICY_CHANGE',
      proposer: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
      target: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
      data: '0x12345678',
      actionHash: '0x1111222233334444555566667777888899990000111122223333444455556666',
      reasonHash: '0xaaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999',
      reason: 'Update AML Large Transaction Threshold to 12.0 ETH',
      createdAt: 1700000000,
      notBefore: 1700000000,
      expiresAt: Math.floor(Date.now() / 1000) + 86400, // Valid future time
      status: 0, // PENDING
      statusName: 'PENDING',
      approvalCount: 1,
      rejectionCount: 0,
      requiredApprovals: 2,
      approvers: ['0x5FbDB2315678afecb367f032d93F642f64180aa3'],
      hasVoted: false,
      isExpired: false,
      description: 'Update AML Large Transaction Threshold to 12.0 ETH',
      descriptionAr: 'تعديل سقف التحويلات الكبيرة إلى 12.0 ETH',
    },
    {
      id: 2,
      proposalType: 2,
      proposalTypeName: 'EMERGENCY_UNPAUSE',
      proposer: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
      target: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
      data: '0x87654321',
      actionHash: '0x2222333344445555666677778888999900001111222233334444555566667777',
      reasonHash: '0xbbbbccccddddeeeeffff00001111222233334444555566667777888899990000',
      reason: 'Emergency Circuit Breaker Unpause Authorization',
      createdAt: 1700000000,
      notBefore: 1700000000,
      expiresAt: Math.floor(Date.now() / 1000) + 86400,
      status: 1, // APPROVED but NOT EXECUTED!
      statusName: 'APPROVED',
      approvalCount: 2,
      rejectionCount: 0,
      requiredApprovals: 2,
      approvers: [
        '0x5FbDB2315678afecb367f032d93F642f64180aa3',
        '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      ],
      hasVoted: true,
      isExpired: false,
      description: 'Emergency Circuit Breaker Unpause Authorization',
      descriptionAr: 'رفع التجميد الاحترازي واستئناف المعاملات بمصادقة ثنائية',
    },
    {
      id: 3,
      proposalType: 0,
      proposalTypeName: 'OVERRIDE_WARNING',
      proposer: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      target: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
      data: '0x99998888',
      actionHash: '0x3333444455556666777788889999000011112222333344445555666677778888',
      reasonHash: '0xccccddddeeeeffff000011112222333344445555666677778888999900001111',
      reason: 'Expired proposal test',
      createdAt: 1690000000,
      notBefore: 1690000000,
      expiresAt: 1690086400, // Past timestamp => EXPIRED
      status: 4, // EXPIRED
      statusName: 'EXPIRED',
      approvalCount: 0,
      rejectionCount: 0,
      requiredApprovals: 2,
      approvers: [],
      hasVoted: false,
      isExpired: true,
      description: 'Expired Proposal Test',
      descriptionAr: 'اختبار مقترح منتهي الصلاحية',
    },
  ]

  const mockRoles = [
    {
      account: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
      role: 'SUPER_ADMIN',
      roleAr: 'المسؤول الإداري الأعلى (Super Admin)',
      active: true,
      generation: 1,
    },
    {
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      role: 'AUDITOR',
      roleAr: 'مدقق امتثال قضائي (Forensic Auditor)',
      active: true,
      generation: 1,
    },
  ]

  let mockGovernance

  beforeEach(() => {
    mockGovernance = {
      proposals: mockProposals,
      roles: mockRoles,
      requiredApprovals: 2,
      userRole: 'AUDITOR',
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      loading: false,
      error: null,
      createProposal: vi.fn().mockResolvedValue({ status: 'confirmed', transactionHash: '0xtx1' }),
      approveProposal: vi.fn().mockResolvedValue({ status: 'confirmed', transactionHash: '0xtx2' }),
      executeProposal: vi.fn().mockResolvedValue({ status: 'confirmed', transactionHash: '0xtx3' }),
      rejectProposal: vi.fn().mockResolvedValue({ status: 'confirmed', transactionHash: '0xtx4' }),
      refreshGovernance: vi.fn(),
    }

    vi.spyOn(governanceHook, 'useGovernance').mockImplementation(() => mockGovernance)
  })

  it('displays action data, actionHash, target, and expiresAt before signing', () => {
    render(<RoleManagement isRtl={false} />)

    // Verify Action Hash is visible
    expect(screen.getByText(/0x11112222...55556666/i)).toBeDefined()
    // Verify Target is visible across proposals
    expect(screen.getAllByText(/0xDc64a140...962f0cF6C9/i).length).toBeGreaterThan(0)
    // Verify Status is PENDING
    expect(screen.getByText('PENDING')).toBeDefined()
  })

  it('APPROVED proposal is NOT automatically EXECUTED and shows Execute Action button', async () => {
    render(<RoleManagement isRtl={false} />)

    // Proposal #2 has status APPROVED
    const approvedBadge = screen.getByText('APPROVED')
    expect(approvedBadge).toBeDefined()

    // It should have an Execute button because it is approved but not executed
    const executeButton = screen.getByRole('button', { name: /execute/i })
    expect(executeButton).toBeDefined()

    // Clicking execute calls executeProposal with proposal ID 2
    fireEvent.click(executeButton)
    await waitFor(() => {
      expect(mockGovernance.executeProposal).toHaveBeenCalledWith(2)
    })
  })

  it('rejects duplicate voting when user has already voted on proposal', async () => {
    // Current user has already voted on Proposal #2
    render(<RoleManagement isRtl={false} />)

    // Proposal #2 shows user has voted and does not allow approving again
    const p2Card = screen.getByText(/EMERGENCY_UNPAUSE/i).closest('div.proposal-card')
    // No "Confirm / Approve" button for proposal #2
    const approveBtnForP2 = p2Card?.querySelector('button.approve-btn')
    expect(approveBtnForP2).toBeNull()
  })

  it('rejects approval if caller is the proposer (Separation of Duties)', async () => {
    // Current user is the proposer of Proposal #1
    mockGovernance.account = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
    render(<RoleManagement isRtl={false} />)

    // Find Proposal #1 card
    const p1Card = screen.getByText(/POLICY_CHANGE/i).closest('div.proposal-card')
    // Proposer cannot approve own proposal; button should indicate cannot self-approve or be disabled
    const selfApproveMsg = p1Card?.querySelector('.proposer-restriction')
    expect(selfApproveMsg).not.toBeNull()
  })

  it('handles signature rejection gracefully without advancing status', async () => {
    mockGovernance.approveProposal = vi.fn().mockResolvedValue({
      status: 'rejected',
      error: 'User denied transaction signature',
    })

    render(<RoleManagement isRtl={false} />)

    const approveButton = screen.getByRole('button', { name: /confirm|approve/i })
    fireEvent.click(approveButton)

    await waitFor(() => {
      expect(screen.getByText(/User denied transaction signature/i)).toBeDefined()
    })
  })

  it('blocks approval and execution on EXPIRED proposals', () => {
    render(<RoleManagement isRtl={false} />)

    // Proposal #3 has status EXPIRED
    expect(screen.getByText('EXPIRED')).toBeDefined()
    const p3Card = screen.getByText(/Expired Proposal Test/i).closest('div.proposal-card')
    // Should have no action button
    expect(p3Card?.querySelector('button')).toBeNull()
  })

  it('updates permissions when account switches to an unauthorized role (OPERATOR)', () => {
    // Switch to OPERATOR (cannot approve MultiSig proposals)
    mockGovernance.userRole = 'OPERATOR'
    mockGovernance.account = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'

    render(<RoleManagement isRtl={false} />)

    // Role display reflects OPERATOR
    expect(screen.getAllByText(/OPERATOR/i).length).toBeGreaterThan(0)
    // Operators cannot vote on MultiSig, all approve buttons should be hidden or disabled
    expect(screen.queryByRole('button', { name: /confirm \(2nd eye\)/i })).toBeNull()
  })
})
