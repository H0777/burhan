import { useState, useEffect, useCallback } from 'react'
import { ethers } from 'ethers'
import {
  getProvider,
  getContractInstance,
  getSignedContract,
  shortAddress,
} from '../utils/contract.js'
import { isInstitutionalMode, OperationResult } from '../config/runtime.js'
import { DEMO_PROPOSALS, DEMO_ROLES } from '../demo/fixtures.js'

export const PROPOSAL_STATUS_NAMES = [
  'PENDING',
  'APPROVED',
  'EXECUTED',
  'REJECTED',
  'EXPIRED',
  'CANCELLED',
]

export const PROPOSAL_TYPE_NAMES = [
  'OVERRIDE_WARNING',
  'POLICY_CHANGE',
  'EMERGENCY_UNPAUSE',
  'ROLE_CHANGE',
  'GOVERNANCE_CONFIG',
]

export const ROLE_NAMES = [
  'NONE',
  'SUPER_ADMIN',
  'AUDITOR',
  'OPERATOR',
  'REGULATOR',
]

export function useGovernance() {
  const [proposals, setProposals] = useState([])
  const [roles, setRoles] = useState([])
  const [requiredApprovals, setRequiredApprovals] = useState(2)
  const [userRole, setUserRole] = useState('NONE')
  const [userRoleCode, setUserRoleCode] = useState(0)
  const [account, setAccount] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Fetch governance state directly from contracts
  const fetchGovernanceData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const provider = getProvider()
      const multiSig = getContractInstance('MultiSigApproval', provider)
      const roleManager = getContractInstance('RoleManager', provider)

      // Test RPC connection
      const totalPropsBN = await multiSig.totalProposals().catch(() => null)

      if (totalPropsBN === null) {
        if (isInstitutionalMode()) {
          setProposals([])
          setRoles([])
          setUserRole('NONE')
          setUserRoleCode(0)
          setError('MultiSigApproval contract unreachable on current RPC provider')
          return
        }
        // Demo fallback
        setProposals(DEMO_PROPOSALS)
        setRoles(DEMO_ROLES)
        setRequiredApprovals(2)
        setUserRole('SUPER_ADMIN')
        setUserRoleCode(1)
        return
      }

      const reqApp = await multiSig.requiredApprovals().catch(() => 2n)
      setRequiredApprovals(Number(reqApp))

      // Get current signer address if connected
      let currentAccount = null
      if (window.ethereum) {
        try {
          const accounts = await window.ethereum.request({ method: 'eth_accounts' })
          if (accounts && accounts.length > 0) {
            currentAccount = accounts[0]
            setAccount(currentAccount)
          }
        } catch {
          // ignore window.ethereum query failure
        }
      }

      // Query role for current account
      if (currentAccount && roleManager) {
        try {
          const rCode = await roleManager.getRole(currentAccount)
          const codeNum = Number(rCode)
          setUserRoleCode(codeNum)
          setUserRole(ROLE_NAMES[codeNum] || 'NONE')
        } catch {
          setUserRole('NONE')
          setUserRoleCode(0)
        }
      } else if (!isInstitutionalMode()) {
        setUserRole('SUPER_ADMIN')
        setUserRoleCode(1)
      } else {
        setUserRole('NONE')
        setUserRoleCode(0)
      }

      // Fetch all proposals
      const totalCount = Number(totalPropsBN)
      const loadedProposals = []

      for (let id = totalCount; id >= 1; id--) {
        try {
          const p = await multiSig.getProposal(id)
          const approvers = await multiSig.getApprovers(id).catch(() => [])
          const hasVoted = currentAccount
            ? await multiSig.hasVoted(id, currentAccount).catch(() => false)
            : false

          const statusCode = Number(p.status)
          const expiresAtSec = Number(p.expiresAt)
          const isExpired = Date.now() / 1000 >= expiresAtSec && statusCode === 0
          const effectiveStatusCode = isExpired ? 4 : statusCode

          loadedProposals.push({
            id: Number(p.id),
            proposalType: Number(p.proposalType),
            proposalTypeName: PROPOSAL_TYPE_NAMES[Number(p.proposalType)] || 'UNKNOWN',
            proposer: p.proposer,
            target: p.target,
            data: p.data,
            actionHash: p.actionHash,
            reasonHash: p.reasonHash,
            reason: p.reason || '',
            createdAt: Number(p.createdAt),
            notBefore: Number(p.notBefore),
            expiresAt: expiresAtSec,
            status: effectiveStatusCode,
            statusName: PROPOSAL_STATUS_NAMES[effectiveStatusCode] || 'UNKNOWN',
            approvalCount: Number(p.approvalCount),
            rejectionCount: Number(p.rejectionCount),
            requiredApprovals: Number(reqApp),
            approvers: approvers.map((a) => a.toLowerCase()),
            hasVoted,
            isExpired,
            description: p.reason || `${PROPOSAL_TYPE_NAMES[Number(p.proposalType)]} on ${shortAddress(p.target)}`,
          })
        } catch (propErr) {
          console.warn(`Failed to fetch proposal #${id}:`, propErr)
        }
      }

      setProposals(loadedProposals)

      // Fetch roles from RoleManager
      try {
        const members = await roleManager.getAllMembers().catch(() => [])
        const loadedRoles = []
        for (const m of members) {
          const rCode = await roleManager.getRole(m).catch(() => 0n)
          const codeNum = Number(rCode)
          if (codeNum !== 0) {
            const part = await roleManager.getParticipant(m).catch(() => null)
            loadedRoles.push({
              account: m,
              role: ROLE_NAMES[codeNum] || 'NONE',
              roleCode: codeNum,
              roleAr: getRoleArabicName(ROLE_NAMES[codeNum]),
              active: part ? Boolean(part.active) : true,
              generation: part ? Number(part.generation) : 1,
              participantId: part ? part.participantId : '0x',
            })
          }
        }
        setRoles(loadedRoles)
      } catch {
        if (!isInstitutionalMode()) {
          setRoles(DEMO_ROLES)
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch governance data')
      if (!isInstitutionalMode()) {
        setProposals(DEMO_PROPOSALS)
        setRoles(DEMO_ROLES)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  // Wallet event listener for account switching
  useEffect(() => {
    fetchGovernanceData()

    if (window.ethereum) {
      const handleAccounts = (accounts) => {
        const nextAccount = accounts[0] || null
        setAccount(nextAccount)
        fetchGovernanceData()
      }
      window.ethereum.on('accountsChanged', handleAccounts)
      return () => {
        window.ethereum.removeListener('accountsChanged', handleAccounts)
      }
    }
  }, [fetchGovernanceData])

  // Create Proposal
  const createProposal = useCallback(
    async (type, target, data = '0x', reason = '') => {
      try {
        setLoading(true)
        setError(null)

        if (isInstitutionalMode() && (!account || (userRole !== 'SUPER_ADMIN' && userRole !== 'AUDITOR'))) {
          const res = OperationResult.rejected('Caller lacks SUPER_ADMIN or AUDITOR role for proposal submission')
          setError(res.error)
          return res
        }

        const contract = await getSignedContract('MultiSigApproval')
        const reasonBytes = ethers.toUtf8Bytes(reason)
        const reasonHash = ethers.keccak256(reasonBytes)

        const tx = await contract.createProposal(type, target, data, reasonHash)
        const receipt = await tx.wait()
        await fetchGovernanceData()
        return OperationResult.confirmed(receipt.hash || tx.hash)
      } catch (err) {
        const msg = err.reason || err.message || 'Failed to create proposal'
        const res = err.code === 'ACTION_REJECTED' || err.code === 4001
          ? OperationResult.rejected('User denied transaction signature')
          : OperationResult.failed(msg)
        setError(res.error)
        return res
      } finally {
        setLoading(false)
      }
    },
    [account, userRole, fetchGovernanceData]
  )

  // Approve Proposal
  const approveProposal = useCallback(
    async (proposalId) => {
      try {
        setLoading(true)
        setError(null)

        const proposal = proposals.find((p) => p.id === proposalId)
        if (!proposal) {
          return OperationResult.failed('Proposal does not exist')
        }

        if (proposal.status !== 0) {
          return OperationResult.rejected(`Proposal is not pending (status: ${proposal.statusName})`)
        }

        if (proposal.isExpired) {
          return OperationResult.rejected('Cannot approve expired proposal')
        }

        if (account && proposal.proposer.toLowerCase() === account.toLowerCase()) {
          return OperationResult.rejected('Proposer cannot approve own proposal (Separation of Duties)')
        }

        if (account && proposal.hasVoted) {
          return OperationResult.rejected('Caller has already voted on this proposal')
        }

        const contract = await getSignedContract('MultiSigApproval')
        const tx = await contract.approveProposal(proposalId)
        const receipt = await tx.wait()
        await fetchGovernanceData()
        return OperationResult.confirmed(receipt.hash || tx.hash)
      } catch (err) {
        const msg = err.reason || err.message || 'Failed to approve proposal'
        const res = err.code === 'ACTION_REJECTED' || err.code === 4001
          ? OperationResult.rejected('User denied transaction signature')
          : OperationResult.failed(msg)
        setError(res.error)
        return res
      } finally {
        setLoading(false)
      }
    },
    [proposals, account, fetchGovernanceData]
  )

  // Execute Proposal
  const executeProposal = useCallback(
    async (proposalId) => {
      try {
        setLoading(true)
        setError(null)

        const proposal = proposals.find((p) => p.id === proposalId)
        if (!proposal) {
          return OperationResult.failed('Proposal does not exist')
        }

        if (proposal.status !== 1) {
          return OperationResult.rejected(`Proposal is not approved (status: ${proposal.statusName})`)
        }

        if (proposal.isExpired) {
          return OperationResult.rejected('Cannot execute expired proposal')
        }

        const contract = await getSignedContract('MultiSigApproval')
        const tx = await contract.executeProposal(proposalId)
        const receipt = await tx.wait()
        await fetchGovernanceData()
        return OperationResult.confirmed(receipt.hash || tx.hash)
      } catch (err) {
        const msg = err.reason || err.message || 'Failed to execute proposal'
        const res = err.code === 'ACTION_REJECTED' || err.code === 4001
          ? OperationResult.rejected('User denied transaction signature')
          : OperationResult.failed(msg)
        setError(res.error)
        return res
      } finally {
        setLoading(false)
      }
    },
    [proposals, fetchGovernanceData]
  )

  // Reject Proposal
  const rejectProposal = useCallback(
    async (proposalId, reason = 'Rejected by compliance reviewer') => {
      try {
        setLoading(true)
        setError(null)

        const proposal = proposals.find((p) => p.id === proposalId)
        if (!proposal || proposal.status !== 0) {
          return OperationResult.rejected('Proposal not pending')
        }

        const contract = await getSignedContract('MultiSigApproval')
        const tx = await contract.rejectProposal(proposalId, reason)
        const receipt = await tx.wait()
        await fetchGovernanceData()
        return OperationResult.confirmed(receipt.hash || tx.hash)
      } catch (err) {
        const msg = err.reason || err.message || 'Failed to reject proposal'
        const res = err.code === 'ACTION_REJECTED' || err.code === 4001
          ? OperationResult.rejected('User denied transaction signature')
          : OperationResult.failed(msg)
        setError(res.error)
        return res
      } finally {
        setLoading(false)
      }
    },
    [proposals, fetchGovernanceData]
  )

  return {
    proposals,
    roles,
    requiredApprovals,
    userRole,
    userRoleCode,
    account,
    loading,
    error,
    createProposal,
    approveProposal,
    executeProposal,
    rejectProposal,
    refreshGovernance: fetchGovernanceData,
  }
}

function getRoleArabicName(roleName) {
  switch (roleName) {
    case 'SUPER_ADMIN':
      return 'المسؤول الإداري الأعلى (Super Admin)'
    case 'AUDITOR':
      return 'مدقق امتثال قضائي (Forensic Auditor)'
    case 'OPERATOR':
      return 'مشغل تحويلات مالية (Financial Operator)'
    case 'REGULATOR':
      return 'مفتش البنك المركزي (CBI Regulator)'
    default:
      return 'غير مصرح (No Role)'
  }
}
