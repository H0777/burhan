import { describe, it, expect, vi } from 'vitest'
import { getVerifiedDeployment, OperationResult } from '../config/runtime.js'
import { connectWallet } from '../utils/contract.js'

describe('Runtime Config & Deployment Verification (T08)', () => {
  it('should verify deployment when contracts have deployed bytecode', async () => {
    const mockProvider = {
      getNetwork: vi.fn().mockResolvedValue({ chainId: 1337n }),
      getCode: vi.fn().mockResolvedValue('0x608060405234801561001057600080fd5b50')
    }

    const manifest = await getVerifiedDeployment(
      'INST-TEST',
      mockProvider,
      { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
      1337
    )

    expect(manifest.institutionId).toBe('INST-TEST')
    expect(manifest.chainId).toBe(1337)
    expect(manifest.contracts.AuditEngine).toBe('0x5FbDB2315678afecb367f032d93F642f64180aa3')
  })

  it('should reject deployment verification if contract has empty bytecode (not deployed)', async () => {
    const mockProvider = {
      getNetwork: vi.fn().mockResolvedValue({ chainId: 1337n }),
      getCode: vi.fn().mockResolvedValue('0x') // Empty code!
    }

    await expect(
      getVerifiedDeployment(
        'INST-TEST',
        mockProvider,
        { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
        1337
      )
    ).rejects.toThrow('has no deployed bytecode')
  })

  it('should reject deployment verification if chain ID mismatches', async () => {
    const mockProvider = {
      getNetwork: vi.fn().mockResolvedValue({ chainId: 1n }), // Ethereum Mainnet
      getCode: vi.fn().mockResolvedValue('0x6080')
    }

    await expect(
      getVerifiedDeployment(
        'INST-TEST',
        mockProvider,
        { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
        1337
      )
    ).rejects.toThrow('Chain ID mismatch')
  })

  it('OperationResult constructs confirmed, rejected, and failed states correctly', () => {
    const confirmed = OperationResult.confirmed('0xabcdef1234')
    expect(confirmed.status).toBe('confirmed')
    expect(confirmed.transactionHash).toBe('0xabcdef1234')
    expect(confirmed.error).toBeNull()

    const rejected = OperationResult.rejected('User rejected transaction')
    expect(rejected.status).toBe('rejected')
    expect(rejected.error).toBe('User rejected transaction')

    const failed = OperationResult.failed(new Error('Out of gas'))
    expect(failed.status).toBe('failed')
    expect(failed.error).toBe('Out of gas')
  })
})

// ---------------------------------------------------------------------------
// R13 — institutional write gates in useAuditEngine.
// ---------------------------------------------------------------------------

const runtimeState = vi.hoisted(() => ({
  institutional: false,
  chain_id: 31337,
}))

vi.mock('../config/runtime.js', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    isInstitutionalMode: () => runtimeState.institutional,
    assertChainIdMatchesConfig: async (network) => {
      const chainId = Number(network?.chainId)
      if (!Number.isInteger(chainId) || chainId !== runtimeState.chain_id) {
        throw new Error(`Chain ID mismatch: config expects ${runtimeState.chain_id}, connected to ${chainId}`)
      }
      return true
    },
  }
})

const contractMocks = vi.hoisted(() => ({
  getProvider: vi.fn(),
  getContractInstance: vi.fn(),
  getSignedContract: vi.fn(),
  connectWallet: vi.fn(),
  formatAmount: vi.fn(() => '10.0'),
  parseAmount: vi.fn(() => 10n),
  shortAddress: vi.fn(() => '0x123'),
  ROLES: {},
  CONTRACT_ADDRESSES: {},
}))

vi.mock('../utils/contract.js', () => contractMocks)

vi.mock('../api/client.js', () => ({
  apiV2Client: {
    listTransactions: vi.fn().mockRejectedValue(new Error('offline')),
    importTransactions: vi.fn(),
  },
}))

import { renderHook, act } from '@testing-library/react'
import { useAuditEngine } from './useAuditEngine.js'

function setupInstitutional({ chainId = 31337 } = {}) {
  runtimeState.institutional = true
  runtimeState.chain_id = chainId
}

describe('useAuditEngine institutional write gates (R13)', () => {
  it('wrong_chain_even_31337_rejected — connect on a mismatched chain errors and leaves role NONE in institutional', async () => {
    setupInstitutional({ chainId: 1337 })
    // Wallet connects to 31337 while the config expects 1337:
    contractMocks.connectWallet.mockResolvedValue({
      address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      provider: { getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }) },
    })
    contractMocks.getProvider.mockReturnValue({
      getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }),
    })
    contractMocks.getContractInstance.mockReturnValue({
      totalTransactions: vi.fn().mockRejectedValue(new Error('offline')),
    })

    const { result } = renderHook(() => useAuditEngine())

    await act(async () => {
      await result.current.connect()
    })

    expect(result.current.error).toMatch(/Chain ID mismatch/)
    expect(result.current.userRole).toBe('NONE')
    expect(result.current.isAdmin).toBe(false)
  })

  it('no_getSigner_zero_fallback — submit is blocked while wallet/config bootstrap is pending and never writes locally', async () => {
    setupInstitutional()
    contractMocks.connectWallet.mockRejectedValue(new Error('no provider'))
    contractMocks.getProvider.mockReturnValue({
      // chain matches (31337) but chain state calls all fail → offline
      getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }),
    })
    contractMocks.getContractInstance.mockReturnValue({
      totalTransactions: vi.fn().mockRejectedValue(new Error('offline')),
    })

    const { result } = renderHook(() => useAuditEngine())

    // Wait for bootstrap to settle
    await act(async () => {
      await vi.waitFor(() => {
        if (result.current.writesBlockedReason === null) throw new Error('not settled')
      }, { timeout: 3000 }).catch(() => {})
    })

    const transactionsBefore = result.current.transactions.length
    let outcome
    await act(async () => {
      outcome = await result.current.submitTransaction('0x70997970C51812dc3A010C7d01b50e0d17dc79C8', '5.0')
    })

    // Institutional offline: no signer #0 fallback, no local fake write.
    expect(contractMocks.getSignedContract).not.toHaveBeenCalled()
    expect(outcome.success).toBe(false)
    expect(outcome.blocked).toBe(true)
    expect(result.current.transactions.length).toBe(transactionsBefore)
    expect(result.current.error).toMatch(/disabled|refused|Institutional/i)
  })
})
