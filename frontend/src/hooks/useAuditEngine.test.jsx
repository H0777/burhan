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
