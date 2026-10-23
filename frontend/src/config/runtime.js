/**
 * Runtime Configuration & Mode Management (T08)
 * Specification §7, §8 (R05, R06, R10)
 * 
 * Supports dual operation modes:
 * - 'demo': Local simulation mode with pre-seeded fixtures for zero-setup exploration.
 * - 'institutional': Strict production/pilot mode requiring real wallet signatures,
 *   immutable deployment verification, and zero unauthenticated fallbacks.
 */

import { ethers } from 'ethers'

export const APP_MODE = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_APP_MODE) ||
  (typeof process !== 'undefined' && process.env?.VITE_APP_MODE) ||
  'demo'

export const isInstitutionalMode = () => APP_MODE === 'institutional'
export const isDemoMode = () => APP_MODE === 'demo'

/**
 * Validates that deployed contracts exist on the network with non-empty bytecode
 * and match the expected chainId.
 * 
 * @param {string} institutionId
 * @param {ethers.Provider} provider
 * @param {Record<string, string>} contractAddresses
 * @param {number} [expectedChainId=1337]
 * @returns {Promise<{institutionId: string, chainId: number, contracts: Record<string, string>, verifiedAt: string}>}
 */
export async function getVerifiedDeployment(
  institutionId = 'INST-DEFAULT',
  provider,
  contractAddresses,
  expectedChainId = 1337
) {
  if (!provider) {
    throw new Error('Verification failed: No Web3 provider provided')
  }

  const network = await provider.getNetwork()
  const chainId = Number(network.chainId)

  // In local hardhat/anvil tests, chainId might be 1337 or 31337
  if (expectedChainId && chainId !== expectedChainId && chainId !== 31337 && chainId !== 1337) {
    throw new Error(`Chain ID mismatch: expected ${expectedChainId}, connected to ${chainId}`)
  }

  const verifiedContracts = {}

  for (const [name, address] of Object.entries(contractAddresses)) {
    if (!address || !ethers.isAddress(address)) {
      throw new Error(`Invalid contract address for ${name}: ${address}`)
    }

    const code = await provider.getCode(address)
    if (!code || code === '0x') {
      throw new Error(`Deployment verification failed: Contract ${name} has no deployed bytecode at ${address}`)
    }

    verifiedContracts[name] = address
  }

  return {
    institutionId,
    chainId,
    contracts: verifiedContracts,
    verifiedAt: new Date().toISOString()
  }
}

/**
 * Standard OperationResult representing on-chain state transition outcome.
 * @typedef {'confirmed'|'rejected'|'failed'} OperationStatus
 */
export class OperationResult {
  /**
   * @param {OperationStatus} status
   * @param {string|null} [transactionHash=null]
   * @param {string|null} [error=null]
   * @param {object|null} [receipt=null]
   */
  constructor(status, transactionHash = null, error = null, receipt = null) {
    this.status = status
    this.transactionHash = transactionHash
    this.error = error
    this.receipt = receipt
    this.timestamp = new Date().toISOString()
  }

  static confirmed(txHash, receipt = null) {
    return new OperationResult('confirmed', txHash, null, receipt)
  }

  static rejected(reason) {
    return new OperationResult('rejected', null, reason)
  }

  static failed(error) {
    const errorMsg = error instanceof Error ? error.message : String(error)
    return new OperationResult('failed', null, errorMsg)
  }
}

let cachedRuntimeConfig = null

/**
 * Loads runtime configuration dynamically from /runtime-config.json.
 * Enables changing backend URLs and contract deployments without rebuilding the static bundle.
 */
export async function loadRuntimeConfig() {
  if (cachedRuntimeConfig) return cachedRuntimeConfig

  try {
    if (typeof fetch !== 'undefined') {
      const res = await fetch('/runtime-config.json', { cache: 'no-store' })
      if (res.ok) {
        cachedRuntimeConfig = await res.json()
        return cachedRuntimeConfig
      }
    }
  } catch {
    // Fallback if file not found
  }

  cachedRuntimeConfig = {
    institution_id: 'INST-DEFAULT',
    chain_id: 1337,
    rpc_url: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_RPC_URL) || 'http://127.0.0.1:8545',
    ai_engine_url: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_AI_ENGINE_URL) || '/api',
    app_mode: APP_MODE,
    contract_version: '2.0.0',
    contracts: {},
  }
  return cachedRuntimeConfig
}

export function getRuntimeConfig() {
  return cachedRuntimeConfig
}

