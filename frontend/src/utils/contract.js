import { ethers } from 'ethers'
import {
  AuditEngineABI,
  ForensicTrailABI,
  MultiSigApprovalABI,
  RoleManagerABI,
  InsiderActivityLogABI,
  ComplianceRulesABI,
  CONTRACT_ABIS
} from '../contracts/generated/index.js'
import { APP_MODE, isInstitutionalMode, isDemoMode, OperationResult } from '../config/runtime.js'
import { DEMO_FALLBACK_WALLET } from '../demo/fixtures.js'

// Deployed contract addresses (matching deployments/localhost.json)
export const CONTRACT_ADDRESSES = {
  AuditEngine: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_AUDIT_ENGINE_ADDRESS) || '0x610178dA211FEF7D417bC0e6FeD39F05609AD788',
  ForensicTrail: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FORENSIC_TRAIL_ADDRESS) || '0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6',
  InsiderActivityLog: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_INSIDER_LOG_ADDRESS) || '0x8A791620dd6260079BF849Dc5567aDC3F2FdC318',
  MultiSigApproval: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_MULTISIG_ADDRESS) || '0xa513E6E4b8f2a923D98304ec87F64353C4D5C853',
  RoleManager: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_ROLE_MANAGER_ADDRESS) || '0x0165878A594ca255338adfa4d48449f69242Eb8F',
  ComplianceRules: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_COMPLIANCE_RULES_ADDRESS) || '0x5FbDB2315678afecb367f032d93F642f64180aa3',
}

export const LOCAL_RPC_URL = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_RPC_URL) || 'http://127.0.0.1:8545'

export const CONTRACT_ADDRESS = CONTRACT_ADDRESSES.AuditEngine

export const ROLES = {
  SUPER_ADMIN: '0x0000000000000000000000000000000000000000000000000000000000000000',
  AUDITOR_ROLE: ethers.keccak256(ethers.toUtf8Bytes('AUDITOR_ROLE')),
  OPERATOR_ROLE: ethers.keccak256(ethers.toUtf8Bytes('OPERATOR_ROLE')),
  REGULATOR_ROLE: ethers.keccak256(ethers.toUtf8Bytes('REGULATOR_ROLE')),
}

// Authoritative ABIs re-exported from generated artifacts
export const AUDIT_ENGINE_ABI = AuditEngineABI
export const FORENSIC_TRAIL_ABI = ForensicTrailABI
export const INSIDER_LOG_ABI = InsiderActivityLogABI
export const MULTISIG_ABI = MultiSigApprovalABI
export const ROLE_MANAGER_ABI = RoleManagerABI
export const COMPLIANCE_RULES_ABI = ComplianceRulesABI

export { CONTRACT_ABIS, OperationResult, APP_MODE, isInstitutionalMode, isDemoMode }

/**
 * Get read-only or local JSON-RPC provider.
 */
export function getLocalProvider() {
  return new ethers.JsonRpcProvider(LOCAL_RPC_URL)
}

export function getProvider() {
  if (typeof window !== 'undefined' && window.ethereum && window.__USE_METAMASK) {
    return new ethers.BrowserProvider(window.ethereum)
  }
  return getLocalProvider()
}

export function getContractInstance(name, providerOrSigner) {
  const address = CONTRACT_ADDRESSES[name]
  const abi = CONTRACT_ABIS[name] || AUDIT_ENGINE_ABI
  return new ethers.Contract(address, abi, providerOrSigner)
}

export function getContract(provider) {
  return getContractInstance('AuditEngine', provider)
}

export async function getSignedContract(name = 'AuditEngine') {
  if (typeof window !== 'undefined' && window.ethereum && window.__USE_METAMASK) {
    const provider = new ethers.BrowserProvider(window.ethereum)
    const signer = await provider.getSigner()
    return getContractInstance(name, signer)
  }

  if (isInstitutionalMode()) {
    throw new Error(
      'Institutional Mode: Unlocked signer #0 is prohibited in institutional mode. ' +
      'Please connect an authorized hardware or Web3 institutional signer.'
    )
  }

  // Use local Hardhat node's unlocked Signer #0 for local demo
  const localProvider = getLocalProvider()
  const signer = await localProvider.getSigner(0)
  return getContractInstance(name, signer)
}

/**
 * Connect wallet: Supports MetaMask if requested, otherwise connects directly to Hardhat local node.
 * In institutional mode, connection failure strictly halts and NEVER falls back to simulated identity.
 */
export async function connectWallet(preferMetaMask = false) {
  if (preferMetaMask && typeof window !== 'undefined' && window.ethereum) {
    window.__USE_METAMASK = true
    const provider = new ethers.BrowserProvider(window.ethereum)
    await provider.send('eth_requestAccounts', [])
    const signer = await provider.getSigner()
    const address = await signer.getAddress()
    return {
      provider,
      signer,
      address,
      isLocalNode: false,
      label: `MetaMask (${shortAddress(address)})`,
    }
  }

  // Connect to live local Hardhat node
  try {
    const localProvider = getLocalProvider()
    const signer = await localProvider.getSigner(0)
    const address = await signer.getAddress()
    const balance = await localProvider.getBalance(address)
    if (typeof window !== 'undefined') {
      window.__USE_METAMASK = false
    }

    return {
      provider: localProvider,
      signer,
      address,
      balance: ethers.formatEther(balance),
      isLocalNode: true,
      label: `Hardhat Node Signer #0 (${shortAddress(address)} - 10,000 ETH)`,
    }
  } catch (err) {
    if (isInstitutionalMode()) {
      throw new Error(`Institutional connection failed: ${err.message}. Simulated fallback is disabled in institutional mode.`)
    }

    console.warn('[Contract] Local node connection failed, using demo simulated wallet:', err.message)
    return {
      provider: null,
      signer: null,
      ...DEMO_FALLBACK_WALLET
    }
  }
}

export function formatAmount(wei) {
  if (!wei) return '0.0000'
  return ethers.formatEther(wei)
}

export function parseAmount(eth) {
  if (!eth || isNaN(eth)) return ethers.parseEther('0')
  return ethers.parseEther(eth.toString())
}

export function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A'
  return new Date(Number(timestamp) * 1000).toLocaleString('en-US', {
    dateStyle: 'short',
    timeStyle: 'medium',
  })
}

export function shortAddress(address) {
  if (!address) return ''
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}

/**
 * Query on-chain participant enrollment and authorization generation from RoleManager.
 * @param {string} address
 * @param {ethers.Provider} [provider]
 * @returns {Promise<{participantId: string, generation: number, role: number, active: boolean}|null>}
 */
export async function getOnChainParticipant(address, provider = null) {
  if (!address || !ethers.isAddress(address)) return null
  const p = provider || getProvider()
  const roleManager = getContractInstance('RoleManager', p)
  try {
    const [participantId, generation, role, active] = await roleManager.getParticipant(address)
    return {
      participantId,
      generation: Number(generation),
      role: Number(role),
      active: Boolean(active),
    }
  } catch (err) {
    console.warn(`[Contract] Failed to fetch on-chain participant for ${address}:`, err.message)
    return null
  }
}

