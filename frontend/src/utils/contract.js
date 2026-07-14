import { ethers } from 'ethers'

// ABI - Generated from AuditEngine.sol
export const AUDIT_ENGINE_ABI = [
  // Events
  'event TransactionSubmitted(uint256 indexed txId, address indexed sender, address indexed receiver, uint256 amount, uint256 timestamp)',
  'event TransactionFlagged(uint256 indexed txId, address indexed flaggedBy, string reason)',
  'event TransactionCleared(uint256 indexed txId, address indexed clearedBy)',
  'event AddressBlacklisted(address indexed addr, address indexed by)',
  'event KYCVerified(address indexed addr, address indexed by)',

  // View functions
  'function admin() view returns (address)',
  'function totalTransactions() view returns (uint256)',
  'function getTransaction(uint256 txId) view returns (tuple(uint256 id, address sender, address receiver, uint256 amount, uint256 timestamp, bool isFlagged, string flagReason, uint8 status))',
  'function getAllTransactions() view returns (tuple(uint256 id, address sender, address receiver, uint256 amount, uint256 timestamp, bool isFlagged, string flagReason, uint8 status)[])',
  'function getFlaggedTransactions() view returns (uint256[])',
  'function isBlacklisted(address addr) view returns (bool)',
  'function isKYCVerified(address addr) view returns (bool)',
  'function getDailyVolume(address addr, uint256 date) view returns (uint256)',
  'function LARGE_TRANSACTION_THRESHOLD() view returns (uint256)',
  'function DAILY_VOLUME_LIMIT() view returns (uint256)',
  'function KYC_REQUIRED_THRESHOLD() view returns (uint256)',

  // Write functions
  'function submitTransaction(address receiver, uint256 amount) returns (uint256)',
  'function flagTransaction(uint256 txId, string reason)',
  'function clearTransaction(uint256 txId)',
  'function blacklistAddress(address addr)',
  'function verifyKYC(address addr)',
]

// Contract address - update after deployment
export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || ''

/**
 * Get a read-only provider (no wallet needed)
 */
export function getProvider() {
  if (window.ethereum) {
    return new ethers.BrowserProvider(window.ethereum)
  }
  // Fallback to local hardhat node
  return new ethers.JsonRpcProvider(
    import.meta.env.VITE_RPC_URL || 'http://127.0.0.1:8545'
  )
}

/**
 * Get contract instance (read-only)
 */
export function getContract(provider) {
  return new ethers.Contract(CONTRACT_ADDRESS, AUDIT_ENGINE_ABI, provider)
}

/**
 * Get contract instance with signer (write operations)
 */
export async function getSignedContract() {
  const provider = await getProvider()
  const signer = await provider.getSigner()
  return new ethers.Contract(CONTRACT_ADDRESS, AUDIT_ENGINE_ABI, signer)
}

/**
 * Connect MetaMask wallet
 */
export async function connectWallet() {
  if (!window.ethereum) {
    throw new Error('MetaMask not installed. Please install MetaMask.')
  }
  const provider = new ethers.BrowserProvider(window.ethereum)
  await provider.send('eth_requestAccounts', [])
  const signer = await provider.getSigner()
  return {
    provider,
    signer,
    address: await signer.getAddress(),
  }
}

/**
 * Format amount from wei to ETH string
 */
export function formatAmount(wei) {
  return ethers.formatEther(wei)
}

/**
 * Parse amount from ETH to wei
 */
export function parseAmount(eth) {
  return ethers.parseEther(eth.toString())
}

/**
 * Format timestamp to readable date
 */
export function formatTimestamp(timestamp) {
  return new Date(Number(timestamp) * 1000).toLocaleString('en-IQ')
}

/**
 * Shorten address for display
 */
export function shortAddress(address) {
  if (!address) return ''
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}
