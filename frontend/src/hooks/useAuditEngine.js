import { useState, useEffect, useCallback } from 'react'
import {
  getProvider,
  getContract,
  getSignedContract,
  connectWallet,
  formatAmount,
  parseAmount,
} from '../utils/contract'

/**
 * Main hook for interacting with AuditEngine smart contract
 */
export function useAuditEngine() {
  const [account, setAccount] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [transactions, setTransactions] = useState([])
  const [flaggedIds, setFlaggedIds] = useState([])
  const [stats, setStats] = useState({
    total: 0,
    flagged: 0,
    cleared: 0,
    threshold: '0',
    dailyLimit: '0',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Connect wallet
  const connect = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const { address } = await connectWallet()
      setAccount(address)

      // Check if admin
      const provider = getProvider()
      const contract = getContract(provider)
      const adminAddress = await contract.admin()
      setIsAdmin(address.toLowerCase() === adminAddress.toLowerCase())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  // Fetch all transactions
  const fetchTransactions = useCallback(async () => {
    try {
      setLoading(true)
      const provider = getProvider()
      const contract = getContract(provider)
      const txs = await contract.getAllTransactions()
      const flagged = await contract.getFlaggedTransactions()

      setTransactions(
        txs.map((tx) => ({
          id: Number(tx.id),
          sender: tx.sender,
          receiver: tx.receiver,
          amount: formatAmount(tx.amount),
          timestamp: Number(tx.timestamp),
          isFlagged: tx.isFlagged,
          flagReason: tx.flagReason,
          status: Number(tx.status), // 0=PENDING, 1=CLEARED, 2=FLAGGED, 3=BLOCKED
        }))
      )
      setFlaggedIds(flagged.map(Number))

      // Fetch stats
      const total = await contract.totalTransactions()
      const threshold = await contract.LARGE_TRANSACTION_THRESHOLD()
      const dailyLimit = await contract.DAILY_VOLUME_LIMIT()

      setStats({
        total: Number(total),
        flagged: flagged.length,
        cleared: txs.filter((tx) => Number(tx.status) === 1).length,
        threshold: formatAmount(threshold),
        dailyLimit: formatAmount(dailyLimit),
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  // Submit a transaction
  const submitTransaction = useCallback(async (receiver, amount) => {
    try {
      setLoading(true)
      setError(null)
      const contract = await getSignedContract()
      const amountWei = parseAmount(amount)
      const tx = await contract.submitTransaction(receiver, amountWei)
      await tx.wait()
      await fetchTransactions()
      return { success: true }
    } catch (err) {
      setError(err.message)
      return { success: false, error: err.message }
    } finally {
      setLoading(false)
    }
  }, [fetchTransactions])

  // Flag a transaction (admin only)
  const flagTransaction = useCallback(async (txId, reason) => {
    try {
      setLoading(true)
      const contract = await getSignedContract()
      const tx = await contract.flagTransaction(txId, reason)
      await tx.wait()
      await fetchTransactions()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [fetchTransactions])

  // Clear a transaction (admin only)
  const clearTransaction = useCallback(async (txId) => {
    try {
      setLoading(true)
      const contract = await getSignedContract()
      const tx = await contract.clearTransaction(txId)
      await tx.wait()
      await fetchTransactions()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [fetchTransactions])

  // Verify KYC (admin only)
  const verifyKYC = useCallback(async (address) => {
    try {
      setLoading(true)
      const contract = await getSignedContract()
      const tx = await contract.verifyKYC(address)
      await tx.wait()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  // Listen for account changes in MetaMask
  useEffect(() => {
    if (window.ethereum) {
      window.ethereum.on('accountsChanged', (accounts) => {
        setAccount(accounts[0] || null)
      })
    }
    fetchTransactions()
  }, [fetchTransactions])

  return {
    account,
    isAdmin,
    transactions,
    flaggedIds,
    stats,
    loading,
    error,
    connect,
    fetchTransactions,
    submitTransaction,
    flagTransaction,
    clearTransaction,
    verifyKYC,
  }
}
