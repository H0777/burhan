import { useState, useEffect, useCallback } from 'react'
import {
  getProvider,
  getContractInstance,
  getSignedContract,
  connectWallet,
  formatAmount,
  parseAmount,
  shortAddress,
  ROLES,
  CONTRACT_ADDRESSES,
} from '../utils/contract'
import { isInstitutionalMode, assertChainIdMatchesConfig } from '../config/runtime'
import { apiV2Client } from '../api/client'

const ROLE_NAMES = ['NONE', 'SUPER_ADMIN', 'AUDITOR', 'OPERATOR', 'REGULATOR']

// Realistic initial demo transactions if chain is cold
const DEMO_TRANSACTIONS = [
  {
    id: 1,
    sender: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    receiver: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    amount: '4.5000',
    timestamp: Math.floor(Date.now() / 1000) - 7200,
    isFlagged: false,
    flagReason: '',
    status: 1, // CLEARED
    riskScore: 12.5,
    riskTier: 'LOW',
  },
  {
    id: 2,
    sender: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    receiver: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    amount: '9.8500',
    timestamp: Math.floor(Date.now() / 1000) - 3600,
    isFlagged: true,
    flagReason: 'Structuring Suspicion: Transfer approaching 10 ETH regulatory threshold (98.5%)',
    status: 2, // FLAGGED
    riskScore: 78.4,
    riskTier: 'HIGH',
  },
  {
    id: 3,
    sender: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    receiver: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
    amount: '18.2000',
    timestamp: Math.floor(Date.now() / 1000) - 1800,
    isFlagged: true,
    flagReason: 'Large Transaction Threshold Exceeded (>= 10 ETH) with unverified sender KYC',
    status: 3, // BLOCKED
    riskScore: 92.0,
    riskTier: 'CRITICAL',
  },
  {
    id: 4,
    sender: '0x976EA74026E726554dB657fA54763abd0C3a0aa9',
    receiver: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
    amount: '2.1000',
    timestamp: Math.floor(Date.now() / 1000) - 900,
    isFlagged: false,
    flagReason: '',
    status: 1, // CLEARED
    riskScore: 8.0,
    riskTier: 'LOW',
  },
  {
    id: 5,
    sender: '0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f',
    receiver: '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720',
    amount: '9.9000',
    timestamp: Math.floor(Date.now() / 1000) - 300,
    isFlagged: true,
    flagReason: 'Smurfing velocity: 3rd transfer near 10 ETH limit within 2 hours',
    status: 0, // PENDING
    riskScore: 84.5,
    riskTier: 'HIGH',
  },
]

// Realistic initial demo forensic trail entries
const DEMO_FORENSIC_TRAIL = [
  {
    index: 0,
    timestamp: Math.floor(Date.now() / 1000) - 86400,
    incidentType: 'GENESIS_CHAIN_INITIALIZED',
    operator: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    actor: '0x0000000000000000000000000000000000000000',
    evidenceHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
    previousEntryHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
    entryHash: '0x8f2d5e135b91a783427019cfef940df63a2333be1e433cb8e0724a7374b7c6c4',
  },
  {
    index: 1,
    timestamp: Math.floor(Date.now() / 1000) - 3600,
    incidentType: 'CRITICAL_TRANSACTION_ANOMALY',
    operator: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    actor: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    evidenceHash: '0x4f128e6c73b009e512497678d910a3014a8217bbcc4076356778f249c55d0458',
    previousEntryHash: '0x8f2d5e135b91a783427019cfef940df63a2333be1e433cb8e0724a7374b7c6c4',
    entryHash: '0x1c8b9394f4a34d2847c07b6f6f7d49e6f99b244799014b2b627cf99e5a1b3c99',
  },
  {
    index: 2,
    timestamp: Math.floor(Date.now() / 1000) - 1200,
    incidentType: 'INSIDER_EXCESSIVE_OVERRIDE_ALERT',
    operator: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    actor: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    evidenceHash: '0xa3712b84234c00e1591942478d10a2414a8217bbcc4076356778f249c55d0781',
    previousEntryHash: '0x1c8b9394f4a34d2847c07b6f6f7d49e6f99b244799014b2b627cf99e5a1b3c99',
    entryHash: '0x9924ac9341efcb909247c07b6f6f7d49e6f99b244799014b2b627cf99e5a1bfa2',
  },
]

export function useAuditEngine() {
  const [account, setAccount] = useState(null)
  const [userRole, setUserRole] = useState(isInstitutionalMode() ? 'NONE' : 'SUPER_ADMIN')
  const [isAdmin, setIsAdmin] = useState(!isInstitutionalMode())
  const [transactions, setTransactions] = useState(DEMO_TRANSACTIONS)
  const [forensicTrail, setForensicTrail] = useState(DEMO_FORENSIC_TRAIL)
  const [isChainValid, setIsChainValid] = useState(true)
  const [isCircuitBreakerPaused, setIsCircuitBreakerPaused] = useState(false)
  const [stats, setStats] = useState({
    total: DEMO_TRANSACTIONS.length,
    flagged: 3,
    cleared: 2,
    threshold: '10.0',
    dailyLimit: '50.0',
    totalAuditedVolume: '44.55 ETH',
    chainOfCustodyEntries: DEMO_FORENSIC_TRAIL.length,
    insiderIncidents: 1,
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [networkConnected, setNetworkConnected] = useState(false)
  // R13: config/identity/wallet gating — submit stays disabled while any of
  // them loads (no_getSigner_zero_fallback) and writes halt on account/chain change.
  const [walletReady, setWalletReady] = useState(false)
  const [bootstrapping, setBootstrapping] = useState(true)
  const [writesHalted, setWritesHalted] = useState(false)

  // Institutional writes require: config loaded (guaranteed by main.jsx gate),
  // an authenticated identity, a connected wallet on the configured chain, and
  // no account/chain-change halt. Demo keeps the historical local flow.
  const writesBlockedReason = (() => {
    if (bootstrapping) return 'config-or-wallet-loading'
    if (writesHalted) return 'account-or-chain-changed'
    if (isInstitutionalMode() && !networkConnected) return 'wallet-not-connected'
    if (isInstitutionalMode() && !walletReady) return 'wallet-not-ready'
    return null
  })()
  const canSubmit = writesBlockedReason === null

  // Fetch all contract state
  const fetchContractData = useCallback(async () => {
    try {
      const provider = getProvider()
      const auditEngine = getContractInstance('AuditEngine', provider)
      const trail = getContractInstance('ForensicTrail', provider)

      // Test connection with a lightweight call
      const totalTxs = await auditEngine.totalTransactions().catch(() => null)
      if (totalTxs === null) {
        // Fallback to local state
        setNetworkConnected(false)
        return
      }

      setNetworkConnected(true)
      const txIds = await auditEngine.getAllTransactionIds().catch(() => [])
      const flagged = await auditEngine.getFlaggedTransactions().catch(() => [])
      const threshold = await auditEngine.largeTransactionThreshold().catch(() => 10000000000000000000000n)
      const dailyLimit = await auditEngine.dailyVolumeLimit().catch(() => 50000000000000000000000n)
      const isPaused = await auditEngine.isPaused().catch(() => false)

      // 1. Attempt to fetch indexed transactions from V2 API (single indexed query)
      let parsedTxs = []
      try {
        const v2Resp = await apiV2Client.listTransactions({ limit: 50 })
        if (v2Resp && v2Resp.items && v2Resp.items.length > 0) {
          parsedTxs = v2Resp.items.map((tx) => ({
            id: tx.external_id || tx.id,
            sender: tx.sender_ref,
            receiver: tx.receiver_ref,
            amount:
              tx.currency === 'ETH'
                ? (Number(tx.amount_minor) / 1e18).toFixed(4)
                : (Number(tx.amount_minor) / Math.pow(10, tx.scale || 0)).toFixed(Math.min(tx.scale || 0, 4)),
            currency: tx.currency || 'IQD',
            source: tx.source || 'IQD_CSV',
            scale: tx.scale || 0,
            amount_minor: tx.amount_minor,
            timestamp: Math.floor(new Date(tx.occurred_at).getTime() / 1000),
            isFlagged: tx.status === 'FLAGGED' || (tx.risk_score && tx.risk_score >= 70),
            flagReason: tx.risk_score && tx.risk_score >= 70 ? 'High risk AML score flagged by engine' : '',
            status: tx.status === 'CLEARED' ? 1 : tx.status === 'FLAGGED' ? 2 : tx.status === 'BLOCKED' ? 3 : 0,
            riskScore: tx.risk_score || (tx.status === 'FLAGGED' ? 85.0 : 15.0),
            riskTier: tx.risk_score >= 80 ? 'CRITICAL' : tx.risk_score >= 60 ? 'HIGH' : tx.risk_score >= 30 ? 'MEDIUM' : 'LOW',
          }))
        }
      } catch (_e) {
        // Fallback to on-chain querying
      }

      // 2. Fallback to on-chain querying if V2 returned no indexed items
      if (parsedTxs.length === 0) {
        for (const id of txIds) {
          try {
            const tx = await auditEngine.getTransaction(id)
            parsedTxs.push({
              id: Number(tx.id),
              sender: tx.sender,
              receiver: tx.receiver,
              amount: formatAmount(tx.amount),
              currency: 'ETH',
              source: 'EVM',
              scale: 18,
              timestamp: Number(tx.timestamp),
              isFlagged: tx.isFlagged,
              flagReason: tx.flagReason,
              status: Number(tx.status),
              riskScore: tx.isFlagged ? 85.0 : 15.0,
              riskTier: tx.isFlagged ? 'HIGH' : 'LOW',
            })
          } catch (e) {
            console.warn('Error fetching tx', id, e)
          }
        }
      }

      setTransactions(parsedTxs.length ? parsedTxs : DEMO_TRANSACTIONS)
      setIsCircuitBreakerPaused(isPaused)

      // Forensic trail entries
      let entriesCount = 0
      const incidentIds = await trail.getAllIncidentIds().catch(() => [])
      if (incidentIds && incidentIds.length > 0) {
        const entries = []
        let allValid = true
        for (const incId of incidentIds) {
          try {
            const chain = await trail.getEvidenceChain(incId)
            for (const ev of chain) {
              entries.push({
                index: Number(ev.evidenceIndex),
                timestamp: Number(ev.timestamp),
                incidentType: ev.evidenceType,
                operator: ev.submittedBy,
                actor: ev.submittedBy,
                evidenceHash: ev.dataHash,
                previousEntryHash: ev.previousHash,
                entryHash: ev.entryHash,
              })
            }
            const valid = await trail.verifyChainIntegrity(incId).catch(() => true)
            if (!valid) allValid = false
          } catch (e) {
            console.warn('Error fetching evidence for incident', incId, e)
          }
        }
        if (entries.length > 0) {
          setForensicTrail(entries)
          setIsChainValid(allValid)
          entriesCount = entries.length
        }
      }

      // Stats
      const activeTxs = parsedTxs.length ? parsedTxs : DEMO_TRANSACTIONS
      const totalVolume = activeTxs.reduce((acc, t) => acc + parseFloat(t.amount || 0), 0)
      setStats({
        total: Number(totalTxs),
        flagged: flagged.length,
        cleared: activeTxs.filter((tx) => Number(tx.status) === 1).length,
        threshold: formatAmount(threshold),
        dailyLimit: formatAmount(dailyLimit),
        totalAuditedVolume: `${totalVolume.toFixed(2)} ETH`,
        chainOfCustodyEntries: entriesCount || DEMO_FORENSIC_TRAIL.length,
        insiderIncidents: incidentIds.length || 1,
      })
    } catch (err) {
      console.warn('Blockchain provider not accessible, operating with demo state:', err.message)
      setNetworkConnected(false)
    }
  }, [])

  // Connect wallet
  const connect = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const { address, provider: walletProvider } = await connectWallet()

      // R13: strict chain check — chainId must equal RuntimeConfig.chain_id
      // EXACTLY, even locally (wrong_chain_even_31337_rejected).
      const netProvider = walletProvider || getProvider()
      const network = await netProvider.getNetwork()
      await assertChainIdMatchesConfig(network)

      setAccount(address)

      const provider = getProvider()
      const roleManager = getContractInstance('RoleManager', provider)
      const rCode = await roleManager.getRole(address).catch(() => 0n)
      const rNum = Number(rCode)
      const roleName = ROLE_NAMES[rNum] || (isInstitutionalMode() ? 'NONE' : 'SUPER_ADMIN')

      setUserRole(roleName)
      setIsAdmin(roleName === 'SUPER_ADMIN')
      setWalletReady(true)
      setWritesHalted(false)
      await fetchContractData()
    } catch (err) {
      setError(err.message)
      if (isInstitutionalMode()) {
        setUserRole('NONE')
        setIsAdmin(false)
        setWalletReady(false)
      }
    } finally {
      setLoading(false)
    }
  }, [fetchContractData])

  // Submit transaction
  const submitTransaction = useCallback(async (receiver, amount) => {
    // R13 no_getSigner_zero_fallback: while config/identity/wallet load or a
    // halt is active, submit is refused outright — never a local fake write and
    // never an unlocked signer #0 fallback.
    if (!canSubmit) {
      const reason = `Submit disabled (${writesBlockedReason}) — connect an authorized institutional wallet.`
      setError(reason)
      return { success: false, blocked: true, reason }
    }

    try {
      setLoading(true)
      setError(null)

      if (networkConnected) {
        const contract = await getSignedContract('AuditEngine')
        const amountWei = parseAmount(amount)
        const tx = await contract.submitTransaction(receiver, amountWei)
        await tx.wait()
        await fetchContractData()
        return { success: true }
      }

      if (isInstitutionalMode()) {
        // Institutional offline = NO local state write (no simulated success).
        const reason = 'Institutional mode: chain unavailable — write refused (no local fallback).'
        setError(reason)
        return { success: false, blocked: true, reason }
      }

      // Demo-only local state update when offline
      const newTx = {
        id: transactions.length + 1,
        sender: account || '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        receiver,
        amount: parseFloat(amount).toFixed(4),
        timestamp: Math.floor(Date.now() / 1000),
        isFlagged: parseFloat(amount) >= 10.0,
        flagReason: parseFloat(amount) >= 10.0 ? 'Large transaction threshold exceeded (>= 10 ETH)' : '',
        status: parseFloat(amount) >= 10.0 ? 2 : 1,
        riskScore: parseFloat(amount) >= 10.0 ? 88.0 : 12.0,
        riskTier: parseFloat(amount) >= 10.0 ? 'HIGH' : 'LOW',
      }

      setTransactions(prev => [newTx, ...prev])
      setStats(prev => ({
        ...prev,
        total: prev.total + 1,
        flagged: newTx.isFlagged ? prev.flagged + 1 : prev.flagged,
        cleared: !newTx.isFlagged ? prev.cleared + 1 : prev.cleared,
      }))

      return { success: true }
    } catch (err) {
      setError(err.message)
      return { success: false, error: err.message }
    } finally {
      setLoading(false)
    }
  }, [account, canSubmit, writesBlockedReason, networkConnected, transactions.length, fetchContractData])

  // Flag / block transaction
  const flagTransaction = useCallback(async (txId, reason) => {
    try {
      setLoading(true)
      if (networkConnected) {
        const contract = await getSignedContract('AuditEngine')
        const tx = await contract.blockTransaction(txId)
        await tx.wait()
        await fetchContractData()
        return
      }

      setTransactions(prev => prev.map(t => t.id === txId ? { ...t, isFlagged: true, flagReason: reason, status: 3 } : t))
      setStats(prev => ({ ...prev, flagged: prev.flagged + 1 }))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [networkConnected, fetchContractData])

  // Clear transaction (override / approve)
  const clearTransaction = useCallback(async (txId) => {
    try {
      setLoading(true)
      if (networkConnected) {
        const contract = await getSignedContract('AuditEngine')
        const tx = await contract.overrideWarning(txId, 'Approved after enhanced forensic verification')
        await tx.wait()
        await fetchContractData()
        return
      }

      setTransactions(prev => prev.map(t => t.id === txId ? { ...t, isFlagged: false, status: 1 } : t))
      setStats(prev => ({ ...prev, cleared: prev.cleared + 1 }))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [networkConnected, fetchContractData])

  // Toggle circuit breaker
  const toggleCircuitBreaker = useCallback(async () => {
    try {
      setLoading(true)
      if (networkConnected) {
        const contract = await getSignedContract('AuditEngine')
        if (isCircuitBreakerPaused) {
          // unpause requires proposal or admin
          const tx = await contract.emergencyUnpause(0)
          await tx.wait()
        } else {
          const tx = await contract.emergencyPause('Emergency Circuit Breaker activated from Audit Console')
          await tx.wait()
        }
        await fetchContractData()
        return
      }

      setIsCircuitBreakerPaused(prev => !prev)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [networkConnected, isCircuitBreakerPaused, fetchContractData])

  // Initial load & wallet listener
  useEffect(() => {
    // R13: account_or_chain_change halts writes until the wallet is re-bound;
    // role resets to NONE in institutional mode (identity handled by AuthProvider).
    const handleAccountOrChainChange = () => {
      if (!isInstitutionalMode()) return
      setWalletReady(false)
      setWritesHalted(true)
      setUserRole('NONE')
      setIsAdmin(false)
      setError('Wallet account or chain changed — writes halted until the wallet is re-connected.')
    }

    const syncRole = async (addr) => {
      if (!addr) {
        setAccount(null)
        setWalletReady(false)
        setUserRole(isInstitutionalMode() ? 'NONE' : 'SUPER_ADMIN')
        setIsAdmin(!isInstitutionalMode())
        return
      }
      setAccount(addr)
      try {
        const provider = getProvider()
        const roleManager = getContractInstance('RoleManager', provider)
        const rCode = await roleManager.getRole(addr).catch(() => 0n)
        const rNum = Number(rCode)
        const roleName = ROLE_NAMES[rNum] || (isInstitutionalMode() ? 'NONE' : 'SUPER_ADMIN')
        setUserRole(roleName)
        setIsAdmin(roleName === 'SUPER_ADMIN')
      } catch {
        setUserRole(isInstitutionalMode() ? 'NONE' : 'SUPER_ADMIN')
        setIsAdmin(!isInstitutionalMode())
      }
    }

    if (window.ethereum) {
      const handleAccounts = (accounts) => {
        if (isInstitutionalMode()) {
          handleAccountOrChainChange()
        }
        syncRole(accounts[0] || null)
      }
      const handleChainChanged = () => {
        handleAccountOrChainChange()
        syncRole(window.ethereum?.selectedAddress || null)
      }
      window.ethereum.on('accountsChanged', handleAccounts)
      window.ethereum.on('chainChanged', handleChainChanged)
    }

    // Auto-connect to local node or unlocked signer
    connectWallet().then(res => {
      if (res && res.address) {
        syncRole(res.address)
      } else if (isInstitutionalMode()) {
        setUserRole('NONE')
        setIsAdmin(false)
      }
    }).catch(() => {
      if (isInstitutionalMode()) {
        setUserRole('NONE')
        setIsAdmin(false)
      }
    }).finally(() => {
      // Bootstrap finished: config+wallet loading state clears either way.
      setBootstrapping(false)
    })

    fetchContractData()
  }, [fetchContractData])

  // Inject transaction directly into state (for live stream & attack scenarios)
  const injectTransaction = useCallback((tx) => {
    setTransactions((prev) => [tx, ...prev])
    setStats((prev) => {
      const newTotal = prev.total + 1
      const isFlagged = tx.isFlagged || tx.status === 2 || tx.status === 3
      const newFlagged = isFlagged ? prev.flagged + 1 : prev.flagged
      const newCleared = tx.status === 1 ? prev.cleared + 1 : prev.cleared
      const newVolume = (parseFloat(prev.totalAuditedVolume || 0) + parseFloat(tx.amount || 0)).toFixed(2)
      return {
        ...prev,
        total: newTotal,
        flagged: newFlagged,
        cleared: newCleared,
        totalAuditedVolume: `${newVolume} ETH`,
      }
    })
  }, [])

  // Inject forensic entry
  const injectForensicEntry = useCallback((entry) => {
    setForensicTrail((prev) => [...prev, entry])
    setStats((prev) => ({
      ...prev,
      chainOfCustodyEntries: prev.chainOfCustodyEntries + 1,
      insiderIncidents: entry.incidentType.includes('INSIDER') ? prev.insiderIncidents + 1 : prev.insiderIncidents,
    }))
  }, [])

  // Reset to initial demo baseline
  const resetDemoState = useCallback(() => {
    setTransactions(DEMO_TRANSACTIONS)
    setForensicTrail(DEMO_FORENSIC_TRAIL)
    setIsChainValid(true)
    setIsCircuitBreakerPaused(false)
    setStats({
      total: DEMO_TRANSACTIONS.length,
      flagged: 3,
      cleared: 2,
      threshold: '10.0',
      dailyLimit: '50.0',
      totalAuditedVolume: '44.55 ETH',
      chainOfCustodyEntries: DEMO_FORENSIC_TRAIL.length,
      insiderIncidents: 1,
    })
  }, [])

  const importBankingCSV = useCallback(
    async (file, source = 'IQD_CSV') => {
      setLoading(true)
      setError(null)
      try {
        const resp = await apiV2Client.importTransactions(file, { source })
        await fetchContractData()
        return resp
      } catch (err) {
        setError(err.message || 'Failed to import banking CSV')
        throw err
      } finally {
        setLoading(false)
      }
    },
    [fetchContractData]
  )

  return {
    account,
    userRole,
    isAdmin,
    transactions,
    forensicTrail,
    isChainValid,
    isCircuitBreakerPaused,
    stats,
    loading,
    error,
    networkConnected,
    // R13 write gates
    canSubmit,
    writesBlockedReason,
    writesHalted,
    connect,
    fetchTransactions: fetchContractData,
    submitTransaction,
    flagTransaction,
    clearTransaction,
    toggleCircuitBreaker,
    injectTransaction,
    injectForensicEntry,
    resetDemoState,
    importBankingCSV,
  }
}
