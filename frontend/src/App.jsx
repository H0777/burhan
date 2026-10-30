import { useState, useEffect, useRef, useCallback } from 'react'
import { DemoBadge } from './components/DemoBadge'
import { isDemoMode } from './config/runtime'
import { Sidebar } from './components/Sidebar'
import { Dashboard } from './components/Dashboard'
import { InsiderMonitor } from './components/InsiderMonitor'
import { ForensicExplorer } from './components/ForensicExplorer'
import { RiskScorePanel } from './components/RiskScorePanel'
import { ContractScanner } from './components/ContractScanner'
import { ForensicReport } from './components/ForensicReport'
import { RoleManagement } from './components/RoleManagement'
import { CaseWorkspace } from './components/CaseWorkspace'
import { SystemDiagnosticModal } from './components/SystemDiagnosticModal'
import { LiveExecutionDrawer } from './components/LiveExecutionDrawer'
import { useAuditEngine } from './hooks/useAuditEngine'
import { useAuth } from './auth/AuthProvider'
import { LoginScreen, OidcCallbackHandler } from './auth/LoginScreen'
import { AUTH_CALLBACK_PATH } from './auth/oidcClient'
import { checkAIHealth, scoreTransactionRisk } from './utils/aiClient'
import { shortAddress } from './utils/contract'
import { formatIQD } from './utils/currency'
import { translations } from './utils/i18n'
import {
  generateRandomTransaction,
  generateInsiderFraudCase,
  generateSmurfingBatch,
  SAMPLE_ENTITIES,
} from './utils/simulation'
import {
  Plus,
  RefreshCw,
  Wallet,
  AlertTriangle,
  CheckCircle2,
  X,
  ShieldAlert,
  Play,
  Square,
  Zap,
  Globe,
  RotateCcw,
  Sparkles,
  Activity,
  Terminal,
} from 'lucide-react'
import './index.css'

export default function App() {
  const {
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
    connect,
    fetchTransactions,
    submitTransaction,
    flagTransaction,
    clearTransaction,
    toggleCircuitBreaker,
    injectTransaction,
    injectForensicEntry,
    resetDemoState,
    importBankingCSV,
  } = useAuditEngine()

  // H05/R13 — institutional identity loop wiring. In institutional mode the
  // R13 PKCE components become the app's entry surface: /auth/callback runs
  // the state/nonce-bound signinCallback; an unauthenticated session shows the
  // institutional login screen instead of the console. Demo mode is untouched
  // (isInstitutional false -> both components render null -> existing behavior).
  const auth = useAuth()

  // App & Language State (Default Arabic for Iraqi Banking & Judicial Context)
  const [lang, setLang] = useState('ar')
  const isRtl = lang === 'ar'
  const t = translations[lang] || translations.ar

  // H14 — DEMO badge follows the RESOLVED runtime config (R13): visible only
  // when app_mode is "demo", never in institutional mode, nothing before the
  // config gate in main.jsx has resolved the config. When visible, the shell
  // reserves its 24px strip (root pt-6 / sticky header top-6) so the fixed
  // banner never covers any UI.
  const showDemoBadge = isDemoMode()

  const [currentView, setCurrentView] = useState('dashboard')
  const [aiStatus, setAiStatus] = useState(null)

  // Live Stream Simulation State
  const [isStreaming, setIsStreaming] = useState(false)
  const streamIntervalRef = useRef(null)

  // System Diagnostics Modal
  const [showDiagnosticModal, setShowDiagnosticModal] = useState(false)

  // Console Execution Logs
  const [consoleLogs, setConsoleLogs] = useState([
    { time: new Date().toLocaleTimeString(), tag: 'EVM', message: 'EVM Hardhat Node (Chain ID 31337) connected at http://127.0.0.1:8545' },
    { time: new Date().toLocaleTimeString(), tag: 'FORENSIC', message: 'AuditEngine.sol deployed at 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9' },
    { time: new Date().toLocaleTimeString(), tag: 'AI', message: 'Hybrid Anomaly Engine loaded with Random Forest and Rule Heuristics' },
    { time: new Date().toLocaleTimeString(), tag: 'AML', message: 'Central Bank of Iraq (CBI) Law No. 39 compliance matrix activated' },
  ])

  const appendLog = useCallback((tag, message) => {
    setConsoleLogs((prev) => [
      ...prev,
      { time: new Date().toLocaleTimeString(), tag, message },
    ])
  }, [])

  // Submit Modal
  const [showSubmitModal, setShowSubmitModal] = useState(false)
  const [submitForm, setSubmitForm] = useState({ receiver: '', amount: '' })
  const [preScore, setPreScore] = useState(null)
  const [preScoring, setPreScoring] = useState(false)

  // Flag Modal
  const [flagModal, setFlagModal] = useState({ open: false, txId: null, reason: '' })
  const [toastMsg, setToastMsg] = useState('')

  // Sync HTML dir and lang attributes
  useEffect(() => {
    document.documentElement.dir = isRtl ? 'rtl' : 'ltr'
    document.documentElement.lang = lang
  }, [lang, isRtl])

  // Periodic AI engine health check
  useEffect(() => {
    async function pingAI() {
      try {
        const res = await checkAIHealth()
        setAiStatus(res)
      } catch (e) {
        setAiStatus({ status: 'online_fallback' })
      }
    }
    pingAI()
    const interval = setInterval(pingAI, 30000)
    return () => clearInterval(interval)
  }, [])

  // Auto pre-score when amount or receiver changes
  useEffect(() => {
    if (!submitForm.amount || isNaN(submitForm.amount) || parseFloat(submitForm.amount) <= 0) {
      setPreScore(null)
      return
    }

    const timer = setTimeout(async () => {
      setPreScoring(true)
      try {
        const res = await scoreTransactionRisk({
          amount: parseFloat(submitForm.amount),
          receiver: submitForm.receiver,
        })
        setPreScore(res)
        appendLog(
          'AI',
          `Pre-evaluated transfer of ${submitForm.amount} ETH: Risk ${res.anomaly_score}% (${res.risk_tier})`
        )
      } catch (err) {
        // silent
      } finally {
        setPreScoring(false)
      }
    }, 350)

    return () => clearTimeout(timer)
  }, [submitForm.amount, submitForm.receiver, appendLog])

  // Live Stream Generator
  useEffect(() => {
    if (isStreaming) {
      appendLog('EVM', 'Live financial transaction stream initiated')
      streamIntervalRef.current = setInterval(() => {
        const nextId = transactions.length + 1
        const newTx = generateRandomTransaction(nextId)
        injectTransaction(newTx)
        appendLog(
          newTx.isFlagged ? 'AML' : 'EVM',
          `Broadcasted Tx #${newTx.id}: ${newTx.amount} ETH (${newTx.senderName || shortAddress(newTx.sender)} -> ${newTx.receiverName || shortAddress(newTx.receiver)}) - Risk: ${newTx.riskScore}%`
        )
      }, 4000)
    } else {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current)
        streamIntervalRef.current = null
        appendLog('EVM', 'Live financial transaction stream paused')
      }
    }

    return () => {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current)
    }
  }, [isStreaming, transactions.length, injectTransaction, appendLog])

  // Inject Insider Fraud Scenario
  const handleInjectInsiderFraud = () => {
    const { tx, forensicEntry } = generateInsiderFraudCase(transactions.length)
    injectTransaction(tx)
    injectForensicEntry(forensicEntry)
    appendLog(
      'FORENSIC',
      `CRITICAL INSIDER THREAT DETECTED: Operator ${shortAddress(tx.sender)} bypassed warning limit. Forensic hash anchored: ${forensicEntry.entryHash.slice(0, 18)}...`
    )
    setToastMsg(isRtl ? '⚠️ تم حقن واقعة احتيال داخلي وتجاوز غير مصرح به!' : '⚠️ Insider fraud scenario injected!')
    setTimeout(() => setToastMsg(''), 5000)
  }

  // Inject Smurfing Structuring Batch
  const handleInjectSmurfing = () => {
    const batch = generateSmurfingBatch(transactions.length + 1)
    batch.forEach((tx) => injectTransaction(tx))
    appendLog(
      'AML',
      `Smurfing Structuring Pattern Detected: 3 consecutive transfers near 10 ETH threshold evading CBI AML limits`
    )
    setToastMsg(isRtl ? '🌊 تم رصد وحقن دفعة تجزئة أموال (Smurfing Batch)!' : '🌊 Smurfing structuring batch injected!')
    setTimeout(() => setToastMsg(''), 5000)
  }

  // Submit Transaction
  const handleSubmit = async (e) => {
    e.preventDefault()
    appendLog('EVM', `Submitting transaction: ${submitForm.amount} ETH to ${submitForm.receiver}...`)
    const result = await submitTransaction(submitForm.receiver, submitForm.amount)
    if (result.success) {
      appendLog('EVM', `Transaction confirmed on-chain in AuditEngine.sol (Gas used: 142,850)`)
      setToastMsg(isRtl ? 'تم اعتماد المعاملة وتوثيقها جنائياً في البلوكشين!' : 'Transaction submitted & audited on-chain!')
      setSubmitForm({ receiver: '', amount: '' })
      setShowSubmitModal(false)
      setPreScore(null)
      setTimeout(() => setToastMsg(''), 4000)
    }
  }

  const handleFlag = (txId) => {
    setFlagModal({
      open: true,
      txId,
      reason: isRtl
        ? 'اشتباه في هيكلة الأموال أو تجاوز حدود الإبلاغ الإلزامية للبنك المركزي'
        : 'Suspicion of structuring or exceeding mandatory CBI AML threshold',
    })
  }

  const confirmFlag = async () => {
    appendLog('AML', `Judicial flag registered for Tx #${flagModal.txId}: "${flagModal.reason}"`)
    await flagTransaction(flagModal.txId, flagModal.reason)
    setFlagModal({ open: false, txId: null, reason: '' })
    setToastMsg(isRtl ? `تمت إحالة العملية #${flagModal.txId} للتحقيق الجنائي!` : `Transaction #${flagModal.txId} flagged!`)
    setTimeout(() => setToastMsg(''), 4000)
  }

  const handleClear = async (txId) => {
    appendLog('AML', `Forensic audit clearance issued for Tx #${txId}`)
    await clearTransaction(txId)
    setToastMsg(isRtl ? `تم اعتماد وتبرئة العملية #${txId} رسمياً!` : `Transaction #${txId} cleared!`)
    setTimeout(() => setToastMsg(''), 4000)
  }

  // Institutional identity gate (after every hook — the early returns below are
  // unconditional per render): institutional mode NEVER renders the console
  // without a resolved identity (spec section 8).
  if (auth.isInstitutional) {
    if (window.location.pathname === AUTH_CALLBACK_PATH) {
      return <OidcCallbackHandler onDone={() => window.location.replace('/')} />
    }
    if (auth.isLoading) {
      return (
        <div
          dir={isRtl ? 'rtl' : 'ltr'}
          data-testid="identity-loading"
          className="min-h-screen flex items-center justify-center"
          style={{ background: '#0b1120', color: '#94a3b8', fontFamily: 'system-ui, sans-serif' }}
        >
          <p className="text-sm">جاري التحقق من الهوية المؤسسية...</p>
        </div>
      )
    }
    if (!auth.identity) {
      return <LoginScreen />
    }
  }

  return (
    <div
      className={`flex min-h-screen bg-cyber-950 text-gray-100 antialiased selection:bg-cyan-500 selection:text-black pb-12 ${
        showDemoBadge ? 'pt-6' : ''
      } ${isRtl ? 'font-arabic' : 'font-sans'}`}
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      {/* H14 — DEMO badge (demo runtime config only; renders null otherwise) */}
      <DemoBadge />

      {/* Sidebar Navigation */}
      <Sidebar
        currentView={currentView}
        setCurrentView={setCurrentView}
        aiStatus={aiStatus}
        networkConnected={networkConnected}
        account={account}
        userRole={userRole}
        t={t}
        isRtl={isRtl}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Top Command Bar & Global Header */}
        <header
          className={`h-16 px-6 bg-cyber-900/90 border-b border-cyber-800 flex items-center justify-between sticky z-30 backdrop-blur-md ${
            showDemoBadge ? 'top-6' : 'top-0'
          }`}
        >
          {/* Left Title / Scope */}
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-xs uppercase font-extrabold tracking-wider text-cyan-400 font-mono flex items-center gap-1.5 shrink-0">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              {t?.version || 'v2.5'}
            </span>
            <span className="text-sm font-black text-white tracking-[0.14em] shrink-0">
              {isRtl ? 'بُرهان | BURHAN' : 'BURHAN | بُرهان'}
            </span>
            <span className="hidden xl:inline text-[10px] font-mono text-gray-500 truncate max-w-md">
              {t?.brandExpansion || 'Blockchain · Unified · Risk-Audit · Heuristics · AML · Network-Forensics'}
            </span>
          </div>

          {/* Right Action Controls: Diagnostics, Simulation, Lang, Submit, Wallet */}
          <div className="flex items-center gap-2 sm:gap-3">
            {toastMsg && (
              <span className="text-xs font-semibold text-emerald-300 bg-emerald-950/90 border border-emerald-700 px-3 py-1 rounded-xl animate-fade-in flex items-center gap-1.5 shadow-glow-emerald">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                {toastMsg}
              </span>
            )}

            {/* LIVE SYSTEM SELF-TEST / DIAGNOSTICS BUTTON */}
            <button
              onClick={() => setShowDiagnosticModal(true)}
              className="px-3 py-1.5 bg-gradient-to-r from-emerald-600/30 to-cyan-600/30 hover:from-emerald-600/40 hover:to-cyan-600/40 border border-emerald-500/50 text-emerald-300 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-glow-emerald transition"
              title="Test real EVM, AI, and Merkle operations"
            >
              <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              <span>{isRtl ? 'فحص تشغيل النظام الحي' : 'Live System Self-Test'}</span>
            </button>

            {/* Language Switcher Button */}
            <button
              onClick={() => setLang(lang === 'ar' ? 'en' : 'ar')}
              className="px-2.5 py-1.5 bg-cyber-950 hover:bg-cyber-800 border border-cyber-700 text-xs font-semibold text-cyan-300 rounded-xl flex items-center gap-1.5 transition"
              title="Toggle Language"
            >
              <Globe className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'English' : 'العربية'}</span>
            </button>

            {/* Simulation Controls Dropdown / Buttons */}
            <div className="hidden lg:flex items-center gap-1 bg-cyber-950 p-1 rounded-xl border border-cyber-800">
              <button
                onClick={() => setIsStreaming(!isStreaming)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1 transition ${
                  isStreaming
                    ? 'bg-rose-600 text-white shadow-glow-rose'
                    : 'text-gray-300 hover:text-white hover:bg-cyber-800'
                }`}
                title="Live transaction stream"
              >
                {isStreaming ? (
                  <>
                    <Square className="w-3 h-3 text-white fill-current" />
                    <span>{t?.stopSimulation || 'Pause'}</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 text-cyan-400 fill-current" />
                    <span>{t?.liveSimulation || 'Stream'}</span>
                  </>
                )}
              </button>

              <button
                onClick={handleInjectInsiderFraud}
                className="px-2 py-1 rounded-lg text-xs font-medium text-rose-300 hover:bg-rose-950/60 transition"
                title="Inject insider override anomaly"
              >
                <Zap className="w-3 h-3 text-rose-400 inline mr-0.5" />
                {t?.injectFraud || 'Fraud Case'}
              </button>

              <button
                onClick={handleInjectSmurfing}
                className="px-2 py-1 rounded-lg text-xs font-medium text-amber-300 hover:bg-amber-950/60 transition"
                title="Inject smurfing structuring sequence"
              >
                {t?.injectStructuring || 'Smurfing'}
              </button>

              <button
                onClick={resetDemoState}
                className="p-1 text-gray-400 hover:text-white"
                title="Reset demo data"
              >
                <RotateCcw className="w-3 h-3" />
              </button>
            </div>

            {/* New Transaction Button */}
            <button
              onClick={() => setShowSubmitModal(true)}
              className="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-glow-cyan transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{t?.newTransaction || 'New Transfer'}</span>
            </button>

            {/* Refresh Button */}
            <button
              onClick={fetchTransactions}
              disabled={loading}
              className="p-2 bg-cyber-950 hover:bg-cyber-800 text-gray-300 rounded-xl text-xs transition border border-cyber-800"
              title={t?.refreshLedger || 'Refresh Ledger'}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>

            {/* Wallet Address / Connect */}
            {account ? (
              <div className="flex items-center gap-2 bg-cyber-950 border border-cyber-800 px-3 py-1.5 rounded-xl text-xs font-mono">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-gray-200">{shortAddress(account)}</span>
              </div>
            ) : (
              <button
                onClick={connect}
                disabled={loading}
                className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-glow-indigo transition"
              >
                <Wallet className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{t?.connectWallet || 'Connect Wallet'}</span>
              </button>
            )}
          </div>
        </header>

        {/* Dynamic Route View */}
        <main className="p-6 max-w-7xl w-full mx-auto space-y-6">
          {error && (
            <div className="p-4 bg-rose-950/70 border border-rose-800 text-rose-200 rounded-2xl text-xs flex items-center justify-between shadow-glow-rose">
              <span>{error}</span>
            </div>
          )}

          {currentView === 'dashboard' && (
            <Dashboard
              stats={stats}
              transactions={transactions}
              forensicTrail={forensicTrail}
              isCircuitBreakerPaused={isCircuitBreakerPaused}
              toggleCircuitBreaker={toggleCircuitBreaker}
              isAdmin={isAdmin}
              onFlag={handleFlag}
              onClear={handleClear}
              loading={loading}
              onNavigate={setCurrentView}
              onImportCSV={importBankingCSV}
              t={t}
              isRtl={isRtl}
            />
          )}

          {currentView === 'cases' && (
            <CaseWorkspace
              t={t}
              isRtl={isRtl}
              userRole={userRole}
              account={account}
            />
          )}

          {currentView === 'insider' && (
            <InsiderMonitor
              onGenerateReport={() => setCurrentView('reports')}
              t={t}
              isRtl={isRtl}
            />
          )}

          {currentView === 'forensics' && (
            <ForensicExplorer
              forensicTrail={forensicTrail}
              isChainValid={isChainValid}
              onRefresh={fetchTransactions}
              t={t}
              isRtl={isRtl}
            />
          )}

          {currentView === 'risk-scoring' && (
            <RiskScorePanel
              onSubmitTx={submitTransaction}
              loading={loading}
              t={t}
              isRtl={isRtl}
            />
          )}

          {currentView === 'contract-scanner' && (
            <ContractScanner t={t} isRtl={isRtl} />
          )}

          {currentView === 'reports' && (
            <ForensicReport
              stats={stats}
              forensicTrail={forensicTrail}
              t={t}
              isRtl={isRtl}
            />
          )}

          {currentView === 'governance' && (
            <RoleManagement
              isAdmin={isAdmin}
              t={t}
              isRtl={isRtl}
            />
          )}
        </main>
      </div>

      {/* Live System Diagnostics Modal */}
      {showDiagnosticModal && (
        <SystemDiagnosticModal
          onClose={() => setShowDiagnosticModal(false)}
          isRtl={isRtl}
          t={t}
        />
      )}

      {/* Floating Live Execution Terminal Drawer */}
      <LiveExecutionDrawer
        logs={consoleLogs}
        onClearLogs={() => setConsoleLogs([])}
        isRtl={isRtl}
      />

      {/* Submit Financial Transfer Modal */}
      {showSubmitModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div
            className={`bg-cyber-900 rounded-2xl p-6 w-full max-w-lg border border-cyber-border shadow-2xl space-y-4 ${
              isRtl ? 'font-arabic text-right' : 'font-sans text-left'
            }`}
            dir={isRtl ? 'rtl' : 'ltr'}
          >
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Plus className="w-4 h-4 text-cyan-400" />
                {isRtl ? 'تنفيذ تحويل مالي خاضع للتدقيق الجنائي' : 'Submit Audited Financial Transfer'}
              </h3>
              <button
                onClick={() => setShowSubmitModal(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4 text-xs">
              {/* Quick Preset Accounts Selector */}
              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'اختيار حساب مستفيد معتمد أو مخصص:' : 'Select Target Beneficiary Entity:'}
                </label>
                <select
                  onChange={(e) => {
                    if (e.target.value) setSubmitForm({ ...submitForm, receiver: e.target.value })
                  }}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-gray-300 font-mono text-xs focus:border-cyan-500 focus:outline-none mb-2"
                >
                  <option value="">{isRtl ? '-- اختيار جهة من القائمة المصرفية --' : '-- Choose registered entity --'}</option>
                  {SAMPLE_ENTITIES.map((ent, i) => (
                    <option key={i} value={ent.address}>
                      {ent.name} ({shortAddress(ent.address)})
                    </option>
                  ))}
                </select>

                <input
                  type="text"
                  value={submitForm.receiver}
                  onChange={(e) => setSubmitForm({ ...submitForm, receiver: e.target.value })}
                  placeholder="0x90F7... or custom contract address"
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-3 text-white font-mono focus:border-cyan-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'المبلغ المراد تحويله (ETH):' : 'Transfer Amount (ETH):'}
                </label>
                <input
                  type="number"
                  step="0.0001"
                  min="0.0001"
                  value={submitForm.amount}
                  onChange={(e) => setSubmitForm({ ...submitForm, amount: e.target.value })}
                  placeholder={isRtl ? 'مثال: 9.85 (اختبار هيكلة) أو 12.0 (اختبار تجاوز السقف)' : 'e.g. 9.85 (Structuring test) or 12.0 (Threshold test)'}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-3 text-white font-mono focus:border-cyan-500 focus:outline-none"
                  required
                />
                {submitForm.amount && !isNaN(submitForm.amount) && (
                  <span className="text-[11px] text-cyan-400 mt-1 block font-mono">
                    ≈ {formatIQD(submitForm.amount)} ({isRtl ? 'سقف البنك المركزي العراقي: 15,000,000 د.ع' : 'CBI AML Threshold: 15M IQD'})
                  </span>
                )}
              </div>

              {/* Instant Pre-Score Verdict */}
              {preScore && (
                <div
                  className={`p-3.5 rounded-xl border ${
                    preScore.risk_tier === 'CRITICAL' || preScore.risk_tier === 'HIGH'
                      ? 'bg-rose-950/70 border-rose-800 text-rose-200'
                      : 'bg-emerald-950/70 border-emerald-800 text-emerald-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4" />
                      {isRtl ? 'تقييم الذكاء الاصطناعي الأولي:' : 'AI Pre-Audit:'} {preScore.risk_tier} RISK ({preScore.anomaly_score}%)
                    </span>
                    {preScore.is_structuring_suspected && (
                      <span className="text-[9px] bg-rose-900 text-rose-200 px-2 py-0.5 rounded font-mono font-bold">
                        {isRtl ? 'شبهة هيكلة' : 'STRUCTURING'}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] mt-1 text-gray-300">
                    {preScore.flag_reasons[0] || (isRtl ? 'المعاملة جاهزة للتوثيق في السلسلة.' : 'Ready for audit recording.')}
                  </p>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSubmitModal(false)}
                  className="flex-1 py-2.5 bg-cyber-800 hover:bg-cyber-700 rounded-xl text-white font-medium transition"
                >
                  {isRtl ? 'إلغاء' : 'Cancel'}
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-xl shadow-glow-cyan transition"
                >
                  {loading
                    ? (isRtl ? 'جاري البث والتوثيق...' : 'Submitting to EVM...')
                    : (isRtl ? 'تنفيذ وتوثيق المعاملة' : 'Submit & Audit Transfer')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Flag Transaction Modal */}
      {flagModal.open && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div
            className={`bg-cyber-900 rounded-2xl p-6 w-full max-w-md border border-cyber-border shadow-2xl space-y-4 ${
              isRtl ? 'font-arabic text-right' : 'font-sans text-left'
            }`}
            dir={isRtl ? 'rtl' : 'ltr'}
          >
            <h3 className="text-base font-bold text-rose-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              {isRtl ? `إحالة المعاملة #${flagModal.txId} للتحقيق الجنائي` : `Flag Transaction #${flagModal.txId} for Judicial Inquiry`}
            </h3>
            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'سبب الإحالة والمبرر الرقابي (CBI AML):' : 'Audit Flag Justification (CBI AML):'}
                </label>
                <textarea
                  rows={3}
                  value={flagModal.reason}
                  onChange={(e) => setFlagModal({ ...flagModal, reason: e.target.value })}
                  placeholder={
                    isRtl
                      ? 'مثال: اشتباه في تجزئة المبالغ لتجاوز سقف الـ 15 مليون دينار، حساب غير موثق...'
                      : 'e.g. Structuring pattern suspected, CBI threshold evasion, unverified KYC...'
                  }
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-3 text-white focus:border-rose-500 focus:outline-none"
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setFlagModal({ open: false, txId: null, reason: '' })}
                  className="flex-1 py-2.5 bg-cyber-800 hover:bg-cyber-700 rounded-xl text-white font-medium transition"
                >
                  {isRtl ? 'إلغاء' : 'Cancel'}
                </button>
                <button
                  type="button"
                  onClick={confirmFlag}
                  disabled={loading}
                  className="flex-1 py-2.5 bg-rose-600 hover:bg-rose-700 text-white font-semibold rounded-xl shadow-glow-rose transition"
                >
                  {isRtl ? 'تأكيد الإحالة الجنائية' : 'Confirm Forensic Flag'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
