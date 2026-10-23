import React, { useState } from 'react'
import {
  ShieldCheck,
  AlertTriangle,
  FileCheck2,
  Lock,
  Unlock,
  TrendingUp,
  AlertOctagon,
  ArrowUpRight,
  ExternalLink,
  Zap,
  Search,
  Filter,
  Download,
  FileSpreadsheet,
  FileJson,
  Layers,
  Activity,
  Users,
  Eye,
  Upload,
  CheckCircle2,
} from 'lucide-react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from 'recharts'
import { shortAddress, formatTimestamp } from '../utils/contract'
import { formatIQD, formatUSD } from '../utils/currency'
import { exportTransactionsCSV, exportTransactionsJSON } from '../utils/simulation'
import { TransactionInspectorModal } from './TransactionInspectorModal'

const STATUS_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#f43f5e']

const RISK_TIER_STYLES = {
  LOW: 'bg-emerald-950 text-emerald-400 border-emerald-800/80',
  MEDIUM: 'bg-cyan-950 text-cyan-400 border-cyan-800/80',
  HIGH: 'bg-amber-950 text-amber-400 border-amber-800/80',
  CRITICAL: 'bg-rose-950 text-rose-400 border-rose-800/80',
}

export function Dashboard({
  stats,
  transactions,
  forensicTrail,
  isCircuitBreakerPaused,
  toggleCircuitBreaker,
  isAdmin,
  onFlag,
  onClear,
  loading,
  onNavigate,
  onImportCSV,
  t,
  isRtl,
}) {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [selectedTxForInspect, setSelectedTxForInspect] = useState(null)
  const [isImporting, setIsImporting] = useState(false)
  const [importStatus, setImportStatus] = useState(null)
  const [importError, setImportError] = useState(null)

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setIsImporting(true)
    setImportError(null)
    setImportStatus(null)
    try {
      if (onImportCSV) {
        const resp = await onImportCSV(file)
        setImportStatus(
          isRtl
            ? `اكتمل استيراد ${resp.accepted_rows} معاملة بنجاح (المرفوض: ${resp.rejected_rows})`
            : `Successfully imported ${resp.accepted_rows} transactions (Rejected: ${resp.rejected_rows})`
        )
      }
    } catch (err) {
      setImportError(err.message || 'Import failed')
    } finally {
      setIsImporting(false)
      e.target.value = ''
    }
  }

  // Status breakdown for Pie Chart
  const statusLabels = [
    t?.statusPending || 'Pending',
    t?.statusCleared || 'Cleared',
    t?.statusFlagged || 'Flagged',
    t?.statusBlocked || 'Blocked',
  ]

  const statusData = statusLabels.map((label, i) => ({
    name: label,
    value: transactions.filter((tx) => tx.status === i).length,
    color: STATUS_COLORS[i],
  }))

  // Volume vs Risk Trend Data
  const volumeTrend = transactions.slice(-10).map((tx) => ({
    name: `#${tx.id}`,
    amount: parseFloat(tx.amount || 0),
    risk: tx.riskScore || (tx.isFlagged ? 85 : 12),
  }))

  // Department Distribution Data
  const departmentData = [
    { name: isRtl ? 'الخزينة المركزية (بغداد)' : 'Baghdad Treasury', volume: 68, risk: 89 },
    { name: isRtl ? 'فرع البصرة التجاري' : 'Basra Trade Hub', volume: 42, risk: 16 },
    { name: isRtl ? 'مركز أربيل الإقليمي' : 'Erbil Regional Hub', volume: 35, risk: 68 },
    { name: isRtl ? 'المقاصة الإلكترونية' : 'ACH Core Settlement', volume: 55, risk: 34 },
  ]

  // Filtered transactions
  const filteredTxs = [...transactions].reverse().filter((tx) => {
    const matchesSearch =
      tx.id.toString().includes(searchTerm) ||
      tx.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tx.receiver.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (tx.flagReason && tx.flagReason.toLowerCase().includes(searchTerm.toLowerCase()))

    const matchesStatus =
      statusFilter === 'ALL' || tx.status.toString() === statusFilter

    const matchesRisk =
      riskFilter === 'ALL' || (tx.riskTier || 'LOW') === riskFilter

    return matchesSearch && matchesStatus && matchesRisk
  })

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner: Emergency Circuit Breaker Alert if active */}
      {isCircuitBreakerPaused && (
        <div className="bg-rose-950/80 border border-rose-700/80 rounded-2xl p-4 flex items-center justify-between shadow-glow-rose">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-600/30 border border-rose-500 flex items-center justify-center">
              <AlertOctagon className="w-6 h-6 text-rose-400 animate-pulse" />
            </div>
            <div>
              <h4 className="text-rose-200 font-bold text-sm tracking-wide">
                {t?.circuitBreakerActive || 'CIRCUIT BREAKER ENGAGED — SYSTEM PAUSED'}
              </h4>
              <p className="text-xs text-rose-300/80">
                {t?.circuitBreakerDesc || 'All blockchain transfer executions are halted. Unpausing requires Four-Eyes MultiSig approval.'}
              </p>
            </div>
          </div>
          {isAdmin && (
            <button
              onClick={toggleCircuitBreaker}
              disabled={loading}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-semibold rounded-xl text-xs transition flex items-center gap-1.5 shadow"
            >
              <Unlock className="w-3.5 h-3.5" />
              {t?.requestUnpause || 'Request MultiSig Unpause'}
            </button>
          )}
        </div>
      )}

      {/* Live Telemetry Ticker */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-cyber-950/80 border border-cyber-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] text-gray-400 block font-medium">
              {isRtl ? 'سعر صرف الإيثيريوم المعتمد' : 'ETH/IQD Official Rate'}
            </span>
            <span className="text-xs font-mono font-bold text-cyan-400">
              1 ETH ≈ 3,960,000 د.ع
            </span>
          </div>
          <span className="text-[10px] font-mono text-gray-500">$3,000 USD</span>
        </div>

        <div className="p-3 bg-cyber-950/80 border border-cyber-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] text-gray-400 block font-medium">
              {isRtl ? 'سقف الإبلاغ الإلزامي (CBI)' : 'Mandatory AML Threshold'}
            </span>
            <span className="text-xs font-mono font-bold text-amber-400">
              15,000,000 د.ع
            </span>
          </div>
          <span className="text-[10px] font-mono text-gray-500">~3.79 ETH</span>
        </div>

        <div className="p-3 bg-cyber-950/80 border border-cyber-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] text-gray-400 block font-medium">
              {isRtl ? 'ارتفاع الكتلة الحالية' : 'Current Block Height'}
            </span>
            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              #1,492,084
            </span>
          </div>
          <span className="text-[10px] font-mono text-gray-500">18.4 Gwei</span>
        </div>

        <div className="p-3 bg-cyber-950/80 border border-cyber-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] text-gray-400 block font-medium">
              {isRtl ? 'مستوى التأهب السيبراني' : 'DEFCON Threat Level'}
            </span>
            <span className="text-xs font-mono font-bold text-rose-400">
              DEFCON 2 (ELEVATED)
            </span>
          </div>
          <span className="text-[10px] bg-rose-950 text-rose-300 px-1.5 py-0.5 rounded font-mono font-bold">
            ACTIVE
          </span>
        </div>
      </div>

      {/* Header Summary & Circuit Breaker Switch */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              {t?.navDashboard || 'Executive Cyber-Auditing Overview'}
            </h2>
            <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              {t?.cbiCompliant || 'CBI Law No. 39 Compliant'}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {isRtl
              ? 'مراقبة فورية للتهديدات الداخلية، خوارزميات كشف الشذوذ، وسلسلة الحيازة الجنائية غير القابلة للإنكار.'
              : 'Real-time insider threat telemetry, behavioral anomaly scoring, and cryptographic chain of custody.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('risk-scoring')}
            className="px-3.5 py-2 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-cyan-300 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            {isRtl ? 'اختبار مخاطر الذكاء الاصطناعي' : 'Run AI Risk Test'}
          </button>
          {isAdmin && (
            <button
              onClick={toggleCircuitBreaker}
              disabled={loading}
              className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition border ${
                isCircuitBreakerPaused
                  ? 'bg-amber-600/20 text-amber-300 border-amber-600/50 hover:bg-amber-600/30'
                  : 'bg-rose-600/20 text-rose-300 border-rose-600/50 hover:bg-rose-600/30'
              }`}
            >
              {isCircuitBreakerPaused ? (
                <>
                  <Unlock className="w-3.5 h-3.5 text-amber-400" />
                  {t?.requestUnpause || 'MultiSig Resume'}
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5 text-rose-400" />
                  {t?.emergencyHalt || 'Emergency Halt'}
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards Row (4 Cards) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title={t?.totalAuditedVolume || 'Total Audited Volume'}
          value={stats.totalAuditedVolume || '44.55 ETH'}
          subtitle={`≈ ${formatIQD(parseFloat(stats.totalAuditedVolume || 44.55))} | ${stats.total || 0} Txs`}
          icon={TrendingUp}
          color="blue"
        />
        <KpiCard
          title={t?.anomaliesDetected || 'Anomalies & Structuring'}
          value={stats.flagged || 0}
          subtitle={isRtl ? 'إنذارات غسل الأموال والهيكلة' : 'AML & Structuring Flags'}
          icon={AlertTriangle}
          color="amber"
          badge="AI Flagged"
          onClick={() => onNavigate('risk-scoring')}
        />
        <KpiCard
          title={t?.insiderIncidents || 'Insider Threat Alerts'}
          value={stats.insiderIncidents || 1}
          subtitle={isRtl ? 'تجاوزات المشغلين المسجلة' : 'Behavioral Overrides Logged'}
          icon={AlertOctagon}
          color="rose"
          badge="High Priority"
          onClick={() => onNavigate('insider')}
        />
        <KpiCard
          title={t?.chainHealth || 'Chain of Custody Health'}
          value={stats.chainOfCustodyEntries || forensicTrail?.length || 3}
          subtitle={isRtl ? 'أدلة قضائية معتمدة ومحكمة' : 'Court-Admissible SHA-256 Entries'}
          icon={FileCheck2}
          color="emerald"
          badge="100% Intact"
          onClick={() => onNavigate('forensics')}
        />
      </div>

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Status Disposition Pie Chart (4 cols) */}
        <div className="lg:col-span-4 cyber-card rounded-2xl p-5 shadow-xl">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyber-800">
            <h3 className="text-white text-sm font-semibold">
              {t?.chartDisposition || 'Regulatory Disposition Breakdown'}
            </h3>
            <span className="text-[11px] text-gray-400 font-mono">EVM State</span>
          </div>

          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {statusData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#090e1c',
                    borderColor: '#1e2c4f',
                    borderRadius: '12px',
                    color: '#ffffff',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-cyber-800 text-xs">
            {statusData.map((s, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-gray-400">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.color }}></span>
                  {s.name}
                </span>
                <span className="font-mono font-semibold text-gray-200">{s.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Transaction Volume vs Anomaly Trend (8 cols) */}
        <div className="lg:col-span-8 cyber-card rounded-2xl p-5 shadow-xl">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyber-800">
            <div>
              <h3 className="text-white text-sm font-semibold">
                {t?.chartVolumeRisk || 'Volume vs. AI Anomaly Risk Score'}
              </h3>
              <p className="text-[11px] text-gray-400">
                {isRtl ? 'الارتباط بين حجم التحويل ومؤشر الشذوذ السلوكي' : 'Correlation between transfer magnitude and forensic risk score'}
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-2 h-2 rounded bg-cyan-500"></span> Volume (ETH)
              </span>
              <span className="flex items-center gap-1 text-rose-400">
                <span className="w-2 h-2 rounded bg-rose-500"></span> Risk Score
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={volumeTrend}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#090e1c',
                    borderColor: '#1e2c4f',
                    borderRadius: '12px',
                    color: '#ffffff',
                  }}
                />
                <Bar dataKey="amount" fill="#06b6d4" radius={[6, 6, 0, 0]} name="Volume (ETH)" />
                <Bar dataKey="risk" fill="#f43f5e" radius={[6, 6, 0, 0]} name="Risk Score (/100)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Real-Time Audited Transactions Ledger */}
      <div className="cyber-card rounded-2xl overflow-hidden shadow-xl">
        <div className="px-5 py-4 border-b border-cyber-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-cyber-950/60">
          <div>
            <h3 className="text-white font-semibold text-sm flex items-center gap-2">
              {t?.ledgerTitle || 'Audited Transactions Ledger'}
              <span className="text-[10px] bg-emerald-900/60 text-emerald-300 border border-emerald-700 px-2.5 py-0.5 rounded-full font-mono">
                {t?.courtAdmissible || 'Cryptographically Linked'}
              </span>
            </h3>
            <p className="text-xs text-gray-400">
              {t?.ledgerSubtitle || 'Continuous AML evaluation & insider override tracking'}
            </p>
          </div>

          {/* Search, Filters, and Export Buttons */}
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 sm:w-56">
              <Search className={`w-3.5 h-3.5 text-gray-400 absolute top-3 ${isRtl ? 'left-3' : 'right-3'}`} />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={t?.searchPlaceholder || 'Search address, ID...'}
                className="w-full bg-cyber-900 border border-cyber-800 rounded-xl px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-800 text-xs text-gray-300 rounded-xl px-2.5 py-1.5 focus:outline-none"
            >
              <option value="ALL">{isRtl ? 'كافة الحالات' : 'All Status'}</option>
              <option value="1">{t?.statusCleared || 'Cleared'}</option>
              <option value="2">{t?.statusFlagged || 'Flagged'}</option>
              <option value="3">{t?.statusBlocked || 'Blocked'}</option>
              <option value="0">{t?.statusPending || 'Pending'}</option>
            </select>

            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-800 text-xs text-gray-300 rounded-xl px-2.5 py-1.5 focus:outline-none"
            >
              <option value="ALL">{isRtl ? 'كافة المخاطر' : 'All Risk'}</option>
              <option value="CRITICAL">{t?.riskCritical || 'Critical'}</option>
              <option value="HIGH">{t?.riskHigh || 'High'}</option>
              <option value="MEDIUM">{t?.riskMedium || 'Medium'}</option>
              <option value="LOW">{t?.riskLow || 'Low'}</option>
            </select>

            <label
              className="p-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 hover:text-white transition cursor-pointer flex items-center gap-1 text-xs font-semibold"
              title={isRtl ? 'استيراد معاملات مصرفية (CSV)' : 'Import Banking CSV'}
            >
              <Upload className="w-4 h-4 text-cyan-400" />
              <span className="hidden sm:inline">{isRtl ? 'استيراد CSV' : 'Import CSV'}</span>
              <input
                type="file"
                accept=".csv"
                onChange={handleFileChange}
                disabled={isImporting}
                className="hidden"
              />
            </label>

            <button
              onClick={() => exportTransactionsCSV(transactions)}
              className="p-1.5 rounded-lg bg-cyber-900 hover:bg-cyber-800 text-gray-300 border border-cyber-800 hover:text-white transition"
              title="Export CSV"
            >
              <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            </button>
            <button
              onClick={() => exportTransactionsJSON(transactions)}
              className="p-1.5 rounded-lg bg-cyber-900 hover:bg-cyber-800 text-gray-300 border border-cyber-800 hover:text-white transition"
              title="Export JSON"
            >
              <FileJson className="w-4 h-4 text-cyan-400" />
            </button>
          </div>
        </div>

        {/* Source Verification Institutional Legal Banner */}
        <div className="px-5 py-2.5 bg-blue-950/40 border-b border-cyber-800 flex items-center gap-2 text-[11px] text-blue-300">
          <AlertTriangle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span>
            {isRtl
              ? 'تنويه إثبات المصدر: المصدر المصرفي (IQD_CSV) يثبت ورود سجل فقط، ولا يثبت تسوية نقدية أو دقة إدخال العميل.'
              : 'Source Verification Notice: Banking connector source proves record ingress only; does not establish cash settlement or customer entry veracity.'}
          </span>
        </div>

        {/* Import Status Alert */}
        {importStatus && (
          <div className="px-5 py-2 bg-emerald-950/60 border-b border-emerald-800 flex items-center gap-2 text-xs text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>{importStatus}</span>
          </div>
        )}
        {importError && (
          <div className="px-5 py-2 bg-rose-950/60 border-b border-rose-800 flex items-center gap-2 text-xs text-rose-300">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
            <span>{importError}</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="text-gray-400 uppercase bg-cyber-950 border-b border-cyber-800 text-[10px]">
                <th className="px-4 py-3">{t?.colTxId || 'Tx ID'}</th>
                <th className="px-4 py-3">{isRtl ? 'المصدر والعملة' : 'Source & Asset'}</th>
                <th className="px-4 py-3">{t?.colSender || 'Originator'}</th>
                <th className="px-4 py-3">{t?.colReceiver || 'Beneficiary'}</th>
                <th className="px-4 py-3 text-right">{t?.colAmount || 'Amount'}</th>
                <th className="px-4 py-3 text-center">{t?.colRiskTier || 'AI Risk Score'}</th>
                <th className="px-4 py-3 text-center">{t?.colStatus || 'Status'}</th>
                <th className="px-4 py-3">{t?.colFlags || 'Audit Notes & Flags'}</th>
                <th className="px-4 py-3 text-right">{t?.colTimestamp || 'Timestamp'}</th>
                <th className="px-4 py-3 text-center">{t?.colActions || 'Actions'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-800 text-gray-300">
              {filteredTxs.map((tx) => (
                <tr key={tx.id} className="hover:bg-cyber-800/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-cyan-400 font-semibold">#{tx.id}</td>
                  <td className="px-4 py-3 font-mono text-[11px]">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-cyan-400">{tx.currency || 'ETH'}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyber-900 border border-cyber-800 text-gray-400">
                        {tx.source || 'EVM'}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-300">{shortAddress(tx.sender)}</td>
                  <td className="px-4 py-3 font-mono text-emerald-300">{shortAddress(tx.receiver)}</td>
                  <td className="px-4 py-3 text-right font-mono">
                    <div className="font-bold text-white">
                      {tx.currency === 'IQD'
                        ? `${Number(tx.amount || 0).toLocaleString()} IQD`
                        : `${parseFloat(tx.amount || 0).toFixed(4)} ETH`}
                    </div>
                    {tx.currency !== 'IQD' && (
                      <div className="text-[10px] text-cyan-400 font-sans">{formatIQD(tx.amount)}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span
                      className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border ${
                        RISK_TIER_STYLES[tx.riskTier || (tx.isFlagged ? 'HIGH' : 'LOW')]
                      }`}
                    >
                      {tx.riskTier || (tx.isFlagged ? 'HIGH' : 'LOW')} ({tx.riskScore ? `${tx.riskScore}%` : 'N/A'})
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <StatusBadge status={tx.status} t={t} />
                  </td>
                  <td className="px-4 py-3 max-w-xs truncate text-[11px]">
                    {tx.isFlagged ? (
                      <span className="text-rose-400 flex items-center gap-1" title={tx.flagReason}>
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        {tx.flagReason}
                      </span>
                    ) : (
                      <span className="text-gray-500">{isRtl ? 'مطابق وموثق' : 'Verified clean'}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-400 font-mono text-[11px]">
                    {formatTimestamp(tx.timestamp)}
                  </td>
                  <td className="px-4 py-3 text-center space-x-1.5 whitespace-nowrap">
                    <button
                      onClick={() => setSelectedTxForInspect(tx)}
                      className="px-2 py-1 bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 rounded text-[10px] font-medium transition"
                      title="Inspect"
                    >
                      <Eye className="w-3 h-3 inline mr-0.5" />
                      {t?.actionInspect || 'Inspect'}
                    </button>

                    {isAdmin && tx.status === 0 && (
                      <>
                        <button
                          onClick={() => onFlag(tx.id)}
                          disabled={loading}
                          className="px-2 py-1 bg-rose-600/80 hover:bg-rose-600 text-white rounded text-[10px] font-medium"
                        >
                          {t?.actionFlag || 'Flag'}
                        </button>
                        <button
                          onClick={() => onClear(tx.id)}
                          disabled={loading}
                          className="px-2 py-1 bg-emerald-600/80 hover:bg-emerald-600 text-white rounded text-[10px] font-medium"
                        >
                          {t?.actionClear || 'Clear'}
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Transaction Forensic Inspector Modal */}
      {selectedTxForInspect && (
        <TransactionInspectorModal
          tx={selectedTxForInspect}
          onClose={() => setSelectedTxForInspect(null)}
          onFlag={onFlag}
          onClear={onClear}
          isAdmin={isAdmin}
          t={t}
          isRtl={isRtl}
        />
      )}
    </div>
  )
}

function KpiCard({ title, value, subtitle, icon: Icon, color, badge, onClick }) {
  const styles = {
    blue: 'border-cyan-500/30 text-cyan-400 bg-cyan-500/10 shadow-glow-cyan',
    amber: 'border-amber-500/30 text-amber-400 bg-amber-500/10 shadow-glow-amber',
    rose: 'border-rose-500/30 text-rose-400 bg-rose-500/10 shadow-glow-rose',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10 shadow-glow-emerald',
  }

  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-2xl cyber-card relative overflow-hidden transition-all ${
        onClick ? 'cursor-pointer hover:border-cyan-500 hover:scale-[1.01]' : ''
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400 font-medium">{title}</span>
        <div className={`p-2 rounded-xl ${styles[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-2">
        <h3 className="text-2xl font-bold text-white tracking-tight font-mono">{value}</h3>
        <p className="text-[11px] text-gray-400 mt-0.5">{subtitle}</p>
      </div>
      {badge && (
        <span className="absolute top-2 right-2 text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyber-950 border border-cyber-800 text-gray-300">
          {badge}
        </span>
      )}
    </div>
  )
}

function StatusBadge({ status, t }) {
  const config = [
    { label: t?.statusPending || 'Pending', cls: 'bg-blue-950 text-blue-300 border-blue-800' },
    { label: t?.statusCleared || 'Cleared', cls: 'bg-emerald-950 text-emerald-300 border-emerald-800' },
    { label: t?.statusFlagged || 'Flagged', cls: 'bg-amber-950 text-amber-300 border-amber-800' },
    { label: t?.statusBlocked || 'Blocked', cls: 'bg-rose-950 text-rose-300 border-rose-800' },
  ]
  const { label, cls } = config[status] || config[0]
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${cls}`}>
      {label}
    </span>
  )
}
