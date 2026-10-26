import React, { useState } from 'react'
import {
  UserX,
  AlertTriangle,
  Clock,
  Repeat,
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle,
  FileText,
  Sliders,
  UserCheck,
  Network,
  Building2,
  TrendingUp,
  Search,
} from 'lucide-react'
import { analyzeInsiderThreat } from '../utils/aiClient'
import { shortAddress } from '../utils/contract'

const OPERATORS_DATA = [
  {
    address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    name: 'Ahmed Al-Kinani (Senior Auditor)',
    nameAr: 'أحمد الكناني (مدقق أول)',
    department: 'Baghdad Central Treasury',
    departmentAr: 'الخزينة المركزية - بغداد',
    role: 'SENIOR_AUDITOR',
    totalActions: 48,
    warningOverrides: 7, // Above limit (5)
    afterHoursCount: 4,  // Above limit (3)
    topBeneficiaryApprovals: 12, // Collusion
    topBeneficiary: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
    avgDecisionTime: 8.5, // Rubber-stamping (< 10s)
    threatScore: 89.5,
    threatLevel: 'CRITICAL',
    isFlagged: true,
    flagsAr: [
      'تجاوز تحذيرات النظام 7 مرات (الحد المسموح: 5)',
      'شبهة تواطؤ مالي: 12 موافقة متتالية لنفس المستفيد الخارجي',
      'تنفيذ عمليات متكررة خارج أوقات الدوام الرسمي (4 مرات)',
      'سرعة اعتماد مفرطة وغير معقولة (8.5 ثوانٍ لكل عملية)',
    ],
    flagsEn: [
      'Warning overrides exceeded policy limit (7 > 5)',
      'Collusion anomaly: 12 approvals to beneficiary 0x14dC...9955',
      'Habitual off-hours operations (4 times after 22:00)',
      'Rapid rubber-stamping (8.5s avg decision velocity)',
    ],
  },
  {
    address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    name: 'Fatima Al-Hashemi (Compliance Lead)',
    nameAr: 'فاطمة الهاشمي (مسؤولة الامتثال)',
    department: 'Basra Trade Branch',
    departmentAr: 'فرع البصرة التجاري',
    role: 'COMPLIANCE_OPERATOR',
    totalActions: 142,
    warningOverrides: 2,
    afterHoursCount: 1,
    topBeneficiaryApprovals: 4,
    topBeneficiary: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    avgDecisionTime: 135.0,
    threatScore: 16.5,
    threatLevel: 'LOW',
    isFlagged: false,
    flagsAr: ['سلوك طبيعي مطابق للسياسات الرقابية'],
    flagsEn: ['Normal compliant operational baseline'],
  },
  {
    address: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    name: 'Omar Al-Bayati (Branch Auditor)',
    nameAr: 'عمر البياتي (مدقق فرع)',
    department: 'Erbil Regional Hub',
    departmentAr: 'مركز أربيل الإقليمي',
    role: 'REGIONAL_AUDITOR',
    totalActions: 38,
    warningOverrides: 5,
    afterHoursCount: 3,
    topBeneficiaryApprovals: 9,
    topBeneficiary: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    avgDecisionTime: 42.0,
    threatScore: 68.0,
    threatLevel: 'HIGH',
    isFlagged: true,
    flagsAr: [
      'تجاوز التحذيرات وصل للحد الأقصى (5/5)',
      'تركيز غير معتاد في الاعتمادات لشركة مقاولات إقليمية',
      '3 عمليات بعد منتصف الليل',
    ],
    flagsEn: [
      'Warning overrides reached upper limit (5/5)',
      'High approval concentration to regional entity',
      '3 off-hours transactions logged',
    ],
  },
  {
    address: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    name: 'Zaid Al-Saadi (Settlement Officer)',
    nameAr: 'زيد الساعدي (موظف تسويات)',
    department: 'Core Banking IT',
    departmentAr: 'تقنية الخدمات المصرفية الشاملة',
    role: 'SETTLEMENT_OFFICER',
    totalActions: 85,
    warningOverrides: 3,
    afterHoursCount: 2,
    topBeneficiaryApprovals: 6,
    topBeneficiary: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
    avgDecisionTime: 65.0,
    threatScore: 34.0,
    threatLevel: 'MEDIUM',
    isFlagged: false,
    flagsAr: ['ضمن المعدلات المقبولة مع مراقبة أسبوعية'],
    flagsEn: ['Moderate risk, scheduled for bi-weekly review'],
  },
]

export function InsiderMonitor({ onGenerateReport, t, isRtl }) {
  const [operators, setOperators] = useState(OPERATORS_DATA)
  const [selectedOp, setSelectedOp] = useState(OPERATORS_DATA[0])
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState('matrix') // 'matrix' or 'graph'

  // Interactive Simulation Controls
  const [simState, setSimState] = useState({
    operatorAddress: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    totalActions: 45,
    warningOverrides: 6,
    afterHoursCount: 4,
    topBeneficiaryApprovalCount: 12,
    avgDecisionTimeSeconds: 8.2,
    reversalRate: 0.18,
  })

  const [simResult, setSimResult] = useState(null)
  const [isSimulating, setIsSimulating] = useState(false)
  const [actionSuccess, setActionSuccess] = useState('')

  const filteredOperators = operators.filter(
    (op) =>
      op.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      op.nameAr.includes(searchTerm) ||
      op.address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      op.department.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const handleRunSimulation = async () => {
    setIsSimulating(true)
    try {
      const res = await analyzeInsiderThreat(simState)
      setSimResult(res)
    } catch (err) {
      console.error('Simulation error:', err)
    } finally {
      setIsSimulating(false)
    }
  }

  const handleFreezeOperator = (addr, name) => {
    setActionSuccess(
      isRtl
        ? `تم رفع مقترح تجميد فوري عبر التوقيع المتعدد للمشغل: ${name || shortAddress(addr)}`
        : `MultiSig Freeze proposal initiated for operator: ${name || shortAddress(addr)}`
    )
    setTimeout(() => setActionSuccess(''), 4500)
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              {t?.insiderTitle || 'Insider Threat Profiler & Collusion Matrix'}
            </h2>
            <span className="text-[10px] bg-rose-950/80 text-rose-300 border border-rose-700 px-2 py-0.5 rounded-full font-mono font-bold">
              AI Behavioral Profiler
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t?.insiderSubtitle || 'Detects unauthorized override clustering, off-hours fraud spikes, and operator-beneficiary collusion.'}
          </p>
        </div>

        {/* View Switcher: Matrix Table vs Collusion Network */}
        <div className="flex items-center gap-2 bg-cyber-950 p-1 rounded-xl border border-cyber-800">
          <button
            onClick={() => setActiveTab('matrix')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'matrix' ? 'bg-cyan-600 text-white shadow-glow-cyan' : 'text-gray-400 hover:text-white'
            }`}
          >
            {isRtl ? 'سجل المشغلين والإنذارات' : 'Operators Matrix'}
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
              activeTab === 'graph' ? 'bg-cyan-600 text-white shadow-glow-cyan' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            {isRtl ? 'شبكة التواطؤ البصرية' : 'Collusion Graph'}
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs font-medium flex items-center gap-2 animate-fade-in shadow-glow-emerald">
          <CheckCircle className="w-4 h-4 text-emerald-400" />
          {actionSuccess}
        </div>
      )}

      {/* Main Tab Content */}
      {activeTab === 'graph' ? (
        /* Visual Collusion Network Graph */
        <div className="cyber-card rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                {isRtl ? 'مخطط شبكة العلاقات ورصد التواطؤ الداخلي' : 'Visual Insider Collusion & Relationship Network'}
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                {isRtl
                  ? 'رسم بياني لعلاقات المشغلين بالمستفيدين، تبرز الخطوط الحمراء كثافة الموافقات المشبوهة.'
                  : 'Interactive entity relationship map highlighting anomalous approval density and collusion risks.'}
              </p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 bg-cyber-950 px-2.5 py-1 rounded-lg border border-cyber-800">
              4 Operators ↔ 4 Beneficiaries
            </span>
          </div>

          {/* SVG Visual Network */}
          <div className="relative w-full h-80 bg-cyber-950 rounded-xl border border-cyber-800 p-4 overflow-hidden flex items-center justify-center">
            <svg className="w-full h-full" viewBox="0 0 800 300">
              <defs>
                <linearGradient id="suspiciousEdge" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#f43f5e" />
                  <stop offset="100%" stopColor="#f59e0b" />
                </linearGradient>
                <linearGradient id="normalEdge" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#06b6d4" />
                  <stop offset="100%" stopColor="#10b981" />
                </linearGradient>
              </defs>

              {/* Edge 1: Ahmed Al-Kinani -> Blacklisted Shell (CRITICAL COLLUSION) */}
              <line x1="200" y1="80" x2="600" y2="80" stroke="url(#suspiciousEdge)" strokeWidth="4" strokeDasharray="6 3" />
              <text x="400" y="70" fill="#f43f5e" fontSize="11" textAnchor="middle" fontWeight="bold">
                12x Approvals (CRITICAL COLLUSION)
              </text>

              {/* Edge 2: Omar Al-Bayati -> Regional Construction (HIGH) */}
              <line x1="200" y1="220" x2="600" y2="220" stroke="#f59e0b" strokeWidth="2.5" />
              <text x="400" y="212" fill="#f59e0b" fontSize="10" textAnchor="middle">
                9x Approvals (Concentrated)
              </text>

              {/* Edge 3: Fatima -> Baghdad Oil (NORMAL) */}
              <line x1="200" y1="150" x2="600" y2="150" stroke="url(#normalEdge)" strokeWidth="1.5" strokeOpacity="0.6" />
              <text x="400" y="142" fill="#10b981" fontSize="10" textAnchor="middle">
                4x Approvals (Compliant)
              </text>

              {/* Left Column: Operators */}
              {/* Operator 1 */}
              <g transform="translate(140, 80)" className="cursor-pointer" onClick={() => setSelectedOp(operators[0])}>
                <circle r="32" fill="#15203b" stroke="#f43f5e" strokeWidth="3" />
                <text y="-6" fill="#ffffff" fontSize="11" fontWeight="bold" textAnchor="middle">
                  Ahmed K.
                </text>
                <text y="10" fill="#f43f5e" fontSize="9" fontWeight="bold" textAnchor="middle">
                  89.5% Threat
                </text>
              </g>

              {/* Operator 2 */}
              <g transform="translate(140, 150)" className="cursor-pointer" onClick={() => setSelectedOp(operators[1])}>
                <circle r="26" fill="#15203b" stroke="#10b981" strokeWidth="2" />
                <text y="-3" fill="#ffffff" fontSize="10" textAnchor="middle">
                  Fatima H.
                </text>
                <text y="11" fill="#10b981" fontSize="8" textAnchor="middle">
                  16.5% Low
                </text>
              </g>

              {/* Operator 3 */}
              <g transform="translate(140, 220)" className="cursor-pointer" onClick={() => setSelectedOp(operators[2])}>
                <circle r="28" fill="#15203b" stroke="#f59e0b" strokeWidth="2.5" />
                <text y="-4" fill="#ffffff" fontSize="10" textAnchor="middle">
                  Omar B.
                </text>
                <text y="10" fill="#f59e0b" fontSize="9" textAnchor="middle">
                  68% High
                </text>
              </g>

              {/* Right Column: Beneficiary Accounts */}
              {/* Beneficiary 1: Shell Entity */}
              <g transform="translate(660, 80)">
                <rect x="-60" y="-20" width="120" height="40" rx="8" fill="#1e1322" stroke="#f43f5e" strokeWidth="2" />
                <text y="-2" fill="#fca5a5" fontSize="10" fontWeight="bold" textAnchor="middle">
                  Shell Entity 9955
                </text>
                <text y="12" fill="#ef4444" fontSize="8" textAnchor="middle">
                  Blacklisted Account
                </text>
              </g>

              {/* Beneficiary 2: Oil Services */}
              <g transform="translate(660, 150)">
                <rect x="-60" y="-18" width="120" height="36" rx="8" fill="#0f1f2e" stroke="#06b6d4" strokeWidth="1.5" />
                <text y="-1" fill="#67e8f9" fontSize="10" textAnchor="middle">
                  Baghdad Oil Corp
                </text>
                <text y="11" fill="#38bdf8" fontSize="8" textAnchor="middle">
                  KYC Verified
                </text>
              </g>

              {/* Beneficiary 3: Regional Construction */}
              <g transform="translate(660, 220)">
                <rect x="-60" y="-18" width="120" height="36" rx="8" fill="#1e1d24" stroke="#f59e0b" strokeWidth="1.5" />
                <text y="-1" fill="#fde047" fontSize="10" textAnchor="middle">
                  Erbil Regional Co
                </text>
                <text y="11" fill="#f59e0b" fontSize="8" textAnchor="middle">
                  Under Audit Watch
                </text>
              </g>
            </svg>
          </div>
        </div>
      ) : (
        /* Operators Matrix & Dossier Card */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Table (7 cols) */}
          <div className="lg:col-span-7 cyber-card rounded-2xl overflow-hidden shadow-xl">
            <div className="p-4 border-b border-cyber-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-cyber-950/60">
              <div className="relative w-full sm:w-64">
                <Search className={`w-3.5 h-3.5 text-gray-400 absolute top-3 ${isRtl ? 'left-3' : 'right-3'}`} />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder={isRtl ? 'بحث بالمشغل، الفرع...' : 'Search operator or branch...'}
                  className="w-full bg-cyber-900 border border-cyber-800 rounded-xl px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <span className="text-[11px] text-gray-400 font-mono">
                {filteredOperators.length} {isRtl ? 'مشغلين مسجلين' : 'Active Operators'}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-gray-400 uppercase bg-cyber-950 border-b border-cyber-800 text-[10px]">
                    <th className="px-4 py-3">{isRtl ? 'المشغل والفرع' : 'Operator & Branch'}</th>
                    <th className="px-3 py-3 text-center">{isRtl ? 'التجاوزات' : 'Overrides'}</th>
                    <th className="px-3 py-3 text-center">{isRtl ? 'خارج الدوام' : 'Off-Hours'}</th>
                    <th className="px-3 py-3 text-center">{isRtl ? 'التواطؤ' : 'Collusion'}</th>
                    <th className="px-3 py-3 text-center">{isRtl ? 'درجة الخطر' : 'Threat'}</th>
                    <th className="px-3 py-3 text-right">{isRtl ? 'الإجراء' : 'Action'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-800 text-gray-300">
                  {filteredOperators.map((op) => {
                    const isSelected = selectedOp?.address === op.address
                    return (
                      <tr
                        key={op.address}
                        onClick={() => setSelectedOp(op)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'hover:bg-cyber-800/40'
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {op.isFlagged ? (
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                            ) : (
                              <UserCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            )}
                            <div>
                              <div className="font-semibold text-white text-xs">
                                {isRtl ? op.nameAr : op.name}
                              </div>
                              <div className="text-[10px] text-gray-400 font-mono">
                                {shortAddress(op.address)} • {isRtl ? op.departmentAr : op.department}
                              </div>
                            </div>
                          </div>
                        </td>

                        <td className="px-3 py-3 text-center font-mono">
                          <span className={`font-bold ${op.warningOverrides > 5 ? 'text-rose-400' : 'text-gray-300'}`}>
                            {op.warningOverrides} / 5
                          </span>
                        </td>

                        <td className="px-3 py-3 text-center font-mono">
                          <span className={`font-bold ${op.afterHoursCount > 3 ? 'text-amber-400' : 'text-gray-300'}`}>
                            {op.afterHoursCount} / 3
                          </span>
                        </td>

                        <td className="px-3 py-3 text-center font-mono">
                          <span className={op.topBeneficiaryApprovals > 10 ? 'text-rose-400 font-bold' : 'text-gray-400'}>
                            {op.topBeneficiaryApprovals}x
                          </span>
                        </td>

                        <td className="px-3 py-3 text-center font-mono">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              op.threatLevel === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border-rose-800'
                                : op.threatLevel === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border-amber-800'
                                : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                            }`}
                          >
                            {op.threatScore}%
                          </span>
                        </td>

                        <td className="px-3 py-3 text-right">
                          {op.isFlagged && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                handleFreezeOperator(op.address, isRtl ? op.nameAr : op.name)
                              }}
                              className="px-2.5 py-1 bg-rose-600/80 hover:bg-rose-600 text-white rounded text-[10px] font-semibold transition"
                            >
                              {isRtl ? 'تجميد' : 'Freeze'}
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Operator Dossier Card (5 cols) */}
          <div className="lg:col-span-5 cyber-card rounded-2xl p-5 shadow-xl flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
                <div>
                  <h4 className="text-white font-bold text-sm">
                    {isRtl ? selectedOp.nameAr : selectedOp.name}
                  </h4>
                  <p className="text-[11px] font-mono text-cyan-400">{selectedOp.address}</p>
                </div>
                <span
                  className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${
                    selectedOp.threatLevel === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-400 border-rose-800'
                      : selectedOp.threatLevel === 'HIGH'
                      ? 'bg-amber-950 text-amber-400 border-amber-800'
                      : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  }`}
                >
                  {selectedOp.threatLevel}
                </span>
              </div>

              {/* Progress Gauge */}
              <div className="my-4">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400">{isRtl ? 'مؤشر الشذوذ السلوكي' : 'Behavioral Anomaly Index'}</span>
                  <span className="font-mono font-bold text-white">{selectedOp.threatScore} / 100</span>
                </div>
                <div className="w-full bg-cyber-950 rounded-full h-3 overflow-hidden border border-cyber-800">
                  <div
                    className={`h-full transition-all duration-500 ${
                      selectedOp.threatScore >= 75
                        ? 'bg-gradient-to-r from-amber-500 to-rose-500'
                        : selectedOp.threatScore >= 40
                        ? 'bg-gradient-to-r from-cyan-500 to-amber-500'
                        : 'bg-gradient-to-r from-cyan-500 to-emerald-500'
                    }`}
                    style={{ width: `${selectedOp.threatScore}%` }}
                  ></div>
                </div>
              </div>

              {/* Key Behavioral Indicators */}
              <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                <div className="p-2.5 rounded-xl bg-cyber-950 border border-cyber-800">
                  <span className="text-gray-400 text-[10px] block">{isRtl ? 'متوسط سرعة القرار' : 'Decision Velocity'}</span>
                  <span className="font-mono font-bold text-white text-xs">{selectedOp.avgDecisionTime}s</span>
                </div>
                <div className="p-2.5 rounded-xl bg-cyber-950 border border-cyber-800">
                  <span className="text-gray-400 text-[10px] block">{isRtl ? 'موافقات المستفيد المشبوه' : 'Collusion Approvals'}</span>
                  <span className="font-mono font-bold text-rose-400 text-xs">{selectedOp.topBeneficiaryApprovals}x</span>
                </div>
              </div>

              {/* Flagged Signals */}
              <div className="space-y-1.5 text-xs">
                <h5 className="text-gray-400 text-[10px] uppercase font-bold tracking-wider">
                  {isRtl ? 'المؤشرات السلوكية المرصودة' : 'Flagged Behavioral Signals'}
                </h5>
                {(isRtl ? selectedOp.flagsAr : selectedOp.flagsEn).map((f, i) => (
                  <div key={i} className="p-2 rounded-lg bg-cyber-950 border border-cyber-800 flex items-start gap-2">
                    <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
                    <span className="text-gray-300 text-[11px] leading-snug">{f}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-cyber-800 space-y-2">
              <button
                onClick={() => handleFreezeOperator(selectedOp.address, isRtl ? selectedOp.nameAr : selectedOp.name)}
                className="w-full py-2.5 bg-rose-600 hover:bg-rose-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-1.5 shadow-glow-rose transition"
              >
                <UserX className="w-3.5 h-3.5" />
                {isRtl ? 'تفعيل مقترح تجميد الصلاحيات (MultiSig)' : 'Initiate MultiSig Operator Freeze'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Behavioral Simulation Testbed */}
      <div className="cyber-card rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-cyan-600/20 text-cyan-400 border border-cyan-500/30">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">
                {t?.simulationTestbed || 'Real-Time Insider Behavior Simulation Testbed'}
              </h3>
              <p className="text-xs text-gray-400">
                {isRtl
                  ? 'عدّل معايير سلوك المشغل لاختبار استجابة الذكاء الاصطناعي وحدود التجميد التلقائي'
                  : 'Adjust operator parameters to test ML heuristic scoring and automated regulatory actions.'}
              </p>
            </div>
          </div>

          <button
            onClick={handleRunSimulation}
            disabled={isSimulating}
            className="px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-glow-cyan transition"
          >
            <Play className="w-3.5 h-3.5" />
            {isSimulating ? (isRtl ? 'جاري تقييم النموذج...' : 'Evaluating Model...') : (isRtl ? 'تشغيل المحاكاة' : 'Simulate Behavior')}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
          {/* Column 1 */}
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-300 font-medium">{isRtl ? 'تجاوزات التحذير' : 'Warning Overrides'}</span>
                <span className="font-mono text-cyan-400 font-bold">{simState.warningOverrides} (Limit: 5)</span>
              </div>
              <input
                type="range"
                min="0"
                max="15"
                value={simState.warningOverrides}
                onChange={(e) => setSimState({ ...simState, warningOverrides: parseInt(e.target.value, 10) })}
                className="w-full accent-cyan-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-300 font-medium">{isRtl ? 'عمليات خارج الدوام' : 'After-Hours Executions'}</span>
                <span className="font-mono text-amber-400 font-bold">{simState.afterHoursCount} (Limit: 3)</span>
              </div>
              <input
                type="range"
                min="0"
                max="10"
                value={simState.afterHoursCount}
                onChange={(e) => setSimState({ ...simState, afterHoursCount: parseInt(e.target.value, 10) })}
                className="w-full accent-amber-500"
              />
            </div>
          </div>

          {/* Column 2 */}
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-300 font-medium">{isRtl ? 'اعتمادات لمستفيد واحد' : 'Single Beneficiary Approvals'}</span>
                <span className="font-mono text-purple-400 font-bold">{simState.topBeneficiaryApprovalCount} (Limit: 10)</span>
              </div>
              <input
                type="range"
                min="1"
                max="25"
                value={simState.topBeneficiaryApprovalCount}
                onChange={(e) => setSimState({ ...simState, topBeneficiaryApprovalCount: parseInt(e.target.value, 10) })}
                className="w-full accent-purple-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-300 font-medium">{isRtl ? 'سرعة القرار' : 'Avg Decision Velocity'}</span>
                <span className="font-mono text-cyan-400 font-bold">{simState.avgDecisionTimeSeconds}s</span>
              </div>
              <input
                type="range"
                min="1"
                max="120"
                value={simState.avgDecisionTimeSeconds}
                onChange={(e) => setSimState({ ...simState, avgDecisionTimeSeconds: parseFloat(e.target.value) })}
                className="w-full accent-cyan-500"
              />
            </div>
          </div>

          {/* AI Result Card */}
          <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 flex flex-col justify-between">
            <div>
              <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">
                {isRtl ? 'نتيجة تقييم الذكاء الاصطناعي' : 'AI Model Evaluation'}
              </span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-white font-mono">
                  {simResult ? simResult.threat_score : 88.5}%
                </span>
                <span
                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                    (simResult?.threat_level || 'CRITICAL') === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                  }`}
                >
                  {simResult?.threat_level || 'CRITICAL'}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 mt-2">
                <strong>{isRtl ? 'الإجراء الموصى به:' : 'Recommended Action:'}</strong>{' '}
                <span className="text-amber-400 font-mono">
                  {simResult?.recommended_action || 'MANDATE_MULTISIG_FREEZE'}
                </span>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
