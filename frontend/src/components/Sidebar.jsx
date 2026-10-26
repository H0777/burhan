import React from 'react'
import {
  ShieldAlert,
  LayoutDashboard,
  UserCheck,
  FileSearch,
  Activity,
  Code2,
  FileText,
  KeyRound,
  FolderCheck,
  Wifi,
  WifiOff,
  Cpu,
  Lock,
} from 'lucide-react'
import { shortAddress } from '../utils/contract'

export function Sidebar({
  currentView,
  setCurrentView,
  aiStatus,
  networkConnected,
  account,
  userRole,
  t,
  isRtl,
}) {
  const navSections = [
    {
      title: isRtl ? 'الرقابة التنفيذية والعمليات' : 'Operations & Monitoring',
      items: [
        { id: 'dashboard', label: t?.navDashboard || 'Executive Overview', icon: LayoutDashboard },
        { id: 'cases', label: t?.navCases || (isRtl ? 'إدارة القضايا الجنائية (V2)' : 'Case Lifecycle & Governance'), icon: FolderCheck, badge: 'V2' },
      ],
    },
    {
      title: isRtl ? 'التحقيق الجنائي والذكاء الاصطناعي' : 'Forensics & AI Detection',
      items: [
        { id: 'insider', label: t?.navInsider || 'Insider Threat Monitor', icon: UserCheck, badge: 'AI' },
        { id: 'forensics', label: t?.navForensics || 'Forensic Chain of Custody', icon: FileSearch, badge: 'Proof' },
        { id: 'risk-scoring', label: t?.navRiskScoring || 'AI Fraud Risk Engine', icon: Activity },
        { id: 'contract-scanner', label: t?.navContractScanner || 'Smart Contract Auditor', icon: Code2 },
      ],
    },
    {
      title: isRtl ? 'الحوكمة والتقارير الرقابية' : 'Governance & Dossier',
      items: [
        { id: 'reports', label: t?.navReports || 'Bilingual Forensic Dossier', icon: FileText },
        { id: 'governance', label: t?.navGovernance || 'RBAC & MultiSig 4-Eyes', icon: KeyRound },
      ],
    },
  ]

  return (
    <aside
      className={`w-64 bg-cyber-900/95 backdrop-blur-xl border-cyber-800 flex flex-col justify-between shrink-0 min-h-screen z-20 ${
        isRtl ? 'border-l font-arabic text-right' : 'border-r font-sans text-left'
      }`}
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      {/* Brand & Title */}
      <div>
        <div className="p-5 border-b border-cyber-800/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-glow-cyan shrink-0 ring-1 ring-cyan-400/30">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0">
              <h2 className="font-extrabold text-white text-base tracking-[0.18em] leading-none flex items-center gap-1.5">
                BURHAN
                <span className="text-[9px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded font-mono font-bold border border-cyan-500/30 tracking-normal">
                  v2.5
                </span>
              </h2>
              <p className={`text-[12px] text-cyan-300 font-bold leading-tight mt-1 ${isRtl ? 'font-arabic' : ''}`}>
                {isRtl ? 'بُرهان' : 'Risk-audit · AML · Forensics'}
              </p>
            </div>
          </div>
          <p className="mt-2.5 text-[8px] font-mono text-gray-500 leading-[1.5] tracking-tight">
            [B]lockchain • [U]nified • [R]isk-Audit
            <br />
            [H]euristics • [A]ML • [N]etwork-Forensics
          </p>
          <div className="mt-2.5 px-2.5 py-1.5 bg-cyber-950/90 rounded-xl border border-cyber-800/90 flex items-center justify-between">
            <p className="text-[10px] text-gray-400 leading-snug truncate">
              {t?.projectScope || 'CBI Law No. 39 | AML Compliance'}
            </p>
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shrink-0" title="Operational"></span>
          </div>
        </div>

        {/* Navigation Links Grouped */}
        <nav className="p-3 space-y-4 overflow-y-auto max-h-[calc(100vh-270px)]">
          {navSections.map((section, sIdx) => (
            <div key={sIdx} className="space-y-1">
              <div className="px-3 text-[10px] font-mono font-bold uppercase tracking-wider text-gray-500/90 mb-1.5">
                {section.title}
              </div>
              {section.items.map((item) => {
                const Icon = item.icon
                const isActive = currentView === item.id
                return (
                  <button
                    key={item.id}
                    onClick={() => setCurrentView(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold transition-all ${
                      isActive
                        ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-glow-cyan ring-1 ring-cyan-400/40'
                        : 'text-gray-400 hover:text-white hover:bg-cyber-800/60'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-gray-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.badge && (
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold shrink-0 ${
                          isActive
                            ? 'bg-white/20 text-white'
                            : 'bg-cyan-950 text-cyan-300 border border-cyan-800/80'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* System Status Footer */}
      <div className="p-4 border-t border-cyber-800 space-y-3 bg-cyber-950/60">
        {/* User Role Card */}
        <div className="p-3 rounded-xl bg-cyber-900 border border-cyber-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-400 font-bold flex items-center gap-1 font-sans">
              <Lock className="w-3 h-3 text-cyan-400" />
              {t?.connectedAs || 'Connected Role'}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-bold">
              {userRole}
            </span>
          </div>
          <p className="text-xs font-mono text-gray-300 truncate">
            {account ? shortAddress(account) : '0xf39F...2266 (Admin)'}
          </p>
        </div>

        {/* Live Status Indicators */}
        <div className="space-y-1.5 text-[11px]">
          <div className="flex items-center justify-between text-gray-400">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" /> AI Engine
            </span>
            <span className="flex items-center gap-1 text-emerald-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              {aiStatus?.status === 'online_fallback'
                ? (isRtl ? 'معالجة محلية' : 'Local Heuristics')
                : (isRtl ? 'جاهز ومتصل' : 'Operational')}
            </span>
          </div>

          <div className="flex items-center justify-between text-gray-400">
            <span className="flex items-center gap-1.5">
              {networkConnected ? (
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <WifiOff className="w-3.5 h-3.5 text-amber-400" />
              )}
              Chain RPC
            </span>
            <span className={`font-medium ${networkConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
              {networkConnected ? 'Hardhat (31337)' : (isRtl ? 'محاكاة محلية' : 'Local Emulation')}
            </span>
          </div>
        </div>
      </div>
    </aside>
  )
}
