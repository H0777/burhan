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
  const navItems = [
    { id: 'dashboard', label: t?.navDashboard || 'Executive Overview', icon: LayoutDashboard },
    { id: 'cases', label: t?.navCases || (isRtl ? 'دورة القضايا والحوكمة (V2)' : 'Case Lifecycle & Governance'), icon: FolderCheck, badge: 'V2' },
    { id: 'insider', label: t?.navInsider || 'Insider Threat Monitor', icon: UserCheck, badge: 'AI' },
    { id: 'forensics', label: t?.navForensics || 'Forensic Chain of Custody', icon: FileSearch, badge: 'Proof' },
    { id: 'risk-scoring', label: t?.navRiskScoring || 'AI Fraud Risk Engine', icon: Activity },
    { id: 'contract-scanner', label: t?.navContractScanner || 'Smart Contract Auditor', icon: Code2 },
    { id: 'reports', label: t?.navReports || 'Bilingual Forensic Dossier', icon: FileText },
    { id: 'governance', label: t?.navGovernance || 'RBAC & MultiSig 4-Eyes', icon: KeyRound },
  ]

  return (
    <aside
      className={`w-64 bg-cyber-900 border-cyber-800 flex flex-col justify-between shrink-0 min-h-screen z-20 ${
        isRtl ? 'border-l font-arabic text-right' : 'border-r font-sans text-left'
      }`}
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      {/* Brand & Title */}
      <div>
        <div className="p-5 border-b border-cyber-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-glow-cyan shrink-0">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="font-bold text-white text-sm tracking-wide flex items-center gap-1.5">
                CYBER-AUDIT
                <span className="text-[9px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded font-mono font-bold">
                  v2.5
                </span>
              </h2>
              <p className="text-[11px] text-gray-400 font-medium leading-tight">
                {isRtl ? 'التدقيق والتحقيق الجنائي' : 'Digital Forensics & AML'}
              </p>
            </div>
          </div>
          <div className="mt-3 px-2.5 py-1.5 bg-cyber-950/80 rounded-xl border border-cyber-800/80">
            <p className="text-[10px] text-gray-400 leading-snug">
              {t?.projectScope || 'Central Bank of Iraq (CBI) | Insider Threat Fraud Mitigation'}
            </p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = currentView === item.id
            return (
              <button
                key={item.id}
                onClick={() => setCurrentView(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-glow-cyan'
                    : 'text-gray-400 hover:text-white hover:bg-cyber-800/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-gray-400'}`} />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                      isActive
                        ? 'bg-white/20 text-white'
                        : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            )
          })}
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
