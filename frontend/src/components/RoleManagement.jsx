import React, { useState } from 'react'
import {
  KeyRound,
  Users,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  PlusCircle,
  FileCheck,
  Scale,
  PlayCircle,
  Hash,
  Clock,
} from 'lucide-react'
import { shortAddress } from '../utils/contract.js'
import { useGovernance, PROPOSAL_TYPE_NAMES } from '../hooks/useGovernance.js'

// Separation of Duties Matrix
const SOD_MATRIX = [
  {
    roleA: 'OPERATOR',
    roleB: 'AUDITOR',
    status: 'FORBIDDEN',
    reasonAr: 'يحظر على المشغل تدقيق أو تبرئة عملياته الخاصة لمنع الاحتيال الذاتي',
    reasonEn: 'Cannot audit or clear self-initiated transactions',
  },
  {
    roleA: 'SUPER_ADMIN',
    roleB: 'OPERATOR',
    status: 'RESTRICTED',
    reasonAr: 'يتطلب موافقة رباعية الأعين (MultiSig) لأي تحويل مالي',
    reasonEn: 'Mandatory MultiSig required for any direct fund movement',
  },
  {
    roleA: 'AUDITOR',
    roleB: 'REGULATOR',
    status: 'COMPLIANT',
    reasonAr: 'تكامل رقابي مسموح به بين وحدة التحريات والبنك المركزي',
    reasonEn: 'Permissible coordination between Internal Audit and CBI',
  },
]

function shortHash(hash) {
  if (!hash || hash.length < 18) return hash || ''
  return `${hash.slice(0, 10)}...${hash.slice(-8)}`
}

function shortTarget(target) {
  if (!target || target.length < 20) return target || ''
  return `${target.slice(0, 10)}...${target.slice(-10)}`
}

export function RoleManagement({ isRtl = false, t = {} }) {
  const {
    proposals,
    roles,
    requiredApprovals,
    userRole,
    account,
    loading,
    error: governanceError,
    createProposal,
    approveProposal,
    executeProposal,
  } = useGovernance()

  const [feedback, setFeedback] = useState('')
  const [feedbackError, setFeedbackError] = useState('')
  const [showNewProposal, setShowNewProposal] = useState(false)
  const [newProposalType, setNewProposalType] = useState(1) // POLICY_CHANGE
  const [newProposalTarget, setNewProposalTarget] = useState(
    '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9'
  )
  const [newProposalData, setNewProposalData] = useState('0x')
  const [newProposalReason, setNewProposalReason] = useState('')

  const handleApprove = async (id) => {
    setFeedback('')
    setFeedbackError('')
    const res = await approveProposal(id)
    if (res.status === 'confirmed') {
      setFeedback(
        isRtl
          ? `تم اعتماد المقترح #${id} بنجاح وفق مبدأ الرقابة الثنائية! المعاملة: ${shortAddress(res.transactionHash)}`
          : `Proposal #${id} approved via Four-Eyes Principle! Tx: ${shortAddress(res.transactionHash)}`
      )
      setTimeout(() => setFeedback(''), 5000)
    } else {
      setFeedbackError(res.error || 'Approval rejected')
      setTimeout(() => setFeedbackError(''), 5000)
    }
  }

  const handleExecute = async (id) => {
    setFeedback('')
    setFeedbackError('')
    const res = await executeProposal(id)
    if (res.status === 'confirmed') {
      setFeedback(
        isRtl
          ? `تم تنفيذ المقترح #${id} على السلسلة بنجاح! المعاملة: ${shortAddress(res.transactionHash)}`
          : `Proposal #${id} executed atomically on-chain! Tx: ${shortAddress(res.transactionHash)}`
      )
      setTimeout(() => setFeedback(''), 5000)
    } else {
      setFeedbackError(res.error || 'Execution rejected')
      setTimeout(() => setFeedbackError(''), 5000)
    }
  }

  const handleCreateProposalSubmit = async (e) => {
    e.preventDefault()
    if (!newProposalReason.trim()) return

    setFeedback('')
    setFeedbackError('')
    const res = await createProposal(
      Number(newProposalType),
      newProposalTarget.trim(),
      newProposalData.trim() || '0x',
      newProposalReason.trim()
    )

    if (res.status === 'confirmed') {
      setFeedback(
        isRtl
          ? `تم نشر مقترح الحوكمة والتوقيع المتعدد في السجل! المعاملة: ${shortAddress(res.transactionHash)}`
          : `New MultiSig governance proposal published! Tx: ${shortAddress(res.transactionHash)}`
      )
      setShowNewProposal(false)
      setNewProposalReason('')
      setTimeout(() => setFeedback(''), 5000)
    } else {
      setFeedbackError(res.error || 'Proposal creation failed')
      setTimeout(() => setFeedbackError(''), 5000)
    }
  }

  const isSignerRole = userRole === 'SUPER_ADMIN' || userRole === 'AUDITOR'

  return (
    <div
      className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`}
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      {/* Top Banner */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-indigo-400" />
              {t?.governanceTitle || 'Role-Based Access Control (RBAC) & Four-Eyes Governance'}
            </h2>
            <span className="text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              Separation of Duties (SoD)
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t?.governanceSubtitle ||
              'Enforces strict dual-control authorization for policy modifications, warning overrides, and emergency unpauses.'}
          </p>
          <div className="mt-2 flex items-center gap-3 text-xs">
            <span className="text-gray-400">
              {isRtl ? 'الدور الحالي:' : 'Current Role:'}{' '}
              <span className="font-mono font-bold text-cyan-300">{userRole}</span>
            </span>
            <span className="text-gray-400">
              {isRtl ? 'المحفظة:' : 'Connected:'}{' '}
              <span className="font-mono text-gray-300">
                {account ? shortAddress(account) : isRtl ? 'غير متصل' : 'Not Connected'}
              </span>
            </span>
          </div>
        </div>

        {isSignerRole && (
          <button
            onClick={() => setShowNewProposal(true)}
            className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-glow-indigo transition"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            {t?.newProposal || 'New Governance Proposal'}
          </button>
        )}
      </div>

      {feedback && (
        <div className="p-3.5 bg-emerald-950/80 border border-emerald-700 text-emerald-300 rounded-xl text-xs font-medium flex items-center gap-2 shadow-glow-emerald animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{feedback}</span>
        </div>
      )}

      {(feedbackError || governanceError) && (
        <div className="p-3.5 bg-rose-950/80 border border-rose-700 text-rose-300 rounded-xl text-xs font-medium flex items-center gap-2 shadow-glow-rose animate-fade-in">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{feedbackError || governanceError}</span>
        </div>
      )}

      {/* Grid: MultiSig Proposals Queue + Active RBAC Directory */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MultiSig Proposals Queue */}
        <div className="cyber-card rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-cyan-400" />
              {isRtl
                ? 'قائمة مقترحات الحوكمة الرباعية (MultiSig Queue)'
                : 'Four-Eyes MultiSig Proposals Queue'}
            </h3>
            <span className="text-xs text-gray-400 font-mono">
              {requiredApprovals} Required Approvals
            </span>
          </div>

          <div className="space-y-3">
            {proposals.length === 0 ? (
              <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 text-xs text-gray-500 text-center">
                {isRtl ? 'لا توجد مقترحات حوكمة مسجلة حالياً' : 'No governance proposals recorded'}
              </div>
            ) : (
              proposals.map((p) => {
                const isProposer =
                  account && p.proposer && p.proposer.toLowerCase() === account.toLowerCase()
                const hasVoted = p.hasVoted || (account && p.approvers?.includes(account.toLowerCase()))
                const isPending = p.status === 0 && !p.isExpired
                const isApproved = p.status === 1 && !p.isExpired
                const isExecuted = p.status === 2
                const isExpired = p.status === 4 || p.isExpired

                return (
                  <div
                    key={p.id}
                    className="proposal-card p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-3 text-xs"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono font-bold text-cyan-400">
                            PROPOSAL #{p.id}
                          </span>
                          <span className="text-[9px] bg-cyber-900 border border-cyber-700 px-2 py-0.5 rounded text-gray-300 font-mono">
                            {p.proposalTypeName}
                          </span>
                        </div>
                        <h4 className="text-white font-semibold mt-1">
                          {isRtl ? p.descriptionAr || p.description : p.description}
                        </h4>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                          isExecuted
                            ? 'bg-emerald-950 text-emerald-400 border-emerald-700'
                            : isApproved
                            ? 'bg-indigo-950 text-indigo-400 border-indigo-700'
                            : isExpired
                            ? 'bg-gray-900 text-gray-400 border-gray-700'
                            : 'bg-amber-950 text-amber-400 border-amber-700'
                        }`}
                      >
                        {isExecuted
                          ? t?.executed || 'EXECUTED'
                          : isApproved
                          ? t?.approved || 'APPROVED'
                          : isExpired
                          ? t?.expired || 'EXPIRED'
                          : t?.pendingApproval || 'PENDING'}
                      </span>
                    </div>

                    {/* Pre-signing Action Verification Details */}
                    <div className="p-2.5 rounded-lg bg-cyber-900/60 border border-cyber-800/80 space-y-1 font-mono text-[11px] text-gray-400">
                      <div className="flex justify-between items-center">
                        <span className="flex items-center gap-1">
                          <Hash className="w-3 h-3 text-indigo-400" /> Action Hash:
                        </span>
                        <span className="text-gray-300">{shortHash(p.actionHash)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>Target:</span>
                        <span className="text-gray-300">{shortTarget(p.target)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-amber-400" />
                          {isRtl ? 'صالح حتى:' : 'Expires:'}
                        </span>
                        <span className="text-gray-300">
                          {new Date(p.expiresAt * 1000).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-gray-400 font-mono">
                      <span>Proposer: {shortAddress(p.proposer)}</span>
                      <span>
                        Approvals: {p.approvalCount} / {p.requiredApprovals}
                      </span>
                    </div>

                    {/* Progress bar */}
                    <div className="w-full bg-cyber-900 h-1.5 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          isExecuted
                            ? 'bg-emerald-500'
                            : isApproved
                            ? 'bg-indigo-500'
                            : isExpired
                            ? 'bg-gray-600'
                            : 'bg-amber-500'
                        }`}
                        style={{
                          width: `${Math.min(
                            100,
                            (p.approvalCount / p.requiredApprovals) * 100
                          )}%`,
                        }}
                      ></div>
                    </div>

                    {/* Action buttons & SoD constraints */}
                    <div className="pt-2 flex items-center justify-between">
                      <div>
                        {isProposer && isPending && (
                          <span className="proposer-restriction text-amber-400 text-[11px]">
                            {isRtl
                              ? 'لا يمكن لمقدم المقترح اعتماده ذاتياً (فصل الصلاحيات)'
                              : 'Proposer cannot self-approve (Separation of Duties)'}
                          </span>
                        )}
                        {!isProposer && hasVoted && isPending && (
                          <span className="text-cyan-400 text-[11px] font-mono">
                            {isRtl
                              ? 'تم التصويت - بانتظار توقيع المدقق الآخر'
                              : 'Voted — Awaiting second signer'}
                          </span>
                        )}
                        {isExpired && (
                          <span className="text-gray-500 text-[11px]">
                            {isRtl ? 'المقترح منتهي الصلاحية' : 'Proposal Expired'}
                          </span>
                        )}
                      </div>

                      <div className="flex gap-2">
                        {isPending && isSignerRole && !isProposer && !hasVoted && (
                          <button
                            onClick={() => handleApprove(p.id)}
                            className="approve-btn px-3 py-1.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-glow-cyan transition"
                          >
                            <ShieldCheck className="w-3.5 h-3.5" />
                            {t?.confirmSecondEye || 'Confirm (2nd Eye)'}
                          </button>
                        )}

                        {isApproved && isSignerRole && (
                          <button
                            onClick={() => handleExecute(p.id)}
                            className="execute-btn px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-glow-emerald transition"
                          >
                            <PlayCircle className="w-3.5 h-3.5" />
                            {t?.executeAction || 'Execute Action'}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Active RBAC Directory */}
        <div className="cyber-card rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Users className="w-4 h-4 text-purple-400" />
              {isRtl ? 'سجل الأدوار والصلاحيات الممنوحة' : 'Active Role Assignments Directory'}
            </h3>
            <span className="text-xs text-gray-400 font-mono">RoleManager.sol</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="text-gray-400 uppercase bg-cyber-950 border-b border-cyber-800 text-[10px]">
                  <th className="px-3 py-2.5">{isRtl ? 'الحساب' : 'Account'}</th>
                  <th className="px-3 py-2.5">{isRtl ? 'الدور المصرح به' : 'Role'}</th>
                  <th className="px-3 py-2.5 text-center">{isRtl ? 'الحالة' : 'Status'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-800 text-gray-300">
                {roles.map((r, i) => (
                  <tr key={i} className="hover:bg-cyber-800/40">
                    <td className="px-3 py-2.5 font-mono text-cyan-300">
                      {shortAddress(r.account)}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="font-semibold text-white text-xs">
                        {isRtl ? r.roleAr : r.role}
                      </div>
                      <div className="font-mono text-[10px] text-gray-400">{r.role}</div>
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                          r.active
                            ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                            : 'bg-rose-950 text-rose-400 border-rose-800'
                        }`}
                      >
                        {r.active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Separation of Duties (SoD) Conflict Matrix */}
          <div className="pt-3 border-t border-cyber-800 space-y-2">
            <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
              <Scale className="w-3.5 h-3.5 text-amber-400" />
              {t?.conflictMatrix || 'Separation of Duties (SoD) Conflict Matrix'}
            </h4>
            <div className="space-y-1.5 text-[11px]">
              {SOD_MATRIX.map((s, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-xl bg-cyber-950 border border-cyber-800 flex items-start justify-between gap-2"
                >
                  <div>
                    <span className="font-mono text-cyan-300 font-bold">{s.roleA}</span>
                    <span className="text-gray-400 mx-1.5">↔</span>
                    <span className="font-mono text-purple-300 font-bold">{s.roleB}</span>
                    <p className="text-gray-400 mt-0.5">
                      {isRtl ? s.reasonAr : s.reasonEn}
                    </p>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[9px] font-bold font-mono shrink-0 border ${
                      s.status === 'FORBIDDEN'
                        ? 'bg-rose-950 text-rose-300 border-rose-800'
                        : s.status === 'RESTRICTED'
                        ? 'bg-amber-950 text-amber-300 border-amber-800'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                    }`}
                  >
                    {s.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* New Proposal Modal */}
      {showNewProposal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div className="bg-cyber-900 rounded-2xl p-6 w-full max-w-md border border-cyber-border shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white">
              {isRtl
                ? 'إنشاء مقترح حوكمة وتوقيع متعدد جديد'
                : 'Create MultiSig Governance Proposal'}
            </h3>
            <form onSubmit={handleCreateProposalSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'نوع الإجراء الرقابي:' : 'Action Type:'}
                </label>
                <select
                  value={newProposalType}
                  onChange={(e) => setNewProposalType(Number(e.target.value))}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white focus:border-cyan-500 focus:outline-none"
                >
                  {PROPOSAL_TYPE_NAMES.map((name, idx) => (
                    <option key={idx} value={idx}>
                      {name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'العقد المستهدف (Target):' : 'Target Contract Address:'}
                </label>
                <input
                  type="text"
                  value={newProposalTarget}
                  onChange={(e) => setNewProposalTarget(e.target.value)}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white font-mono focus:border-cyan-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1 font-medium">
                  {isRtl ? 'وصف المقترح والمبرر الرقابي:' : 'Proposal Action / Justification:'}
                </label>
                <textarea
                  rows={3}
                  value={newProposalReason}
                  onChange={(e) => setNewProposalReason(e.target.value)}
                  placeholder={
                    isRtl
                      ? 'مثال: رفع السقف اليومي للتحويلات إلى 60 إيثيريوم بناءً على تعليمات البنك المركزي...'
                      : 'e.g. Increase AML daily limit to 60.0 ETH based on CBI inflation adjustment directive...'
                  }
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-3 text-white focus:border-cyan-500 focus:outline-none"
                  required
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewProposal(false)}
                  className="flex-1 py-2 bg-cyber-800 hover:bg-cyber-700 rounded-xl text-white font-medium transition"
                >
                  {isRtl ? 'إلغاء' : 'Cancel'}
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold rounded-xl shadow-glow-indigo transition disabled:opacity-50"
                >
                  {loading
                    ? isRtl
                      ? 'جارٍ الإرسال...'
                      : 'Submitting...'
                    : isRtl
                    ? 'نشر المقترح'
                    : 'Publish Proposal'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
