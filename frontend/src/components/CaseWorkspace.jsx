import React, { useState, useEffect, useCallback } from 'react'
import {
  FolderCheck,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  CheckCircle2,
  Clock,
  ArrowRight,
  ArrowLeft,
  UserCheck,
  AlertTriangle,
  FileText,
  Upload,
  Lock,
  Eye,
  Sliders,
  Scale,
  XCircle,
  RotateCcw,
} from 'lucide-react'
import { apiV2Client } from '../api/client'

const MOCK_IDENTITIES = [
  { sub: 'operator-1', role: 'OPERATOR', name: 'Investigator Tariq (Operator)' },
  { sub: 'auditor-2', role: 'AUDITOR', name: 'Lead Auditor Fatima (Auditor)' },
  { sub: 'admin-master', role: 'SUPER_ADMIN', name: 'Admin Haider (Super Admin)' },
  { sub: 'cbi-regulator', role: 'REGULATOR', name: 'CBI Inspector (Regulator - Read Only)' },
]

export function CaseWorkspace({ t, isRtl, userRole, account }) {
  const [cases, setCases] = useState([])
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const [caseDetail, setCaseDetail] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  // Demo Persona Selector for Four-Eyes Principle testing
  const [currentPersona, setCurrentPersona] = useState(MOCK_IDENTITIES[0])

  // Filters
  const [searchFilter, setSearchFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')

  // Create Case Modal
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [createForm, setCreateForm] = useState({
    case_number: `CASE-${Date.now().toString().slice(-4)}`,
    title: '',
    description: '',
    severity: 'MEDIUM',
  })

  // Transition Reason Modal
  const [transitionAction, setTransitionAction] = useState(null)
  const [transitionReason, setTransitionReason] = useState('')
  const [showReasonModal, setShowReasonModal] = useState(false)

  // Load cases list
  const loadCases = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const resp = await apiV2Client.listCases({ limit: 50 })
      const items = resp.items || []
      setCases(items)
      if (items.length > 0 && !selectedCaseId) {
        setSelectedCaseId(items[0].id)
      }
    } catch (err) {
      setError(err.message || 'Failed to load cases')
    } finally {
      setLoading(false)
    }
  }, [selectedCaseId])

  // Load single case detail
  const loadCaseDetail = useCallback(async (caseId) => {
    if (!caseId) return
    setLoading(true)
    setError(null)
    try {
      const resp = await apiV2Client.getCase(caseId)
      setCaseDetail(resp)
    } catch (err) {
      setError(err.message || 'Failed to fetch case detail')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadCases()
  }, [loadCases])

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetail(selectedCaseId)
    }
  }, [selectedCaseId, loadCaseDetail])

  // Handle case creation
  const handleCreateCase = async (e) => {
    e.preventDefault()
    setError(null)
    setSuccessMsg(null)
    try {
      const created = await apiV2Client.createCase({
        case_number: createForm.case_number,
        title: createForm.title,
        description: createForm.description,
        severity: createForm.severity,
        assigned_to_sub: currentPersona.sub,
      })
      setShowCreateModal(false)
      setCreateForm({
        case_number: `CASE-${Date.now().toString().slice(-4)}`,
        title: '',
        description: '',
        severity: 'MEDIUM',
      })
      setSuccessMsg(
        isRtl
          ? `تم إنشاء القضية بنجاح [${created.case_number}]`
          : `Case created successfully [${created.case_number}]`
      )
      await loadCases()
      setSelectedCaseId(created.id)
    } catch (err) {
      setError(err.message || 'Failed to create case')
    }
  }

  // Handle transition
  const handleExecuteTransition = async (action, reason = '') => {
    if (!caseDetail || !caseDetail.case) return
    setError(null)
    setSuccessMsg(null)
    try {
      const updated = await apiV2Client.transitionCase(caseDetail.case.id, {
        action,
        expected_version: caseDetail.case.version,
        reason,
        new_assignee_sub: action === 'return_to_review' ? currentPersona.sub : null,
      })
      setShowReasonModal(false)
      setTransitionAction(null)
      setTransitionReason('')
      setSuccessMsg(
        isRtl
          ? `تم تحديث حالة القضية إلى [${updated.status}] (الإصدار v${updated.version})`
          : `Case status transitioned to [${updated.status}] (version v${updated.version})`
      )
      await loadCaseDetail(caseDetail.case.id)
      await loadCases()
    } catch (err) {
      setError(err.message || 'Transition failed')
    }
  }

  const promptTransition = (action) => {
    if (['reject_resolution', 'escalate', 'return_to_review', 'reopen'].includes(action)) {
      setTransitionAction(action)
      setShowReasonModal(true)
    } else {
      handleExecuteTransition(action, '')
    }
  }

  // Check if current persona is the last requester of approval
  const lastApprovalRequestEvent = caseDetail?.events
    ?.slice()
    ?.reverse()
    ?.find((e) => e.event_type === 'request_approval')
  const isSelfApprovalRisk =
    lastApprovalRequestEvent && lastApprovalRequestEvent.actor_sub === currentPersona.sub

  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      c.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      c.case_number.toLowerCase().includes(searchFilter.toLowerCase())
    const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const getStatusBadge = (status) => {
    switch (status) {
      case 'OPEN':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40'
      case 'IN_REVIEW':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/40'
      case 'AWAITING_APPROVAL':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40 animate-pulse'
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
      case 'CLOSED':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40'
      case 'ESCALATED':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40'
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/40'
    }
  }

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-600/30 text-rose-300 border-rose-600/50'
      case 'HIGH':
        return 'bg-amber-600/30 text-amber-300 border-amber-600/50'
      case 'MEDIUM':
        return 'bg-blue-600/30 text-blue-300 border-blue-600/50'
      case 'LOW':
        return 'bg-emerald-600/30 text-emerald-300 border-emerald-600/50'
      default:
        return 'bg-gray-600/30 text-gray-300 border-gray-600/50'
    }
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Header Banner */}
      <div className="bg-cyber-900 border border-cyber-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-glow-cyan shrink-0">
                <FolderCheck className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white flex items-center gap-2">
                  {isRtl ? 'دورة إدارة القضايا والحوكمة المؤسسية (V2)' : 'Institutional Case Lifecycle & Governance (V2)'}
                  <span className="text-xs bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded-full font-mono">
                    Four-Eyes SoD
                  </span>
                </h1>
                <p className="text-xs text-gray-400 mt-1">
                  {isRtl
                    ? 'نظام تتبع وإثبات القضايا المالية الجنائية — منع الاعتماد الذاتي، أقفال التزامن، ومسار تدقيق غير قابل للتعديل'
                    : 'Auditable case state machine — Four-Eyes principle, optimistic locking, and append-only event ledger'}
                </p>
              </div>
            </div>
          </div>

          {/* Persona Switcher for Four-Eyes Verification */}
          <div className="bg-cyber-950/80 border border-cyber-800 p-3 rounded-xl flex items-center gap-3">
            <Sliders className="w-4 h-4 text-cyan-400 shrink-0" />
            <div className="text-xs">
              <span className="text-gray-400 block text-[10px]">
                {isRtl ? 'محاكاة هوية المراجع (لاختبار الصلاحيات والأعين الأربع):' : 'Active Persona (Four-Eyes Testing):'}
              </span>
              <select
                aria-label="Active Persona"
                value={currentPersona.sub}
                onChange={(e) => {
                  const p = MOCK_IDENTITIES.find((x) => x.sub === e.target.value)
                  if (p) setCurrentPersona(p)
                }}
                className="bg-cyber-900 border border-cyber-700 text-cyan-300 rounded px-2 py-1 text-xs font-mono font-semibold focus:outline-none focus:border-cyan-500 mt-0.5"
              >
                {MOCK_IDENTITIES.map((id) => (
                  <option key={id.sub} value={id.sub}>
                    {id.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Global Alert Messages */}
        {error && (
          <div className="mt-4 p-3 bg-rose-950/70 border border-rose-800 rounded-xl text-rose-300 text-xs flex items-center gap-2 animate-fade-in">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
        {successMsg && (
          <div className="mt-4 p-3 bg-emerald-950/70 border border-emerald-800 rounded-xl text-emerald-300 text-xs flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{successMsg}</span>
          </div>
        )}
      </div>

      {/* Main Grid: Cases List (Left) + Detail & History (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Cases List Pane (5 cols) */}
        <div className="lg:col-span-5 bg-cyber-900 border border-cyber-800 rounded-2xl p-4 flex flex-col h-[750px]">
          {/* List Toolbar */}
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800 gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute top-2.5 left-2.5 rtl:left-auto rtl:right-2.5" />
              <input
                type="text"
                placeholder={isRtl ? 'بحث برقم أو عنوان القضية...' : 'Search case # or title...'}
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl py-1.5 px-8 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-cyber-950 border border-cyber-800 text-gray-300 rounded-xl px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">{isRtl ? 'كل الحالات' : 'All Statuses'}</option>
              <option value="OPEN">OPEN</option>
              <option value="IN_REVIEW">IN_REVIEW</option>
              <option value="AWAITING_APPROVAL">AWAITING_APPROVAL</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="CLOSED">CLOSED</option>
              <option value="ESCALATED">ESCALATED</option>
            </select>

            <button
              onClick={() => setShowCreateModal(true)}
              className="px-3 py-1.5 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-glow-cyan hover:opacity-90 shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{isRtl ? 'قضية جديدة' : 'New'}</span>
            </button>
          </div>

          {/* Cases Scroll Area */}
          <div className="flex-1 overflow-y-auto space-y-2 mt-3 pr-1">
            {filteredCases.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-xs">
                {isRtl ? 'لا توجد قضايا مطابقة' : 'No matching cases found'}
              </div>
            ) : (
              filteredCases.map((c) => {
                const isSelected = selectedCaseId === c.id
                return (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`p-3 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-cyber-800/80 border-cyan-500 shadow-md'
                        : 'bg-cyber-950/60 border-cyber-800 hover:border-cyber-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-[11px] font-bold text-cyan-400">
                        {c.case_number}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono font-bold ${getSeverityBadge(c.severity)}`}>
                          {c.severity}
                        </span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono font-bold ${getStatusBadge(c.status)}`}>
                          {c.status}
                        </span>
                      </div>
                    </div>
                    <h4 className="text-xs font-semibold text-white truncate">{c.title}</h4>
                    <div className="flex items-center justify-between text-[10px] text-gray-500 mt-2 font-mono">
                      <span>v{c.version}</span>
                      <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Case Details and Events Pane (7 cols) */}
        <div className="lg:col-span-7 bg-cyber-900 border border-cyber-800 rounded-2xl p-5 flex flex-col h-[750px] overflow-y-auto">
          {!caseDetail ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-500 text-xs">
              <FolderCheck className="w-10 h-10 mb-2 text-gray-600" />
              <span>{isRtl ? 'حدد قضية من القائمة للاطلاع على تفاصيلها' : 'Select a case from the list to view details'}</span>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header Box */}
              <div className="bg-cyber-950/70 border border-cyber-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                      {caseDetail.case.case_number}
                    </span>
                    <span className="text-xs text-gray-400 font-mono">
                      v{caseDetail.case.version}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-mono font-bold ${getSeverityBadge(caseDetail.case.severity)}`}>
                      {caseDetail.case.severity}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-mono font-bold ${getStatusBadge(caseDetail.case.status)}`}>
                      {caseDetail.case.status}
                    </span>
                  </div>
                </div>

                <h2 className="text-base font-bold text-white">{caseDetail.case.title}</h2>
                {caseDetail.case.description && (
                  <p className="text-xs text-gray-300 leading-relaxed bg-cyber-900/60 p-2.5 rounded-lg border border-cyber-800/80">
                    {caseDetail.case.description}
                  </p>
                )}

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1 border-t border-cyber-800/60 font-mono text-gray-400">
                  <div>
                    <span className="block text-gray-500 text-[10px]">{isRtl ? 'المؤسسة:' : 'Institution:'}</span>
                    <span className="text-gray-300 truncate block">{caseDetail.case.institution_id}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[10px]">{isRtl ? 'المراجع المعين:' : 'Assignee:'}</span>
                    <span className="text-cyan-300 truncate block">{caseDetail.case.assigned_to_sub || '—'}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[10px]">{isRtl ? 'الأدلة المرفقة:' : 'Evidence Count:'}</span>
                    <span className="text-emerald-400 font-bold">{caseDetail.evidence_count} files</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-[10px]">{isRtl ? 'تاريخ التحديث:' : 'Updated:'}</span>
                    <span className="text-gray-400">{new Date(caseDetail.case.updated_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>

              {/* Four-Eyes Governance Actions Box */}
              <div className="bg-cyber-950/70 border border-cyber-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white flex items-center gap-2">
                    <Scale className="w-4 h-4 text-cyan-400" />
                    <span>{isRtl ? 'إجراءات الحوكمة واعتماد الحل (Four-Eyes)' : 'Governance & Resolution Actions (Four-Eyes)'}</span>
                  </h3>
                  <span className="text-[10px] font-mono text-gray-400">
                    {isRtl ? 'الدور الفعال:' : 'Role:'} <strong className="text-cyan-300">{currentPersona.role}</strong>
                  </span>
                </div>

                {/* Self-approval Warning if applicable */}
                {isSelfApprovalRisk && caseDetail.case.status === 'AWAITING_APPROVAL' && (
                  <div className="p-2.5 bg-amber-950/70 border border-amber-800 rounded-lg text-amber-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
                    <span>
                      {isRtl
                        ? 'تنبيه الأعين الأربع: أنت من طلب الاعتماد لهذه القضية. لا يمكنك اعتمادها ذاتياً ويجب أن يقوم بذلك مراجع آخر.'
                        : 'Four-Eyes Alert: You requested approval for this case. Self-approval is strictly forbidden.'}
                    </span>
                  </div>
                )}

                {/* Regulator Read-Only Alert */}
                {currentPersona.role === 'REGULATOR' && (
                  <div className="p-2.5 bg-blue-950/70 border border-blue-800 rounded-lg text-blue-300 text-xs flex items-center gap-2">
                    <Lock className="w-4 h-4 shrink-0 text-blue-400" />
                    <span>
                      {isRtl
                        ? 'حساب رقابي للقراءة فقط (REGULATOR): لا تملك صلاحية تعديل حالة القضايا.'
                        : 'Regulator read-only access: Write transitions are prohibited for REGULATOR role.'}
                    </span>
                  </div>
                )}

                {/* Action Buttons Row */}
                <div className="flex flex-wrap gap-2 pt-1">
                  {caseDetail.case.status === 'OPEN' && (
                    <button
                      onClick={() => promptTransition('start_review')}
                      disabled={currentPersona.role === 'REGULATOR'}
                      className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-50"
                    >
                      <UserCheck className="w-3.5 h-3.5" />
                      <span>{isRtl ? 'بدء المراجعة والتحقيق' : 'Start Review'}</span>
                    </button>
                  )}

                  {caseDetail.case.status === 'IN_REVIEW' && (
                    <>
                      <button
                        onClick={() => promptTransition('request_approval')}
                        disabled={currentPersona.role === 'REGULATOR'}
                        className="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-50"
                      >
                        <Clock className="w-3.5 h-3.5" />
                        <span>{isRtl ? 'طلب اعتماد الحل (إحالة للأعين الأربع)' : 'Request Approval (Four-Eyes)'}</span>
                      </button>

                      <button
                        onClick={() => promptTransition('escalate')}
                        disabled={currentPersona.role === 'REGULATOR'}
                        className="px-3 py-2 bg-rose-600/80 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>{isRtl ? 'تصعيد القضية للإدارة' : 'Escalate'}</span>
                      </button>
                    </>
                  )}

                  {caseDetail.case.status === 'AWAITING_APPROVAL' && (
                    <>
                      <button
                        onClick={() => promptTransition('approve_resolution')}
                        disabled={
                          currentPersona.role === 'REGULATOR' ||
                          currentPersona.role === 'OPERATOR' ||
                          isSelfApprovalRisk
                        }
                        title={
                          isSelfApprovalRisk
                            ? 'Self-approval strictly prohibited under Four-Eyes principle'
                            : 'Approve case resolution'
                        }
                        className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{isRtl ? 'اعتماد الحل رسمياً (Four-Eyes)' : 'Approve Resolution'}</span>
                      </button>

                      <button
                        onClick={() => promptTransition('reject_resolution')}
                        disabled={currentPersona.role === 'REGULATOR' || currentPersona.role === 'OPERATOR'}
                        className="px-3 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-40"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>{isRtl ? 'رفض الحل وإعادة للعمل' : 'Reject & Rework'}</span>
                      </button>

                      <button
                        onClick={() => promptTransition('escalate')}
                        disabled={currentPersona.role === 'REGULATOR'}
                        className="px-3 py-2 bg-rose-700/80 hover:bg-rose-600 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>{isRtl ? 'تصعيد للإدارة' : 'Escalate'}</span>
                      </button>
                    </>
                  )}

                  {caseDetail.case.status === 'RESOLVED' && (
                    <button
                      onClick={() => promptTransition('close')}
                      disabled={currentPersona.role === 'REGULATOR' || currentPersona.role === 'OPERATOR'}
                      className="px-3.5 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-40"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>{isRtl ? 'إغلاق وأرشفة القضية' : 'Close Case'}</span>
                    </button>
                  )}

                  {caseDetail.case.status === 'CLOSED' && (
                    <button
                      onClick={() => promptTransition('reopen')}
                      disabled={currentPersona.role !== 'SUPER_ADMIN'}
                      className="px-3.5 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-40"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>{isRtl ? 'إعادة فتح القضية (Admin)' : 'Reopen Case (Admin)'}</span>
                    </button>
                  )}

                  {caseDetail.case.status === 'ESCALATED' && (
                    <button
                      onClick={() => promptTransition('return_to_review')}
                      disabled={currentPersona.role !== 'SUPER_ADMIN'}
                      className="px-3.5 py-2 bg-purple-700 hover:bg-purple-600 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md disabled:opacity-40"
                    >
                      <UserCheck className="w-3.5 h-3.5" />
                      <span>{isRtl ? 'إعادة للمراجعة والتحقيق (Admin)' : 'Return to Review (Admin)'}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Append-Only Case Event Timeline */}
              <div className="bg-cyber-950/70 border border-cyber-800 rounded-xl p-4 space-y-3">
                <h3 className="text-xs font-bold text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>{isRtl ? 'سجل الأحداث الجنائية غير القابل للتعديل (Append-Only)' : 'Immutable Audit Trail (Append-Only)'}</span>
                </h3>

                <div className="space-y-2 mt-2">
                  {caseDetail.events.length === 0 ? (
                    <p className="text-xs text-gray-500">{isRtl ? 'لا توجد أحداث مسجلة' : 'No recorded events'}</p>
                  ) : (
                    caseDetail.events.map((ev) => (
                      <div
                        key={ev.id}
                        className="p-3 bg-cyber-900/80 border border-cyber-800/80 rounded-xl text-xs flex flex-col gap-1 font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-cyan-300 uppercase">{ev.event_type}</span>
                            <span className="text-[10px] text-gray-500">by {ev.actor_sub}</span>
                          </div>
                          <span className="text-[10px] text-gray-500">
                            {new Date(ev.created_at).toLocaleString()}
                          </span>
                        </div>

                        {ev.payload && (
                          <div className="text-[11px] text-gray-400 space-y-0.5 mt-1 bg-cyber-950/60 p-2 rounded border border-cyber-800/40">
                            {ev.payload.from_status && ev.payload.to_status && (
                              <div>
                                {isRtl ? 'الانتقال:' : 'Transition:'}{' '}
                                <span className="text-purple-300 font-bold">{ev.payload.from_status}</span>
                                {' → '}
                                <span className="text-emerald-300 font-bold">{ev.payload.to_status}</span>
                              </div>
                            )}
                            {ev.payload.reason && (
                              <div>
                                {isRtl ? 'المبرر الرقابي:' : 'Justification:'}{' '}
                                <span className="text-gray-300">{ev.payload.reason}</span>
                              </div>
                            )}
                            {ev.payload.assignee && (
                              <div>
                                {isRtl ? 'المعين:' : 'Assignee:'}{' '}
                                <span className="text-cyan-300">{ev.payload.assignee}</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div className="bg-cyber-900 border border-cyber-700 rounded-2xl p-6 w-full max-w-md space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Plus className="w-4 h-4 text-cyan-400" />
              <span>{isRtl ? 'فتح قضية تدقيق مالي جنائي جديدة' : 'Open New Forensic Case'}</span>
            </h3>

            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-400 mb-1">{isRtl ? 'رقم القضية المؤسسي:' : 'Case Number:'}</label>
                <input
                  type="text"
                  value={createForm.case_number}
                  onChange={(e) => setCreateForm({ ...createForm, case_number: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white font-mono focus:border-cyan-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">{isRtl ? 'عنوان القضية:' : 'Case Title:'}</label>
                <input
                  type="text"
                  value={createForm.title}
                  onChange={(e) => setCreateForm({ ...createForm, title: e.target.value })}
                  placeholder={isRtl ? 'مثال: اشتباه تحويلات هيكلة لشركة تجارة عامة' : 'e.g. Suspected smurfing transfers'}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white focus:border-cyan-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">{isRtl ? 'مستوى الخطورة الجنائية:' : 'Severity:'}</label>
                <select
                  value={createForm.severity}
                  onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>

              <div>
                <label className="block text-gray-400 mb-1">{isRtl ? 'التفاصيل والسياق التحقيقي:' : 'Description:'}</label>
                <textarea
                  rows="3"
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-2 bg-cyber-800 hover:bg-cyber-700 text-gray-300 rounded-xl font-semibold"
                >
                  {isRtl ? 'إلغاء' : 'Cancel'}
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl font-semibold shadow-glow-cyan"
                >
                  {isRtl ? 'إنشاء القضية' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Justification / Reason Modal */}
      {showReasonModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div className="bg-cyber-900 border border-cyber-700 rounded-2xl p-6 w-full max-w-md space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Scale className="w-4 h-4 text-amber-400" />
              <span>
                {isRtl ? `تأكيد الإجراء: ${transitionAction}` : `Confirm Action: ${transitionAction}`}
              </span>
            </h3>

            <p className="text-xs text-gray-400">
              {isRtl
                ? 'يتطلب هذا الإجراء تسبيب وتوثيق مبرر رقابي في سجل الأحداث الجنائية غير القابل للتعديل.'
                : 'This action strictly requires justification recorded in the immutable audit trail.'}
            </p>

            <textarea
              rows="3"
              value={transitionReason}
              onChange={(e) => setTransitionReason(e.target.value)}
              placeholder={isRtl ? 'اكتب المبرر الرقابي هنا...' : 'Enter justification reason...'}
              className="w-full bg-cyber-950 border border-cyber-800 rounded-xl p-2.5 text-white text-xs focus:border-cyan-500 focus:outline-none"
            />

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => {
                  setShowReasonModal(false)
                  setTransitionAction(null)
                  setTransitionReason('')
                }}
                className="px-3.5 py-2 bg-cyber-800 hover:bg-cyber-700 text-gray-300 rounded-xl text-xs font-semibold"
              >
                {isRtl ? 'إلغاء' : 'Cancel'}
              </button>
              <button
                type="button"
                onClick={() => handleExecuteTransition(transitionAction, transitionReason)}
                disabled={!transitionReason.trim()}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-semibold shadow-md disabled:opacity-40"
              >
                {isRtl ? 'تأكيد وحفظ السجل' : 'Confirm & Record'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
