import React, { useState } from 'react'
import {
  Activity,
  Sliders,
  Play,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Send,
  Zap,
  BarChart2,
  Clock,
  Layers,
  Sparkles,
} from 'lucide-react'
import { scoreTransactionRisk } from '../utils/aiClient'
import { shortAddress } from '../utils/contract'
import { formatIQD } from '../utils/currency'

export function RiskScorePanel({ onSubmitTx, loading, t, isRtl }) {
  const [formData, setFormData] = useState({
    amount: '9.85',
    dailyVolume: '32.0',
    txCount1h: 3,
    hourOfDay: 23,
    isKycVerified: false,
    sender: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    receiver: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  })

  const [aiVerdict, setAiVerdict] = useState({
    anomaly_score: 84.5,
    risk_tier: 'HIGH',
    is_structuring_suspected: true,
    flag_reasons: [
      'Structuring suspicion: Amount (9.85 ETH) approaches 10 ETH regulatory threshold (98.5%)',
      'Unverified sender KYC on high-value transfer',
      'Off-hours operation (23:00 UTC+3)',
    ],
    model_type: 'Hybrid Random Forest & Rule Engine',
    feature_contributions: [
      { name: 'Structuring Proximity (9.85 ETH / 10.0 ETH)', nameAr: 'قرب المبلغ من سقف الـ 10 إيثيريوم', weight: 38 },
      { name: 'Off-Hours Execution (23:00)', nameAr: 'تنفيذ خارج أوقات الدوام (23:00)', weight: 26 },
      { name: 'Unverified Originator KYC', nameAr: 'غياب التحقق من الهوية (KYC)', weight: 21 },
      { name: 'Rapid Hourly Velocity (3 Txs/1h)', nameAr: 'تكرار التحويلات بالساعة (3 تحويلات)', weight: 15 },
    ],
  })

  const [scoring, setScoring] = useState(false)
  const [submitFeedback, setSubmitFeedback] = useState('')

  const applyPreset = (presetType) => {
    let data = {}
    if (presetType === 'normal') {
      data = {
        amount: '2.5',
        dailyVolume: '5.0',
        txCount1h: 1,
        hourOfDay: 11,
        isKycVerified: true,
        sender: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        receiver: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      }
    } else if (presetType === 'structuring') {
      data = {
        amount: '9.90',
        dailyVolume: '28.0',
        txCount1h: 4,
        hourOfDay: 14,
        isKycVerified: true,
        sender: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
        receiver: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
      }
    } else if (presetType === 'critical') {
      data = {
        amount: '28.0',
        dailyVolume: '75.0',
        txCount1h: 6,
        hourOfDay: 2,
        isKycVerified: false,
        sender: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
        receiver: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
      }
    }
    setFormData(data)
    handleScore(data)
  }

  const handleScore = async (overrideData = null) => {
    setScoring(true)
    const target = overrideData || formData
    try {
      const result = await scoreTransactionRisk(target)
      // Attach feature explainability
      const amountNum = parseFloat(target.amount || 0)
      const isStruct = amountNum >= 9.5 && amountNum < 10.0
      const isOffHours = target.hourOfDay < 8 || target.hourOfDay >= 18
      const features = [
        {
          name: isStruct ? 'Structuring Proximity (Smurfing)' : 'Transaction Magnitude Weight',
          nameAr: isStruct ? 'هيكلة وتجزئة مشبوهة (Smurfing)' : 'وزن حجم المعاملة المالية',
          weight: isStruct ? 40 : amountNum > 10 ? 45 : 15,
        },
        {
          name: isOffHours ? 'Off-Hours High Risk Window' : 'Normal Operating Hours',
          nameAr: isOffHours ? 'عملية خارج ساعات الدوام الرسمي' : 'أوقات الدوام الاعتيادية',
          weight: isOffHours ? 25 : 5,
        },
        {
          name: target.isKycVerified ? 'Verified KYC Credentials' : 'KYC Authentication Missing',
          nameAr: target.isKycVerified ? 'هوية مصرفية موثقة' : 'حساب غير مكتمل التوثيق (KYC)',
          weight: target.isKycVerified ? 5 : 25,
        },
        {
          name: `Temporal Velocity (${target.txCount1h} txs/h)`,
          nameAr: `كثافة وتكرار المعاملات (${target.txCount1h} في الساعة)`,
          weight: Math.min(30, target.txCount1h * 8),
        },
      ]
      setAiVerdict({ ...result, feature_contributions: features })
    } catch (err) {
      console.error('Error scoring risk:', err)
    } finally {
      setScoring(false)
    }
  }

  const handleSubmitToChain = async () => {
    if (!onSubmitTx) return
    const res = await onSubmitTx(formData.receiver, formData.amount)
    if (res?.success) {
      setSubmitFeedback(isRtl ? 'تم بث المعاملة وتوثيقها في عقد AuditEngine بنجاح!' : 'Transaction broadcasted & recorded on AuditEngine!')
      setTimeout(() => setSubmitFeedback(''), 4000)
    }
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              {t?.riskEngineTitle || 'AI AML Risk Evaluation & Structuring Detection Engine'}
            </h2>
            <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              FastAPI + ML Hybrid
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t?.riskEngineSubtitle || 'Pre-execution risk evaluation detecting structuring, velocity spikes, and unverified high-value flows.'}
          </p>
        </div>

        {/* Quick Presets */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => applyPreset('normal')}
            className="px-3 py-1.5 rounded-xl bg-cyber-950 hover:bg-cyber-800 text-emerald-400 border border-emerald-800/80 text-xs font-semibold transition"
          >
            {t?.presetNormal || 'Normal Payroll'}
          </button>
          <button
            onClick={() => applyPreset('structuring')}
            className="px-3 py-1.5 rounded-xl bg-cyber-950 hover:bg-cyber-800 text-amber-400 border border-amber-800/80 text-xs font-semibold transition"
          >
            {t?.presetStructuring || 'Structuring (9.9 ETH)'}
          </button>
          <button
            onClick={() => applyPreset('critical')}
            className="px-3 py-1.5 rounded-xl bg-cyber-950 hover:bg-cyber-800 text-rose-400 border border-rose-800/80 text-xs font-semibold transition"
          >
            {t?.presetCritical || 'Critical Outlier'}
          </button>
        </div>
      </div>

      {submitFeedback && (
        <div className="p-3.5 bg-emerald-950/80 border border-emerald-700 text-emerald-300 rounded-xl text-xs font-medium flex items-center gap-2 shadow-glow-emerald">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          {submitFeedback}
        </div>
      )}

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Form Inputs (7 cols) */}
        <div className="lg:col-span-7 cyber-card rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              {isRtl ? 'معايير المعاملة المالية قيد الفحص' : 'Transaction Evaluation Parameters'}
            </h3>
            <span className="text-[11px] text-gray-400 font-mono">Real-Time Simulation</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'مبلغ التحويل (ETH):' : 'Transfer Amount (ETH):'}
              </label>
              <input
                type="number"
                step="0.01"
                value={formData.amount}
                onChange={(e) => setFormData({ ...formData, amount: e.target.value })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono focus:border-cyan-500 focus:outline-none"
              />
              <span className="text-[10px] text-cyan-400 mt-1 block font-mono">
                ≈ {formatIQD(formData.amount)} ({isRtl ? 'سقف البنك المركزي:' : 'CBI Limit:'} 15M د.ع)
              </span>
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'إجمالي الحجم اليومي (ETH):' : 'Daily Volume (ETH):'}
              </label>
              <input
                type="number"
                step="0.1"
                value={formData.dailyVolume}
                onChange={(e) => setFormData({ ...formData, dailyVolume: e.target.value })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono focus:border-cyan-500 focus:outline-none"
              />
              <span className="text-[10px] text-gray-500 mt-1 block">
                {isRtl ? 'الحد اليومي المعتمد: 50.0 ETH' : 'Daily Policy Threshold: 50.0 ETH'}
              </span>
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'عدد العمليات في الساعة:' : 'Hourly Tx Velocity (1h):'}
              </label>
              <input
                type="number"
                min="1"
                max="50"
                value={formData.txCount1h}
                onChange={(e) => setFormData({ ...formData, txCount1h: parseInt(e.target.value, 10) })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'ساعة التنفيذ (0 - 23):' : 'Hour of Day (0 - 23):'}
              </label>
              <input
                type="number"
                min="0"
                max="23"
                value={formData.hourOfDay}
                onChange={(e) => setFormData({ ...formData, hourOfDay: parseInt(e.target.value, 10) })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono focus:border-cyan-500 focus:outline-none"
              />
              <span className="text-[10px] text-gray-500 mt-1 block font-mono">
                {formData.hourOfDay < 8 || formData.hourOfDay >= 17
                  ? (isRtl ? '⚠️ تنفيذ خارج الدوام الرسمي' : '⚠️ Off-Hours Risk Spike')
                  : (isRtl ? 'ساعات العمل الرسمية' : 'Standard Banking Hours')}
              </span>
            </div>
          </div>

          <div className="text-xs space-y-3 pt-2">
            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'عنوان المرسل (Originator):' : 'Sender Address (Originator):'}
              </label>
              <input
                type="text"
                value={formData.sender}
                onChange={(e) => setFormData({ ...formData, sender: e.target.value })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono text-[11px] focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-medium">
                {isRtl ? 'عنوان المستفيد (Beneficiary):' : 'Receiver Address (Beneficiary):'}
              </label>
              <input
                type="text"
                value={formData.receiver}
                onChange={(e) => setFormData({ ...formData, receiver: e.target.value })}
                className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-3.5 py-2 text-white font-mono text-[11px] focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-between p-3.5 bg-cyber-950 rounded-xl border border-cyber-800">
              <span className="text-gray-300 font-medium">
                {isRtl ? 'توثيق الهوية المصرفية (KYC Verified)' : 'Originator KYC Verified'}
              </span>
              <button
                type="button"
                onClick={() => setFormData({ ...formData, isKycVerified: !formData.isKycVerified })}
                className={`px-3 py-1 rounded-lg text-xs font-bold border transition ${
                  formData.isKycVerified
                    ? 'bg-emerald-950 text-emerald-400 border-emerald-700'
                    : 'bg-rose-950 text-rose-400 border-rose-700'
                }`}
              >
                {formData.isKycVerified ? (isRtl ? 'موثق' : 'Verified') : (isRtl ? 'غير موثق' : 'Unverified')}
              </button>
            </div>
          </div>

          <div className="flex gap-3 pt-3">
            <button
              onClick={() => handleScore()}
              disabled={scoring}
              className="flex-1 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-glow-cyan transition"
            >
              <Play className="w-3.5 h-3.5" />
              {scoring ? (isRtl ? 'جاري التحليل...' : 'Scoring...') : (t?.evaluateRisk || 'Evaluate AI Risk')}
            </button>
            <button
              onClick={handleSubmitToChain}
              disabled={loading}
              className="px-5 py-2.5 bg-cyber-800 hover:bg-cyber-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 transition"
            >
              <Send className="w-3.5 h-3.5" />
              {loading ? (isRtl ? 'جاري البث...' : 'Submitting...') : (t?.submitToChain || 'Submit to Chain')}
            </button>
          </div>
        </div>

        {/* AI Output Card with Radial Meter & XAI Feature Weights (5 cols) */}
        <div className="lg:col-span-5 cyber-card rounded-2xl p-6 shadow-xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <span className="text-xs uppercase font-bold text-gray-400 tracking-wider">
                {isRtl ? 'نتيجة تقييم المخاطر الجنائية' : 'AI Forensic Verdict'}
              </span>
              <span
                className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border ${
                  aiVerdict.risk_tier === 'CRITICAL'
                    ? 'bg-rose-950 text-rose-400 border-rose-800'
                    : aiVerdict.risk_tier === 'HIGH'
                    ? 'bg-amber-950 text-amber-400 border-amber-800'
                    : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                }`}
              >
                {aiVerdict.risk_tier} RISK
              </span>
            </div>

            {/* Score Radial Meter */}
            <div className="my-5 flex flex-col items-center">
              <div className="relative w-36 h-36 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-cyber-950"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={
                      aiVerdict.anomaly_score >= 80
                        ? 'text-rose-500'
                        : aiVerdict.anomaly_score >= 50
                        ? 'text-amber-500'
                        : 'text-emerald-500'
                    }
                    strokeDasharray={`${aiVerdict.anomaly_score}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className="text-3xl font-extrabold font-mono text-white">
                    {aiVerdict.anomaly_score}
                  </span>
                  <span className="text-[10px] text-gray-400 uppercase">{isRtl ? 'مؤشر الشذوذ' : 'Risk Index'}</span>
                </div>
              </div>

              {aiVerdict.is_structuring_suspected && (
                <div className="mt-3 px-3 py-1 bg-amber-950/80 border border-amber-600 text-amber-300 rounded-full text-[11px] font-bold flex items-center gap-1.5 animate-pulse shadow-glow-amber">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  {isRtl ? 'تم رصد شبهة هيكلة وتجزئة (Smurfing)' : 'STRUCTURING / SMURFING DETECTED'}
                </div>
              )}
            </div>

            {/* Explainable AI (XAI) Feature Contributions */}
            <div className="space-y-2 text-xs pt-2 border-t border-cyber-800">
              <h5 className="text-gray-400 font-semibold text-[10px] uppercase tracking-wider flex items-center gap-1.5">
                <BarChart2 className="w-3.5 h-3.5 text-cyan-400" />
                {t?.aiFactorWeights || 'Explainable AI Feature Contributions (XAI)'}
              </h5>
              <div className="space-y-2">
                {(aiVerdict.feature_contributions || []).map((fc, i) => (
                  <div key={i} className="space-y-0.5">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-gray-300">{isRtl ? fc.nameAr : fc.name}</span>
                      <span className="font-mono font-bold text-cyan-400">{fc.weight}%</span>
                    </div>
                    <div className="w-full bg-cyber-950 h-1.5 rounded-full overflow-hidden border border-cyber-800">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                        style={{ width: `${fc.weight}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-cyber-800 text-[10px] text-gray-500 flex items-center justify-between">
            <span>Model: {aiVerdict.model_type}</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" /> Real-Time Inference
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
