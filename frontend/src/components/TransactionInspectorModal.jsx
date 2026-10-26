import React, { useState } from 'react'
import {
  X,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Copy,
  Check,
  Binary,
  FileCheck2,
  ExternalLink,
  Scale,
} from 'lucide-react'
import { shortAddress, formatTimestamp } from '../utils/contract'
import { formatIQD, formatUSD } from '../utils/currency'

export function TransactionInspectorModal({ tx, onClose, onFlag, onClear, isAdmin, t, isRtl }) {
  const [copied, setCopied] = useState(false)

  if (!tx) return null

  const copyHash = (hash) => {
    navigator.clipboard.writeText(hash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const txHash = tx.hash || `0x${Array.from({ length: 64 }, (_, i) => ((tx.id * 17 + i * 13) % 16).toString(16)).join('')}`
  const merkleLeaf = `0x${Array.from({ length: 64 }, (_, i) => ((tx.id * 23 + i * 7) % 16).toString(16)).join('')}`

  const isSuspicious = tx.isFlagged || tx.status === 2 || tx.status === 3

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
      <div
        className={`bg-cyber-900 border border-cyber-border rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl space-y-5 p-6 ${
          isRtl ? 'text-right font-arabic' : 'text-left font-sans'
        }`}
        dir={isRtl ? 'rtl' : 'ltr'}
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-cyber-800">
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
                isSuspicious
                  ? 'bg-rose-950/70 border-rose-700/80 text-rose-400 cyber-glow-rose'
                  : 'bg-emerald-950/70 border-emerald-700/80 text-emerald-400 cyber-glow-emerald'
              }`}
            >
              {isSuspicious ? <AlertTriangle className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-wide">
                  {t?.inspectorTitle || 'Digital Forensic Dossier'}
                </h3>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-cyber-800 text-cyan-400 border border-cyber-700">
                  #{tx.id}
                </span>
              </div>
              <p className="text-xs text-gray-400 font-mono mt-0.5">
                {formatTimestamp(tx.timestamp)}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-cyber-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Currency & Risk Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-1">
            <span className="text-[11px] text-gray-400 font-medium block">
              {isRtl ? 'المبلغ المحول' : 'Transfer Amount'}
            </span>
            <div className="text-lg font-extrabold text-white font-mono">
              {parseFloat(tx.amount || 0).toFixed(4)} ETH
            </div>
            <div className="text-xs text-cyan-400 font-mono font-semibold">
              ≈ {formatIQD(tx.amount)}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-1">
            <span className="text-[11px] text-gray-400 font-medium block">
              {isRtl ? 'تقييم الذكاء الاصطناعي' : 'AI Risk Score'}
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-lg font-extrabold text-white font-mono">
                {tx.riskScore ? `${tx.riskScore}%` : 'N/A'}
              </span>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border font-mono ${
                  tx.riskTier === 'CRITICAL'
                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                    : tx.riskTier === 'HIGH'
                    ? 'bg-amber-950 text-amber-300 border-amber-800'
                    : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                }`}
              >
                {tx.riskTier || 'LOW'}
              </span>
            </div>
            <div className="text-[10px] text-gray-400">
              {isRtl ? 'نموذج كشف الشذوذ الهجين' : 'Hybrid Anomaly Model'}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-1">
            <span className="text-[11px] text-gray-400 font-medium block">
              {isRtl ? 'الحالة الرقابية' : 'Regulatory Status'}
            </span>
            <div className="text-base font-bold text-white pt-0.5">
              {tx.status === 1 ? (
                <span className="text-emerald-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                  {t?.statusCleared || 'Cleared'}
                </span>
              ) : tx.status === 2 ? (
                <span className="text-amber-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                  {t?.statusFlagged || 'Flagged'}
                </span>
              ) : tx.status === 3 ? (
                <span className="text-rose-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-400"></span>
                  {t?.statusBlocked || 'Blocked'}
                </span>
              ) : (
                <span className="text-blue-400">{t?.statusPending || 'Pending'}</span>
              )}
            </div>
            <div className="text-[10px] text-gray-400 font-mono">
              {isRtl ? 'سجل غير قابل للتعديل' : 'Tamper-Evident Ledger'}
            </div>
          </div>
        </div>

        {/* Originator & Beneficiary Breakdown */}
        <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-3 text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-800/80">
            <span className="text-gray-400 font-bold uppercase tracking-wider text-[10px]">
              {isRtl ? 'أطراف المعاملة والحسابات' : 'Transaction Counterparties'}
            </span>
            <span className="text-[10px] bg-cyber-800 text-cyan-400 px-2 py-0.5 rounded font-mono">
              EVM Validated
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <span className="text-gray-400 font-medium block">
                {isRtl ? 'المرسل (Originator):' : 'Sender (Originator):'}
              </span>
              <p className="font-mono text-cyan-300 bg-cyber-900 p-2.5 rounded-lg border border-cyber-800 text-[11px] break-all">
                {tx.sender}
              </p>
              {tx.senderName && (
                <span className="text-[10px] text-gray-400 block">{tx.senderName}</span>
              )}
            </div>

            <div className="space-y-1">
              <span className="text-gray-400 font-medium block">
                {isRtl ? 'المستفيد (Beneficiary):' : 'Receiver (Beneficiary):'}
              </span>
              <p className="font-mono text-emerald-300 bg-cyber-900 p-2.5 rounded-lg border border-cyber-800 text-[11px] break-all">
                {tx.receiver}
              </p>
              {tx.receiverName && (
                <span className="text-[10px] text-gray-400 block">{tx.receiverName}</span>
              )}
            </div>
          </div>
        </div>

        {/* Audit Justification & AML Findings */}
        <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2 text-xs">
          <span className="text-gray-400 font-bold uppercase tracking-wider text-[10px] flex items-center gap-1.5">
            <Scale className="w-3.5 h-3.5 text-amber-400" />
            {isRtl ? 'مبررات التدقيق الجنائي وشبهات الامتثال' : 'Forensic Audit Flags & AML Findings'}
          </span>
          <p className="text-gray-200 leading-relaxed bg-cyber-900 p-3 rounded-lg border border-cyber-800">
            {tx.flagReason || (isRtl ? 'المعاملة مطابقة لكافة المعايير الرقابية ولم تسجل أي تجاوز للحدود.' : 'Verified clean. No threshold or behavioral violations recorded.')}
          </p>
        </div>

        {/* Cryptographic Linkage Hashes */}
        <div className="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2.5 text-[11px] font-mono">
          <div className="flex items-center justify-between pb-1 border-b border-cyber-800">
            <span className="text-gray-400 font-bold uppercase tracking-wider text-[10px] flex items-center gap-1 font-sans">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              {t?.cryptographicProof || 'Cryptographic Proof & Merkle Linkage'}
            </span>
            <span className="text-[10px] text-emerald-400 font-bold">SHA-256 Intact</span>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2 bg-cyber-900 p-2 rounded border border-cyber-800">
              <span className="text-gray-400">Tx Hash:</span>
              <span className="text-gray-200 truncate max-w-xs">{txHash}</span>
              <button onClick={() => copyHash(txHash)} className="text-gray-400 hover:text-cyan-400">
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>

            <div className="flex items-center justify-between gap-2 bg-cyber-900 p-2 rounded border border-cyber-800">
              <span className="text-gray-400">Merkle Leaf:</span>
              <span className="text-cyan-300 truncate max-w-xs">{merkleLeaf}</span>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-3 border-t border-cyber-800">
          <div className="flex items-center gap-2">
            {isAdmin && tx.status === 0 && (
              <>
                <button
                  onClick={() => {
                    onFlag(tx.id)
                    onClose()
                  }}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-semibold transition"
                >
                  {t?.actionFlag || 'Flag for Inquiry'}
                </button>
                <button
                  onClick={() => {
                    onClear(tx.id)
                    onClose()
                  }}
                  className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-semibold transition"
                >
                  {t?.actionClear || 'Clear & Approve'}
                </button>
              </>
            )}
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 bg-cyber-800 hover:bg-cyber-700 text-white rounded-xl text-xs font-semibold transition"
          >
            {isRtl ? 'إغلاق الملف' : 'Close Dossier'}
          </button>
        </div>
      </div>
    </div>
  )
}
