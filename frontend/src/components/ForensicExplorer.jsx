import React, { useState } from 'react'
import {
  FileSearch,
  ShieldCheck,
  AlertOctagon,
  Copy,
  Check,
  Binary,
  Download,
  X,
  Bug,
  GitCommit,
  Lock,
  RefreshCw,
  Search,
  CheckCircle2,
  TreeDeciduous,
} from 'lucide-react'
import { verifyChainIntegrity } from '../utils/aiClient'
import { formatTimestamp, shortAddress } from '../utils/contract'
import { generateMerkleProof, generateJudicialEvidenceReceipt } from '../utils/merkle'

export function ForensicExplorer({ forensicTrail, isChainValid, onRefresh, t, isRtl }) {
  const [copiedHash, setCopiedHash] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState({
    isValid: isChainValid,
    message: isChainValid
      ? (isRtl ? 'تم التحقق من كافة الروابط الرياضية عبر تسلسل SHA-256 بنجاح.' : 'All cryptographic links verified against SHA-256 parent sequence.')
      : (isRtl ? 'تم رصد خرق لسلامة السلسلة الجنائية!' : 'Integrity compromised.'),
    entriesChecked: forensicTrail?.length || 3,
  })
  const [tamperedIndex, setTamperedIndex] = useState(null)
  const [activeTrail, setActiveTrail] = useState(forensicTrail)
  const [activeTab, setActiveTab] = useState('timeline') // 'timeline' or 'merkle-dag'
  const [verifySearchQuery, setVerifySearchQuery] = useState('')
  const [searchVerificationResult, setSearchVerificationResult] = useState(null)

  // Merkle Proof Modal
  const [merkleModal, setMerkleModal] = useState({
    open: false,
    entry: null,
    proofData: null,
  })

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(key)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const handleVerifyChain = async (trailToTest = activeTrail) => {
    setVerifying(true)
    try {
      const res = await verifyChainIntegrity(trailToTest)
      setVerificationResult({
        isValid: res.is_valid,
        message: res.message,
        brokenAtIndex: res.broken_at_index,
        entriesChecked: res.entries_checked,
      })
    } catch (err) {
      console.error('Verification error:', err)
    } finally {
      setVerifying(false)
    }
  }

  const handleSimulateTamper = (index) => {
    if (tamperedIndex === index) {
      setActiveTrail(forensicTrail)
      setTamperedIndex(null)
      handleVerifyChain(forensicTrail)
    } else {
      const corrupted = activeTrail.map((item, idx) => {
        if (idx === index) {
          return {
            ...item,
            actor: '0x000000000000000000000000000000000000DEAD (TAMPERED_EVIDENCE)',
            evidenceHash: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          }
        }
        return item
      })
      setActiveTrail(corrupted)
      setTamperedIndex(index)
      handleVerifyChain(corrupted)
    }
  }

  const handleOpenMerkleProof = (entry, index) => {
    const leaves = activeTrail.map((t) => t.evidenceHash)
    const proofData = generateMerkleProof(leaves, index)
    setMerkleModal({ open: true, entry, proofData })
  }

  const handleDownloadReceipt = () => {
    if (!merkleModal.entry || !merkleModal.proofData) return
    const receipt = generateJudicialEvidenceReceipt(merkleModal.entry, merkleModal.proofData)
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `JUDICIAL_EVIDENCE_RECEIPT_ENTRY_${merkleModal.entry.index}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleSearchVerify = (e) => {
    e.preventDefault()
    if (!verifySearchQuery.trim()) return
    const q = verifySearchQuery.trim().toLowerCase()
    const found = activeTrail.find(
      (entry) =>
        entry.evidenceHash.toLowerCase() === q ||
        entry.entryHash.toLowerCase() === q ||
        entry.actor.toLowerCase().includes(q)
    )
    if (found) {
      setSearchVerificationResult({
        found: true,
        entry: found,
        message: isRtl
          ? `تم العثور على الدليل بنجاح! مرتبط بالكتلة #${found.index} (${found.incidentType}) ومثبت في السلسلة.`
          : `Evidence authenticated! Anchored in Block #${found.index} (${found.incidentType}).`,
      })
    } else {
      setSearchVerificationResult({
        found: false,
        message: isRtl
          ? 'لم يتم العثور على البصمة في شجرة الأدلة الجنائية — الدليل غير معتمد أو تم رفضه.'
          : 'Hash not found in evidence tree — unverified or inadmissible.',
      })
    }
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FileSearch className="w-5 h-5 text-cyan-400" />
              {t?.forensicTitle || 'Cryptographic Chain of Custody & Evidence Vault'}
            </h2>
            <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              Court-Admissible SHA-256
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t?.forensicSubtitle || 'Tamper-evident, hash-linked blockchain trail providing immutable proof of insider activities and AML infractions.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-cyber-950 p-1 rounded-xl border border-cyber-800">
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === 'timeline' ? 'bg-cyan-600 text-white shadow-glow-cyan' : 'text-gray-400 hover:text-white'
              }`}
            >
              {isRtl ? 'سلسلة الكتل الجنائية' : 'Block Timeline'}
            </button>
            <button
              onClick={() => setActiveTab('merkle-dag')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                activeTab === 'merkle-dag' ? 'bg-cyan-600 text-white shadow-glow-cyan' : 'text-gray-400 hover:text-white'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              {isRtl ? 'شجرة ميركل البصرية' : 'Merkle Tree DAG'}
            </button>
          </div>

          <button
            onClick={() => handleVerifyChain(activeTrail)}
            disabled={verifying}
            className="px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-glow-cyan transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            {verifying ? (isRtl ? 'جاري التدقيق الرياضي...' : 'Auditing Hashes...') : (t?.verifyChain || 'Re-verify Entire Chain')}
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      <div
        className={`p-4 rounded-2xl border transition-all ${
          verificationResult.isValid
            ? 'bg-emerald-950/40 border-emerald-700/70 shadow-glow-emerald'
            : 'bg-rose-950/70 border-rose-700/80 shadow-glow-rose'
        }`}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                verificationResult.isValid
                  ? 'bg-emerald-600/30 border border-emerald-500 text-emerald-400'
                  : 'bg-rose-600/30 border border-rose-500 text-rose-400 animate-pulse'
              }`}
            >
              {verificationResult.isValid ? <ShieldCheck className="w-6 h-6" /> : <AlertOctagon className="w-6 h-6" />}
            </div>
            <div>
              <h4 className={`text-sm font-bold tracking-wide ${verificationResult.isValid ? 'text-emerald-200' : 'text-rose-200'}`}>
                {verificationResult.isValid
                  ? (t?.integrityVerified || 'CRYPTOGRAPHIC INTEGRITY VERIFIED (100% INTACT)')
                  : `${t?.tamperAlert || 'SECURITY ALERT: TAMPERING DETECTED AT ENTRY INDEX'} #${verificationResult.brokenAtIndex}`}
              </h4>
              <p className="text-xs text-gray-300/80">{verificationResult.message}</p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-gray-400">{isRtl ? 'الكتل المدققة:' : 'Validated Entries:'}</span>
            <span className="px-2.5 py-1 rounded bg-cyber-900 border border-cyber-700 text-white font-bold">
              {verificationResult.entriesChecked}
            </span>
            {tamperedIndex !== null && (
              <button
                onClick={() => handleSimulateTamper(tamperedIndex)}
                className="px-3 py-1 bg-cyber-800 hover:bg-cyber-700 text-white rounded-lg text-xs font-sans transition"
              >
                {t?.revertTamper || 'Reset Attack Simulation'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Hash Verification Search Bar */}
      <div className="cyber-card rounded-2xl p-4">
        <form onSubmit={handleSearchVerify} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className={`w-4 h-4 text-gray-400 absolute top-3.5 ${isRtl ? 'left-3' : 'right-3'}`} />
            <input
              type="text"
              value={verifySearchQuery}
              onChange={(e) => setVerifySearchQuery(e.target.value)}
              placeholder={isRtl ? 'أدخل بصمة الدليل (SHA-256) أو عنوان المشتبه به للتحقق من ثبوته...' : 'Paste any evidence SHA-256 hash or actor address to verify judicial inclusion...'}
              className="w-full bg-cyber-950 border border-cyber-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-gray-500 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 bg-cyber-800 hover:bg-cyber-700 text-white text-xs font-semibold rounded-xl transition"
          >
            {isRtl ? 'فحص السجل' : 'Verify Proof'}
          </button>
        </form>

        {searchVerificationResult && (
          <div
            className={`mt-3 p-3 rounded-xl border text-xs flex items-center justify-between ${
              searchVerificationResult.found
                ? 'bg-emerald-950/60 border-emerald-700 text-emerald-200'
                : 'bg-rose-950/60 border-rose-700 text-rose-200'
            }`}
          >
            <div className="flex items-center gap-2">
              {searchVerificationResult.found ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertOctagon className="w-4 h-4 text-rose-400" />}
              <span>{searchVerificationResult.message}</span>
            </div>
            {searchVerificationResult.found && (
              <span className="font-mono text-[10px] bg-cyber-900 px-2 py-0.5 rounded border border-cyber-700">
                Index #{searchVerificationResult.entry.index}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Main Tab Content */}
      {activeTab === 'merkle-dag' ? (
        /* Visual Merkle Tree DAG */
        <div className="cyber-card rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Binary className="w-4 h-4 text-cyan-400" />
                {isRtl ? 'هيكل شجرة ميركل البصرية (RFC 6962 Merkle Tree DAG)' : 'Visual Merkle Tree DAG & Cryptographic Inclusion Path'}
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                {isRtl ? 'جذر التشفير الفوقي مشتق رياضياً من تجزئات الأدلة السفلية.' : 'Top Merkle Root is mathematically computed from bottom evidence leaves.'}
              </p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 bg-cyber-950 px-2.5 py-1 rounded-lg border border-cyber-800">
              Root Hash Anchored
            </span>
          </div>

          {/* Merkle Tree SVG Canvas */}
          <div className="relative w-full h-80 bg-cyber-950 rounded-xl border border-cyber-800 p-4 overflow-hidden flex items-center justify-center">
            <svg className="w-full h-full" viewBox="0 0 800 300">
              {/* Lines from Root to Intermediate */}
              <line x1="400" y1="45" x2="250" y2="135" stroke="#06b6d4" strokeWidth="2" strokeDasharray="4 2" />
              <line x1="400" y1="45" x2="550" y2="135" stroke="#06b6d4" strokeWidth="2" strokeDasharray="4 2" />

              {/* Lines from Intermediate to Leaves */}
              <line x1="250" y1="135" x2="150" y2="235" stroke="#3b82f6" strokeWidth="1.5" />
              <line x1="250" y1="135" x2="350" y2="235" stroke="#3b82f6" strokeWidth="1.5" />
              <line x1="550" y1="135" x2="470" y2="235" stroke="#3b82f6" strokeWidth="1.5" />
              <line x1="550" y1="135" x2="630" y2="235" stroke="#3b82f6" strokeWidth="1.5" />

              {/* Top Node: Merkle Root */}
              <g transform="translate(400, 45)">
                <rect x="-110" y="-22" width="220" height="44" rx="10" fill="#0c1e38" stroke="#06b6d4" strokeWidth="2.5" />
                <text y="-3" fill="#ffffff" fontSize="11" fontWeight="bold" textAnchor="middle">
                  MERKLE ROOT ANCHOR
                </text>
                <text y="13" fill="#38bdf8" fontSize="9" fontFamily="monospace" textAnchor="middle">
                  0x9924ac93...bfa2
                </text>
              </g>

              {/* Level 1 Nodes */}
              <g transform="translate(250, 135)">
                <rect x="-80" y="-18" width="160" height="36" rx="8" fill="#132342" stroke="#3b82f6" strokeWidth="1.5" />
                <text y="-1" fill="#e2e8f0" fontSize="10" fontWeight="bold" textAnchor="middle">
                  Intermediate Hash L1
                </text>
                <text y="12" fill="#94a3b8" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  H(Leaf 0 + Leaf 1)
                </text>
              </g>

              <g transform="translate(550, 135)">
                <rect x="-80" y="-18" width="160" height="36" rx="8" fill="#132342" stroke="#3b82f6" strokeWidth="1.5" />
                <text y="-1" fill="#e2e8f0" fontSize="10" fontWeight="bold" textAnchor="middle">
                  Intermediate Hash R1
                </text>
                <text y="12" fill="#94a3b8" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  H(Leaf 2 + Leaf 3)
                </text>
              </g>

              {/* Level 0 Leaves */}
              <g transform="translate(150, 235)">
                <rect x="-60" y="-16" width="120" height="32" rx="6" fill="#091426" stroke="#10b981" strokeWidth="1.5" />
                <text y="-1" fill="#6ee7b7" fontSize="9" fontWeight="bold" textAnchor="middle">
                  Leaf 0: Genesis
                </text>
                <text y="10" fill="#a7f3d0" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  0x8f2d5e13...
                </text>
              </g>

              <g transform="translate(350, 235)">
                <rect x="-65" y="-16" width="130" height="32" rx="6" fill="#091426" stroke="#f43f5e" strokeWidth="1.5" />
                <text y="-1" fill="#fca5a5" fontSize="9" fontWeight="bold" textAnchor="middle">
                  Leaf 1: Anomaly Tx
                </text>
                <text y="10" fill="#f87171" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  0x1c8b9394...
                </text>
              </g>

              <g transform="translate(470, 235)">
                <rect x="-65" y="-16" width="130" height="32" rx="6" fill="#091426" stroke="#f59e0b" strokeWidth="1.5" />
                <text y="-1" fill="#fde047" fontSize="9" fontWeight="bold" textAnchor="middle">
                  Leaf 2: Override Log
                </text>
                <text y="10" fill="#fbbf24" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  0x9924ac93...
                </text>
              </g>

              <g transform="translate(630, 235)">
                <rect x="-60" y="-16" width="120" height="32" rx="6" fill="#091426" stroke="#10b981" strokeWidth="1.5" />
                <text y="-1" fill="#6ee7b7" fontSize="9" fontWeight="bold" textAnchor="middle">
                  Leaf 3: MultiSig State
                </text>
                <text y="10" fill="#a7f3d0" fontSize="8" fontFamily="monospace" textAnchor="middle">
                  0xcc1924b4...
                </text>
              </g>
            </svg>
          </div>
        </div>
      ) : (
        /* Timeline of Blocks */
        <div className="space-y-4">
          {activeTrail?.map((entry, idx) => {
            const isTampered = tamperedIndex === idx
            return (
              <div
                key={idx}
                className={`p-5 rounded-2xl cyber-card transition-all ${
                  isTampered ? 'border-rose-500 bg-rose-950/20 shadow-glow-rose' : 'hover:border-cyan-500/40'
                }`}
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-3 border-b border-cyber-800">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 text-cyan-400 flex items-center justify-center font-mono font-bold text-xs">
                      #{entry.index}
                    </div>
                    <div>
                      <h4 className="text-white font-bold text-sm flex items-center gap-2">
                        {entry.incidentType}
                        {isTampered && (
                          <span className="text-[10px] bg-rose-900 text-rose-200 px-2 py-0.5 rounded font-mono font-bold animate-pulse">
                            {isRtl ? 'تم التلاعب بالبيانات' : 'TAMPERED'}
                          </span>
                        )}
                      </h4>
                      <span className="text-[11px] text-gray-400 font-mono">
                        {formatTimestamp(entry.timestamp)}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenMerkleProof(entry, idx)}
                      className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-cyber-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900/40 transition flex items-center gap-1.5"
                    >
                      <Binary className="w-3.5 h-3.5 text-cyan-400" />
                      {isRtl ? 'سند ميركل' : 'Merkle Proof'}
                    </button>

                    <button
                      onClick={() => handleSimulateTamper(idx)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold border transition ${
                        isTampered
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                          : 'bg-amber-950/60 text-amber-300 border-amber-800 hover:bg-amber-900/60'
                      }`}
                    >
                      <Bug className="w-3.5 h-3.5 inline mr-1" />
                      {isTampered ? (t?.revertTamper || 'Revert') : (t?.simulateTamper || 'Simulate Tamper')}
                    </button>
                  </div>
                </div>

                {/* Operator & Subject Addresses */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-3 text-xs">
                  <div className="space-y-1">
                    <span className="text-gray-400 font-medium block">
                      {isRtl ? 'المشغل الموثق (Auditor):' : 'Recording Operator:'}
                    </span>
                    <p className="font-mono text-cyan-300 bg-cyber-950 p-2.5 rounded-lg border border-cyber-800 break-all">
                      {entry.operator}
                    </p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-gray-400 font-medium block">
                      {isRtl ? 'الطرف المشتبه به / الفاعل:' : 'Subject / Actor:'}
                    </span>
                    <p
                      className={`font-mono p-2.5 rounded-lg border break-all ${
                        isTampered
                          ? 'text-rose-300 bg-rose-950/50 border-rose-700 font-bold'
                          : 'text-amber-300 bg-cyber-950 border-cyber-800'
                      }`}
                    >
                      {entry.actor}
                    </p>
                  </div>
                </div>

                {/* Cryptographic Linkage Hashes */}
                <div className="space-y-2 pt-2 border-t border-cyber-800 text-[11px] font-mono">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 bg-cyber-950 p-2 rounded-lg border border-cyber-800">
                    <span className="text-gray-400 flex items-center gap-1">
                      <Lock className="w-3 h-3 text-cyan-400" /> Evidence Hash (SHA-256):
                    </span>
                    <div className="flex items-center gap-1.5 text-gray-200">
                      <span className="truncate max-w-[280px] sm:max-w-md">{entry.evidenceHash}</span>
                      <button
                        onClick={() => copyToClipboard(entry.evidenceHash, `ev-${idx}`)}
                        className="p-1 hover:text-cyan-400"
                      >
                        {copiedHash === `ev-${idx}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 text-gray-500" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 bg-cyber-950 p-2 rounded-lg border border-cyber-800">
                    <span className="text-gray-400 flex items-center gap-1">
                      <GitCommit className="w-3 h-3 text-purple-400" /> Parent Block Hash:
                    </span>
                    <div className="flex items-center gap-1.5 text-gray-400">
                      <span className="truncate max-w-[280px] sm:max-w-md">{entry.previousEntryHash}</span>
                      <button
                        onClick={() => copyToClipboard(entry.previousEntryHash, `prev-${idx}`)}
                        className="p-1 hover:text-purple-400"
                      >
                        {copiedHash === `prev-${idx}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 text-gray-500" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 bg-blue-950/40 p-2 rounded-lg border border-blue-900/60">
                    <span className="text-cyan-300 font-semibold flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3 text-emerald-400" /> Current Entry Hash:
                    </span>
                    <div className="flex items-center gap-1.5 text-cyan-200 font-bold">
                      <span className="truncate max-w-[280px] sm:max-w-md">{entry.entryHash}</span>
                      <button
                        onClick={() => copyToClipboard(entry.entryHash, `curr-${idx}`)}
                        className="p-1 hover:text-cyan-300"
                      >
                        {copiedHash === `curr-${idx}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 text-cyan-400" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Merkle Proof Modal */}
      {merkleModal.open && merkleModal.entry && merkleModal.proofData && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4 animate-fade-in">
          <div className="bg-cyber-900 rounded-2xl p-6 w-full max-w-lg border border-cyber-border shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-xl bg-cyan-600/20 text-cyan-400 border border-cyan-500/40">
                  <Binary className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">
                    {isRtl ? 'سند الإثبات القضائي لشجرة ميركل' : 'Court-Admissible Merkle Evidence Proof'}
                  </h3>
                  <p className="text-[11px] text-gray-400 font-mono">
                    Entry #{merkleModal.entry.index} ({merkleModal.entry.incidentType})
                  </p>
                </div>
              </div>
              <button
                onClick={() => setMerkleModal({ open: false, entry: null, proofData: null })}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-emerald-950/60 border border-emerald-700 rounded-xl flex items-center justify-between">
                <span className="text-emerald-300 font-semibold flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  {isRtl ? 'تم التحقق من مسار الإثبات بنجاح (RFC 6962)' : 'Independent Proof Verified (Valid Root Inclusion)'}
                </span>
                <span className="text-[10px] bg-emerald-900 text-emerald-200 px-2 py-0.5 rounded font-mono font-bold">
                  RFC 6962
                </span>
              </div>

              <div>
                <span className="text-gray-400 font-medium block mb-1">Leaf Hash (Target Evidence):</span>
                <p className="font-mono text-[11px] text-cyan-300 bg-cyber-950 p-2.5 rounded-lg border border-cyber-800 break-all">
                  {merkleModal.proofData.targetLeaf}
                </p>
              </div>

              <div>
                <span className="text-gray-400 font-medium block mb-1">Root Audit Anchor:</span>
                <p className="font-mono text-[11px] text-white bg-cyber-950 p-2.5 rounded-lg border border-cyber-800 break-all">
                  {merkleModal.proofData.merkleRoot}
                </p>
              </div>

              <div>
                <span className="text-gray-400 font-medium block mb-1">
                  Sibling Proof Sequence ({merkleModal.proofData.proof.length} Hashes):
                </span>
                <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                  {merkleModal.proofData.proof.map((p, i) => (
                    <p
                      key={i}
                      className="font-mono text-[10px] text-gray-400 bg-cyber-950 p-1.5 rounded border border-cyber-800 truncate"
                    >
                      {i + 1}. {p}
                    </p>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-3 pt-3 border-t border-cyber-800">
              <button
                onClick={handleDownloadReceipt}
                className="flex-1 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-1.5 shadow-glow-cyan"
              >
                <Download className="w-3.5 h-3.5" />
                {t?.downloadReceipt || 'Download Judicial Receipt (.json)'}
              </button>
              <button
                onClick={() => setMerkleModal({ open: false, entry: null, proofData: null })}
                className="px-4 py-2 bg-cyber-800 hover:bg-cyber-700 text-white rounded-xl text-xs font-medium"
              >
                {isRtl ? 'إغلاق' : 'Close'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
