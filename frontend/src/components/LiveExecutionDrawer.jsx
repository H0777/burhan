import React, { useState } from 'react'
import {
  Terminal,
  ChevronUp,
  ChevronDown,
  Trash2,
  Copy,
  Check,
  Zap,
  Activity,
  ShieldCheck,
} from 'lucide-react'

export function LiveExecutionDrawer({ logs, onClearLogs, isRtl }) {
  const [isOpen, setIsOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  const copyLogs = () => {
    const text = logs.map((l) => `[${l.time}] [${l.tag}] ${l.message}`).join('\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const tagColors = {
    EVM: 'text-cyan-400 bg-cyan-950/80 border-cyan-800',
    AI: 'text-purple-400 bg-purple-950/80 border-purple-800',
    FORENSIC: 'text-emerald-400 bg-emerald-950/80 border-emerald-800',
    AML: 'text-amber-400 bg-amber-950/80 border-amber-800',
    MULTISIG: 'text-blue-400 bg-blue-950/80 border-blue-800',
    ERROR: 'text-rose-400 bg-rose-950/80 border-rose-800',
  }

  return (
    <div
      className={`fixed bottom-0 left-0 right-0 z-40 bg-cyber-900 border-t border-cyber-800 shadow-2xl transition-all duration-300 ${
        isOpen ? 'h-72' : 'h-10'
      }`}
    >
      {/* Drawer Bar Header */}
      <div
        onClick={() => setIsOpen(!isOpen)}
        className="h-10 px-6 flex items-center justify-between cursor-pointer bg-cyber-950 hover:bg-cyber-900 transition border-b border-cyber-800 text-xs font-mono select-none"
      >
        <div className="flex items-center gap-3">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-white tracking-wide flex items-center gap-2">
            CYBER-FORENSIC EXECUTION CONSOLE
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          </span>
          <span className="text-[11px] text-gray-400">
            ({logs.length} live system events)
          </span>
        </div>

        <div className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
          {isOpen && (
            <>
              <button
                onClick={copyLogs}
                className="text-gray-400 hover:text-cyan-400 p-1 flex items-center gap-1 text-[11px]"
                title="Copy console output"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy</span>
              </button>
              <button
                onClick={onClearLogs}
                className="text-gray-400 hover:text-rose-400 p-1 flex items-center gap-1 text-[11px]"
                title="Clear logs"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            </>
          )}

          <button
            onClick={() => setIsOpen(!isOpen)}
            className="text-gray-400 hover:text-white p-1"
          >
            {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Console Output Body */}
      {isOpen && (
        <div className="p-4 h-[calc(100%-40px)] overflow-y-auto font-mono text-[11px] space-y-1.5 bg-black/90 text-gray-200">
          {logs.map((log, idx) => (
            <div key={idx} className="flex items-start gap-2 leading-relaxed hover:bg-cyber-900/50 p-0.5 rounded">
              <span className="text-gray-500 shrink-0 font-sans text-[10px]">{log.time}</span>
              <span
                className={`text-[9px] font-bold px-1.5 py-0.2 rounded border uppercase shrink-0 ${
                  tagColors[log.tag] || 'text-gray-400 bg-gray-900 border-gray-700'
                }`}
              >
                {log.tag}
              </span>
              <span className="break-all">{log.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
