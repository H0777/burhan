import React, { useState } from 'react'
import {
  Code2,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  Play,
  CheckCircle2,
  FileCode,
  Sparkles,
  ArrowRight,
  GitCommit,
  Check,
} from 'lucide-react'
import { scanSmartContract } from '../utils/aiClient'

const CONTRACT_SAMPLES = {
  clean: {
    name: 'IraqiTreasuryBridge.sol',
    grade: 'A+',
    score: 98,
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title IraqiTreasuryBridge
 * @notice Central Bank of Iraq Compliant Multi-Sig Treasury
 */
contract IraqiTreasuryBridge is AccessControl, ReentrancyGuard {
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    uint256 public constant CBI_THRESHOLD = 10 ether; // 39.6M IQD
    mapping(address => uint256) public balances;

    event DepositLogged(address indexed sender, uint256 amount);
    event WithdrawalAudited(address indexed receiver, uint256 amount, bytes32 proof);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit rejected");
        balances[msg.sender] += msg.value;
        emit DepositLogged(msg.sender, msg.value);
    }

    function withdraw(uint256 amount, bytes32 proof) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer execution failed");

        emit WithdrawalAudited(msg.sender, amount, proof);
    }
}`,
    findings: [],
  },

  backdoored: {
    name: 'BackdooredVault.sol',
    grade: 'F',
    score: 22,
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BackdooredVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY 1: Phishing authorization via tx.origin (CWE-287)
    function emergencyTransfer(address payable recipient, uint256 amount) external {
        require(tx.origin == owner, "Unauthorized");
        recipient.transfer(amount);
    }

    // VULNERABILITY 2: Dangerous selfdestruct backdoor (CWE-284)
    function destroyVault() external {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(owner));
    }

    // VULNERABILITY 3: Reentrancy state change post external call (CWE-829)
    function withdrawAll() external {
        uint256 bal = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Failed");
        balances[msg.sender] = 0; // State changed after external call
    }
}`,
    findings: [
      {
        severity: 'CRITICAL',
        type: 'Authentication via tx.origin (Phishing Vector)',
        typeAr: 'ثغرة مصادقة عبر tx.origin (هجوم تصيد احتيالي)',
        line: 14,
        snippet: 'require(tx.origin == owner, "Unauthorized");',
        desc: 'Using tx.origin for authentication allows malicious contracts to impersonate the owner and drain funds.',
        descAr: 'استخدام tx.origin للتحقق يتيح للعقود الخبيثة انتحال هوية المالك وسحب أموال الخزينة.',
        remediation: 'Replace tx.origin with msg.sender and implement OpenZeppelin AccessControl.',
        cwe: 'CWE-287',
      },
      {
        severity: 'CRITICAL',
        type: 'Self-Destruct Backdoor Opcode',
        typeAr: 'باب خلفي للتدمير الذاتي (Self-Destruct Backdoor)',
        line: 20,
        snippet: 'selfdestruct(payable(owner));',
        desc: 'Selfdestruct opcode enables unilateral destruction of the contract and permanent erasure of forensic evidence.',
        descAr: 'أمر التدمير الذاتي يتيح للمشغل المنفرد إتلاف العقد ومحو الأدلة الجنائية نهائياً.',
        remediation: 'Remove selfdestruct opcode completely. Adopt MultiSig emergency freeze.',
        cwe: 'CWE-284',
      },
      {
        severity: 'HIGH',
        type: 'Reentrancy State Mutation Post-Call',
        typeAr: 'ثغرة إعادة الدخول (Reentrancy Post-Call)',
        line: 28,
        snippet: 'balances[msg.sender] = 0; // After external call',
        desc: 'State variable updated after external transfer call creates classic reentrancy exploit risk.',
        descAr: 'تحديث الرصيد بعد استدعاء التحويل الخارجي يتيح للمهاجم تكرار السحب حتى نفاد السيولة.',
        remediation: 'Adopt Checks-Effects-Interactions pattern or inherit ReentrancyGuard.',
        cwe: 'CWE-829',
      },
    ],
  },

  centralized: {
    name: 'CentralizedPrivilegeBypass.sol',
    grade: 'D',
    score: 45,
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CentralizedPrivilegeBypass {
    address public admin;
    uint256 public dailyLimit = 50 ether;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // VULNERABILITY: Secret unlogged override function bypassing audit logs
    function stealthBypassTransfer(address to, uint256 amount) external onlyAdmin {
        // No event emitted, no forensic hash created, no MultiSig required!
        payable(to).transfer(amount);
    }
}`,
    findings: [
      {
        severity: 'HIGH',
        type: 'Unlogged Stealth Transfer (Audit Trail Bypass)',
        typeAr: 'تحويل سري غير موثق (تجاوز سجل التدقيق الجنائي)',
        line: 14,
        snippet: 'payable(to).transfer(amount); // No event',
        desc: 'Direct fund transfer without emitting on-chain events or recording SHA-256 evidence violates CBI cyber-audit regulations.',
        descAr: 'تحويل الأموال دون إطلاق Event أو تسجيل بصمة في ForensicTrail يخالف معايير البنك المركزي.',
        remediation: 'Integrate ForensicTrail.recordIncident() and mandate MultiSig approval.',
        cwe: 'CWE-778',
      },
    ],
  },
}

export function ContractScanner({ t, isRtl }) {
  const [selectedKey, setSelectedKey] = useState('backdoored')
  const [contractName, setContractName] = useState(CONTRACT_SAMPLES.backdoored.name)
  const [sourceCode, setSourceCode] = useState(CONTRACT_SAMPLES.backdoored.code)
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState({
    contract_name: CONTRACT_SAMPLES.backdoored.name,
    security_grade: CONTRACT_SAMPLES.backdoored.grade,
    security_score: CONTRACT_SAMPLES.backdoored.score,
    total_findings: CONTRACT_SAMPLES.backdoored.findings.length,
    scan_timestamp: new Date().toISOString(),
    scanner_engine: 'Hybrid AST Pattern & Gemini 1.5 Analysis',
    findings: CONTRACT_SAMPLES.backdoored.findings,
  })

  const loadPreset = (key) => {
    const item = CONTRACT_SAMPLES[key]
    if (!item) return
    setSelectedKey(key)
    setContractName(item.name)
    setSourceCode(item.code)
    setScanResult({
      contract_name: item.name,
      security_grade: item.grade,
      security_score: item.score,
      total_findings: item.findings.length,
      scan_timestamp: new Date().toISOString(),
      scanner_engine: 'Hybrid AST Pattern Analyzer',
      findings: item.findings,
    })
  }

  const handleScan = async () => {
    setScanning(true)
    try {
      const res = await scanSmartContract(sourceCode, contractName)
      setScanResult(res)
    } catch (err) {
      console.error('Scan error:', err)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className={`space-y-6 ${isRtl ? 'font-arabic text-right' : 'font-sans text-left'}`} dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Top Banner */}
      <div className="cyber-card p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Code2 className="w-5 h-5 text-purple-400" />
              {t?.contractScannerTitle || 'Smart Contract Security & Backdoor AST Auditor'}
            </h2>
            <span className="text-[10px] bg-purple-950 text-purple-300 border border-purple-700 px-2.5 py-0.5 rounded-full font-mono font-bold">
              AST + LLM Hybrid
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            {t?.contractScannerSubtitle || 'Detects insider-planted backdoors, privilege escalation hooks, and reentrancy vectors in Solidity contracts.'}
          </p>
        </div>

        {/* Preset Contract Switchers */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => loadPreset('clean')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
              selectedKey === 'clean'
                ? 'bg-emerald-950 text-emerald-300 border-emerald-600 shadow-glow-emerald'
                : 'bg-cyber-950 text-gray-400 border-cyber-800 hover:text-white'
            }`}
          >
            {isRtl ? 'عقد الخزينة الآمن (A+)' : 'Secure Treasury (A+)'}
          </button>
          <button
            onClick={() => loadPreset('backdoored')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
              selectedKey === 'backdoored'
                ? 'bg-rose-950 text-rose-300 border-rose-600 shadow-glow-rose'
                : 'bg-cyber-950 text-gray-400 border-cyber-800 hover:text-white'
            }`}
          >
            {isRtl ? 'عقد ملغوم بالثغرات (F)' : 'Backdoored Vault (F)'}
          </button>
          <button
            onClick={() => loadPreset('centralized')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
              selectedKey === 'centralized'
                ? 'bg-amber-950 text-amber-300 border-amber-600 shadow-glow-amber'
                : 'bg-cyber-950 text-gray-400 border-cyber-800 hover:text-white'
            }`}
          >
            {isRtl ? 'تجاوز الامتيازات (D)' : 'Stealth Bypass (D)'}
          </button>
        </div>
      </div>

      {/* Editor & Scan Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Solidity Source Code Editor (7 cols) */}
        <div className="lg:col-span-7 cyber-card rounded-2xl p-6 shadow-xl space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-cyber-800">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-purple-400" />
              <input
                type="text"
                value={contractName}
                onChange={(e) => setContractName(e.target.value)}
                className="bg-transparent font-semibold text-white text-sm focus:outline-none border-b border-cyber-700 hover:border-cyber-500 font-mono"
                placeholder="Contract Name"
              />
            </div>
            <span className="text-[11px] text-gray-400 font-mono">Solidity ^0.8.20</span>
          </div>

          <textarea
            rows={18}
            value={sourceCode}
            onChange={(e) => setSourceCode(e.target.value)}
            className="w-full bg-cyber-950 font-mono text-xs text-gray-200 p-4 rounded-xl border border-cyber-800 focus:border-purple-500 focus:outline-none resize-none leading-relaxed"
            placeholder="Paste Solidity code here..."
            dir="ltr"
          />

          <button
            onClick={handleScan}
            disabled={scanning}
            className="w-full py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-glow-indigo transition"
          >
            <Play className="w-3.5 h-3.5" />
            {scanning
              ? (isRtl ? 'جاري الفحص النحوي والتحليل المنطقي...' : 'Scanning AST & Patterns...')
              : (t?.auditContract || 'Audit Contract Security')}
          </button>
        </div>

        {/* Audit Report & Remediation Code (5 cols) */}
        <div className="lg:col-span-5 cyber-card rounded-2xl p-6 shadow-xl flex flex-col justify-between space-y-4">
          <div>
            {/* Header Grade Summary */}
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <span className="text-xs uppercase font-bold text-gray-400 tracking-wider">
                {isRtl ? 'تقرير التدقيق الأمني' : 'Security Audit Verdict'}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400 font-mono">Score: {scanResult.security_score}/100</span>
                <span
                  className={`text-sm font-extrabold font-mono px-3 py-1 rounded-xl border ${
                    scanResult.security_grade === 'A+'
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-700 shadow-glow-emerald'
                      : scanResult.security_grade === 'D'
                      ? 'bg-amber-950 text-amber-400 border-amber-700 shadow-glow-amber'
                      : 'bg-rose-950 text-rose-400 border-rose-700 shadow-glow-rose'
                  }`}
                >
                  Grade {scanResult.security_grade}
                </span>
              </div>
            </div>

            {/* Findings List */}
            <div className="my-4 space-y-3 max-h-[460px] overflow-y-auto pr-1">
              {scanResult.findings.length === 0 ? (
                <div className="p-8 text-center bg-cyber-950 rounded-xl border border-cyber-800 flex flex-col items-center">
                  <ShieldCheck className="w-12 h-12 text-emerald-400 mb-2" />
                  <h4 className="text-sm font-bold text-white">
                    {isRtl ? 'العقد آمن وخالٍ من الأبواب الخلفية' : 'Zero High-Severity Vulnerabilities'}
                  </h4>
                  <p className="text-xs text-gray-400 mt-1 max-w-xs leading-relaxed">
                    {isRtl
                      ? 'العقد يطبق الفصل الصارم بين الصلاحيات (SoD) والحماية من إعادة الدخول وفق متطلبات البنك المركزي.'
                      : 'Contract conforms to strict role-based separation of duties and lacks unlogged privilege backdoors.'}
                  </p>
                </div>
              ) : (
                scanResult.findings.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-rose-300 flex items-center gap-1.5">
                        <AlertOctagon className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                        {isRtl ? f.typeAr || f.type : f.type}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                        {f.cwe}
                      </span>
                    </div>

                    <div className="bg-black/60 p-2 rounded border border-cyber-800 font-mono text-[11px] text-amber-300" dir="ltr">
                      Line {f.line}: {f.snippet}
                    </div>

                    <p className="text-gray-300 text-[11px] leading-relaxed">
                      {isRtl ? f.descAr || f.desc : f.desc}
                    </p>

                    <div className="text-[11px] text-cyan-400 font-medium pt-1 border-t border-cyber-800">
                      <strong>Fix:</strong> {f.remediation}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-cyber-800 text-[10px] text-gray-500 flex items-center justify-between font-mono">
            <span>Engine: {scanResult.scanner_engine}</span>
            <span>{new Date(scanResult.scan_timestamp).toLocaleTimeString()}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
