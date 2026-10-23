#!/usr/bin/env node
/**
 * Contract ABI Drift Checker (T08)
 * Specification §7, §8 (R05, R06, R10)
 * 
 * Verifies that frontend/src/contracts/generated/ ABIs match compiled Hardhat artifacts.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const ROOT_DIR = path.resolve(__dirname, '..')
const ARTIFACTS_DIR = path.join(ROOT_DIR, 'artifacts', 'contracts')
const TARGET_DIR = path.join(ROOT_DIR, 'frontend', 'src', 'contracts', 'generated')

const CONTRACTS_MAP = {
  AuditEngine: path.join(ARTIFACTS_DIR, 'AuditEngine.sol', 'AuditEngine.json'),
  ComplianceRules: path.join(ARTIFACTS_DIR, 'ComplianceRules.sol', 'ComplianceRules.json'),
  MultiSigApproval: path.join(ARTIFACTS_DIR, 'access', 'MultiSigApproval.sol', 'MultiSigApproval.json'),
  RoleManager: path.join(ARTIFACTS_DIR, 'access', 'RoleManager.sol', 'RoleManager.json'),
  ForensicTrail: path.join(ARTIFACTS_DIR, 'forensics', 'ForensicTrail.sol', 'ForensicTrail.json'),
  InsiderActivityLog: path.join(ARTIFACTS_DIR, 'forensics', 'InsiderActivityLog.sol', 'InsiderActivityLog.json'),
}

export function checkContracts() {
  for (const [name, artifactPath] of Object.entries(CONTRACTS_MAP)) {
    if (!fs.existsSync(artifactPath)) {
      console.error(`[ERROR] Compiled artifact missing: ${artifactPath}`)
      return false
    }

    const targetJsonPath = path.join(TARGET_DIR, `${name}.json`)
    if (!fs.existsSync(targetJsonPath)) {
      console.error(`[ERROR] Exported ABI missing: ${targetJsonPath}`)
      return false
    }

    const artifactAbi = JSON.parse(fs.readFileSync(artifactPath, 'utf-8')).abi
    const exportedAbi = JSON.parse(fs.readFileSync(targetJsonPath, 'utf-8'))

    if (JSON.stringify(artifactAbi) !== JSON.stringify(exportedAbi)) {
      console.error(`[ERROR] ABI drift detected for ${name}! Run 'npm run contracts:export' to synchronize.`)
      return false
    }
  }

  console.log('[SUCCESS] All contract ABIs match compiled artifacts (no drift detected).')
  return true
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const ok = checkContracts()
  process.exit(ok ? 0 : 1)
}
