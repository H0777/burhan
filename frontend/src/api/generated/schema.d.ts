/**
 * Generated TypeScript Types for Cyber-Forensic Auditing Framework - OpenAPI V2
 * Specification §7 (R06)
 * 
 * Auto-derived from shared/openapi-v2.json.
 * Consumed by JavaScript files via JSDoc @type annotations.
 */

export interface EvidenceV2 {
  schemaVersion?: number
  schema_version?: number
  chainId: number
  chain_id?: number
  contractAddress: string
  contract_address?: string
  incidentId: number
  incident_id?: number
  evidenceId: number
  evidence_id?: number
  submittedBy: string
  submitted_by?: string
  timestamp: number
  evidenceTypeHash: string
  evidence_type_hash?: string
  descriptionHash: string
  description_hash?: string
  evidenceHash: string
  evidence_hash?: string
  previousEntryHash: string
  previous_entry_hash?: string
  entryHash?: string
  entry_hash?: string
}

export interface SnapshotInfo {
  blockNumber?: number
  block_number?: number
  blockHash?: string
  block_hash?: string
}

export interface EvidenceVerificationRequest {
  caseId?: number
  case_id?: number
  incidentId: number
  incident_id?: number
  evidenceIds?: number[]
  evidence_ids?: number[]
  schemaVersion?: number
  schema_version?: number
  chainId?: number
  chain_id?: number
  contractAddress?: string
  contract_address?: string
  entries: EvidenceV2[]
  snapshot?: SnapshotInfo
}

export interface AnchorInfo {
  chainId?: number
  chain_id?: number
  contractAddress?: string
  contract_address?: string
  count?: number
  head?: string
  blockNumber?: number
  block_number?: number
  blockHash?: string
  block_hash?: string
}

export interface EvidenceVerificationResult {
  status: 'verified' | 'invalid' | 'unavailable'
  provenance_status: string
  checked_entries: EvidenceV2[]
  reasons: string[]
  block_number?: number
  block_hash?: string
  anchor?: AnchorInfo
  source?: string
}

export interface PolicyThresholds {
  large_transaction: string
  daily_volume_limit: string
  max_daily_transactions: number
  max_single_transaction: string
  kyc_required_threshold: string
}

export interface PolicyVersion {
  policy_id: string
  version: string
  asset: 'ETH' | 'IQD'
  currency: string
  scale: number
  thresholds: PolicyThresholds
  effective_at: string
  source: string
  institution_id?: string
}

export interface LiveHealthResponse {
  status: 'live'
  service: string
  timestamp: string
}

export interface ReadyHealthResponse {
  status: 'ready' | 'degraded'
  live: boolean
  ready: boolean
  checks: Record<string, boolean>
  details: Record<string, any>
}

export interface APIErrorResponse {
  code: string
  message: string
  request_id?: string
  details?: Record<string, any>
}

// ---------------------------------------------------------------------------
// TODO-V3 (R13 reconciliation duty — DO NOT hand-edit into real types):
// The V3 OpenAPI export (POST /api/v3/evidence/verify) is generated from the
// R07 backend (codex/verified-remediation lane). At the time of this commit
// R07 had NOT landed, so the V3 request/result interfaces below are NOT
// generated yet and must NOT be fabricated by hand. The frontend client calls
// V3 with IDs only and types the result as `unknown` until the pipeline
// (scripts/export-openapi.py) can regenerate this file with:
//   VerifyEvidenceRequest { case_id: string; evidence_ids: string[]; snapshot_id?: string }
//   VerificationResult  { status: 'verified'|'invalid'|'unavailable'; reasons: string[];
//                         snapshot_id?: string; checked_evidence_ids: string[]; deployment_id?: string }
// Per spec §5: 401 unauthenticated, 404 out-of-institution case/evidence, 422
// malformed/duplicate IDs; V2 verify answers 410 with a V3 pointer in
// institutional mode. Regenerate + reconcile in R13 self-review once R07 lands.
// ---------------------------------------------------------------------------
