/**
 * Strict API V2/V3 Client — R13
 * Cyber-Forensic Auditing Framework — Specification §5, §7, §8 (R06, R07, R13)
 *
 * R13 fixes (F09):
 *  - No hardcoded 127.0.0.1 default base URL: the client is constructed from the
 *    resolved RuntimeConfig via createApiClient(config).
 *  - api_origin is "" (same-origin) or an absolute origin WITHOUT "/api"; the
 *    client prepends nothing else and every path carries /api/v2 or /api/v3
 *    EXACTLY ONCE (rejects /api/api/..., api/v1, ...).
 *  - Identity is fetched through the SAME client (getIdentity()).
 *  - POST /api/v3/evidence/verify sends IDs only (spec §5: the browser never
 *    sends entries/chain_id/contract_address to V3).
 *  - HTTP 410 on legacy V2 verify is surfaced as an explicit V3-transition
 *    error (legacyGone) — never silently accepted as a legacy result.
 *  - The legacy apiV2Client singleton delegates to the active configured client
 *    (set by main.jsx after config load) so unmodified consumers cannot use a
 *    stale hardcoded base URL.
 *
 * @typedef {import('./generated/schema').EvidenceVerificationRequest} EvidenceVerificationRequest
 * @typedef {import('./generated/schema').EvidenceVerificationResult} EvidenceVerificationResult
 * @typedef {import('./generated/schema').PolicyVersion} PolicyVersion
 * @typedef {import('./generated/schema').LiveHealthResponse} LiveHealthResponse
 * @typedef {import('./generated/schema').ReadyHealthResponse} ReadyHealthResponse
 */

const V2_OR_V3_PREFIX = /^\/api\/v[23](\/|$)/

/**
 * True when the PATH portion of an absolute origin contains "/api".
 * Only the path is inspected — a hostname like api.bank-iq.example is legal
 * (the "//api" substring of "https://api..." must not trip the guard).
 */
function originPathContainsApi(origin) {
  const match = /^https?:\/\/[^/]+(\/.*)?$/.exec(origin)
  return Boolean(match && /\/api/i.test(match[1] || ''))
}

/** Error carrying the HTTP status and body of a failed API call. */
export class ApiError extends Error {
  constructor(status, message, body = null) {
    super(`API Error [${status}]: ${message}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
    // R13: HTTP 410 on a legacy V2 write/verify endpoint marks the deliberate
    // V3 contract break (spec §5) — callers must present it as a V3 transition.
    this.legacyGone = status === 410
  }
}

/** Thrown when a caller violates the single-/api/vN-prefix path discipline. */
export class ApiPathError extends Error {
  constructor(message) {
    super(`Invalid API path: ${message}`)
    this.name = 'ApiPathError'
  }
}

/**
 * Maps an on-chain anchor/outbox state to the UI distinction required by R13:
 * pending | submitted | anchored | failed | reorged | unavailable.
 * SUBMITTED is explicitly NOT final (spec §7).
 * @param {string|null|undefined} status
 * @returns {string}
 */
export function mapAnchorState(status) {
  switch (String(status || '').toUpperCase()) {
    case 'PENDING':
      return 'pending'
    case 'SUBMITTED':
      return 'submitted'
    case 'ANCHORED':
      return 'anchored'
    case 'FAILED':
    case 'DEAD':
      return 'failed'
    case 'REORGED':
      return 'unavailable'
    case '':
    case 'NULL':
    case 'UNDEFINED':
      return 'unavailable'
    default:
      return String(status).toLowerCase()
  }
}

/**
 * Maps a verification result (V3 VerificationResult or a client error) to the
 * UI distinction required by R13: verified | invalid | unavailable | demo | legacy.
 * `onChain` is true only for an authoritative verified result — an HTTP-only
 * upload or a legacy 410 response must never be presented as blockchain success.
 * @param {object|null} result
 * @returns {{state: 'verified'|'invalid'|'unavailable'|'demo'|'legacy', onChain: boolean, reasons: string[]}}
 */
export function mapVerificationOutcome(result) {
  if (!result || result.legacyGone || result.status === 410) {
    return { state: 'legacy', onChain: false, reasons: ['Legacy V2 verification retired — use /api/v3/evidence/verify'] }
  }
  const reasons = Array.isArray(result.reasons) ? result.reasons : []
  const provenance = String(result.provenance_status || 'official').toLowerCase()
  if (provenance === 'demo') {
    return { state: 'demo', onChain: false, reasons }
  }
  const status = String(result.status || '').toLowerCase()
  if (status === 'verified' || status === 'invalid' || status === 'unavailable') {
    return { state: status, onChain: status === 'verified' && !result.http_only, reasons }
  }
  return { state: 'unavailable', onChain: false, reasons }
}

export class ApiV2Client {
  /**
   * @param {object} config a resolved RuntimeConfig (see config/runtime.js)
   */
  constructor(config) {
    if (!config || typeof config !== 'object' || typeof config.app_mode !== 'string') {
      throw new Error(
        'ApiClient requires a resolved RuntimeConfig — call createApiClient(config) after loadRuntimeConfig() succeeds'
      )
    }
    if (typeof config.api_origin !== 'string') {
      throw new Error('ApiClient requires RuntimeConfig.api_origin ("" for same-origin)')
    }
    if (originPathContainsApi(config.api_origin)) {
      throw new Error('RuntimeConfig api_origin must NOT contain "/api": the client adds /api/v2 or /api/v3 exactly once')
    }
    this.apiOrigin = config.api_origin.replace(/\/+$/, '')
    this.appMode = config.app_mode
    this.accessToken = null
  }

  /** Stores the current OIDC access token (kept in memory/sessionStorage only). */
  setAccessToken(token) {
    this.accessToken = typeof token === 'string' && token.length > 0 ? token : null
  }

  clearAccessToken() {
    this.accessToken = null
  }

  /**
   * Resolves an API path to the request URL with exactly one /api/v2|v3 prefix.
   * @private
   */
  resolveUrl(path) {
    if (typeof path !== 'string' || !path.startsWith('/')) {
      throw new ApiPathError(`"${path}" must start with "/"`)
    }
    if (!V2_OR_V3_PREFIX.test(path)) {
      throw new ApiPathError(`"${path}" must start with /api/v2 or /api/v3`)
    }
    if (path.slice(1).includes('/api/')) {
      throw new ApiPathError(`"${path}" must contain the /api/vN prefix exactly once`)
    }
    // Same-origin (api_origin="") stays a RELATIVE path: fetch resolves it
    // against the document origin — one /api/vN prefix, no host duplication.
    if (this.apiOrigin === '') {
      return path
    }
    return `${this.apiOrigin}${path}`
  }

  buildHeaders(options = {}) {
    const headers = {
      Accept: 'application/json',
      ...(options.headers || {})
    }
    if (!options.isFormData) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json'
    }
    if (this.accessToken && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.accessToken}`
    }
    return headers
  }

  /**
   * Single request entry point.
   * @param {string} path path starting with /api/v2 or /api/v3 (exactly once)
   * @param {RequestInit} [options]
   * @returns {Promise<unknown>}
   */
  async request(path, options = {}) {
    const url = this.resolveUrl(path)
    const headers = this.buildHeaders(options)

    let response
    try {
      response = await fetch(url, { ...options, headers })
    } catch (err) {
      throw new Error(`API Connection Failed: Unable to reach ${url} (${err.message})`)
    }

    const contentType = response.headers?.get?.('content-type') || ''
    let data
    if (contentType.includes('application/json')) {
      data = await response.json()
    } else {
      data = await response.text().catch(() => null)
    }

    if (!response.ok) {
      const errorMsg = typeof data === 'object' && data !== null
        ? data.message || data.detail || JSON.stringify(data)
        : String(data ?? '')
      throw new ApiError(response.status, errorMsg, data)
    }

    return data
  }

  // ---------------------------------------------------------------- identity

  /** Authenticated institutional identity through the SAME client (spec §8). */
  async getIdentity() {
    return this.request('/api/v2/identity/me', { method: 'GET' })
  }

  // ---------------------------------------------------------------- evidence

  /**
   * V2 evidence verification. In institutional mode the server answers 410
   * with a V3 pointer (deliberate contract break, spec §5) — surfaced as
   * ApiError with legacyGone=true.
   * @param {EvidenceVerificationRequest} request
   * @returns {Promise<EvidenceVerificationResult>}
   */
  async verifyEvidence(request) {
    return this.request('/api/v2/evidence/verify', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  }

  /**
   * POST /api/v3/evidence/verify — IDs only (spec §5): case_id, evidence_ids
   * and an optional snapshot_id. No entries, chain_id or contract_address is
   * ever sent from the browser.
   * @param {string} caseId
   * @param {string[]} evidenceIds
   * @param {string|null} [snapshotId=null]
   * @returns {Promise<unknown>} VerificationResult {status, reasons, snapshot_id, ...}
   */
  async verifyEvidenceV3(caseId, evidenceIds, snapshotId = null) {
    if (!caseId || !Array.isArray(evidenceIds) || evidenceIds.length === 0) {
      throw new ApiPathError('verifyEvidenceV3 requires a caseId and a non-empty evidence_ids list')
    }
    const body = { case_id: String(caseId), evidence_ids: evidenceIds.map(String) }
    if (snapshotId) body.snapshot_id = String(snapshotId)
    return this.request('/api/v3/evidence/verify', {
      method: 'POST',
      body: JSON.stringify(body)
    })
  }

  // ---------------------------------------------------------------- policies

  /**
   * Retrieve active AML/KYC policy version and thresholds.
   * @param {'ETH'|'IQD'} asset
   * @param {string|null} institutionId
   * @returns {Promise<PolicyVersion>}
   */
  async getActivePolicy(asset = 'ETH', institutionId = null) {
    const params = new URLSearchParams({ asset })
    if (institutionId) {
      params.append('institutionId', institutionId)
    }
    return this.request(`/api/v2/policies/active?${params.toString()}`, {
      method: 'GET'
    })
  }

  // ------------------------------------------------------------------ health

  /**
   * Check process liveness.
   * @returns {Promise<LiveHealthResponse>}
   */
  async checkLiveHealth() {
    return this.request('/api/v2/health/live', { method: 'GET' })
  }

  /**
   * Check subsystem readiness (ML engine, policy engine).
   * @returns {Promise<ReadyHealthResponse>}
   */
  async checkReadyHealth() {
    return this.request('/api/v2/health/ready', { method: 'GET' })
  }

  // ------------------------------------------------------------------- cases

  /**
   * List institutional cases with pagination cursor.
   * @param {Object} options
   * @param {number} [options.limit=50]
   * @param {string|null} [options.cursor=null]
   */
  async listCases({ limit = 50, cursor = null } = {}) {
    const params = new URLSearchParams()
    if (limit) params.append('limit', String(limit))
    if (cursor) params.append('cursor', cursor)
    const qs = params.toString() ? `?${params.toString()}` : ''
    return this.request(`/api/v2/cases${qs}`, { method: 'GET' })
  }

  /**
   * Get case details, timeline events, and evidence count.
   * @param {string} caseId
   */
  async getCase(caseId, options = {}) {
    return this.request(`/api/v2/cases/${encodeURIComponent(caseId)}`, { method: 'GET', ...options })
  }

  /**
   * Create new institutional case.
   * @param {Object} payload
   * @param {Object} [options]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async createCase(payload, { idempotencyKey = null } = {}) {
    const headers = idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}
    return this.request('/api/v2/cases', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
  }

  /**
   * Transition case state with Four-Eyes governance.
   * @param {string} caseId
   * @param {Object} payload
   * @param {Object} [options]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async transitionCase(caseId, payload, { idempotencyKey = null } = {}) {
    const headers = idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}
    return this.request(`/api/v2/cases/${encodeURIComponent(caseId)}/transition`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
  }

  /**
   * Upload non-fungible evidence file attached to a case.
   * The response is HTTP-only (stored object); it carries NO blockchain claim —
   * anchoring state arrives later via mapAnchorState (spec §7).
   * @param {string} caseId
   * @param {File|Blob} file
   * @param {Object} [options]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async uploadCaseEvidence(caseId, file, { idempotencyKey = null } = {}) {
    const url = this.resolveUrl(`/api/v2/cases/${encodeURIComponent(caseId)}/evidence`)
    const formData = new FormData()
    formData.append('file', file)
    const headers = {}
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey

    let response
    try {
      response = await fetch(url, { method: 'POST', headers, body: formData })
    } catch (err) {
      throw new Error(`API Connection Failed: Unable to reach ${url} (${err.message})`)
    }
    const data = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new ApiError(response.status, data.detail || `Upload failed with status ${response.status}`, data)
    }
    return data
  }

  // ------------------------------------------------------------ transactions

  /**
   * List indexed transactions with server-side pagination and filters.
   * @param {Object} options
   * @param {number} [options.limit=50]
   * @param {string|null} [options.cursor=null]
   * @param {string|null} [options.source=null]
   * @param {string|null} [options.currency=null]
   */
  async listTransactions({ limit = 50, cursor = null, source = null, currency = null } = {}) {
    const params = new URLSearchParams()
    if (limit) params.append('limit', String(limit))
    if (cursor) params.append('cursor', cursor)
    if (source) params.append('source', source)
    if (currency) params.append('currency', currency)
    const qs = params.toString() ? `?${params.toString()}` : ''
    return this.request(`/api/v2/transactions${qs}`, { method: 'GET' })
  }

  /**
   * Stream import banking transactions CSV.
   * @param {File|Blob} file
   * @param {Object} [options]
   * @param {string} [options.source='IQD_CSV']
   */
  async importTransactions(file, { source = 'IQD_CSV' } = {}) {
    const url = this.resolveUrl(`/api/v2/imports/transactions?source=${encodeURIComponent(source)}`)
    const formData = new FormData()
    formData.append('file', file)
    const headers = {}
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`

    let response
    try {
      response = await fetch(url, { method: 'POST', headers, body: formData })
    } catch (err) {
      throw new Error(`API Connection Failed: Unable to reach ${url} (${err.message})`)
    }
    const data = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new ApiError(response.status, data.detail || `Import failed with status ${response.status}`, data)
    }
    return data
  }

  /**
   * Perform authoritative server-side risk assessment on an indexed transaction.
   * @param {string} transactionId
   * @param {Object} [options]
   * @param {string|null} [options.asOf=null]
   */
  async assessTransaction(transactionId, { asOf = null } = {}) {
    return this.request('/api/v2/risk/assess', {
      method: 'POST',
      body: JSON.stringify({
        transaction_id: transactionId,
        ...(asOf ? { as_of: asOf } : {})
      })
    })
  }

  /**
   * Preview transaction risk score in simulation mode without persisting.
   * @param {string} transactionId
   * @param {Object} [options]
   * @param {string|null} [options.asOf=null]
   */
  async previewRisk(transactionId, { asOf = null } = {}) {
    return this.request('/api/v2/risk/preview', {
      method: 'POST',
      body: JSON.stringify({
        transaction_id: transactionId,
        ...(asOf ? { as_of: asOf } : {})
      })
    })
  }

  /**
   * Get historical assessment records for a specific transaction.
   * @param {string} transactionId
   */
  async getTransactionAssessments(transactionId) {
    return this.request(`/api/v2/risk/assessments/${encodeURIComponent(transactionId)}`, {
      method: 'GET'
    })
  }

  // ----------------------------------------------------------------- reports

  /**
   * Generate authoritative versioned forensic investigation report for a case.
   * @param {string} caseId
   * @param {Object} [options]
   * @param {'en'|'ar'} [options.language='en']
   * @param {string[]|null} [options.evidenceIds=null]
   * @param {string[]|null} [options.assessmentIds=null]
   */
  async generateCaseReport(caseId, { language = 'en', evidenceIds = null, assessmentIds = null } = {}) {
    return this.request(`/api/v2/cases/${encodeURIComponent(caseId)}/reports`, {
      method: 'POST',
      body: JSON.stringify({
        language,
        ...(evidenceIds ? { evidence_ids: evidenceIds } : {}),
        ...(assessmentIds ? { assessment_ids: assessmentIds } : {})
      })
    })
  }

  /**
   * List all historical report versions for a case.
   * @param {string} caseId
   */
  async listCaseReports(caseId) {
    return this.request(`/api/v2/cases/${encodeURIComponent(caseId)}/reports`, {
      method: 'GET'
    })
  }

  /**
   * Retrieve a specific case report version.
   * @param {string} caseId
   * @param {string} reportId
   */
  async getCaseReport(caseId, reportId) {
    return this.request(
      `/api/v2/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}`,
      { method: 'GET' }
    )
  }

  /**
   * Get direct download URL for court-admissible evidence export ZIP bundle.
   * @param {string} caseId
   * @param {string} reportId
   */
  getCaseReportExportUrl(caseId, reportId) {
    return this.resolveUrl(
      `/api/v2/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/export`
    )
  }

  // ----------------------------------------------------------------- scanner

  /**
   * Scan smart contract with honest limitations.
   * @param {string} sourceCode
   * @param {Object} [options]
   * @param {string} [options.mode='patterns']
   */
  async scanContract(sourceCode, { mode = 'patterns' } = {}) {
    return this.request('/api/v2/scanner/scan', {
      method: 'POST',
      body: JSON.stringify({ source_code: sourceCode, mode })
    })
  }

  /**
   * Generate privacy-redacted narrative summary.
   * @param {string} caseTitle
   * @param {Object} [options]
   * @param {string} [options.caseDescription='']
   * @param {string[]} [options.evidenceDescriptions=[]]
   * @param {boolean} [options.enableCloud=false]
   */
  async generateNarrative(caseTitle, { caseDescription = '', evidenceDescriptions = [], enableCloud = false } = {}) {
    return this.request('/api/v2/scanner/narrative', {
      method: 'POST',
      body: JSON.stringify({
        case_title: caseTitle,
        case_description: caseDescription,
        evidence_descriptions: evidenceDescriptions,
        enable_cloud: enableCloud
      })
    })
  }
}

/**
 * Creates an ApiClient bound to a resolved RuntimeConfig (spec §8 single source).
 * @param {object} config RuntimeConfig from loadRuntimeConfig()
 * @returns {ApiV2Client}
 */
export function createApiClient(config) {
  return new ApiV2Client(config)
}

// ---------------------------------------------------------------------------
// Active-client indirection: main.jsx sets the configured client right after a
// successful loadRuntimeConfig(), BEFORE any consumer renders. The legacy
// apiV2Client binding stays import-compatible for components outside the R13
// file set, but can never again serve a stale hardcoded base URL.
// ---------------------------------------------------------------------------

let activeApiClient = null

/**
 * Installs (or clears, with null) the active configured API client.
 * @param {ApiV2Client|null} client
 */
export function setActiveApiClient(client) {
  if (client !== null && !(client instanceof ApiV2Client)) {
    throw new Error('setActiveApiClient requires an ApiV2Client created via createApiClient(config)')
  }
  activeApiClient = client
}

/** Returns the active configured client; throws before configuration loads. */
export function getApiClient() {
  if (!activeApiClient) {
    throw new Error('API client not initialized: runtime configuration was not loaded (config_error state)')
  }
  return activeApiClient
}

export const apiV2Client = new Proxy({}, {
  get(_target, prop) {
    if (!activeApiClient) {
      throw new Error('API client not initialized: runtime configuration was not loaded (config_error state)')
    }
    const value = activeApiClient[prop]
    return typeof value === 'function' ? value.bind(activeApiClient) : value
  },
  has(_target, prop) {
    return Boolean(activeApiClient && prop in activeApiClient)
  },
})
