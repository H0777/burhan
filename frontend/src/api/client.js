/**
 * Strict API V2 Client
 * Cyber-Forensic Auditing Framework - Specification §7 (R06)
 * 
 * Provides type-annotated fetch client for authoritative V2 endpoints.
 * Strictly avoids silent fake fallbacks in institutional mode.
 * 
 * @typedef {import('./generated/schema').EvidenceVerificationRequest} EvidenceVerificationRequest
 * @typedef {import('./generated/schema').EvidenceVerificationResult} EvidenceVerificationResult
 * @typedef {import('./generated/schema').PolicyVersion} PolicyVersion
 * @typedef {import('./generated/schema').LiveHealthResponse} LiveHealthResponse
 * @typedef {import('./generated/schema').ReadyHealthResponse} ReadyHealthResponse
 */

const DEFAULT_BASE_URL = 'http://127.0.0.1:8000'

export class ApiV2Client {
  constructor(baseUrl = DEFAULT_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
  }

  /**
   * Internal request helper with strict JSON and error parsing.
   * @private
   */
  async _request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers || {})
    }

    let response
    try {
      response = await fetch(url, { ...options, headers })
    } catch (err) {
      throw new Error(`API Connection Failed: Unable to reach ${url} (${err.message})`)
    }

    const contentType = response.headers.get('content-type') || ''
    let data
    if (contentType.includes('application/json')) {
      data = await response.json()
    } else {
      data = await response.text()
    }

    if (!response.ok) {
      const errorMsg = typeof data === 'object' && data !== null
        ? data.message || data.detail || JSON.stringify(data)
        : String(data)
      const err = new Error(`API Error [${response.status}]: ${errorMsg}`)
      err.status = response.status
      err.body = data
      throw err
    }

    return data
  }

  /**
   * Independently verify an Evidence V2 collection.
   * @param {EvidenceVerificationRequest} request
   * @returns {Promise<EvidenceVerificationResult>}
   */
  async verifyEvidence(request) {
    return this._request('/api/v2/evidence/verify', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  }

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
    return this._request(`/api/v2/policies/active?${params.toString()}`, {
      method: 'GET'
    })
  }

  /**
   * Check process liveness.
   * @returns {Promise<LiveHealthResponse>}
   */
  async checkLiveHealth() {
    return this._request('/api/v2/health/live', { method: 'GET' })
  }

  /**
   * Check subsystem readiness (ML engine, policy engine).
   * @returns {Promise<ReadyHealthResponse>}
   */
  /**
   * Check subsystem readiness (ML engine, policy engine).
   * @returns {Promise<ReadyHealthResponse>}
   */
  async checkReadyHealth() {
    return this._request('/api/v2/health/ready', { method: 'GET' })
  }

  /**
   * List institutional cases with pagination cursor.
   * @param {Object} options
   * @param {number} [options.limit=50]
   * @param {string|null} [options.cursor=null]
   * @param {string|null} [options.token=null]
   */
  async listCases({ limit = 50, cursor = null, token = null } = {}) {
    const params = new URLSearchParams()
    if (limit) params.append('limit', String(limit))
    if (cursor) params.append('cursor', cursor)
    const qs = params.toString() ? `?${params.toString()}` : ''
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return this._request(`/api/v2/cases${qs}`, { method: 'GET', headers })
  }

  /**
   * Get case details, timeline events, and evidence count.
   * @param {string} caseId
   * @param {Object} options
   * @param {string|null} [options.token=null]
   */
  async getCase(caseId, { token = null } = {}) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return this._request(`/api/v2/cases/${caseId}`, { method: 'GET', headers })
  }

  /**
   * Create new institutional case.
   * @param {Object} payload
   * @param {Object} options
   * @param {string|null} [options.token=null]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async createCase(payload, { token = null, idempotencyKey = null } = {}) {
    const headers = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
    return this._request('/api/v2/cases', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
  }

  /**
   * Transition case state with Four-Eyes governance.
   * @param {string} caseId
   * @param {Object} payload
   * @param {Object} options
   * @param {string|null} [options.token=null]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async transitionCase(caseId, payload, { token = null, idempotencyKey = null } = {}) {
    const headers = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
    return this._request(`/api/v2/cases/${caseId}/transition`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
  }

  /**
   * Upload non-fungible evidence file attached to case.
   * @param {string} caseId
   * @param {File|Blob} file
   * @param {Object} options
   * @param {string|null} [options.token=null]
   * @param {string|null} [options.idempotencyKey=null]
   */
  async uploadCaseEvidence(caseId, file, { token = null, idempotencyKey = null } = {}) {
    const url = `${this.baseUrl}/api/v2/cases/${caseId}/evidence`
    const formData = new FormData()
    formData.append('file', file)
    const headers = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    })
    const data = await response.json()
    if (!response.ok) {
      const err = new Error(data.detail || `Upload failed with status ${response.status}`)
      err.status = response.status
      err.body = data
      throw err
    }
    return data
  }

  /**
   * List indexed transactions with server-side pagination and filters.
   * @param {Object} options
   * @param {number} [options.limit=50]
   * @param {string|null} [options.cursor=null]
   * @param {string|null} [options.source=null]
   * @param {string|null} [options.currency=null]
   * @param {string|null} [options.token=null]
   */
  async listTransactions({ limit = 50, cursor = null, source = null, currency = null, token = null } = {}) {
    const params = new URLSearchParams()
    if (limit) params.append('limit', String(limit))
    if (cursor) params.append('cursor', cursor)
    if (source) params.append('source', source)
    if (currency) params.append('currency', currency)
    const qs = params.toString() ? `?${params.toString()}` : ''
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return this._request(`/api/v2/transactions${qs}`, { method: 'GET', headers })
  }

  /**
   * Stream import banking transactions CSV.
   * @param {File|Blob} file
   * @param {Object} options
   * @param {string} [options.source='IQD_CSV']
   * @param {string|null} [options.token=null]
   */
  async importTransactions(file, { source = 'IQD_CSV', token = null } = {}) {
    const url = `${this.baseUrl}/api/v2/imports/transactions?source=${encodeURIComponent(source)}`
    const formData = new FormData()
    formData.append('file', file)
    const headers = {}
    if (token) headers['Authorization'] = `Bearer ${token}`

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    })
    const data = await response.json()
    if (!response.ok) {
      const err = new Error(data.detail || `Import failed with status ${response.status}`)
      err.status = response.status
      err.body = data
      throw err
    }
    return data
  }
}

// Default singleton instance
export const apiV2Client = new ApiV2Client()
