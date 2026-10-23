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
  async checkReadyHealth() {
    return this._request('/api/v2/health/ready', { method: 'GET' })
  }
}

// Default singleton instance
export const apiV2Client = new ApiV2Client()
