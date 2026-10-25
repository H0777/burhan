import { describe, it, expect, vi, afterEach } from 'vitest'

/**
 * R13 — Spec-conformant API client.
 * Specification §8: api_origin="" (same-origin) or absolute origin WITHOUT /api;
 * the client adds /api/v2 or /api/v3 exactly once. No hardcoded 127.0.0.1 in the
 * institutional client config. POST /api/v3/evidence/verify uses IDs only (spec §5).
 */

const originalFetch = global.fetch

function makeConfig(apiOrigin = '', overrides = {}) {
  return {
    app_mode: 'institutional',
    api_origin: apiOrigin,
    chain_id: 1337,
    rpc_url: 'https://rpc.institution.example',
    deployment_id: 'INST-CBI-PROD-001',
    contracts: { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
    oidc: {
      authority: 'https://sso.institution.example/realms/cbi',
      client_id: 'iraq-aml-frontend',
      redirect_uri: 'http://localhost:3000/auth/callback',
      scope: 'openid profile email',
    },
    ...overrides,
  }
}

function okJson(body) {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
  }
}

afterEach(() => {
  global.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('ApiClient path discipline (R13/F09)', () => {
  it('same_origin_has_one_api_prefix — empty api_origin yields a single /api/v2 prefix', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    global.fetch = vi.fn().mockResolvedValue(okJson({ sub: 'usr-1' }))

    await client.request('/api/v2/identity/me')

    expect(global.fetch).toHaveBeenCalledTimes(1)
    const [url] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v2/identity/me')
    expect(url.split('/api/').length - 1).toBe(1)
  })

  it('external_origin_preserves_path — absolute origin is used verbatim before the single prefix', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig('https://api.bank-iq.example'))
    global.fetch = vi.fn().mockResolvedValue(okJson({ items: [] }))

    await client.listCases({ limit: 10 })

    const [url] = global.fetch.mock.calls[0]
    expect(url).toBe('https://api.bank-iq.example/api/v2/cases?limit=10')
    expect(url).not.toContain('127.0.0.1')
  })

  it('createApiClient rejects an api_origin containing /api', async () => {
    const { createApiClient } = await import('./client.js')
    expect(() => createApiClient(makeConfig('http://127.0.0.1:8000/api'))).toThrow(/api_origin/)
    expect(() => createApiClient(makeConfig('https://host.example/api/v2'))).toThrow(/api_origin/)
  })

  it('createApiClient rejects calls without a resolved RuntimeConfig (no stale singleton)', async () => {
    const { createApiClient } = await import('./client.js')
    expect(() => createApiClient(null)).toThrow()
    expect(() => createApiClient(undefined)).toThrow()
    expect(() => createApiClient({})).toThrow()
  })

  it('paths must start with /api/v2 or /api/v3 exactly once', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    global.fetch = vi.fn().mockResolvedValue(okJson({ status: 'verified' }))

    await expect(client.request('/api/v1/risk/score')).rejects.toThrow(/api\/v2|api\/v3/)
    await expect(client.request('api/v2/cases')).rejects.toThrow()
    await expect(client.request('/api/api/v2/cases')).rejects.toThrow()
    await expect(client.request('/api/v2/evidence/api/v3/verify')).rejects.toThrow()
    await expect(client.request('/api/v3/evidence/verify')).resolves.toBeTruthy()
  })

  it('identity is fetched through the SAME client — no scattered base concatenation', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    global.fetch = vi.fn().mockResolvedValue(okJson({ sub: 'usr-1', role: 'AUDITOR' }))

    await client.getIdentity()

    const [url] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v2/identity/me')
  })

  it('attaches Authorization: Bearer from the client token store', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    client.setAccessToken('oidc-access-token')
    global.fetch = vi.fn().mockResolvedValue(okJson({ sub: 'usr-1' }))

    await client.getIdentity()

    const [, options] = global.fetch.mock.calls[0]
    expect(options.headers['Authorization']).toBe('Bearer oidc-access-token')
  })

  it('surfaces 401/404/422 statuses on thrown errors', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Not authenticated' }),
    })
    await expect(client.getIdentity()).rejects.toMatchObject({ status: 401 })

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Case not found in institution' }),
    })
    await expect(client.getCase('case_x')).rejects.toMatchObject({ status: 404 })

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Duplicate evidence identifiers' }),
    })
    await expect(
      client.verifyEvidenceV3('case_x', ['ev-1', 'ev-1'])
    ).rejects.toMatchObject({ status: 422 })
  })

  it('410 on legacy V2 verify is a clear V3 transition, not silent acceptance', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 410,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        detail: 'V2 evidence verify retired in institutional mode; use /api/v3/evidence/verify',
        v3: '/api/v3/evidence/verify',
      }),
    })

    let caught = null
    await client.verifyEvidence({ incident_id: 1, entries: [] }).catch((e) => { caught = e })

    expect(caught).not.toBeNull()
    expect(caught.status).toBe(410)
    expect(caught.legacyGone).toBe(true)
    expect(String(caught.message)).toMatch(/410|V3/)
  })

  it('verifyEvidenceV3 sends IDs only — no entries, chain_id or contract_address from the browser', async () => {
    const { createApiClient } = await import('./client.js')
    const client = createApiClient(makeConfig(''))
    global.fetch = vi.fn().mockResolvedValue(
      okJson({ status: 'verified', reasons: [], snapshot_id: 'snap-1' })
    )

    await client.verifyEvidenceV3('case_9', ['ev-1', 'ev-2'], 'snap-1')

    const [url, options] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v3/evidence/verify')
    const body = JSON.parse(options.body)
    expect(body).toEqual({ case_id: 'case_9', evidence_ids: ['ev-1', 'ev-2'], snapshot_id: 'snap-1' })
    expect(body.entries).toBeUndefined()
    expect(body.chain_id).toBeUndefined()
    expect(body.contract_address).toBeUndefined()
  })

  it('apiV2Client delegates to the active configured client — no stale hardcoded base URL', async () => {
    const { createApiClient, setActiveApiClient, apiV2Client } = await import('./client.js')
    const client = createApiClient(makeConfig('https://api.bank-iq.example'))
    setActiveApiClient(client)
    global.fetch = vi.fn().mockResolvedValue(okJson({ items: [] }))

    await apiV2Client.listCases({ limit: 5 })

    const [url] = global.fetch.mock.calls[0]
    expect(url).toBe('https://api.bank-iq.example/api/v2/cases?limit=5')

    setActiveApiClient(null)
    // Property access itself throws synchronously before any request is made.
    expect(() => apiV2Client.listCases()).toThrow()
  })

  it('anchor/verify/demo state mapping distinguishes pending/submitted/anchored, verified/invalid/unavailable, demo/legacy', async () => {
    const { mapAnchorState, mapVerificationOutcome } = await import('./client.js')

    expect(mapAnchorState('PENDING')).toBe('pending')
    expect(mapAnchorState('SUBMITTED')).toBe('submitted')
    expect(mapAnchorState('ANCHORED')).toBe('anchored')
    expect(mapAnchorState('FAILED')).toBe('failed')
    expect(mapAnchorState(null)).toBe('unavailable')

    expect(mapVerificationOutcome({ status: 'verified', provenance_status: 'official' }).state).toBe('verified')
    expect(mapVerificationOutcome({ status: 'invalid', provenance_status: 'official' }).state).toBe('invalid')
    expect(mapVerificationOutcome({ status: 'unavailable', provenance_status: 'official' }).state).toBe('unavailable')
    expect(mapVerificationOutcome({ status: 'verified', provenance_status: 'demo' }).state).toBe('demo')
    // HTTP-410 legacy verify is never presented as a blockchain-verified claim
    expect(mapVerificationOutcome({ legacyGone: true }).state).toBe('legacy')
    // An HTTP-only upload (no anchor receipt) must never be labelled anchored
    expect(mapVerificationOutcome({ status: 'verified', provenance_status: 'official', http_only: true }).onChain).toBe(false)
  })
})
