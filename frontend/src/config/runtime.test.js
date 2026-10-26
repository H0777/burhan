import { describe, it, expect, vi, afterEach } from 'vitest'

/**
 * R13 — RuntimeConfig is the single source of frontend configuration AFTER load.
 * Specification §8: "RuntimeConfig مصدر الواجهة الوحيد بعد التحميل".
 *
 * RED tests prove the two baseline bugs:
 *  1. mode bug: APP_MODE is a build-time constant, so a fetched institutional
 *     runtime-config.json never controls isInstitutionalMode();
 *  2. config bug: loadRuntimeConfig() silently falls back to defaults when the
 *     config file is missing/corrupt, which still allows rendered writes.
 */

const INSTITUTIONAL_CONFIG = {
  app_mode: 'institutional',
  api_origin: '',
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
}

const DEMO_CONFIG = {
  app_mode: 'demo',
  api_origin: '',
  chain_id: 31337,
  rpc_url: 'http://127.0.0.1:8545',
  deployment_id: 'demo-local',
  contracts: { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
}

const originalFetch = global.fetch

// Fresh module per test so cached config from another test cannot leak.
async function freshRuntime() {
  vi.resetModules()
  return await import('./runtime.js')
}

afterEach(() => {
  global.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('RuntimeConfig single source after load (R13)', () => {
  it('runtime_institutional_controls_mode_after_fetch', async () => {
    const runtime = await freshRuntime()
    // Build-time env default is 'demo'; only the fetched config may control mode.
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => INSTITUTIONAL_CONFIG,
    })

    await runtime.loadRuntimeConfig()

    expect(runtime.getRuntimeConfig().app_mode).toBe('institutional')
    expect(runtime.isInstitutionalMode()).toBe(true)
    expect(runtime.isDemoMode()).toBe(false)
  })

  it('missing_invalid_config_blocks_rendered_writes — missing config rejects instead of silent fallback', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockRejectedValue(new Error('network down'))

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow(/runtime config/i)
    expect(() => runtime.getRuntimeConfig()).toThrow()
  })

  it('missing_invalid_config_blocks_rendered_writes — corrupt JSON rejects', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => {
        throw new SyntaxError('Unexpected token')
      },
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow()
    expect(() => runtime.getRuntimeConfig()).toThrow()
  })

  it('missing_invalid_config_blocks_rendered_writes — api_origin containing /api is rejected', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ...DEMO_CONFIG, api_origin: 'http://127.0.0.1:8000/api' }),
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow(/api_origin/)
    expect(() => runtime.getRuntimeConfig()).toThrow()
  })

  it('strict schema rejects unknown top-level keys', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ...DEMO_CONFIG, secret_hint: 'must-not-pass' }),
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow()
    expect(() => runtime.getRuntimeConfig()).toThrow()
  })

  it('strict schema rejects invalid app_mode values', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ...DEMO_CONFIG, app_mode: 'superuser' }),
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow(/app_mode/)
  })

  it('strict schema requires the oidc block in institutional mode', async () => {
    const runtime = await freshRuntime()
    const { oidc: _oidc, ...withoutOidc } = INSTITUTIONAL_CONFIG
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => withoutOidc,
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow(/oidc/i)
  })

  it('oidc redirect_uri must be origin + /auth/callback', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        ...INSTITUTIONAL_CONFIG,
        oidc: { ...INSTITUTIONAL_CONFIG.oidc, redirect_uri: 'http://evil.example/auth/callback' },
      }),
    })

    await expect(runtime.loadRuntimeConfig()).rejects.toThrow(/redirect_uri/)
  })

  it('demo config with same-origin api_origin loads and mode is demo', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => DEMO_CONFIG,
    })

    await runtime.loadRuntimeConfig()
    expect(runtime.isInstitutionalMode()).toBe(false)
    expect(runtime.getRuntimeConfig().api_origin).toBe('')
  })

  it('wrong_chain_even_31337_rejected — deployment verification matches chainId strictly', async () => {
    const runtime = await freshRuntime()
    const mockProvider = {
      getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }),
      getCode: vi.fn().mockResolvedValue('0x6080604052'),
    }

    await expect(
      runtime.getVerifiedDeployment(
        'INST-TEST',
        mockProvider,
        { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
        1337
      )
    ).rejects.toThrow(/Chain ID mismatch/)
  })

  it('wrong_chain_even_31337_rejected — active chain must equal config.chain_id exactly', async () => {
    const runtime = await freshRuntime()
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => DEMO_CONFIG, // chain_id 31337
    })
    await runtime.loadRuntimeConfig()

    await expect(
      runtime.assertChainIdMatchesConfig({ chainId: 1337n })
    ).rejects.toThrow(/Chain ID mismatch/)
    await expect(
      runtime.assertChainIdMatchesConfig({ chainId: 31337n })
    ).resolves.toBe(true)
  })
})
