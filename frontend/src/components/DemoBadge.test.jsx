import React from 'react'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { DemoBadge } from './DemoBadge'
import { loadRuntimeConfig, getRuntimeConfig } from '../config/runtime.js'

/**
 * H14 — the DEMO badge must follow the R13 runtime-config contract exactly:
 *  - absent before loadRuntimeConfig() resolves (no default/demo fallback),
 *  - visible exactly when the loaded config has app_mode === "demo",
 *  - absent when the loaded config is institutional.
 *
 * The REAL runtime module is exercised (no mock of ../config/runtime.js):
 * each test loads a different /runtime-config.json through the same public
 * API main.jsx uses (mocked fetch), mirroring runtime.test.js semantics.
 * Order matters — vitest gives each test file a fresh module registry, so the
 * first test observes the pristine not-loaded state; later tests load configs
 * the way the running app does (config is resolved once per page load).
 */

const DEMO_CONFIG = {
  app_mode: 'demo',
  api_origin: '',
  chain_id: 31337,
  rpc_url: 'http://127.0.0.1:8545',
  deployment_id: 'demo-local',
  contracts: { AuditEngine: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
}

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

const originalFetch = global.fetch

afterEach(() => {
  global.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('DemoBadge tied to runtime app_mode (H14)', () => {
  it('renders nothing before the runtime config has loaded', () => {
    // Fresh module registry for this file: no loadRuntimeConfig() has run yet,
    // so getRuntimeConfig() throws and isDemoMode() is conservatively false.
    expect(() => getRuntimeConfig()).toThrow()

    render(<DemoBadge />)
    expect(screen.queryByTestId('demo-badge')).toBeNull()
  })

  it('renders the badge when the loaded config app_mode is demo', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => DEMO_CONFIG })
    await loadRuntimeConfig()
    expect(getRuntimeConfig().app_mode).toBe('demo')

    render(<DemoBadge />)
    expect(screen.getByTestId('demo-badge')).toBeDefined()
    expect(screen.getByText(/DEMO/)).toBeDefined()
    expect(screen.getByText(/نسخة تجريبية/)).toBeDefined()
  })

  it('renders nothing when the loaded config app_mode is institutional', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => INSTITUTIONAL_CONFIG })
    await loadRuntimeConfig()
    expect(getRuntimeConfig().app_mode).toBe('institutional')

    render(<DemoBadge />)
    expect(screen.queryByTestId('demo-badge')).toBeNull()
  })

  it('badge reappears when a demo config is loaded after an institutional one', async () => {
    // Proves the decision is re-read from the resolved config (never latched):
    // a redeployment that switches app_mode flips the badge with it.
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => DEMO_CONFIG })
    await loadRuntimeConfig()
    expect(getRuntimeConfig().app_mode).toBe('demo')

    render(<DemoBadge />)
    expect(screen.getByTestId('demo-badge')).toBeDefined()
  })
})
