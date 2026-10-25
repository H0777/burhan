import React from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'

/**
 * R13 — AuthProvider institutional identity (PKCE OIDC) tests.
 * Covers the named cases from the brief:
 *   login_redirect_callback_state_nonce_checked, callback_replay_rejected,
 *   expired_token_clears_identity, logout_clears_session,
 *   wrong_chain_even_31337_rejected (binding boundary),
 *   account_or_chain_change_clears_identity, stale_signature_result_ignored.
 */

const DEMO_CONFIG = {
  app_mode: 'demo',
  api_origin: '',
  chain_id: 31337,
  rpc_url: 'http://127.0.0.1:8545',
  deployment_id: 'demo-local',
  contracts: {},
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

const runtimeMocks = vi.hoisted(() => ({
  getRuntimeConfig: vi.fn(),
  isInstitutionalMode: vi.fn(),
}))

const clientMocks = vi.hoisted(() => ({
  getApiClient: vi.fn(),
}))

const oidcMocks = vi.hoisted(() => ({
  createOidcUserManager: vi.fn(),
  beginLogin: vi.fn(),
  completeLogin: vi.fn(),
  endLogin: vi.fn(),
}))

vi.mock('../config/runtime.js', async (importOriginal) => ({
  ...(await importOriginal()),
  getRuntimeConfig: runtimeMocks.getRuntimeConfig,
  isInstitutionalMode: runtimeMocks.isInstitutionalMode,
}))

vi.mock('../api/client.js', async (importOriginal) => ({
  ...(await importOriginal()),
  getApiClient: clientMocks.getApiClient,
}))

vi.mock('./oidcClient.js', async (importOriginal) => ({
  ...(await importOriginal()),
  createOidcUserManager: oidcMocks.createOidcUserManager,
  beginLogin: oidcMocks.beginLogin,
  completeLogin: oidcMocks.completeLogin,
  endLogin: oidcMocks.endLogin,
}))

import { AuthProvider, useAuth } from './AuthProvider.jsx'

function makeClient() {
  return {
    getIdentity: vi.fn(),
    setAccessToken: vi.fn(),
    clearAccessToken: vi.fn(),
    request: vi.fn(),
  }
}

function makeUserManager() {
  return {
    getUser: vi.fn(),
    signinRedirect: vi.fn(),
    signinCallback: vi.fn(),
    signoutRedirect: vi.fn(),
    removeUser: vi.fn(),
    clearStaleState: vi.fn(),
  }
}

function TestConsumer({ onAuth, probe }) {
  const auth = useAuth()
  React.useEffect(() => {
    if (onAuth) onAuth(auth)
  }, [auth, onAuth])
  return (
    <div>
      <div data-testid="user-sub">{auth.identity?.sub || 'anonymous'}</div>
      <div data-testid="wallet-address">{auth.identity?.wallet_address || 'unbound'}</div>
      <div data-testid="loading">{auth.isLoading ? 'loading' : 'ready'}</div>
      <div data-testid="institutional">{auth.isInstitutional ? 'yes' : 'no'}</div>
      {auth.error && <div data-testid="error">{auth.error}</div>}
      {probe && <div data-testid="probe">{String(probe(auth))}</div>}
      <button onClick={() => auth.logout()} data-testid="btn-logout">Logout</button>
    </div>
  )
}

describe('AuthProvider (R13)', () => {
  let client
  let userManager

  beforeEach(() => {
    window.sessionStorage.clear()
    client = makeClient()
    userManager = makeUserManager()
    clientMocks.getApiClient.mockReturnValue(client)
    oidcMocks.createOidcUserManager.mockReturnValue(userManager)
    oidcMocks.beginLogin.mockReset()
    oidcMocks.completeLogin.mockReset()
    oidcMocks.endLogin.mockReset()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('demo boot loads identity/me through the SAME configured client', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(DEMO_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(false)
    client.getIdentity.mockResolvedValue({ sub: 'usr-demo', institution_id: 'INST-CENTRAL-DEMO' })

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))
    expect(client.getIdentity).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('user-sub').textContent).toBe('usr-demo')
    expect(screen.getByTestId('institutional').textContent).toBe('no')
    expect(oidcMocks.createOidcUserManager).not.toHaveBeenCalled()
  })

  it('institutional boot restores a stored non-expired session and fetches identity with its token', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue({ access_token: 'stored-token', expired: false })
    client.getIdentity.mockResolvedValue({ sub: 'usr-auditor', institution_id: 'INST-CBI-IQ-01' })

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    await waitFor(() => expect(screen.getByTestId('user-sub').textContent).toBe('usr-auditor'))
    expect(client.setAccessToken).toHaveBeenCalledWith('stored-token')
    expect(client.getIdentity).toHaveBeenCalledTimes(1)
  })

  it('institutional boot without a stored session leaves LoginScreen state (no error, no manual token)', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue(null)

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))
    expect(screen.getByTestId('user-sub').textContent).toBe('anonymous')
    expect(screen.queryByTestId('error')).toBeNull()
    expect(client.getIdentity).not.toHaveBeenCalled()
  })

  it('login_redirect_callback_state_nonce_checked — login wraps signinRedirect; completeLogin wraps callback then identity/me', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue(null)
    oidcMocks.beginLogin.mockImplementation((um) => um.signinRedirect())
    oidcMocks.completeLogin.mockImplementation(async (um, url) => {
      expect(url).toContain('/auth/callback?code=')
      await um.signinCallback(url)
      return { access_token: 'code-exchanged-token', expired: false }
    })
    client.getIdentity.mockResolvedValue({ sub: 'usr-oidc', institution_id: 'INST-CBI-IQ-01', role: 'AUDITOR' })

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(a) => { authRef = a }} />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))

    await act(async () => { await authRef.login() })
    expect(userManager.signinRedirect).toHaveBeenCalledTimes(1)

    let identity
    await act(async () => {
      identity = await authRef.completeLogin('http://localhost:3000/auth/callback?code=c&state=s')
    })

    expect(userManager.signinCallback).toHaveBeenCalledWith('http://localhost:3000/auth/callback?code=c&state=s')
    expect(client.setAccessToken).toHaveBeenCalledWith('code-exchanged-token')
    expect(client.getIdentity).toHaveBeenCalledTimes(1)
    expect(identity.sub).toBe('usr-oidc')
    expect(screen.getByTestId('user-sub').textContent).toBe('usr-oidc')
  })

  it('callback_replay_rejected — consumed callback state surfaces an error and never fetches identity', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue(null)
    oidcMocks.completeLogin.mockRejectedValue(new Error('Login callback rejected: callback state was already consumed or invalid (possible replay)'))

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(a) => { authRef = a }} />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))

    await expect(
      authRef.completeLogin('http://localhost:3000/auth/callback?code=c&state=s')
    ).rejects.toThrow(/replay|state/i)

    expect(client.getIdentity).not.toHaveBeenCalled()
    expect(screen.getByTestId('user-sub').textContent).toBe('anonymous')
  })

  it('expired_token_clears_identity — expired session token never reaches the client/identity', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue(null)
    oidcMocks.completeLogin.mockRejectedValue(new Error('Login session expired before identity binding — please sign in again'))

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(a) => { authRef = a }} />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))

    await act(async () => {
      await expect(
        authRef.completeLogin('http://localhost:3000/auth/callback?code=c&state=s')
      ).rejects.toThrow(/expired/)
    })

    expect(client.setAccessToken).not.toHaveBeenCalled()
    expect(client.getIdentity).not.toHaveBeenCalled()
    expect(screen.getByTestId('user-sub').textContent).toBe('anonymous')
    expect(screen.getByTestId('error').textContent).toMatch(/expired/)
  })

  it('logout_clears_session — removeUser + clearStaleState + signoutRedirect and local identity is gone', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG)
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue({ access_token: 'stored-token', expired: false })
    client.getIdentity.mockResolvedValue({ sub: 'usr-active', institution_id: 'INST-CBI' })
    oidcMocks.endLogin.mockImplementation((um) => um.signoutRedirect())

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('user-sub').textContent).toBe('usr-active'))

    await act(async () => {
      screen.getByTestId('btn-logout').click()
      // logout is async; allow the promise chain to settle
      await Promise.resolve()
    })
    await waitFor(() => expect(screen.getByTestId('user-sub').textContent).toBe('anonymous'))

    expect(userManager.removeUser).toHaveBeenCalledTimes(1)
    expect(userManager.clearStaleState).toHaveBeenCalledTimes(1)
    expect(userManager.signoutRedirect).toHaveBeenCalledTimes(1)
    expect(client.clearAccessToken).toHaveBeenCalledTimes(1)
  })

  it('wrong_chain_even_31337_rejected — bindWallet refuses a wallet on a different chain than config', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG) // chain_id 1337
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue({ access_token: 't', expired: false })
    client.getIdentity.mockResolvedValue({ sub: 'usr-bind', institution_id: 'INST-CBI' })

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(a) => { authRef = a }} />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))

    const signer = {
      getAddress: vi.fn().mockResolvedValue('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'),
      provider: { getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }) },
      signMessage: vi.fn(),
    }

    await expect(authRef.bindWallet(signer)).rejects.toThrow(/Chain ID mismatch/)
    expect(signer.signMessage).not.toHaveBeenCalled()
    expect(client.request).not.toHaveBeenCalled()
  })

  it('account_or_chain_change_clears_identity + stale_signature_result_ignored', async () => {
    runtimeMocks.getRuntimeConfig.mockReturnValue(INSTITUTIONAL_CONFIG) // chain 1337
    runtimeMocks.isInstitutionalMode.mockReturnValue(true)
    userManager.getUser.mockResolvedValue({ access_token: 't', expired: false })
    client.getIdentity.mockResolvedValue({ sub: 'usr-bind', institution_id: 'INST-CBI' })
    client.request.mockImplementation(async (path) => {
      if (path === '/api/v2/wallet/challenge') {
        return { challenge_id: 'chal-1', message: 'Sign me' }
      }
      if (path === '/api/v2/wallet/verify') {
        return {
          bound: true,
          wallet_address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
          authorization_generation: 1,
          participant_id: '0xp1',
          role: 'AUDITOR',
        }
      }
      return {}
    })

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(a) => { authRef = a }} />
      </AuthProvider>
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('ready'))

    const signer = {
      getAddress: vi.fn().mockResolvedValue('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'),
      provider: { getNetwork: vi.fn().mockResolvedValue({ chainId: 1337n }) },
      signMessage: vi.fn().mockResolvedValue('0xsig'),
    }

    await act(async () => { await authRef.bindWallet(signer) })
    expect(screen.getByTestId('wallet-address').textContent).toBe('0x70997970C51812dc3A010C7d01b50e0d17dc79C8')

    // Account switch clears the bound identity fields...
    let cleared
    await act(async () => {
      cleared = authRef.handleAccountOrChainChanged({ address: '0x1111111111111111111111111111111111111111', chainId: 1337 })
    })
    expect(cleared).toBe(true)
    await waitFor(() => expect(screen.getByTestId('wallet-address').textContent).toBe('unbound'))
    expect(screen.getByTestId('error').textContent).toMatch(/account or chain changed/i)

    // ...and a signature result from the superseded binding session is ignored.
    const staleResult = { wallet_address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', authorization_generation: 2 }
    expect(authRef.acceptSignatureResult({}, staleResult)).toBe(false)
    expect(screen.getByTestId('wallet-address').textContent).toBe('unbound')
  })
})
