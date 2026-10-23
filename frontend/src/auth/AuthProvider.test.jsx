import React from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import { AuthProvider, useAuth } from './AuthProvider.jsx'

function TestConsumer({ onAuth }) {
  const auth = useAuth()
  React.useEffect(() => {
    if (onAuth) onAuth(auth)
  }, [auth, onAuth])

  return (
    <div>
      <div data-testid="user-sub">{auth.identity?.sub || 'anonymous'}</div>
      <div data-testid="tenant-id">{auth.tenantContext?.institution_id || 'none'}</div>
      <div data-testid="wallet-address">{auth.identity?.wallet_address || 'unbound'}</div>
      <div data-testid="auth-gen">{auth.identity?.authorization_generation ?? 'none'}</div>
      <div data-testid="loading">{auth.isLoading ? 'loading' : 'ready'}</div>
      {auth.error && <div data-testid="error">{auth.error}</div>}
      <button onClick={() => auth.logout()} data-testid="btn-logout">Logout</button>
    </div>
  )
}

describe('Frontend AuthProvider (T13)', () => {
  let originalFetch

  beforeEach(() => {
    originalFetch = global.fetch
    window.sessionStorage.clear()
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('loads initial demo identity when no token exists', async () => {
    const mockIdentity = {
      sub: 'usr-dev-demo',
      institution_id: 'INST-CENTRAL-DEMO',
      role: 'SUPER_ADMIN',
      permissions: ['all'],
      wallet_address: null,
      authorization_generation: null,
    }

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockIdentity,
    })

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    expect(screen.getByTestId('loading').textContent).toBe('loading')

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('ready')
    })

    expect(screen.getByTestId('user-sub').textContent).toBe('usr-dev-demo')
    expect(screen.getByTestId('tenant-id').textContent).toBe('INST-CENTRAL-DEMO')
    expect(screen.getByTestId('wallet-address').textContent).toBe('unbound')
  })

  it('login updates token and fetches institutional identity with Bearer header', async () => {
    const initialIdentity = { sub: 'usr-demo', institution_id: 'INST-DEMO', role: 'NONE' }
    const loggedInIdentity = {
      sub: 'usr-auditor-1',
      institution_id: 'INST-CBI-IQ-01',
      role: 'AUDITOR',
      permissions: ['cases:review'],
    }

    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => initialIdentity,
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => loggedInIdentity,
      })

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(auth) => { authRef = auth }} />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('ready')
    })

    // Perform login
    await act(async () => {
      await authRef.login('test-jwt-token-xyz')
    })

    expect(screen.getByTestId('user-sub').textContent).toBe('usr-auditor-1')
    expect(screen.getByTestId('tenant-id').textContent).toBe('INST-CBI-IQ-01')
    expect(window.sessionStorage.getItem('iraq_aml_oidc_token')).toBe('test-jwt-token-xyz')

    // Verify Authorization header was sent on second fetch
    expect(global.fetch).toHaveBeenLastCalledWith(
      expect.stringContaining('/api/v2/identity/me'),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-jwt-token-xyz',
        }),
      })
    )
  })

  it('logout clears token and identity state', async () => {
    window.sessionStorage.setItem('iraq_aml_oidc_token', 'sample-token')

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        sub: 'usr-active',
        institution_id: 'INST-CBI',
        role: 'AUDITOR',
      }),
    })

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('user-sub').textContent).toBe('usr-active')
    })

    // Click logout
    act(() => {
      screen.getByTestId('btn-logout').click()
    })

    expect(screen.getByTestId('user-sub').textContent).toBe('anonymous')
    expect(window.sessionStorage.getItem('iraq_aml_oidc_token')).toBeNull()
  })

  it('bindWallet executes SIWE challenge signing and updates authorization generation', async () => {
    const mockIdentity = {
      sub: 'usr-auditor-bind',
      institution_id: 'INST-CBI-IQ-01',
      role: 'AUDITOR',
    }

    const mockChallenge = {
      challenge_id: 'chal-1234',
      nonce: 'nonce-abcdef',
      message: 'Sign-in challenge message',
      expires_at: new Date(Date.now() + 300000).toISOString(),
    }

    const mockBinding = {
      bound: true,
      wallet_address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      institution_id: 'INST-CBI-IQ-01',
      participant_id: '0xparticipant123',
      role: 'AUDITOR',
      authorization_generation: 1,
    }

    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockIdentity,
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockChallenge,
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockBinding,
      })

    const mockSigner = {
      getAddress: vi.fn().mockResolvedValue('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'),
      provider: {
        getNetwork: vi.fn().mockResolvedValue({ chainId: 31337n }),
      },
      signMessage: vi.fn().mockResolvedValue('0xsignature1234567890'),
    }

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(auth) => { authRef = auth }} />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('ready')
    })

    // Call bindWallet
    let bindingResult
    await act(async () => {
      bindingResult = await authRef.bindWallet(mockSigner)
    })

    expect(mockSigner.signMessage).toHaveBeenCalledWith('Sign-in challenge message')
    expect(bindingResult.bound).toBe(true)
    expect(screen.getByTestId('wallet-address').textContent).toBe('0x70997970C51812dc3A010C7d01b50e0d17dc79C8')
    expect(screen.getByTestId('auth-gen').textContent).toBe('1')
  })

  it('bindWallet throws when verification fails', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sub: 'usr-1', institution_id: 'INST-1' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ challenge_id: 'chal-fail', message: 'msg' }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ detail: 'Signer address mismatch' }),
      })

    const mockSigner = {
      getAddress: vi.fn().mockResolvedValue('0x1111111111111111111111111111111111111111'),
      signMessage: vi.fn().mockResolvedValue('0xbadsignature'),
    }

    let authRef
    render(
      <AuthProvider>
        <TestConsumer onAuth={(auth) => { authRef = auth }} />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('ready')
    })

    await expect(authRef.bindWallet(mockSigner)).rejects.toThrow('Signer address mismatch')
  })
})
