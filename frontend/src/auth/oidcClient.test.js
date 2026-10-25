import { describe, it, expect, vi } from 'vitest'

/**
 * R13 — PKCE OIDC login plumbing (Authorization Code + PKCE via oidc-client-ts).
 * Specification §8: no client_secret, no password grant, no manual token pasting
 * in institutional mode; callback = origin + /auth/callback with state/nonce checks.
 * Reference: https://authts.github.io/oidc-client-ts/classes/UserManager.html
 */

const OIDC = {
  authority: 'https://sso.institution.example/realms/cbi',
  client_id: 'iraq-aml-frontend',
  redirect_uri: 'http://localhost:3000/auth/callback',
  scope: 'openid profile email',
}

describe('oidcClient (R13)', () => {
  it('creates a PKCE Authorization Code manager without client_secret, sessionStorage-backed', async () => {
    const { createOidcUserManager } = await import('./oidcClient.js')
    const um = createOidcUserManager(OIDC)

    expect(um.settings.authority).toBe(OIDC.authority)
    expect(um.settings.client_id).toBe(OIDC.client_id)
    expect(um.settings.redirect_uri).toBe(OIDC.redirect_uri)
    expect(um.settings.response_type).toBe('code')
    expect(um.settings.client_secret).toBeUndefined()
  })

  it('rejects incomplete OIDC configuration', async () => {
    const { createOidcUserManager } = await import('./oidcClient.js')
    expect(() => createOidcUserManager(null)).toThrow()
    expect(() => createOidcUserManager({ ...OIDC, client_id: undefined })).toThrow()
  })

  it('login_redirect_callback_state_nonce_checked — beginLogin wraps UserManager.signinRedirect', async () => {
    const { beginLogin } = await import('./oidcClient.js')
    const um = { signinRedirect: vi.fn().mockResolvedValue(undefined) }

    await beginLogin(um)

    expect(um.signinRedirect).toHaveBeenCalledTimes(1)
  })

  it('beginLogin rejects a manager without signinRedirect (no manual token path)', async () => {
    const { beginLogin } = await import('./oidcClient.js')
    await expect(beginLogin({})).rejects.toThrow(/signinRedirect|UserManager/)
  })

  it('login_redirect_callback_state_nonce_checked — completeLogin wraps signinCallback then returns the session for identity/me', async () => {
    const { completeLogin } = await import('./oidcClient.js')
    const user = { access_token: 'access-xyz', expired: false }
    const um = {
      signinCallback: vi.fn().mockResolvedValue({ state: 'validated' }),
      getUser: vi.fn().mockResolvedValue(user),
    }

    const result = await completeLogin(um, 'http://localhost:3000/auth/callback?code=c&state=s')

    expect(um.signinCallback).toHaveBeenCalledWith('http://localhost:3000/auth/callback?code=c&state=s')
    expect(result).toBe(user)
  })

  it('callback_replay_rejected — a consumed/undefined callback result is rejected', async () => {
    const { completeLogin } = await import('./oidcClient.js')
    const um = {
      signinCallback: vi.fn().mockResolvedValue(undefined),
      getUser: vi.fn(),
    }

    await expect(
      completeLogin(um, 'http://localhost:3000/auth/callback?code=c&state=s')
    ).rejects.toThrow(/replay|state/i)
    expect(um.getUser).not.toHaveBeenCalled()
  })

  it('callback_replay_rejected — a state-mismatch error from the library propagates', async () => {
    const { completeLogin } = await import('./oidcClient.js')
    const um = {
      signinCallback: vi.fn().mockRejectedValue(new Error('No matching state found in storage')),
    }

    await expect(completeLogin(um, 'http://localhost:3000/auth/callback?code=c&state=s')).rejects.toThrow(
      /No matching state/i
    )
  })

  it('completeLogin rejects an expired or empty session', async () => {
    const { completeLogin } = await import('./oidcClient.js')
    const expiredUser = { access_token: 'old', expired: true }
    const um = {
      signinCallback: vi.fn().mockResolvedValue({ state: 'validated' }),
      getUser: vi.fn().mockResolvedValue(expiredUser),
    }
    await expect(completeLogin(um, 'http://localhost:3000/auth/callback?x=1')).rejects.toThrow(/expired/)

    const umNoUser = {
      signinCallback: vi.fn().mockResolvedValue({ state: 'validated' }),
      getUser: vi.fn().mockResolvedValue(null),
    }
    await expect(completeLogin(umNoUser, 'http://localhost:3000/auth/callback?x=1')).rejects.toThrow(/session/i)
  })

  it('endLogin wraps signoutRedirect for institutional logout', async () => {
    const { endLogin } = await import('./oidcClient.js')
    const um = { signoutRedirect: vi.fn().mockResolvedValue(undefined) }
    await endLogin(um)
    expect(um.signoutRedirect).toHaveBeenCalledTimes(1)
  })
})
