/**
 * OIDC (Authorization Code + PKCE) login plumbing — R13
 * Specification §8: no client_secret, no password grant, no manual token
 * pasting in institutional mode. Callback is origin + /auth/callback and MUST
 * be registered at the issuer. oidc-client-ts generates and validates the
 * state and nonce per redirect; we only wrap the UserManager surface.
 *
 * Reference (pinned oidc-client-ts 3.5.0):
 *   https://authts.github.io/oidc-client-ts/classes/UserManager.html
 *   https://github.com/authts/oidc-client-ts/blob/main/src/OidcClient.ts
 *
 * Session semantics (spec §8 / brief): signin state and the user session live
 * in sessionStorage (or memory) and are removed at logout — never localStorage,
 * never logged.
 */

import { UserManager, WebStorageStateStore } from 'oidc-client-ts'

const AUTH_CALLBACK_PATH = '/auth/callback'

/** Thrown when the OIDC configuration or the manager surface is unusable. */
export class OidcConfigError extends Error {
  constructor(message) {
    super(`OIDC configuration error: ${message}`)
    this.name = 'OidcConfigError'
  }
}

/**
 * Creates a PKCE Authorization Code UserManager from RuntimeConfig.oidc.
 * response_type="code" enables PKCE (S256 challenge) — oidc-client-ts refuses
 * implicit/hybrid flows here because we never pass a client_secret.
 *
 * @param {{authority:string, client_id:string, redirect_uri:string, scope:string}} oidc
 * @returns {UserManager}
 */
export function createOidcUserManager(oidc) {
  if (!oidc || typeof oidc !== 'object') {
    throw new OidcConfigError('RuntimeConfig.oidc is required in institutional mode')
  }
  const { authority, client_id, redirect_uri, scope } = oidc
  for (const [key, value] of Object.entries({ authority, client_id, redirect_uri, scope })) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new OidcConfigError(`oidc.${key} must be a non-empty string`)
    }
  }
  if (typeof window === 'undefined') {
    throw new OidcConfigError('OIDC login requires a browser environment')
  }

  return new UserManager({
    authority,
    client_id,
    redirect_uri,
    scope,
    response_type: 'code', // Authorization Code + PKCE
    // sessionStorage only: state/nonce and the user session never reach
    // localStorage and are removed at logout.
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  })
}

/**
 * beginLogin — wraps UserManager.signinRedirect.
 * The UserManager generates state + nonce and the PKCE verifier, persists them
 * in the sessionStorage stateStore and redirects to the issuer.
 *
 * @param {UserManager|{signinRedirect: Function}} userManager
 * @returns {Promise<void>}
 */
export async function beginLogin(userManager) {
  if (!userManager || typeof userManager.signinRedirect !== 'function') {
    throw new OidcConfigError('a UserManager (oidc-client-ts) with signinRedirect is required — manual token login is not available in institutional mode')
  }
  await userManager.signinRedirect()
}

/**
 * completeLogin — wraps UserManager.signinCallback (which validates the returned
 * state against the stored state and binds the nonce to the ID token), then
 * returns the session for the identity/me fetch performed by AuthProvider.
 *
 * @param {UserManager|{signinCallback: Function, getUser: Function}} userManager
 * @param {string} [callbackUrl] full callback URL (defaults to window.location)
 * @returns {Promise<{access_token:string, expired?:boolean, profile?:object}>} user session
 */
export async function completeLogin(userManager, callbackUrl) {
  if (!userManager || typeof userManager.signinCallback !== 'function') {
    throw new OidcConfigError('a UserManager (oidc-client-ts) with signinCallback is required')
  }

  let callbackState
  try {
    callbackState = await userManager.signinCallback(callbackUrl)
  } catch (err) {
    // Includes "No matching state found in storage" (replayed/forged callback).
    throw new Error(`Login callback rejected (state/nonce check failed): ${err?.message || err}`)
  }

  if (!callbackState) {
    // The state store was already consumed — a replayed or stale callback.
    throw new Error('Login callback rejected: callback state was already consumed or invalid (possible replay)')
  }

  const user = await userManager.getUser()
  if (!user || !user.access_token) {
    throw new Error('Login callback produced no valid session (state/nonce check failed)')
  }
  if (user.expired) {
    throw new Error('Login session expired before identity binding — please sign in again')
  }
  return user
}

/**
 * endLogin — wraps UserManager.signoutRedirect for institutional logout.
 *
 * @param {UserManager|{signoutRedirect: Function}} userManager
 * @returns {Promise<void>}
 */
export async function endLogin(userManager) {
  if (!userManager || typeof userManager.signoutRedirect !== 'function') {
    throw new OidcConfigError('a UserManager (oidc-client-ts) with signoutRedirect is required')
  }
  await userManager.signoutRedirect()
}

export { AUTH_CALLBACK_PATH }
