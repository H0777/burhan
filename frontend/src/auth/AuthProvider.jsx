import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react'
import { getRuntimeConfig, isInstitutionalMode } from '../config/runtime.js'
import { getApiClient } from '../api/client.js'
import {
  createOidcUserManager,
  beginLogin as oidcBeginLogin,
  completeLogin as oidcCompleteLogin,
  endLogin as oidcEndLogin,
} from './oidcClient.js'

/**
 * R13 — institutional identity via PKCE OIDC (Authorization Code), wallet
 * binding via SIWE, identity/me fetched through the SAME configured API client
 * (spec §8: "fetch للهوية من العميل نفسه").
 *
 * Session semantics: the OIDC user session lives in oidc-client-ts's
 * sessionStorage store; our transient binding state lives in memory only.
 * logout/endLogin clears both — never localStorage, never logged.
 */

const AuthContext = createContext(null)

/** Memory-only marker for the wallet-bound generation (cleared at logout). */
let walletBindingMemory = null

export function AuthProvider({ children }) {
  const [identity, setIdentity] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [oidcReady, setOidcReady] = useState(() => !isInstitutionalMode())
  const [userManager, setUserManager] = useState(null)

  const lastLoadKeyRef = React.useRef(undefined)

  /**
   * Boot: in institutional mode build the UserManager and try to restore an
   * existing (non-expired) session; in demo mode fetch the demo identity via
   * the same configured client.
   */
  useEffect(() => {
    let isMounted = true

    async function boot() {
      setIsLoading(true)
      setError(null)
      try {
        if (isInstitutionalMode()) {
          const config = getRuntimeConfig()
          const um = createOidcUserManager(config.oidc)
          if (!isMounted) return
          setUserManager(um)
          setOidcReady(true)

          const user = await um.getUser()
          if (!isMounted) return
          if (user && !user.expired && user.access_token) {
            const client = getApiClient()
            client.setAccessToken(user.access_token)
            const me = await client.getIdentity()
            if (!isMounted) return
            setIdentity(me)
          }
          // No stored session → LoginScreen offers beginLogin(). NOT an error.
        } else {
          const client = getApiClient()
          const me = await client.getIdentity()
          if (!isMounted) return
          setIdentity(me)
        }
      } catch (err) {
        if (isMounted) setError(err?.message || String(err))
      } finally {
        if (isMounted) setIsLoading(false)
      }
    }

    boot()
    return () => {
      isMounted = false
    }
  }, [])

  /**
   * PKCE Authorization Code login — wraps UserManager.signinRedirect.
   * No client_secret, no password grant, no manual token (spec §8).
   */
  const login = useCallback(async () => {
    const um = userManager || createOidcUserManager(getRuntimeConfig().oidc)
    if (!userManager) setUserManager(um)
    await oidcBeginLogin(um)
  }, [userManager])

  /**
   * Completes the /auth/callback redirect: signinCallback validates state and
   * nonce, then identity/me is fetched through the SAME client.
   * The returned Identity is also stored in state.
   */
  const completeLogin = useCallback(async (callbackUrl) => {
    const um = userManager || createOidcUserManager(getRuntimeConfig().oidc)
    setIsLoading(true)
    setError(null)
    try {
      const user = await oidcCompleteLogin(um, callbackUrl)
      const client = getApiClient()
      client.setAccessToken(user.access_token)
      const me = await client.getIdentity()
      setIdentity(me)
      lastLoadKeyRef.current = user.access_token
      return me
    } catch (err) {
      setError(err?.message || String(err))
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [userManager])

  /**
   * Institutional logout: ends the OIDC session at the issuer (signoutRedirect)
   * and clears all local identity state. sessionStorage entries owned by the
   * UserManager state store are removed via clearStaleState plus removal of the
   * user entry.
   */
  const logout = useCallback(async () => {
    walletBindingMemory = null
    setIdentity(null)
    setError(null)
    getApiClient().clearAccessToken()
    const um = userManager
    if (um) {
      try {
        await um.removeUser()
        await um.clearStaleState()
      } catch {
        // Local session cleanup best-effort; state must not survive logout.
      }
      await oidcEndLogin(um)
    }
  }, [userManager])

  /**
   * Local-only logout for demo mode (no issuer round-trip).
   */
  const localLogout = useCallback(() => {
    walletBindingMemory = null
    setIdentity(null)
    setError(null)
    getApiClient().clearAccessToken()
  }, [])

  /**
   * SIWE wallet binding through the SAME configured client. Rejects when the
   * signer's chain differs from RuntimeConfig.chain_id (strict, even locally —
   * wrong_chain_even_31337_rejected at the client boundary as well).
   */
  const bindWallet = useCallback(async (signer) => {
    if (!signer || typeof signer.getAddress !== 'function') {
      throw new Error('Valid ethers Signer is required to bind wallet')
    }

    const config = getRuntimeConfig()
    const client = getApiClient()
    const address = await signer.getAddress()

    let chainId = null
    if (signer.provider && typeof signer.provider.getNetwork === 'function') {
      const net = await signer.provider.getNetwork()
      chainId = Number(net.chainId)
    }
    // No chain information → refuse in institutional mode (no silent default).
    if (chainId === null) {
      if (isInstitutionalMode()) {
        throw new Error('Wallet chain unknown: refusing to bind without a verified chain')
      }
      chainId = config.chain_id
    }
    if (chainId !== config.chain_id) {
      throw new Error(
        `Chain ID mismatch: config expects ${config.chain_id}, wallet connected to ${chainId}`
      )
    }

    const challenge = await client.request('/api/v2/wallet/challenge', {
      method: 'POST',
      body: JSON.stringify({ wallet_address: address, chain_id: chainId }),
    })
    if (!challenge || !challenge.challenge_id) {
      throw new Error('Wallet challenge request failed')
    }

    const signature = await signer.signMessage(challenge.message)

    const binding = await client.request('/api/v2/wallet/verify', {
      method: 'POST',
      body: JSON.stringify({ challenge_id: challenge.challenge_id, signature }),
    })

    walletBindingMemory = {
      wallet_address: binding.wallet_address,
      authorization_generation: binding.authorization_generation,
      participant_id: binding.participant_id,
      role: binding.role,
      bound_chain_id: chainId,
    }

    setIdentity((prev) => {
      if (!prev) return prev
      return { ...prev, ...walletBindingMemory }
    })

    return binding
  }, [])

  const refreshIdentity = useCallback(async () => {
    const client = getApiClient()
    const me = await client.getIdentity()
    setIdentity((prev) => ({ ...me, ...(prev?.wallet_address ? { wallet_address: prev.wallet_address } : {}) }))
    return me
  }, [])

  /**
   * account_or_chain_change_clears_identity: when the active account or its
   * chain changes, the bound identity and any in-flight signature MUST be
   * dropped and writes halted until re-binding (spec §8). Returns true when a
   * change was detected (and handled).
   */
  const handleAccountOrChainChanged = useCallback(
    ({ address, chainId }) => {
      let cleared = false
      if (walletBindingMemory && address && walletBindingMemory.wallet_address && address.toLowerCase() !== walletBindingMemory.wallet_address.toLowerCase()) {
        cleared = true
      }
      const numericChain = Number(chainId)
      if (walletBindingMemory && Number.isInteger(numericChain) && numericChain !== walletBindingMemory.bound_chain_id) {
        cleared = true
      }
      if (cleared) {
        walletBindingMemory = null
        setIdentity((prev) => {
          if (!prev) return prev
          const next = { ...prev }
          delete next.wallet_address
          delete next.authorization_generation
          delete next.participant_id
          return next
        })
        setError('Wallet account or chain changed: identity cleared — re-bind your wallet before writing.')
      }
      return cleared
    },
    []
  )

  /**
   * stale_signature_result_ignored: a signature result arriving after the
   * binding session was superseded (account/chain change or logout) must be
   * discarded instead of merged into identity.
   */
  const acceptSignatureResult = useCallback((bindingSession, bindingResult) => {
    if (!walletBindingMemory || walletBindingMemory !== bindingSession) {
      return false // stale result — ignored
    }
    setIdentity((prev) => (prev ? { ...prev, ...bindingResult } : prev))
    return true
  }, [])

  const value = useMemo(
    () => ({
      identity,
      isLoading,
      error,
      oidcReady,
      userManager,
      isInstitutional: isInstitutionalMode(),
      login,
      completeLogin,
      logout,
      localLogout,
      bindWallet,
      refreshIdentity,
      handleAccountOrChainChanged,
      acceptSignatureResult,
      tenantContext: {
        institution_id: identity?.institution_id || 'INST-DEFAULT',
      },
    }),
    [
      identity,
      isLoading,
      error,
      oidcReady,
      userManager,
      login,
      completeLogin,
      logout,
      localLogout,
      bindWallet,
      refreshIdentity,
      handleAccountOrChainChanged,
      acceptSignatureResult,
    ]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
