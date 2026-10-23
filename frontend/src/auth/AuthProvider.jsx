import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { getRuntimeConfig } from '../config/runtime.js'

const AuthContext = createContext(null)

const TOKEN_STORAGE_KEY = 'iraq_aml_oidc_token'

function getAiBaseUrl() {
  const runtime = getRuntimeConfig()
  if (runtime?.ai_engine_url) {
    return runtime.ai_engine_url.replace(/\/$/, '')
  }
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_AI_ENGINE_URL) {
    return import.meta.env.VITE_AI_ENGINE_URL.replace(/\/$/, '')
  }
  return 'http://localhost:8005'
}

export function AuthProvider({ children }) {
  const [identity, setIdentity] = useState(null)
  const [token, setToken] = useState(() => {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      return window.sessionStorage.getItem(TOKEN_STORAGE_KEY)
    }
    return null
  })
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

  const lastFetchedTokenRef = React.useRef(undefined)

  const fetchIdentity = useCallback(async (authToken) => {
    const baseUrl = getAiBaseUrl()
    const headers = { 'Accept': 'application/json' }
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`
    }

    const res = await fetch(`${baseUrl}/api/v2/identity/me`, {
      method: 'GET',
      headers,
    })

    if (!res || !res.ok) {
      const errBody = res ? await res.json().catch(() => ({})) : {}
      throw new Error(errBody.detail || `Identity fetch failed with status ${res?.status || 'network error'}`)
    }

    return await res.json()
  }, [])

  // Initial load or token change
  useEffect(() => {
    if (lastFetchedTokenRef.current === token) {
      return
    }
    lastFetchedTokenRef.current = token

    let isMounted = true
    setIsLoading(true)
    fetchIdentity(token)
      .then((data) => {
        if (isMounted) {
          setIdentity(data)
          setError(null)
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.warn('[AuthProvider] Failed to load identity:', err.message)
          setError(err.message)
          // If token was invalid/expired, clear it
          if (token) {
            setToken(null)
            if (typeof window !== 'undefined' && window.sessionStorage) {
              window.sessionStorage.removeItem(TOKEN_STORAGE_KEY)
            }
          }
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false)
        }
      })

    return () => {
      isMounted = false
    }
  }, [fetchIdentity, token])

  const login = useCallback(async (newToken) => {
    if (!newToken || typeof newToken !== 'string') {
      throw new Error('Valid token string is required for login')
    }
    setIsLoading(true)
    setError(null)
    try {
      const data = await fetchIdentity(newToken)
      lastFetchedTokenRef.current = newToken
      setToken(newToken)
      setIdentity(data)
      if (typeof window !== 'undefined' && window.sessionStorage) {
        window.sessionStorage.setItem(TOKEN_STORAGE_KEY, newToken)
      }
      return data
    } catch (err) {
      setError(err.message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [fetchIdentity])

  const logout = useCallback(() => {
    lastFetchedTokenRef.current = null
    setToken(null)
    setIdentity(null)
    setError(null)
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY)
    }
  }, [])

  const bindWallet = useCallback(async (signer) => {
    if (!signer || typeof signer.getAddress !== 'function') {
      throw new Error('Valid ethers Signer is required to bind wallet')
    }

    const baseUrl = getAiBaseUrl()
    const address = await signer.getAddress()
    let chainId = 31337
    if (signer.provider && typeof signer.provider.getNetwork === 'function') {
      try {
        const net = await signer.provider.getNetwork()
        chainId = Number(net.chainId)
      } catch {
        // Fallback default chainId
      }
    }

    const authHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }
    if (token) {
      authHeaders['Authorization'] = `Bearer ${token}`
    }

    // 1. Request Challenge
    const challengeRes = await fetch(`${baseUrl}/api/v2/wallet/challenge`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        wallet_address: address,
        chain_id: chainId,
      }),
    })

    if (!challengeRes.ok) {
      const err = await challengeRes.json().catch(() => ({}))
      throw new Error(err.detail || `Wallet challenge request failed: ${challengeRes.status}`)
    }

    const challenge = await challengeRes.json()

    // 2. Sign SIWE message via Web3 Signer
    const signature = await signer.signMessage(challenge.message)

    // 3. Verify Challenge and complete binding
    const verifyRes = await fetch(`${baseUrl}/api/v2/wallet/verify`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        challenge_id: challenge.challenge_id,
        signature,
      }),
    })

    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}))
      throw new Error(err.detail || `Wallet signature verification failed: ${verifyRes.status}`)
    }

    const binding = await verifyRes.json()

    // Update local identity state
    setIdentity((prev) => {
      if (!prev) return prev
      return {
        ...prev,
        wallet_address: binding.wallet_address,
        authorization_generation: binding.authorization_generation,
        participant_id: binding.participant_id,
        role: binding.role,
      }
    })

    return binding
  }, [token])

  const refreshIdentity = useCallback(async () => {
    try {
      const data = await fetchIdentity(token)
      setIdentity(data)
      return data
    } catch (err) {
      setError(err.message)
      throw err
    }
  }, [fetchIdentity, token])

  const tenantContext = {
    institution_id: identity?.institution_id || 'INST-DEFAULT',
  }

  const value = {
    identity,
    token,
    isLoading,
    error,
    login,
    logout,
    bindWallet,
    refreshIdentity,
    tenantContext,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
