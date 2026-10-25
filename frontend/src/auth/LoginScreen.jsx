import React, { useEffect, useState } from 'react'
import { useAuth } from './AuthProvider.jsx'
import { AUTH_CALLBACK_PATH } from './oidcClient.js'

/**
 * R13 — institutional login screen (PKCE Authorization Code via oidc-client-ts)
 * and the /auth/callback handler. No token paste field, no client_secret.
 * No new visual design (brief): single dark card, existing palette.
 */

export function LoginScreen() {
  const { login, error, isInstitutional } = useAuth()
  const [busy, setBusy] = useState(false)

  if (!isInstitutional) return null

  const handleLogin = async () => {
    setBusy(true)
    try {
      await login()
    } catch {
      setBusy(false)
    }
  }

  return (
    <div
      dir="rtl"
      className="min-h-screen flex items-center justify-center p-6"
      style={{ background: '#0b1120', fontFamily: 'system-ui, sans-serif' }}
      data-testid="login-screen"
    >
      <div
        className="rounded-2xl border p-8 w-full max-w-md space-y-4 text-center"
        style={{ borderColor: '#1e293b', background: '#0f172a' }}
      >
        <h1 className="text-lg font-bold" style={{ color: '#67e8f9' }}>
          الدخول المؤسسي — Central Bank AML Audit Chain
        </h1>
        <p className="text-xs" style={{ color: '#94a3b8' }}>
          Institutional sign-in uses Authorization Code + PKCE via your institution's identity
          provider. Access tokens are never pasted manually.
        </p>
        {error && (
          <p data-testid="login-error" className="text-xs" style={{ color: '#f87171' }}>
            {error}
          </p>
        )}
        <button
          type="button"
          onClick={handleLogin}
          disabled={busy}
          data-testid="login-button"
          className="w-full py-2.5 rounded-xl font-semibold text-sm"
          style={{ background: '#0e7490', color: '#ecfeff', border: '1px solid #065f9e' }}
        >
          {busy ? 'جاري التحويل إلى مزود الهوية...' : 'تسجيل الدخول المؤسسي / Sign in'}
        </button>
      </div>
    </div>
  )
}

/** Handles the OIDC /auth/callback redirect inside the SPA. */
export function OidcCallbackHandler({ onDone }) {
  const { completeLogin } = useAuth()
  const [state, setState] = useState('processing')

  useEffect(() => {
    let isMounted = true
    const url = window.location.href
    completeLogin(url)
      .then(() => {
        if (isMounted) {
          setState('done')
          onDone?.()
        }
      })
      .catch(() => {
        if (isMounted) setState('error')
      })
    return () => {
      isMounted = false
    }
  }, [completeLogin, onDone])

  return (
    <div
      dir="rtl"
      className="min-h-screen flex items-center justify-center"
      style={{ background: '#0b1120', fontFamily: 'system-ui, sans-serif' }}
      data-testid={`callback-${state}`}
    >
      <p className="text-sm" style={{ color: '#e2e8f0' }}>
        {state === 'processing' && 'جاري التحقق من استجابة تسجيل الدخول (state/nonce)...'}
        {state === 'done' && 'تم التحقق — يتم الدخول الآن...'}
        {state === 'error' && 'فشل التحقق من رد مزود الهوية (state/nonce). أعد المحاولة.'}
      </p>
    </div>
  )
}

export { AUTH_CALLBACK_PATH }
