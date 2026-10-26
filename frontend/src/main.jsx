import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

import { loadRuntimeConfig } from './config/runtime.js'
import { createApiClient, setActiveApiClient } from './api/client.js'
import { AuthProvider } from './auth/AuthProvider.jsx'

/**
 * R13 — the runtime configuration is the SINGLE source for every render decision.
 * The app renders only after loadRuntimeConfig() succeeds; a missing or corrupt
 * /runtime-config.json renders the config_error screen with a retry instead of
 * the old .finally(render) that silently mounted the app on failure (F09).
 */

function ConfigErrorScreen({ error, onRetry }) {
  return (
    <div
      role="alert"
      dir="rtl"
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        background: '#0b1120',
        color: '#e2e8f0',
        fontFamily: 'system-ui, sans-serif',
        padding: '24px',
        textAlign: 'center',
      }}
    >
      <h1 style={{ fontSize: '18px', color: '#f87171', margin: 0 }}>
        فشل تحميل إعداد التشغيل — بدء الخدمة موقوف
      </h1>
      <p style={{ fontSize: '13px', color: '#94a3b8', maxWidth: '560px', margin: 0 }}>
        Runtime configuration failed to load. Write operations remain blocked until a valid
        /runtime-config.json is served and the page is retried.
      </p>
      <code
        data-testid="config-error-detail"
        style={{
          fontSize: '11px',
          color: '#cbd5e1',
          background: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '8px',
          padding: '8px 12px',
          maxWidth: '640px',
          overflowWrap: 'anywhere',
        }}
      >
        {String(error?.message || error)}
      </code>
      <button
        type="button"
        onClick={onRetry}
        data-testid="config-retry"
        style={{
          marginTop: '8px',
          padding: '8px 20px',
          borderRadius: '10px',
          border: '1px solid #065f9e',
          background: '#0c4a6e',
          color: '#e0f2fe',
          fontSize: '13px',
          fontWeight: 600,
          cursor: 'pointer',
        }}
      >
        إعادة المحاولة / Retry
      </button>
    </div>
  )
}

function mountConfigError(error) {
  const root = ReactDOM.createRoot(document.getElementById('root'))
  root.render(<ConfigErrorScreen error={error} onRetry={() => window.location.reload()} />)
}

function mountApp() {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <AuthProvider>
        <App />
      </AuthProvider>
    </React.StrictMode>
  )
}

loadRuntimeConfig()
  .then((config) => {
    // Install the configured client BEFORE any consumer renders, so providers,
    // hooks and the legacy apiV2Client binding all resolve the same origin —
    // never a stale singleton or a hardcoded 127.0.0.1 base URL.
    setActiveApiClient(createApiClient(config))
    mountApp()
  })
  .catch((error) => {
    // No .finally(render): a failed config must never mount the writable app.
    mountConfigError(error)
  })
