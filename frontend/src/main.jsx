import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

import { loadRuntimeConfig } from './config/runtime.js'
import { AuthProvider } from './auth/AuthProvider.jsx'

loadRuntimeConfig().finally(() => {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <AuthProvider>
        <App />
      </AuthProvider>
    </React.StrictMode>
  )
})
