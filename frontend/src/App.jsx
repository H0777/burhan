import { useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { useAuditEngine } from './hooks/useAuditEngine'
import { shortAddress, parseAmount } from './utils/contract'
import './index.css'

export default function App() {
  const {
    account,
    isAdmin,
    transactions,
    stats,
    loading,
    error,
    connect,
    submitTransaction,
    flagTransaction,
    clearTransaction,
    fetchTransactions,
  } = useAuditEngine()

  const [showSubmit, setShowSubmit] = useState(false)
  const [submitForm, setSubmitForm] = useState({ receiver: '', amount: '' })
  const [flagModal, setFlagModal] = useState({ open: false, txId: null, reason: '' })
  const [successMsg, setSuccessMsg] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    const result = await submitTransaction(submitForm.receiver, submitForm.amount)
    if (result.success) {
      setSuccessMsg('Transaction submitted successfully!')
      setSubmitForm({ receiver: '', amount: '' })
      setShowSubmit(false)
      setTimeout(() => setSuccessMsg(''), 3000)
    }
  }

  const handleFlag = async (txId) => {
    setFlagModal({ open: true, txId, reason: '' })
  }

  const confirmFlag = async () => {
    await flagTransaction(flagModal.txId, flagModal.reason)
    setFlagModal({ open: false, txId: null, reason: '' })
  }

  const handleClear = async (txId) => {
    await clearTransaction(txId)
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center text-sm font-bold">
              IQ
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">Iraq AML Audit Chain</h1>
              <p className="text-xs text-gray-400">Blockchain Financial Audit System</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {successMsg && (
              <span className="text-green-400 text-sm">{successMsg}</span>
            )}
            {account ? (
              <div className="flex items-center gap-2">
                {isAdmin && (
                  <span className="bg-purple-900 text-purple-300 px-2 py-0.5 rounded text-xs">Admin</span>
                )}
                <span className="bg-gray-700 px-3 py-1.5 rounded-lg text-sm font-mono">
                  {shortAddress(account)}
                </span>
                <button
                  onClick={() => setShowSubmit(true)}
                  className="bg-blue-600 hover:bg-blue-700 px-4 py-1.5 rounded-lg text-sm font-medium"
                >
                  New Transaction
                </button>
                <button
                  onClick={fetchTransactions}
                  disabled={loading}
                  className="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg text-sm"
                >
                  {loading ? 'Loading...' : 'Refresh'}
                </button>
              </div>
            ) : (
              <button
                onClick={connect}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg font-medium"
              >
                {loading ? 'Connecting...' : 'Connect MetaMask'}
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto px-6 py-6">
        {error && (
          <div className="mb-4 bg-red-900/50 border border-red-700 text-red-300 px-4 py-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        {!account && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <div className="text-6xl mb-4">&#128279;</div>
            <h2 className="text-2xl font-bold mb-2">Connect Your Wallet</h2>
            <p className="text-gray-400 mb-6 max-w-md">
              Connect MetaMask to interact with the Iraq AML Audit blockchain system
            </p>
            <button
              onClick={connect}
              className="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-xl font-semibold text-lg"
            >
              Connect MetaMask
            </button>
          </div>
        )}

        {account && (
          <Dashboard
            stats={stats}
            transactions={transactions}
            isAdmin={isAdmin}
            onFlag={handleFlag}
            onClear={handleClear}
            loading={loading}
          />
        )}
      </main>

      {/* Submit Transaction Modal */}
      {showSubmit && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700">
            <h2 className="text-xl font-bold mb-4">Submit Transaction</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Receiver Address</label>
                <input
                  type="text"
                  value={submitForm.receiver}
                  onChange={(e) => setSubmitForm({ ...submitForm, receiver: e.target.value })}
                  placeholder="0x..."
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Amount (ETH)</label>
                <input
                  type="number"
                  step="0.0001"
                  min="0"
                  value={submitForm.amount}
                  onChange={(e) => setSubmitForm({ ...submitForm, amount: e.target.value })}
                  placeholder="100"
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSubmit(false)}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 py-2 rounded-lg text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 py-2 rounded-lg text-sm font-medium"
                >
                  {loading ? 'Submitting...' : 'Submit'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Flag Modal */}
      {flagModal.open && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700">
            <h2 className="text-xl font-bold mb-4 text-red-400">Flag Transaction #{flagModal.txId}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Reason</label>
                <textarea
                  value={flagModal.reason}
                  onChange={(e) => setFlagModal({ ...flagModal, reason: e.target.value })}
                  placeholder="Reason for flagging (e.g., AML threshold exceeded, suspicious pattern)"
                  rows={3}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
                />
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => setFlagModal({ open: false, txId: null, reason: '' })}
                  className="flex-1 bg-gray-700 hover:bg-gray-600 py-2 rounded-lg text-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmFlag}
                  disabled={loading}
                  className="flex-1 bg-red-600 hover:bg-red-700 py-2 rounded-lg text-sm font-medium"
                >
                  {loading ? 'Flagging...' : 'Confirm Flag'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
