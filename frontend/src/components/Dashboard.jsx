import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { shortAddress, formatTimestamp } from '../utils/contract'

const STATUS_LABELS = ['Pending', 'Cleared', 'Flagged', 'Blocked']
const STATUS_COLORS = ['#f59e0b', '#10b981', '#ef4444', '#6b7280']

export function Dashboard({ stats, transactions, isAdmin, onFlag, onClear, loading }) {
  const statusData = STATUS_LABELS.map((label, i) => ({
    name: label,
    value: transactions.filter((tx) => tx.status === i).length,
    color: STATUS_COLORS[i],
  }))

  const recentTxs = [...transactions].reverse().slice(0, 10)

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Total Transactions" value={stats.total} color="blue" />
        <StatCard title="Flagged" value={stats.flagged} color="red" />
        <StatCard title="Cleared" value={stats.cleared} color="green" />
        <StatCard title="AML Threshold" value={`${stats.threshold} ETH`} color="yellow" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Status Distribution Pie */}
        <div className="bg-gray-800 rounded-xl p-4">
          <h3 className="text-white font-semibold mb-3">Transaction Status Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={statusData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                dataKey="value"
                label={({ name, value }) => value > 0 ? `${name}: ${value}` : ''}
              >
                {statusData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Volume Bar Chart */}
        <div className="bg-gray-800 rounded-xl p-4">
          <h3 className="text-white font-semibold mb-3">Recent Transaction Volumes (ETH)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={recentTxs}>
              <XAxis dataKey="id" tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }}
                labelStyle={{ color: '#f3f4f6' }}
              />
              <Bar dataKey="amount" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Transactions Table */}
      <div className="bg-gray-800 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-700">
          <h3 className="text-white font-semibold">Recent Transactions</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-xs uppercase bg-gray-900">
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Sender</th>
                <th className="px-4 py-3 text-left">Receiver</th>
                <th className="px-4 py-3 text-right">Amount (ETH)</th>
                <th className="px-4 py-3 text-center">Status</th>
                <th className="px-4 py-3 text-left">Time</th>
                {isAdmin && <th className="px-4 py-3 text-center">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {recentTxs.map((tx) => (
                <tr key={tx.id} className="text-gray-300 hover:bg-gray-750 transition-colors">
                  <td className="px-4 py-3 font-mono">#{tx.id}</td>
                  <td className="px-4 py-3 font-mono text-blue-400">{shortAddress(tx.sender)}</td>
                  <td className="px-4 py-3 font-mono text-green-400">{shortAddress(tx.receiver)}</td>
                  <td className="px-4 py-3 text-right font-semibold">{parseFloat(tx.amount).toFixed(4)}</td>
                  <td className="px-4 py-3 text-center">
                    <StatusBadge status={tx.status} />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">{formatTimestamp(tx.timestamp)}</td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-center space-x-2">
                      {tx.status === 0 && (
                        <>
                          <button
                            onClick={() => onFlag(tx.id)}
                            disabled={loading}
                            className="text-xs bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded"
                          >
                            Flag
                          </button>
                          <button
                            onClick={() => onClear(tx.id)}
                            disabled={loading}
                            className="text-xs bg-green-600 hover:bg-green-700 text-white px-2 py-1 rounded"
                          >
                            Clear
                          </button>
                        </>
                      )}
                      {tx.isFlagged && (
                        <span className="text-xs text-red-400">{tx.flagReason}</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
              {recentTxs.length === 0 && (
                <tr>
                  <td colSpan={isAdmin ? 7 : 6} className="px-4 py-8 text-center text-gray-500">
                    No transactions yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, color }) {
  const colors = {
    blue: 'border-blue-500 text-blue-400',
    red: 'border-red-500 text-red-400',
    green: 'border-green-500 text-green-400',
    yellow: 'border-yellow-500 text-yellow-400',
  }
  return (
    <div className={`bg-gray-800 rounded-xl p-4 border-l-4 ${colors[color]}`}>
      <p className="text-gray-400 text-xs uppercase tracking-wide">{title}</p>
      <p className={`text-2xl font-bold mt-1 ${colors[color].split(' ')[1]}`}>{value}</p>
    </div>
  )
}

function StatusBadge({ status }) {
  const config = [
    { label: 'Pending', cls: 'bg-yellow-900 text-yellow-300' },
    { label: 'Cleared', cls: 'bg-green-900 text-green-300' },
    { label: 'Flagged', cls: 'bg-red-900 text-red-300' },
    { label: 'Blocked', cls: 'bg-gray-700 text-gray-400' },
  ]
  const { label, cls } = config[status] || config[0]
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>{label}</span>
  )
}
