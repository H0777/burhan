/**
 * Demo Fixtures & Local Emulation Data (T08)
 * Specification §7, §8 (R05, R10)
 * 
 * Isolated demo assets for standalone visual presentation.
 * STRICT ISOLATION: Must NEVER be imported or used in institutional mode!
 */

export const DEMO_ACCOUNT = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
export const DEMO_BALANCE = '10000.0'
export const DEMO_ROLE = 'SUPER_ADMIN'

export const DEMO_FALLBACK_WALLET = {
  address: DEMO_ACCOUNT,
  balance: DEMO_BALANCE,
  isLocalNode: false,
  label: 'Demo Standalone Mode (Simulated)',
}

export const DEMO_TRANSACTIONS = [
  {
    id: 1,
    sender: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    receiver: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    amount: '9.85',
    timestamp: 1700000000,
    isFlagged: true,
    flagReason: 'STRUCTURING_RISK: High-frequency transfer close to threshold',
    status: 1 // Flagged
  },
  {
    id: 2,
    sender: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    receiver: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    amount: '2.50',
    timestamp: 1700000060,
    isFlagged: false,
    flagReason: '',
    status: 2 // Cleared
  }
]

export const DEMO_INSIDER_ACTIVITIES = [
  {
    id: 1,
    operator: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    activityType: 1, // Override
    relatedTxId: 1,
    beneficiary: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    timestamp: 1700000020,
    details: 'Urgent treasury rebalancing override'
  }
]
