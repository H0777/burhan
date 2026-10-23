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

export const DEMO_ROLES = [
  {
    account: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    role: 'SUPER_ADMIN',
    roleCode: 1,
    roleAr: 'المسؤول الإداري الأعلى (Super Admin)',
    grantedAt: '2026-10-22',
    grantedBy: '0x0000...0000 (Genesis)',
    active: true,
    generation: 1,
  },
  {
    account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    role: 'AUDITOR',
    roleCode: 2,
    roleAr: 'مدقق امتثال قضائي (Forensic Auditor)',
    grantedAt: '2026-10-22',
    grantedBy: '0x5FbD...aa3',
    active: true,
    generation: 1,
  },
  {
    account: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    role: 'OPERATOR',
    roleCode: 3,
    roleAr: 'مشغل تحويلات مالية (Financial Operator)',
    grantedAt: '2026-10-22',
    grantedBy: '0x5FbD...aa3',
    active: true,
    generation: 1,
  },
  {
    account: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    role: 'REGULATOR',
    roleCode: 4,
    roleAr: 'مفتش البنك المركزي (CBI Regulator)',
    grantedAt: '2026-10-22',
    grantedBy: '0x5FbD...aa3',
    active: true,
    generation: 1,
  },
]

export const DEMO_PROPOSALS = [
  {
    id: 1,
    proposalType: 1,
    proposalTypeName: 'POLICY_CHANGE',
    proposer: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    target: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
    data: '0x',
    actionHash: '0x51c6b3e0d867c427848c909678125433a0279c948e67a0a031a2936239108ec7',
    reasonHash: '0x8b5b48ad72f44dc017849c7198816c729b47e24a7374b7c6c49924ac9341efcb',
    reason: 'Update AML Large Transaction Threshold to 12.0 ETH',
    createdAt: Math.floor(Date.now() / 1000) - 3600,
    notBefore: Math.floor(Date.now() / 1000) - 3600,
    expiresAt: Math.floor(Date.now() / 1000) + 82800,
    status: 0, // PENDING
    statusName: 'PENDING',
    approvalCount: 1,
    rejectionCount: 0,
    requiredApprovals: 2,
    approvers: ['0x5FbDB2315678afecb367f032d93F642f64180aa3'],
    hasVoted: false,
    isExpired: false,
    description: 'Update AML Large Transaction Threshold to 12.0 ETH',
    descriptionAr: 'تعديل سقف التحويلات الكبيرة الخاضعة للتدقيق إلى 12.0 ETH',
  },
  {
    id: 2,
    proposalType: 2,
    proposalTypeName: 'EMERGENCY_UNPAUSE',
    proposer: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    target: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
    data: '0x',
    actionHash: '0x62d7c4f1e978d538959d010789236544b1380da59f78b1b142b3a4734a219fd8',
    reasonHash: '0x9c6c59be83a55ed128950d8209927d830c58f35b8485c8d7d50035bd0452f0dc',
    reason: 'Emergency Circuit Breaker Unpause Authorization',
    createdAt: Math.floor(Date.now() / 1000) - 7200,
    notBefore: Math.floor(Date.now() / 1000) - 7200,
    expiresAt: Math.floor(Date.now() / 1000) + 79200,
    status: 1, // APPROVED but not yet executed!
    statusName: 'APPROVED',
    approvalCount: 2,
    rejectionCount: 0,
    requiredApprovals: 2,
    approvers: [
      '0x5FbDB2315678afecb367f032d93F642f64180aa3',
      '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    ],
    hasVoted: true,
    isExpired: false,
    description: 'Emergency Circuit Breaker Unpause Authorization',
    descriptionAr: 'رفع التجميد الاحترازي واستئناف المعاملات بمصادقة ثنائية',
  },
]

