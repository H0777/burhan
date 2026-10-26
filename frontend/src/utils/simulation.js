// Realistic Iraqi banking entities, operators, and test addresses
export const SAMPLE_ENTITIES = [
  { name: 'Rafidain Bank Central Treasury', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' },
  { name: 'Rasheed Bank Foreign Exchange', address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' },
  { name: 'Trade Bank of Iraq (TBI) Settlement', address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' },
  { name: 'Baghdad Oil Services Corp (KYC Verified)', address: '0x90F79bf6EB2c4f870365E785982E1f101E93b906' },
  { name: 'Erbil Construction Group', address: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65' },
  { name: 'Basra Port Logistics Co', address: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc' },
  { name: 'Unverified Offshore Entity (High Risk)', address: '0x976EA74026E726554dB657fA54763abd0C3a0aa9' },
  { name: 'Blacklisted International Shell Co', address: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955' },
]

export function generateRandomTransaction(idOffset = 100) {
  const isSuspicious = Math.random() < 0.25
  const senderIndex = Math.floor(Math.random() * (SAMPLE_ENTITIES.length - 2))
  let receiverIndex = Math.floor(Math.random() * SAMPLE_ENTITIES.length)
  while (receiverIndex === senderIndex) {
    receiverIndex = Math.floor(Math.random() * SAMPLE_ENTITIES.length)
  }

  const sender = SAMPLE_ENTITIES[senderIndex]
  const receiver = SAMPLE_ENTITIES[receiverIndex]

  if (isSuspicious) {
    // Structuring or Threshold violation
    const isStructuring = Math.random() > 0.5
    const amount = isStructuring
      ? (9.75 + Math.random() * 0.2).toFixed(4)
      : (10.5 + Math.random() * 15.0).toFixed(4)
    const riskScore = parseFloat((75 + Math.random() * 20).toFixed(1))
    const isCritical = parseFloat(amount) >= 15.0

    return {
      id: idOffset,
      sender: sender.address,
      senderName: sender.name,
      receiver: receiver.address,
      receiverName: receiver.name,
      amount,
      timestamp: Math.floor(Date.now() / 1000),
      isFlagged: true,
      flagReason: isStructuring
        ? `Structuring Pattern: ${amount} ETH (approaching CBI 10 ETH threshold)`
        : `Large Transaction: ${amount} ETH exceeds reporting threshold without secondary approval`,
      status: isCritical ? 3 : 2, // 3 = BLOCKED, 2 = FLAGGED
      riskScore,
      riskTier: isCritical ? 'CRITICAL' : 'HIGH',
    }
  }

  // Normal clean transaction
  const amount = (0.5 + Math.random() * 4.0).toFixed(4)
  const riskScore = parseFloat((5 + Math.random() * 20).toFixed(1))

  return {
    id: idOffset,
    sender: sender.address,
    senderName: sender.name,
    receiver: receiver.address,
    receiverName: receiver.name,
    amount,
    timestamp: Math.floor(Date.now() / 1000),
    isFlagged: false,
    flagReason: '',
    status: 1, // CLEARED
    riskScore,
    riskTier: 'LOW',
  }
}

// Generate Insider Fraud Scenario
export function generateInsiderFraudCase(currentMaxId) {
  const timestamp = Math.floor(Date.now() / 1000)
  const tx = {
    id: currentMaxId + 1,
    sender: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', // Compromised Senior Auditor
    senderName: 'Senior Auditor (Compromised)',
    receiver: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955', // Shell entity
    receiverName: 'Blacklisted Offshore Account',
    amount: '14.8500',
    timestamp,
    isFlagged: true,
    flagReason: 'CRITICAL INSIDER THREAT: Operator bypassed AML warning during off-hours (23:42 UTC+3)',
    status: 3, // BLOCKED
    riskScore: 96.5,
    riskTier: 'CRITICAL',
  }

  const forensicEntry = {
    index: Date.now() % 10000,
    timestamp,
    incidentType: 'INSIDER_MALICIOUS_OVERRIDE',
    operator: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    actor: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
    evidenceHash: '0x7bfa4910e53a992bc09817f549c40df63a2333be1e433cb8e0724a7374b79921',
    previousEntryHash: '0x9924ac9341efcb909247c07b6f6f7d49e6f99b244799014b2b627cf99e5a1bfa2',
    entryHash: '0xcc1924b45501fa3829019cfef940df63a2333be1e433cb8e0724a7374b7e801',
  }

  return { tx, forensicEntry }
}

// Generate Smurfing Attack Batch (3 transfers just below 10 ETH)
export function generateSmurfingBatch(startId) {
  const baseTimestamp = Math.floor(Date.now() / 1000)
  const amounts = ['9.8500', '9.9200', '9.8000']
  const receiver = '0x90F79bf6EB2c4f870365E785982E1f101E93b906'

  return amounts.map((amt, idx) => ({
    id: startId + idx,
    sender: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    senderName: 'Compliance Operator (Anomalous Velocity)',
    receiver,
    receiverName: 'Suspicious Regional Entity',
    amount: amt,
    timestamp: baseTimestamp + idx * 30,
    isFlagged: true,
    flagReason: `Structuring Batch (#${idx + 1}/3): Sub-threshold amount ${amt} ETH evading CBI 10 ETH limit`,
    status: 2, // FLAGGED
    riskScore: 84.0 + idx * 3.5,
    riskTier: 'HIGH',
  }))
}

// Export Transactions to CSV
export function exportTransactionsCSV(transactions) {
  const headers = ['Tx ID', 'Originator', 'Beneficiary', 'Amount (ETH)', 'Risk Score', 'Risk Tier', 'Status', 'Audit Notes', 'Timestamp']
  const rows = transactions.map((t) => [
    t.id,
    t.sender,
    t.receiver,
    t.amount,
    t.riskScore,
    t.riskTier,
    t.status === 1 ? 'CLEARED' : t.status === 2 ? 'FLAGGED' : t.status === 3 ? 'BLOCKED' : 'PENDING',
    `"${(t.flagReason || 'Verified clean').replace(/"/g, '""')}"`,
    new Date(t.timestamp * 1000).toISOString(),
  ])

  const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n')
  const encodedUri = encodeURI(csvContent)
  const link = document.createElement('a')
  link.setAttribute('href', encodedUri)
  link.setAttribute('download', `CBI_AUDITED_LEDGER_${Date.now()}.csv`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

// Export Transactions to JSON
export function exportTransactionsJSON(transactions) {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(transactions, null, 2))
  const link = document.createElement('a')
  link.setAttribute('href', dataStr)
  link.setAttribute('download', `CBI_AUDITED_LEDGER_${Date.now()}.json`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}
