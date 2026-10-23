/**
 * Iraqi Dinar (IQD) & Multi-Currency Valuation Engine
 * Aligned with Central Bank of Iraq (CBI) AML/CFT Regulations
 * Official Reference: Law No. 39 of 2015 on Anti-Money Laundering & Counter-Terrorism Financing
 * 
 * IMPORTANT COMPLIANCE NOTICE (T06 / Specification §8):
 * - Fixed exchange rates below (ETH_TO_USD, USD_TO_IQD) are for DEMO / ESTIMATION display only.
 * - Institutional AML decisions MUST NEVER use hardcoded conversion rates to evaluate thresholds.
 * - All financial threshold decisions evaluate native asset minor units (ETH wei scale=18, IQD fils scale=3)
 *   via authoritative policy services or on-chain contracts.
 */

// Exchange rate constants (Reference: Central Bank of Iraq Official Banking Rate - DEMO DISPLAY ONLY)
export const ETH_TO_USD = 3000.0 // 1 ETH = $3,000 USD (Demo Estimate)
export const USD_TO_IQD = 1320.0 // Official CBI Rate: 1 USD = 1,320 IQD (Demo Estimate)
export const ETH_TO_IQD = ETH_TO_USD * USD_TO_IQD // 1 ETH = 3,960,000 IQD (Demo Estimate)

// Central Bank of Iraq Mandatory AML Reporting Thresholds (Demo / Informational)
export const CBI_THRESHOLDS = {
  // Official CBI Mandatory Reporting Limit: 15,000,000 IQD (~$11,363 USD)
  LARGE_TRANSACTION_IQD: 15000000,
  LARGE_TRANSACTION_USD: 11363.64,
  LARGE_TRANSACTION_ETH: 15000000 / ETH_TO_IQD, // ~3.788 ETH (Demo)

  // Daily Corporate Ceiling
  DAILY_CEILING_IQD: 75000000, // 75 Million IQD
  DAILY_CEILING_USD: 56818.18,
  DAILY_CEILING_ETH: 75000000 / ETH_TO_IQD, // ~18.94 ETH (Demo)
}

/**
 * Parses a decimal string (e.g. "9.85") into exact BigInt minor units string
 * without floating-point precision loss.
 * @param {string|number} amountStr
 * @param {number} scale
 * @returns {string} Integer minor units string
 */
export function parseToMinorUnits(amountStr, scale) {
  if (amountStr === null || amountStr === undefined) return '0'
  const str = String(amountStr).trim()
  if (!str) return '0'

  const parts = str.split('.')
  if (parts.length > 2) throw new Error(`Invalid decimal format: ${str}`)

  const wholePart = parts[0] || '0'
  const fracPart = parts[1] || ''

  if (fracPart.length > scale) {
    throw new Error(`Fractional digits (${fracPart.length}) exceed scale (${scale})`)
  }

  const paddedFrac = fracPart.padEnd(scale, '0')
  const combined = wholePart === '0' ? paddedFrac.replace(/^0+/, '') || '0' : wholePart + paddedFrac
  return BigInt(combined).toString()
}

/**
 * Formats integer minor units to an exact human-readable monetary string.
 * @param {string|number|BigInt} amountMinor
 * @param {number} scale
 * @param {string} currency
 * @param {boolean} includeSymbol
 * @returns {string}
 */
export function formatMinorAmount(amountMinor, scale, currency = 'ETH', includeSymbol = true, locale = 'en-US') {
  const minorBig = BigInt(String(amountMinor || 0))
  const divisor = 10n ** BigInt(scale)

  const whole = minorBig / divisor
  const remainder = minorBig % divisor

  let fracStr = remainder.toString().padStart(scale, '0')
  // Trim trailing zeros for ETH, preserve scale for fiat/fixed scale if desired
  if (currency === 'ETH') {
    fracStr = fracStr.replace(/0+$/, '')
  }

  const decStr = fracStr.length > 0 ? `${whole}.${fracStr}` : whole.toString()

  if (currency === 'IQD') {
    const formattedWhole = Number(whole).toLocaleString(locale)
    const finalFormatted = fracStr.length > 0 ? `${formattedWhole}.${fracStr}` : formattedWhole
    return includeSymbol ? `${finalFormatted} د.ع` : finalFormatted
  }

  return includeSymbol ? `${decStr} ${currency}` : decStr
}

/**
 * Format an ETH amount to Iraqi Dinars (IQD) - Demo display helper
 * @param {number|string} ethAmount
 * @param {boolean} includeSymbol - Whether to include "د.ع"
 */
export function formatIQD(ethAmount, includeSymbol = true) {
  const val = parseFloat(ethAmount) || 0
  const iqd = Math.round(val * ETH_TO_IQD)
  const formatted = iqd.toLocaleString('ar-IQ')
  return includeSymbol ? `${formatted} د.ع` : formatted
}

/**
 * Format an ETH amount to USD - Demo display helper
 * @param {number|string} ethAmount
 */
export function formatUSD(ethAmount) {
  const val = parseFloat(ethAmount) || 0
  const usd = val * ETH_TO_USD
  return `$${usd.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

/**
 * Convert IQD to ETH - Demo display helper
 * @param {number|string} iqdAmount
 */
export function iqdToETH(iqdAmount) {
  const val = parseFloat(iqdAmount) || 0
  return val / ETH_TO_IQD
}

/**
 * Get full bilingual monetary summary: e.g. "9.85 ETH ≈ $29,550 USD (39,006,000 د.ع)"
 */
export function formatDualCurrency(ethAmount) {
  const eth = parseFloat(ethAmount) || 0
  return `${eth.toFixed(4)} ETH (${formatUSD(eth)} | ${formatIQD(eth)})`
}
