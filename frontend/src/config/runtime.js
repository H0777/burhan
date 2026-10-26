/**
 * Runtime Configuration & Mode Management (T08 → R13)
 * Specification §8: RuntimeConfig is the SINGLE source of frontend configuration
 * after load: app_mode, api_origin, chain_id, rpc_url, deployment_id, contracts,
 * and oidc={authority,client_id,redirect_uri,scope} (required in institutional).
 *
 * R13 fixes (F09):
 *  - app_mode is NO LONGER a build-time constant; the fetched config controls it.
 *  - A missing or corrupt config REJECTS (no silent demo fallback) so that the
 *    app never renders writable UI without a resolved configuration.
 *  - api_origin containing "/api" is rejected (one single /api/vN prefix rule).
 *  - Strict schema: unknown keys are rejected.
 */

import { ethers } from 'ethers'

const RUNTIME_CONFIG_URL = '/runtime-config.json'
const AUTH_CALLBACK_PATH = '/auth/callback'

const APP_MODES = ['demo', 'institutional']

/**
 * DEPRECATED build-time default, kept ONLY because utils/contract.js re-exports
 * this binding and is outside the R13 file set. No mode decision may read it:
 * all decisions must go through isInstitutionalMode()/isDemoMode(), which read
 * the resolved runtime config (test runtime_institutional_controls_mode_after_fetch).
 */
export const APP_MODE = 'demo'

const KNOWN_CONFIG_KEYS = [
  'app_mode',
  'api_origin',
  'chain_id',
  'rpc_url',
  'deployment_id',
  'contracts',
  'oidc',
  // Back-compat metadata keys carried by existing deployments (validated, not authoritative):
  'institution_id',
  'contract_version',
]

const OIDC_KEYS = ['authority', 'client_id', 'redirect_uri', 'scope']

/** Thrown when the runtime configuration is missing, corrupt or schema-invalid. */
export class RuntimeConfigError extends Error {
  constructor(message) {
    super(`Invalid runtime configuration: ${message}`)
    this.name = 'RuntimeConfigError'
  }
}

function isHttpUrl(value) {
  return typeof value === 'string' && /^https?:\/\//.test(value)
}

/**
 * True when the PATH portion of an absolute origin contains "/api".
 * Only the path is inspected — a hostname like api.bank-iq.example is legal.
 */
function originPathContainsApi(origin) {
  const match = /^https?:\/\/[^/]+(\/.*)?$/.exec(origin)
  return Boolean(match && /\/api/i.test(match[1] || ''))
}

function currentOrigin() {
  return typeof window !== 'undefined' && window.location ? window.location.origin : ''
}

/**
 * Strict RuntimeConfig schema validation (spec §8). Returns the normalized config.
 * @param {unknown} raw
 * @returns {object} normalized RuntimeConfig
 */
export function validateRuntimeConfig(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new RuntimeConfigError('config must be a JSON object')
  }

  for (const key of Object.keys(raw)) {
    if (!KNOWN_CONFIG_KEYS.includes(key)) {
      throw new RuntimeConfigError(`unknown key "${key}" (strict schema)`)
    }
  }

  const { app_mode } = raw
  if (!APP_MODES.includes(app_mode)) {
    throw new RuntimeConfigError(`app_mode must be one of ${JSON.stringify(APP_MODES)}`)
  }
  const institutional = app_mode === 'institutional'

  const api_origin = typeof raw.api_origin === 'string' ? raw.api_origin.trim().replace(/\/+$/, '') : undefined
  if (typeof api_origin !== 'string') {
    throw new RuntimeConfigError('api_origin must be a string ("" for same-origin)')
  }
  if (api_origin === '') {
    // same-origin is allowed
  } else if (!/^https?:\/\/[^/]+\/?$/.test(api_origin)) {
    throw new RuntimeConfigError('api_origin must be "" or an absolute origin (scheme://host) without any path')
  }
  if (originPathContainsApi(api_origin)) {
    throw new RuntimeConfigError('api_origin must NOT contain "/api": the client adds /api/v2 or /api/v3 exactly once')
  }

  const chain_id = raw.chain_id
  if (!Number.isInteger(chain_id) || chain_id < 1) {
    throw new RuntimeConfigError('chain_id must be a positive integer')
  }

  if (!isHttpUrl(raw.rpc_url)) {
    throw new RuntimeConfigError('rpc_url must be an http(s) URL')
  }

  if (institutional && (typeof raw.deployment_id !== 'string' || raw.deployment_id.trim() === '')) {
    throw new RuntimeConfigError('deployment_id is required in institutional mode')
  }
  if (raw.deployment_id !== undefined && typeof raw.deployment_id !== 'string') {
    throw new RuntimeConfigError('deployment_id must be a string')
  }

  const contracts = raw.contracts
  if (contracts === null || typeof contracts !== 'object' || Array.isArray(contracts)) {
    throw new RuntimeConfigError('contracts must be an object of name -> 0x address')
  }
  for (const [name, address] of Object.entries(contracts)) {
    if (typeof address !== 'string' || !ethers.isAddress(address)) {
      throw new RuntimeConfigError(`contracts.${name} is not a valid 0x address`)
    }
  }
  if (institutional && Object.keys(contracts).length === 0) {
    throw new RuntimeConfigError('contracts must list deployed addresses in institutional mode')
  }

  const oidc = raw.oidc
  if (institutional) {
    if (oidc === null || typeof oidc !== 'object' || Array.isArray(oidc)) {
      throw new RuntimeConfigError('oidc={authority,client_id,redirect_uri,scope} is required in institutional mode')
    }
  }
  if (oidc !== undefined && oidc !== null) {
    if (typeof oidc !== 'object' || Array.isArray(oidc)) {
      throw new RuntimeConfigError('oidc must be an object')
    }
    for (const key of Object.keys(oidc)) {
      if (!OIDC_KEYS.includes(key)) {
        throw new RuntimeConfigError(`unknown oidc key "${key}" (strict schema)`)
      }
    }
    for (const key of OIDC_KEYS) {
      if (typeof oidc[key] !== 'string' || oidc[key].trim() === '') {
        throw new RuntimeConfigError(`oidc.${key} must be a non-empty string`)
      }
    }
    if (!/^https?:\/\//.test(oidc.authority)) {
      throw new RuntimeConfigError('oidc.authority must be an http(s) issuer URL')
    }
    const expectedRedirect = `${currentOrigin()}${AUTH_CALLBACK_PATH}`
    if (oidc.redirect_uri !== expectedRedirect) {
      throw new RuntimeConfigError(
        `oidc.redirect_uri must equal origin + ${AUTH_CALLBACK_PATH} (expected "${expectedRedirect}") and be registered at the issuer`
      )
    }
  }

  return {
    ...raw,
    app_mode,
    api_origin,
    chain_id,
    rpc_url: raw.rpc_url,
    deployment_id: raw.deployment_id,
    contracts,
    oidc: oidc || undefined,
  }
}

let resolvedRuntimeConfig = null

/**
 * Loads and strictly validates /runtime-config.json.
 * Rejects when the file is missing, unreachable or schema-invalid — the caller
 * (main.jsx) must then render the config_error state instead of the app.
 * @returns {Promise<object>} RuntimeConfig
 */
export async function loadRuntimeConfig() {
  let res
  try {
    res = await fetch(RUNTIME_CONFIG_URL, { cache: 'no-store' })
  } catch (err) {
    throw new RuntimeConfigError(`could not fetch ${RUNTIME_CONFIG_URL} (${err?.message || err})`)
  }
  if (!res.ok) {
    throw new RuntimeConfigError(`${RUNTIME_CONFIG_URL} responded HTTP ${res.status}`)
  }
  let raw
  try {
    raw = await res.json()
  } catch (err) {
    throw new RuntimeConfigError(`${RUNTIME_CONFIG_URL} is not valid JSON (${err?.message || err})`)
  }
  resolvedRuntimeConfig = validateRuntimeConfig(raw)
  return resolvedRuntimeConfig
}

/**
 * Returns the resolved RuntimeConfig. Throws before a successful load —
 * callers must never fall back to a default configuration.
 * @returns {object} RuntimeConfig
 */
export function getRuntimeConfig() {
  if (!resolvedRuntimeConfig) {
    throw new RuntimeConfigError(
      'not loaded yet — the application must not render writes before loadRuntimeConfig() succeeds'
    )
  }
  return resolvedRuntimeConfig
}

/**
 * Reads the RESOLVED config (never a build-time cached boolean).
 * Returns false while no config is loaded (conservative: not institutional
 * until proven) — rendered writes are blocked separately by the config gate.
 * @returns {boolean}
 */
export function isInstitutionalMode() {
  if (!resolvedRuntimeConfig) return false
  return resolvedRuntimeConfig.app_mode === 'institutional'
}

export function isDemoMode() {
  if (!resolvedRuntimeConfig) return false
  return resolvedRuntimeConfig.app_mode === 'demo'
}

/**
 * Asserts a connected network chainId matches the configured chain_id EXACTLY
 * (spec §8: "chainId يجب أن يطابق تماماً حتى محلياً" — even 31337 vs 1337 is rejected).
 * @param {{chainId: number|bigint}} networkLike
 * @returns {Promise<boolean>}
 */
export async function assertChainIdMatchesConfig(networkLike) {
  const config = getRuntimeConfig()
  const chainId = Number(networkLike?.chainId)
  if (!Number.isInteger(chainId) || chainId !== config.chain_id) {
    throw new Error(`Chain ID mismatch: config expects ${config.chain_id}, connected to ${chainId}`)
  }
  return true
}

/**
 * Validates that deployed contracts exist on the network with non-empty bytecode
 * and match the expected chainId STRICTLY (no local-node tolerance in R13).
 *
 * @param {string} institutionId
 * @param {ethers.Provider} provider
 * @param {Record<string, string>} contractAddresses
 * @param {number} [expectedChainId=1337]
 * @returns {Promise<{institutionId: string, chainId: number, contracts: Record<string, string>, verifiedAt: string}>}
 */
export async function getVerifiedDeployment(
  institutionId = 'INST-DEFAULT',
  provider,
  contractAddresses,
  expectedChainId = 1337
) {
  if (!provider) {
    throw new Error('Verification failed: No Web3 provider provided')
  }

  const network = await provider.getNetwork()
  const chainId = Number(network.chainId)

  // R13: strict equality — the previous tolerance for 31337 when 1337 was
  // expected masked a genuine misconfiguration (test wrong_chain_even_31337_rejected).
  if (expectedChainId && chainId !== expectedChainId) {
    throw new Error(`Chain ID mismatch: expected ${expectedChainId}, connected to ${chainId}`)
  }

  const verifiedContracts = {}

  for (const [name, address] of Object.entries(contractAddresses)) {
    if (!address || !ethers.isAddress(address)) {
      throw new Error(`Invalid contract address for ${name}: ${address}`)
    }

    const code = await provider.getCode(address)
    if (!code || code === '0x') {
      throw new Error(`Deployment verification failed: Contract ${name} has no deployed bytecode at ${address}`)
    }

    verifiedContracts[name] = address
  }

  return {
    institutionId,
    chainId,
    contracts: verifiedContracts,
    verifiedAt: new Date().toISOString()
  }
}

/**
 * Standard OperationResult representing on-chain state transition outcome.
 * @typedef {'confirmed'|'rejected'|'failed'} OperationStatus
 */
export class OperationResult {
  /**
   * @param {OperationStatus} status
   * @param {string|null} [transactionHash=null]
   * @param {string|null} [error=null]
   * @param {object|null} [receipt=null]
   */
  constructor(status, transactionHash = null, error = null, receipt = null) {
    this.status = status
    this.transactionHash = transactionHash
    this.error = error
    this.receipt = receipt
    this.timestamp = new Date().toISOString()
  }

  static confirmed(txHash, receipt = null) {
    return new OperationResult('confirmed', txHash, null, receipt)
  }

  static rejected(reason) {
    return new OperationResult('rejected', null, reason)
  }

  static failed(error) {
    const errorMsg = error instanceof Error ? error.message : String(error)
    return new OperationResult('failed', null, errorMsg)
  }
}
