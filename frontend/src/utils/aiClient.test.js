import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { checkAIHealth } from './aiClient.js'

describe('aiClient - checkAIHealth (T07/T08)', () => {
  const originalFetch = global.fetch

  afterEach(() => {
    global.fetch = originalFetch
  })

  it('should reflect model_loaded true when V2 readiness check passes', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'ready',
        live: true,
        ready: true,
        checks: { ml_engine: true, policy_service: true },
        details: { ml_type: 'IsolationForest' }
      })
    })

    const health = await checkAIHealth()
    expect(health.status).toBe('ready')
    expect(health.ready).toBe(true)
    expect(health.model_loaded).toBe(true)
  })

  it('should report offline and model_loaded: false on connection failure without silent success claim', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused to AI engine'))

    const health = await checkAIHealth()
    expect(health.status).toBe('offline')
    expect(health.ready).toBe(false)
    expect(health.model_loaded).toBe(false)
    expect(health.error).toContain('Connection refused')
  })
})
