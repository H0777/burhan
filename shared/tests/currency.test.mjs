import test from 'node:test'
import assert from 'node:assert/strict'
import { parseToMinorUnits, formatMinorAmount } from '../../frontend/src/utils/currency.js'

test('Currency precision - 9.85 ETH in minor units', () => {
  const weiStr = parseToMinorUnits('9.85', 18)
  assert.equal(weiStr, '9850000000000000000')

  const formatted = formatMinorAmount(weiStr, 18, 'ETH', true)
  assert.equal(formatted, '9.85 ETH')
})

test('Currency precision - 10,000 ETH in minor units', () => {
  const weiStr = parseToMinorUnits('10000', 18)
  assert.equal(weiStr, '10000000000000000000000')

  const formatted = formatMinorAmount(weiStr, 18, 'ETH', true)
  assert.equal(formatted, '10000 ETH')
})

test('Currency precision - IQD scale 3', () => {
  const filsStr = parseToMinorUnits('15000000.500', 3)
  assert.equal(filsStr, '15000000500')

  const formatted = formatMinorAmount(filsStr, 3, 'IQD', false)
  assert.ok(formatted.includes('15') && formatted.includes('500'))
})

test('Currency precision - Rejects excessive decimals beyond scale', () => {
  assert.throws(() => {
    parseToMinorUnits('12.3456', 3)
  }, /exceed scale/)
})
