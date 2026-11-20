import assert from 'node:assert/strict'
import test from 'node:test'
import { scoreCases } from '../src/metrics.js'

test('scores recall, precision, false-safe, and false alarms separately', () => {
  const metrics = scoreCases([
    { category: 'scam', expected: 'likely_scam', predicted: 'likely_scam' },
    { category: 'scam', expected: 'likely_scam', predicted: 'caution' },
    { category: 'scam', expected: 'likely_scam', predicted: 'safe' },
    { category: 'edge', expected: 'caution', predicted: 'likely_scam' },
    { category: 'ok', expected: 'safe', predicted: 'safe' },
    { category: 'ok', expected: 'safe', predicted: 'likely_scam' },
    { category: 'ok', expected: 'safe', predicted: 'caution' },
  ])
  assert.equal(metrics.scamRecall, 2 / 3)
  assert.equal(metrics.falseSafeRate, 1 / 3)
  assert.equal(metrics.falseAlarmRate, 1 / 3)
  assert.equal(metrics.precision, 1 / 3)
  assert.equal(metrics.exactAccuracy, 2 / 7)
  assert.equal(metrics.policyAccuracy, 4 / 7)
  assert.equal(metrics.downgradeToSafe, 1)
})
