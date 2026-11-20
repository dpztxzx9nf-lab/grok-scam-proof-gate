import assert from 'node:assert/strict'
import test from 'node:test'
import { applySafeInvariant, mergeModelVerdict, maxVerdict } from '../src/verdict.js'

const clean = {
  urls: { state: 'skipped' },
  domainAge: { state: 'skipped' },
  brand: { state: 'pass' },
  scamRules: { state: 'pass' },
}

test('safe is legal only when every required check passed or was skipped', () => {
  assert.equal(applySafeInvariant('safe', clean), 'safe')
  assert.equal(applySafeInvariant('safe', { ...clean, domainAge: { state: 'inconclusive' } }), 'caution')
  assert.equal(applySafeInvariant('safe', { ...clean, urls: { state: 'fail' } }), 'caution')
  assert.equal(applySafeInvariant('safe', { brand: { state: 'pass' }, scamRules: { state: 'pass' } }), 'caution')
  assert.equal(applySafeInvariant('likely_scam', { ...clean, urls: { state: 'inconclusive' } }), 'likely_scam')
})

test('model verdicts can only escalate', () => {
  const gate = (verdict, checks = clean) => ({ verdict, checks })
  assert.equal(mergeModelVerdict(gate('likely_scam'), 'safe'), 'likely_scam')
  assert.equal(mergeModelVerdict(gate('caution'), 'safe'), 'caution')
  assert.equal(mergeModelVerdict(gate('safe'), 'safe'), 'safe')
  assert.equal(mergeModelVerdict(gate('safe'), 'caution'), 'caution')
  assert.equal(mergeModelVerdict(gate('safe'), 'likely_scam'), 'likely_scam')
  assert.equal(mergeModelVerdict(gate('caution'), 'likely_scam'), 'likely_scam')
  assert.equal(mergeModelVerdict(gate('safe'), 'SAFE'), 'safe')
  assert.equal(mergeModelVerdict(gate('likely_scam'), null), 'likely_scam')
  assert.equal(mergeModelVerdict(gate('safe', { ...clean, brand: { state: 'inconclusive' } }), 'safe'), 'caution')
  assert.equal(maxVerdict('caution', 'likely_scam'), 'likely_scam')
})
