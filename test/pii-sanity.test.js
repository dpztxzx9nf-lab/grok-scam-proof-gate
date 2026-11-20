import assert from 'node:assert/strict'
import test from 'node:test'
import { scanRepo } from '../scripts/pii-sanity.js'

test('the repository contains no secrets or real dataset PII', async () => {
  const problems = await scanRepo()
  assert.deepEqual(problems, [])
})
