import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'
import { runEvaluation } from '../src/eval.js'

const dataset = JSON.parse(await readFile(new URL('../datasets/scam-eval-v1.json', import.meta.url), 'utf8'))

/**
 * @param {string} name
 */
async function saved(name) {
  return JSON.parse(await readFile(new URL(`../benchmarks/${name}`, import.meta.url), 'utf8'))
}

test('committed offline benchmarks match a fresh run and are not live Grok scores', async () => {
  const deterministic = await saved('eval-deterministic.json')
  const adversarial = await saved('eval-adversarial-llm.json')
  assert.equal(deterministic.mode, 'deterministic')
  assert.equal(adversarial.mode, 'adversarial-llm')
  assert.equal(deterministic.liveModel, false)
  assert.equal(adversarial.liveModel, false)
  assert.equal(deterministic.liveNetwork, false)
  assert.equal(adversarial.liveNetwork, false)

  const freshDeterministic = await runEvaluation({ mode: 'deterministic', dataset })
  const freshAdversarial = await runEvaluation({ mode: 'adversarial-llm', dataset })
  for (const [savedReport, fresh] of [[deterministic, freshDeterministic], [adversarial, freshAdversarial]]) {
    assert.equal(savedReport.metrics.total, fresh.metrics.total)
    assert.equal(savedReport.metrics.exact, fresh.metrics.exact)
    assert.equal(savedReport.metrics.falseSafe, fresh.metrics.falseSafe)
    assert.equal(savedReport.metrics.blockedDowngrades, fresh.metrics.blockedDowngrades)
    assert.equal(savedReport.metrics.falseSafeRate, 0)
    assert.equal(savedReport.metrics.scamRecall, 1)
    assert.equal(savedReport.metrics.falseAlarmRate, 0)
    assert.equal(savedReport.metrics.precision, 1)
    assert.equal(savedReport.datasetSha256.length, 64)
  }
  assert.equal(adversarial.metrics.blockedDowngrades, dataset.cases.filter(item => item.expected !== 'safe').length)
  assert.equal(deterministic.metrics.blockedDowngrades, 0)
})
