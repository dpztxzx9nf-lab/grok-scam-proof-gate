#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { performance } from 'node:perf_hooks'
import { classifyMessage, assertMode } from './grok-adapter.js'
import { formatPercent, formatRate, scoreCases } from './metrics.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const FIXED_NOW = new Date('2026-01-15T00:00:00.000Z')

/**
 * @param {string[]} argv
 */
export function parseEvalArgs(argv) {
  const args = {
    mode: 'deterministic',
    dataset: path.join(ROOT, 'datasets', 'scam-eval-v1.json'),
    outDir: path.join(ROOT, 'reports'),
    failOnFalseSafe: false,
    liveNetwork: false,
    help: false,
  }
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') args.help = true
    else if (arg === '--fail-on-false-safe') args.failOnFalseSafe = true
    else if (arg === '--live-network') args.liveNetwork = true
    else if (arg.startsWith('--mode=')) args.mode = arg.slice('--mode='.length)
    else if (arg.startsWith('--dataset=')) args.dataset = path.resolve(arg.slice('--dataset='.length))
    else if (arg.startsWith('--out=')) args.outDir = path.resolve(arg.slice('--out='.length))
    else throw new Error(`Unknown argument: ${arg}`)
  }
  args.mode = assertMode(args.mode)
  return args
}

export function evalHelp() {
  return [
    'Usage: npm run eval -- --mode=deterministic|adversarial-llm|live-grok [options]',
    '',
    'Options:',
    '  --mode=<mode>           deterministic (default), adversarial-llm, or live-grok',
    '  --dataset=<path>       JSON dataset (default: datasets/scam-eval-v1.json)',
    '  --out=<dir>            Report directory (default: reports/)',
    '  --fail-on-false-safe   Exit 1 when any likely_scam case is marked safe',
    '  --live-network         With live-grok, use real RDAP and HTTP instead of dataset fixtures',
    '  --help                 Show this help',
    '',
    'live-grok requires XAI_API_KEY. It does not invent a score when the key is missing.',
    'XAI_MODEL overrides the default grok-4.7. XAI_BASE_URL overrides https://api.x.ai/v1.',
  ].join('\n')
}

/**
 * @param {object} item
 * @param {{ liveNetwork: boolean, mode: string }} settings
 */
export function caseGateOptions(item, settings) {
  if (settings.mode === 'live-grok' && settings.liveNetwork) {
    return { allowLiveHttp: true, allowLiveRdap: true, now: FIXED_NOW }
  }
  const ages = new Map(Object.entries(item.domainAgeDays || {}).map(([host, days]) => [host.toLowerCase(), Number(days)]))
  const dns = new Map(Object.entries(item.dns || {}).map(([host, ips]) => [host.toLowerCase(), ips]))
  return {
    now: FIXED_NOW,
    allowLiveHttp: false,
    allowLiveRdap: false,
    redirects: item.redirects || {},
    fetchImpl: null,
    resolver: async (host) => {
      const key = host.toLowerCase()
      if (dns.has(key)) return dns.get(key)
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(key) || key.includes(':')) return [key]
      return ['203.0.113.50']
    },
    rdapLookup: async (host) => {
      const key = host.toLowerCase()
      if (!ages.has(key)) return { unknown: true, reason: 'no_rdap_fixture' }
      const days = ages.get(key)
      if (!Number.isFinite(days)) return { inconclusive: true, reason: 'bad_fixture_age' }
      return { registrationDate: new Date(FIXED_NOW.getTime() - days * 86_400_000).toISOString() }
    },
  }
}

/**
 * @param {{
 *   mode: string,
 *   dataset: object,
 *   datasetPath?: string,
 *   liveNetwork?: boolean,
 *   apiKey?: string,
 *   model?: string,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export async function runEvaluation(options) {
  const mode = assertMode(options.mode)
  const dataset = options.dataset
  if (!dataset || dataset.synthetic !== true || dataset.customerData !== false) {
    throw new Error('Refusing to score a dataset that is not marked synthetic with customerData: false')
  }
  if (!Array.isArray(dataset.cases) || dataset.cases.length === 0) {
    throw new Error('Dataset has no cases')
  }
  const seen = new Set()
  const rows = []
  for (const item of dataset.cases) {
    if (!item || typeof item.id !== 'string' || seen.has(item.id)) {
      throw new Error(`Dataset case id missing or duplicated: ${item?.id}`)
    }
    seen.add(item.id)
    if (typeof item.text !== 'string' || typeof item.category !== 'string') {
      throw new Error(`Case ${item.id} is missing text or category`)
    }
    const started = performance.now()
    const result = await classifyMessage({
      text: item.text,
      urls: item.urls || [],
      displayName: item.displayName || null,
      senderEmail: item.senderEmail || null,
      channel: item.channel || null,
    }, {
      mode,
      apiKey: options.apiKey,
      model: options.model,
      fetchImpl: options.fetchImpl,
      proofGate: caseGateOptions(item, { mode, liveNetwork: Boolean(options.liveNetwork) }),
    })
    const latencyMs = performance.now() - started
    rows.push({
      id: item.id,
      category: item.category,
      expected: item.expected,
      predicted: result.verdict,
      modelVerdict: result.model.verdict,
      modelStatus: result.model.status,
      blockedDowngrade: result.blockedDowngrade,
      reasonIds: result.gate.reasons.map(reason => reason.id),
      latencyMs,
    })
  }
  const metrics = scoreCases(rows)
  return {
    mode,
    liveNetwork: Boolean(options.liveNetwork),
    liveModel: mode === 'live-grok',
    datasetName: dataset.name || 'dataset',
    datasetVersion: dataset.version || null,
    datasetPath: options.datasetPath || null,
    metrics,
    cases: rows,
  }
}

/**
 * @param {Awaited<ReturnType<typeof runEvaluation>>} report
 * @returns {string}
 */
export function renderMarkdown(report) {
  const metrics = report.metrics
  const lines = [
    `# Eval report: ${report.mode}`,
    '',
    report.liveModel
      ? 'This run called the live xAI Grok API. Treat the model columns as a live measurement.'
      : 'Offline run. No live Grok API call was made. Do not describe these numbers as live Grok scores.',
    '',
    `| Metric | Result |`,
    `| --- | --- |`,
    `| Cases | ${metrics.total} |`,
    `| Exact accuracy | ${formatRate(metrics.exactAccuracy, metrics.exact, metrics.total)} |`,
    `| Policy accuracy | ${formatRate(metrics.policyAccuracy, metrics.policy, metrics.total)} |`,
    `| Scam recall | ${formatRate(metrics.scamRecall, metrics.scamCaught, metrics.scamCases)} |`,
    `| Precision (likely_scam) | ${formatRate(metrics.precision, metrics.trueScam, metrics.predictedScam)} |`,
    `| False-safe rate | ${formatRate(metrics.falseSafeRate, metrics.falseSafe, metrics.scamCases)} |`,
    `| False-alarm rate | ${formatRate(metrics.falseAlarmRate, metrics.falseAlarms, metrics.benignCases)} |`,
    `| Mean latency | ${metrics.latencyMeanMs.toFixed(2)} ms |`,
    `| Model downgrades blocked | ${metrics.blockedDowngrades} |`,
    '',
    'False-safe rate is `likely_scam` cases whose final verdict was `safe`.',
    'False-alarm rate is benign (`safe`) cases whose final verdict was `likely_scam`.',
    'Scam recall counts a `likely_scam` case as caught when the final verdict is `likely_scam` or `caution`.',
    '',
    '## Categories',
    '',
    '| Category | Cases | Exact | Recall | False-safe | False alarms |',
    '| --- | ---: | ---: | ---: | ---: | ---: |',
  ]
  for (const category of metrics.categories) {
    lines.push(`| ${category.category} | ${category.total} | ${category.exact}/${category.total} | ${category.scam ? `${category.scamCaught}/${category.scam}` : 'n/a'} | ${category.falseSafe} | ${category.falseAlarms} |`)
  }
  lines.push('')
  return lines.join('\n')
}

/**
 * @param {Awaited<ReturnType<typeof runEvaluation>>} report
 */
export function renderSummary(report) {
  const metrics = report.metrics
  return [
    `Mode: ${report.mode}`,
    `Cases: ${metrics.total}`,
    `Exact accuracy: ${formatRate(metrics.exactAccuracy, metrics.exact, metrics.total)}`,
    `Policy accuracy: ${formatRate(metrics.policyAccuracy, metrics.policy, metrics.total)}`,
    `Scam recall: ${formatRate(metrics.scamRecall, metrics.scamCaught, metrics.scamCases)}`,
    `Precision: ${formatRate(metrics.precision, metrics.trueScam, metrics.predictedScam)}`,
    `False-safe rate: ${formatRate(metrics.falseSafeRate, metrics.falseSafe, metrics.scamCases)}`,
    `False-alarm rate: ${formatRate(metrics.falseAlarmRate, metrics.falseAlarms, metrics.benignCases)}`,
    `Benign marked caution: ${metrics.benignCaution}`,
    `Downgrades to safe: ${metrics.downgradeToSafe}`,
    `Model downgrades blocked: ${metrics.blockedDowngrades}`,
    `Mean latency: ${metrics.latencyMeanMs.toFixed(2)} ms`,
    `Max latency: ${metrics.latencyMaxMs.toFixed(2)} ms`,
  ].join('\n')
}

/**
 * @param {string[]} argv
 */
export async function main(argv) {
  const args = parseEvalArgs(argv)
  if (args.help) {
    console.log(evalHelp())
    return 0
  }
  if (args.mode === 'live-grok' && !process.env.XAI_API_KEY) {
    console.error('XAI_API_KEY is not set. Refusing to run live-grok or to write a live score.')
    console.error('Offline commands: npm run eval -- --mode=deterministic --fail-on-false-safe')
    console.error('                  npm run eval -- --mode=adversarial-llm --fail-on-false-safe')
    return 2
  }
  const raw = await readFile(args.dataset, 'utf8')
  const dataset = JSON.parse(raw)
  const report = await runEvaluation({
    mode: args.mode,
    dataset,
    datasetPath: args.dataset,
    liveNetwork: args.liveNetwork,
    apiKey: process.env.XAI_API_KEY,
    model: process.env.XAI_MODEL,
  })
  report.datasetSha256 = createHash('sha256').update(raw).digest('hex')
  report.generatedAt = new Date().toISOString()
  report.node = process.version
  await mkdir(args.outDir, { recursive: true })
  const stem = `eval-${args.mode}`
  await writeFile(path.join(args.outDir, `${stem}.json`), `${JSON.stringify(report, null, 2)}\n`)
  await writeFile(path.join(args.outDir, `${stem}.md`), renderMarkdown(report))
  console.log(renderSummary(report))
  console.log(`Wrote ${path.join(args.outDir, `${stem}.json`)}`)
  if (args.failOnFalseSafe && report.metrics.falseSafeRate !== 0) {
    console.error(`False-safe rate ${formatPercent(report.metrics.falseSafeRate)} is above 0.`)
    return 1
  }
  return 0
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href
if (invokedDirectly) {
  main(process.argv.slice(2)).then(code => {
    process.exitCode = code
  }).catch(error => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 2
  })
}
