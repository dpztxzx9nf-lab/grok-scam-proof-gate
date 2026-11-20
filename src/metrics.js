import { normalizeVerdict } from './verdict.js'

/**
 * @param {'safe' | 'caution' | 'likely_scam'} expected
 * @param {'safe' | 'caution' | 'likely_scam'} predicted
 * @returns {boolean}
 */
export function policyMatch(expected, predicted) {
  if (expected === 'safe') return predicted === 'safe'
  return predicted !== 'safe'
}

/**
 * @param {number} value
 * @param {number} total
 * @returns {number | null}
 */
function rate(value, total) {
  if (!total) return null
  return value / total
}

/**
 * @param {Array<{ id?: string, category: string, expected: string, predicted: string, latencyMs?: number, blockedDowngrade?: boolean }>} cases
 */
export function scoreCases(cases) {
  const rows = cases.map(item => {
    const expected = normalizeVerdict(item.expected)
    const predicted = normalizeVerdict(item.predicted)
    if (!expected || !predicted) {
      throw new Error(`Case ${item.id || '(unknown)'} has a verdict outside safe|caution|likely_scam`)
    }
    return { ...item, expected, predicted, latencyMs: item.latencyMs ?? 0 }
  })

  const total = rows.length
  const exact = rows.filter(row => row.predicted === row.expected).length
  const policy = rows.filter(row => policyMatch(row.expected, row.predicted)).length
  const scamRows = rows.filter(row => row.expected === 'likely_scam')
  const scamCaught = scamRows.filter(row => row.predicted === 'likely_scam' || row.predicted === 'caution').length
  const falseSafe = scamRows.filter(row => row.predicted === 'safe').length
  const predictedScam = rows.filter(row => row.predicted === 'likely_scam')
  const trueScam = predictedScam.filter(row => row.expected === 'likely_scam').length
  const benignRows = rows.filter(row => row.expected === 'safe')
  const falseAlarms = benignRows.filter(row => row.predicted === 'likely_scam').length
  const benignCaution = benignRows.filter(row => row.predicted === 'caution').length
  const downgradeToSafe = rows.filter(row => row.expected !== 'safe' && row.predicted === 'safe').length
  const blockedDowngrades = rows.filter(row => row.blockedDowngrade).length
  const latencies = rows.map(row => row.latencyMs)
  const latencyTotalMs = latencies.reduce((sum, value) => sum + value, 0)

  /** @type {Map<string, { category: string, total: number, exact: number, scam: number, scamCaught: number, falseSafe: number, benign: number, falseAlarms: number }>} */
  const categories = new Map()
  for (const row of rows) {
    const bucket = categories.get(row.category) ?? {
      category: row.category,
      total: 0,
      exact: 0,
      scam: 0,
      scamCaught: 0,
      falseSafe: 0,
      benign: 0,
      falseAlarms: 0,
    }
    bucket.total += 1
    if (row.predicted === row.expected) bucket.exact += 1
    if (row.expected === 'likely_scam') {
      bucket.scam += 1
      if (row.predicted === 'likely_scam' || row.predicted === 'caution') bucket.scamCaught += 1
      if (row.predicted === 'safe') bucket.falseSafe += 1
    }
    if (row.expected === 'safe') {
      bucket.benign += 1
      if (row.predicted === 'likely_scam') bucket.falseAlarms += 1
    }
    categories.set(row.category, bucket)
  }

  return {
    total,
    exact,
    exactAccuracy: rate(exact, total),
    policy,
    policyAccuracy: rate(policy, total),
    scamCases: scamRows.length,
    scamCaught,
    scamRecall: rate(scamCaught, scamRows.length),
    predictedScam: predictedScam.length,
    trueScam,
    precision: rate(trueScam, predictedScam.length),
    falseSafe,
    falseSafeRate: rate(falseSafe, scamRows.length),
    benignCases: benignRows.length,
    falseAlarms,
    falseAlarmRate: rate(falseAlarms, benignRows.length),
    benignCaution,
    downgradeToSafe,
    blockedDowngrades,
    latencyTotalMs,
    latencyMeanMs: total ? latencyTotalMs / total : 0,
    latencyMaxMs: latencies.length ? Math.max(...latencies) : 0,
    categories: [...categories.values()].sort((left, right) => left.category.localeCompare(right.category)),
  }
}

/**
 * @param {number | null} value
 * @returns {string}
 */
export function formatPercent(value) {
  if (value === null) return 'n/a'
  return `${(value * 100).toFixed(1)}%`
}

/**
 * @param {number | null} value
 * @param {number} count
 * @param {number} total
 * @returns {string}
 */
export function formatRate(value, count, total) {
  if (!total) return 'n/a'
  return `${formatPercent(value)} (${count}/${total})`
}
