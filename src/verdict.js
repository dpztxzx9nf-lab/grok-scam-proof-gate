/** @typedef {'safe' | 'caution' | 'likely_scam'} Verdict */

/** @type {readonly Verdict[]} */
export const VERDICTS = Object.freeze(['safe', 'caution', 'likely_scam'])

/** Checks that must have run before a safe verdict is legal. */
export const REQUIRED_CHECKS = Object.freeze(['urls', 'domainAge', 'brand', 'scamRules'])

const RANK = Object.freeze({
  safe: 0,
  caution: 1,
  likely_scam: 2,
})

/**
 * @param {string} value
 * @returns {never}
 */
export function assertNever(value) {
  throw new Error(`Unexpected value: ${String(value)}`)
}

/**
 * @param {unknown} verdict
 * @returns {Verdict | null}
 */
export function normalizeVerdict(verdict) {
  if (verdict === 'safe' || verdict === 'caution' || verdict === 'likely_scam') return verdict
  return null
}

/**
 * @param {Verdict} verdict
 * @returns {number}
 */
export function verdictRank(verdict) {
  const rank = RANK[verdict]
  if (rank === undefined) return assertNever(verdict)
  return rank
}

/**
 * @param {number} rank
 * @returns {Verdict}
 */
export function verdictFromRank(rank) {
  if (rank >= 2) return 'likely_scam'
  if (rank >= 1) return 'caution'
  return 'safe'
}

/**
 * Higher risk wins. A null side is ignored.
 * @param {Verdict | null} left
 * @param {Verdict | null} right
 * @returns {Verdict}
 */
export function maxVerdict(left, right) {
  if (!left && !right) return 'caution'
  if (!left) return /** @type {Verdict} */ (right)
  if (!right) return left
  return verdictRank(left) >= verdictRank(right) ? left : right
}

/**
 * @param {Record<string, { state?: string }>} checks
 * @returns {boolean}
 */
export function checksAllowSafe(checks) {
  for (const name of REQUIRED_CHECKS) {
    const state = checks?.[name]?.state
    if (state !== 'pass' && state !== 'skipped') return false
  }
  return true
}

/**
 * Hard Proof-Gate invariant: never emit safe unless every required check ran
 * and finished pass or skipped. Any other state floors the verdict at caution.
 * Risk can still be higher than caution; this function never lowers a verdict.
 * @param {Verdict} verdict
 * @param {Record<string, { state?: string }>} checks
 * @returns {Verdict}
 */
export function applySafeInvariant(verdict, checks) {
  if (verdict !== 'safe') return verdict
  if (!checksAllowSafe(checks)) return 'caution'
  return 'safe'
}

/**
 * Model output may only escalate. Unknown model strings are ignored.
 * The safe invariant is applied again after the merge.
 * @param {{ verdict: Verdict, checks: Record<string, { state?: string }> }} gate
 * @param {unknown} modelVerdict
 * @returns {Verdict}
 */
export function mergeModelVerdict(gate, modelVerdict) {
  const base = applySafeInvariant(gate.verdict, gate.checks)
  const model = normalizeVerdict(modelVerdict)
  const merged = model ? maxVerdict(base, model) : base
  return applySafeInvariant(merged, gate.checks)
}
