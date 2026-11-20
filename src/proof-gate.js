import { extractUrls, emailHost, unique } from './extract.js'
import { expandUrl, defaultResolver } from './ssrf.js'
import { checkDomainAge } from './rdap.js'
import { analyzeBrand, classifyHost } from './brands.js'
import { matchScamRules } from './scam-rules.js'
import { applySafeInvariant, verdictFromRank, verdictRank } from './verdict.js'

const CREDENTIAL_LANGUAGE = /\b(?:password|one-?time code|sign[\s-]?in|log[\s-]?in|verify your|account (?:is )?(?:locked|frozen|suspended))\b/i

/**
 * Deterministic elder-scam Proof-Gate.
 * A safe verdict is returned only when every required check ran and passed.
 * Callers must merge model output with mergeModelVerdict(), which can only escalate.
 * @param {{
 *   text?: string,
 *   urls?: string[],
 *   displayName?: string | null,
 *   senderEmail?: string | null,
 *   channel?: string | null,
 * }} input
 * @param {{
 *   resolver?: (host: string) => Promise<string[]>,
 *   fetchImpl?: typeof fetch | null,
 *   redirects?: Record<string, string>,
 *   rdapLookup?: (host: string) => Promise<{ registrationDate?: string, unknown?: boolean, inconclusive?: boolean, reason?: string } | null>,
 *   allowLiveHttp?: boolean,
 *   allowLiveRdap?: boolean,
 *   now?: Date,
 *   timeoutMs?: number,
 *   maxRedirects?: number,
 * }} [options]
 */
export async function evaluateProofGate(input, options = {}) {
  const original = String(input?.text ?? '')
  const truncated = original.length > 200_000
  const text = truncated ? original.slice(0, 200_000) : original
  const displayName = input?.displayName ? String(input.displayName) : ''
  const senderEmail = input?.senderEmail ? String(input.senderEmail) : ''
  const channel = input?.channel ? String(input.channel) : ''
  const senderHost = emailHost(senderEmail)
  const net = networkOptions(options)

  const urls = unique([
    ...extractUrls(text),
    ...(Array.isArray(input?.urls) ? input.urls.map(url => String(url)) : []),
  ]).slice(0, 20)

  const urlItems = []
  for (const url of urls) {
    urlItems.push(await expandUrl(url, net))
  }
  const urlHosts = unique(urlItems.flatMap(item => item.hosts || []))
  const brand = analyzeBrand({
    text,
    displayName,
    senderHost,
    hosts: urlHosts,
    channel,
  })

  const ageHosts = unique([
    ...urlHosts,
    ...(senderHost ? [senderHost] : []),
  ])
  const ageItems = []
  for (const host of ageHosts) {
    const classified = classifyHost(host)
    ageItems.push(await checkDomainAge(host, {
      ...net,
      now: net.now,
      official: classified.kind === 'official',
      reserved: classified.kind === 'reserved',
    }))
  }

  const matched = matchScamRules(text)
  const trustedChannel = brand.identityVerified && brand.phonesOk && brand.lookalikes.length === 0
  const suppressed = []
  const hits = []
  for (const hit of matched) {
    if (trustedChannel && hit.soft) suppressed.push(hit.id)
    else hits.push(hit)
  }

  let rank = 0
  /** @type {Array<{ check: string, id: string, severity: 'caution' | 'likely_scam', host?: string }>} */
  const reasons = []
  const bump = (severity, reason) => {
    rank = Math.max(rank, verdictRank(severity))
    reasons.push(reason)
  }

  if (truncated) bump('caution', { check: 'urls', id: 'text_truncated', severity: 'caution' })

  for (const item of urlItems) {
    if (item.state === 'inconclusive') {
      bump('caution', { check: 'urls', id: item.reason || 'url_inconclusive', severity: 'caution' })
    } else if (item.state === 'fail') {
      const severity = item.reason === 'embedded_credentials' ? 'likely_scam' : 'caution'
      bump(severity, { check: 'urls', id: item.reason || 'unsafe_url', severity })
    }
  }

  const credential = CREDENTIAL_LANGUAGE.test(text)
  const hardHit = hits.some(hit => hit.severity === 'likely_scam')
  for (const item of ageItems) {
    if (item.state === 'inconclusive') {
      bump('caution', { check: 'domainAge', id: 'domain_age_inconclusive', severity: 'caution', host: item.host })
    } else if (item.band === 'very_young') {
      const severe = brand.claims.length > 0 || brand.lookalikes.length > 0 || credential || hardHit
      const severity = severe ? 'likely_scam' : 'caution'
      bump(severity, {
        check: 'domainAge',
        id: severe ? 'very_young_domain' : 'young_domain',
        severity,
        host: item.host,
      })
    } else if (item.band === 'young') {
      bump('caution', { check: 'domainAge', id: 'recent_domain', severity: 'caution', host: item.host })
    }
  }

  for (const finding of brand.findings) {
    bump(finding.severity, {
      check: 'brand',
      id: finding.id,
      severity: finding.severity,
      host: finding.host,
    })
  }
  for (const hit of hits) {
    bump(hit.severity, { check: 'scamRules', id: hit.id, severity: hit.severity })
  }

  const checks = {
    urls: {
      state: urlItems.length === 0 ? 'skipped' : aggregate(urlItems),
      items: urlItems.map(item => ({
        state: item.state,
        reason: item.reason,
        hosts: item.hosts || [],
        finalUrl: item.finalUrl || null,
      })),
    },
    domainAge: {
      state: ageItems.length === 0 ? 'skipped' : aggregate(ageItems),
      items: ageItems.map(item => ({
        host: item.host,
        state: item.state,
        reason: item.reason,
        band: item.band,
        ageDays: item.ageDays,
        source: item.source,
      })),
    },
    brand: {
      state: brand.findings.length ? 'fail' : 'pass',
      claims: brand.claims,
      identityVerified: brand.identityVerified,
    },
    scamRules: {
      state: hits.length ? 'fail' : 'pass',
      hits: hits.map(hit => hit.id),
      suppressed,
    },
  }

  const verdict = applySafeInvariant(verdictFromRank(rank), checks)
  return {
    verdict,
    safeEligible: verdict === 'safe',
    checks,
    reasons,
  }
}

/**
 * @param {Array<{ state: string }>} items
 * @returns {'pass' | 'fail' | 'inconclusive' | 'skipped'}
 */
function aggregate(items) {
  if (items.some(item => item.state === 'inconclusive')) return 'inconclusive'
  if (items.some(item => item.state === 'fail')) return 'fail'
  if (items.some(item => item.state === 'pass')) return 'pass'
  if (items.every(item => item.state === 'skipped')) return 'skipped'
  return 'inconclusive'
}

/**
 * @param {NonNullable<Parameters<typeof evaluateProofGate>[1]>} options
 */
function networkOptions(options) {
  const allowLiveHttp = Boolean(options.allowLiveHttp)
  const allowLiveRdap = Boolean(options.allowLiveRdap)
  const live = allowLiveHttp || allowLiveRdap
  return {
    resolver: options.resolver ?? (live ? defaultResolver : undefined),
    fetchImpl: options.fetchImpl === undefined ? (live ? globalThis.fetch : null) : options.fetchImpl,
    redirects: options.redirects ?? {},
    allowLiveHttp,
    allowLiveRdap,
    rdapLookup: options.rdapLookup,
    now: options.now instanceof Date ? options.now : new Date(),
    timeoutMs: options.timeoutMs ?? 4000,
    maxRedirects: options.maxRedirects ?? 3,
  }
}
