import net from 'node:net'
import { inspectUrl, expandUrl } from './ssrf.js'
import { normalizeHost } from './extract.js'

export const VERY_YOUNG_DAYS = 45
export const YOUNG_DAYS = 180

const RDAP_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

/**
 * @param {unknown} body
 * @returns {string | null}
 */
export function registrationDateFromRdap(body) {
  if (!body || typeof body !== 'object') return null
  const events = /** @type {{ events?: unknown }} */ (body).events
  if (!Array.isArray(events)) return null
  const registration = events.find(event => event && typeof event === 'object' && event.eventAction === 'registration')
  const date = registration && typeof registration === 'object' ? registration.eventDate : null
  return typeof date === 'string' ? date : null
}

/**
 * @param {string | Date} registrationDate
 * @param {Date} now
 * @returns {number | null}
 */
export function ageInDays(registrationDate, now) {
  const registered = new Date(registrationDate)
  if (Number.isNaN(registered.getTime()) || Number.isNaN(now.getTime())) return null
  return (now.getTime() - registered.getTime()) / 86_400_000
}

/**
 * @param {number} ageDays
 * @returns {'very_young' | 'young' | 'established'}
 */
export function ageBand(ageDays) {
  if (ageDays < VERY_YOUNG_DAYS) return 'very_young'
  if (ageDays < YOUNG_DAYS) return 'young'
  return 'established'
}

/**
 * HTTPS RDAP client. Redirects are re-checked with the same SSRF rules as
 * ordinary links and are never followed onto a private or metadata address.
 * @param {string} domain
 * @param {{
 *   fetchImpl?: typeof fetch,
 *   resolver?: (host: string) => Promise<string[]>,
 *   timeoutMs?: number,
 *   now?: Date,
 * }} [options]
 */
export async function liveRdapLookup(domain, options = {}) {
  const host = normalizeHost(domain)
  if (!RDAP_DOMAIN.test(host) || net.isIP(host) !== 0) {
    return { inconclusive: true, reason: 'invalid_domain' }
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const start = `https://rdap.org/domain/${encodeURIComponent(host)}`
  const expanded = await expandUrl(start, {
    resolver: options.resolver,
    fetchImpl,
    allowLiveHttp: true,
    maxRedirects: 3,
    timeoutMs: options.timeoutMs ?? 4000,
  })
  if (expanded.state !== 'pass' || !expanded.finalUrl) {
    return { inconclusive: true, reason: expanded.reason || 'rdap_unreachable' }
  }
  const inspected = inspectUrl(expanded.finalUrl)
  if (!inspected.ok) return { inconclusive: true, reason: inspected.reason || 'rdap_unsafe' }
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 4000)
    try {
      const response = await fetchImpl(expanded.finalUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { accept: 'application/rdap+json, application/json' },
      })
      if (!response.ok) return { inconclusive: true, reason: `rdap_http_${response.status}` }
      const body = await response.json()
      const registrationDate = registrationDateFromRdap(body)
      if (!registrationDate) return { inconclusive: true, reason: 'no_registration_event' }
      return { registrationDate }
    } finally {
      clearTimeout(timer)
    }
  } catch (error) {
    const aborted = error && typeof error === 'object' && 'name' in error && error.name === 'AbortError'
    return { inconclusive: true, reason: aborted ? 'timeout' : 'rdap_error' }
  }
}

/**
 * @param {string} host
 * @param {{
 *   rdapLookup?: (host: string) => Promise<{ registrationDate?: string, unknown?: boolean, inconclusive?: boolean, reason?: string } | null>,
 *   allowLiveRdap?: boolean,
 *   fetchImpl?: typeof fetch,
 *   resolver?: (host: string) => Promise<string[]>,
 *   now?: Date,
 *   timeoutMs?: number,
 *   official?: boolean,
 *   reserved?: boolean,
 * }} options
 */
export async function checkDomainAge(host, options) {
  const normalized = normalizeHost(host)
  const now = options.now instanceof Date ? options.now : new Date()
  if (!normalized || normalized.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(normalized)) {
    return { host: normalized, state: 'skipped', reason: 'ip_host', band: null, ageDays: null, source: 'skipped' }
  }

  let record = null
  if (options.rdapLookup) {
    try {
      record = await options.rdapLookup(normalized)
    } catch {
      record = { inconclusive: true, reason: 'rdap_error' }
    }
  } else if (options.allowLiveRdap) {
    record = await liveRdapLookup(normalized, options)
  } else {
    record = { unknown: true, reason: 'no_rdap_fixture' }
  }

  const registrationDate = record?.registrationDate
  const ageDays = registrationDate ? ageInDays(registrationDate, now) : null
  const dated = ageDays !== null && ageDays >= 0

  if (options.official || options.reserved) {
    return {
      host: normalized,
      state: 'pass',
      reason: options.official ? 'allowlisted_domain' : 'reserved_documentation_domain',
      band: 'established',
      ageDays: dated ? ageDays : null,
      source: dated ? 'rdap' : (options.official ? 'allowlist_prior' : 'reserved_prior'),
    }
  }

  if (!dated) {
    return {
      host: normalized,
      state: 'inconclusive',
      reason: record?.reason || 'no_registration_date',
      band: null,
      ageDays: null,
      source: 'rdap',
    }
  }

  const band = ageBand(ageDays)
  return {
    host: normalized,
    state: band === 'established' ? 'pass' : 'fail',
    reason: band,
    band,
    ageDays,
    source: 'rdap',
  }
}
