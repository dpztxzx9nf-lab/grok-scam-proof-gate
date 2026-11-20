import net from 'node:net'
import { lookup } from 'node:dns/promises'
import { normalizeHost } from './extract.js'

const BLOCKED_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.internal',
])

/**
 * @param {string} hostname
 * @returns {boolean}
 */
export function isBlockedHostname(hostname) {
  const host = normalizeHost(hostname)
  if (!host) return true
  if (BLOCKED_HOSTS.has(host)) return true
  if (host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true
  return false
}

/**
 * @param {number} byte
 * @returns {boolean}
 */
function isByte(byte) {
  return Number.isInteger(byte) && byte >= 0 && byte <= 255
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIpv4(ip) {
  const parts = ip.split('.').map(part => Number(part))
  if (parts.length !== 4 || parts.some(part => !isByte(part))) return true
  const [a, b, c] = parts
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a >= 224) return true
  return false
}

/**
 * Expand an IPv6 address to 16 bytes. Returns null when the text is not IPv6.
 * @param {string} ip
 * @returns {number[] | null}
 */
export function ipv6ToBytes(ip) {
  let value = normalizeHost(ip).toLowerCase()
  if (!value.includes(':')) return null
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':')
    const v4 = value.slice(lastColon + 1).split('.').map(part => Number(part))
    if (v4.length !== 4 || v4.some(part => !isByte(part))) return null
    const hex = v4.map(part => part.toString(16).padStart(2, '0')).join('')
    value = `${value.slice(0, lastColon + 1)}${hex.slice(0, 4)}:${hex.slice(4)}`
  }
  const halves = value.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  if (halves.length === 1 && head.length !== 8) return null
  const missing = 8 - head.length - tail.length
  if (missing < 0) return null
  const groups = [...head, ...Array.from({ length: missing }, () => '0'), ...tail]
  if (groups.length !== 8) return null
  const bytes = []
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null
    const parsed = Number.parseInt(group, 16)
    bytes.push((parsed >> 8) & 0xff, parsed & 0xff)
  }
  return bytes
}

/**
 * @param {number[]} bytes
 * @param {number} length
 * @returns {boolean}
 */
function prefixZero(bytes, length) {
  for (let i = 0; i < length; i += 1) {
    if (bytes[i] !== 0) return false
  }
  return true
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIpv6(ip) {
  const bytes = ipv6ToBytes(ip)
  if (!bytes) return true
  const mapped = prefixZero(bytes, 10) && bytes[10] === 0xff && bytes[11] === 0xff
  if (mapped) {
    return isBlockedIpv4(bytes.slice(12).join('.'))
  }
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return isBlockedIpv4(bytes.slice(2, 6).join('.'))
  }
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && prefixZero(bytes.slice(4, 12), 8)) {
    return isBlockedIpv4(bytes.slice(12).join('.'))
  }
  if (bytes.every(byte => byte === 0)) return true
  if (prefixZero(bytes, 15) && bytes[15] === 1) return true
  if (bytes[0] === 0xff) return true
  if ((bytes[0] & 0xfe) === 0xfc) return true
  if (bytes[0] === 0xfe && (bytes[1] & 0x80) === 0x80) return true
  return false
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIp(ip) {
  const value = normalizeHost(ip)
  const kind = net.isIP(value)
  if (kind === 4) return isBlockedIpv4(value)
  if (kind === 6) return isBlockedIpv6(value)
  return true
}

/**
 * @param {string} raw
 * @returns {{
 *   ok: boolean,
 *   reason?: string,
 *   href?: string,
 *   host?: string,
 *   literal?: string | null,
 * }}
 */
export function inspectUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) {
    return { ok: false, reason: 'url_too_long' }
  }
  let url
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, reason: 'unparseable' }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'non_http', href: url.href }
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'embedded_credentials', href: url.href, host: normalizeHost(url.hostname) }
  }
  const host = normalizeHost(url.hostname)
  if (!host) return { ok: false, reason: 'missing_host', href: url.href }
  if (isBlockedHostname(host)) return { ok: false, reason: 'blocked_host', href: url.href, host }
  const literal = net.isIP(host) ? host : null
  if (literal && isBlockedIp(literal)) {
    return { ok: false, reason: 'blocked_ip', href: url.href, host, literal }
  }
  return { ok: true, href: url.href, host, literal }
}

/**
 * @param {string} hostname
 * @returns {Promise<string[]>}
 */
export async function defaultResolver(hostname) {
  const host = normalizeHost(hostname)
  if (net.isIP(host)) return [host]
  const records = await lookup(host, { all: true, verbatim: true })
  return records.map(record => record.address)
}

/**
 * @param {string} current
 * @param {Record<string, string> | undefined} redirects
 * @returns {string | undefined}
 */
function fixtureRedirect(current, redirects) {
  if (!redirects) return undefined
  if (Object.hasOwn(redirects, current)) return redirects[current]
  const trimmed = current.endsWith('/') ? current.slice(0, -1) : `${current}/`
  if (Object.hasOwn(redirects, trimmed)) return redirects[trimmed]
  return undefined
}

/**
 * @param {Response | { status?: number, headers?: Headers | Record<string, string> | { get?: (name: string) => string | null } }} response
 * @returns {string | null}
 */
function locationOf(response) {
  const headers = response.headers
  if (!headers) return null
  if (typeof headers.get === 'function') return headers.get('location')
  const record = /** @type {Record<string, string>} */ (headers)
  return record.location || record.Location || null
}

/**
 * Bounded, SSRF-checked redirect expansion.
 * Each hop is parsed and resolved before it is requested. Private, loopback,
 * link-local, metadata, and IPv6 ULA targets are refused and never fetched.
 * @param {string} raw
 * @param {{
 *   resolver?: (host: string) => Promise<string[]>,
 *   fetchImpl?: typeof fetch | null,
 *   redirects?: Record<string, string>,
 *   maxRedirects?: number,
 *   timeoutMs?: number,
 *   allowLiveHttp?: boolean,
 * }} [options]
 */
export async function expandUrl(raw, options = {}) {
  const maxRedirects = options.maxRedirects ?? 3
  const timeoutMs = options.timeoutMs ?? 2500
  const chain = []
  const hosts = []
  let current = raw

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const inspected = inspectUrl(current)
    if (!inspected.ok || !inspected.host || !inspected.href) {
      return {
        state: 'fail',
        reason: inspected.reason || 'unparseable',
        chain,
        hosts,
        finalUrl: null,
      }
    }

    let ips = []
    if (inspected.literal) {
      ips = [inspected.literal]
    } else if (!options.resolver) {
      return { state: 'inconclusive', reason: 'no_resolver', chain, hosts, finalUrl: null }
    } else {
      try {
        ips = await options.resolver(inspected.host)
      } catch {
        return { state: 'inconclusive', reason: 'dns_error', chain, hosts, finalUrl: null }
      }
      if (!Array.isArray(ips) || ips.length === 0) {
        return { state: 'inconclusive', reason: 'dns_failed', chain, hosts, finalUrl: null }
      }
      if (ips.some(ip => isBlockedIp(ip))) {
        return { state: 'fail', reason: 'blocked_ip', chain, hosts, finalUrl: null, ips }
      }
    }

    chain.push(inspected.href)
    hosts.push(inspected.host)

    const scripted = fixtureRedirect(current, options.redirects) ?? fixtureRedirect(inspected.href, options.redirects)
    let next = scripted === undefined ? null : scripted
    if (scripted === undefined && options.fetchImpl && options.allowLiveHttp !== false) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const response = await options.fetchImpl(inspected.href, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
        })
        const status = response.status ?? 0
        if (status >= 300 && status < 400) {
          next = locationOf(response)
          if (!next) return { state: 'inconclusive', reason: 'redirect_missing', chain, hosts, finalUrl: null }
        } else if (status >= 200 && status < 300) {
          next = null
        } else if (status === 0) {
          next = null
        } else {
          return { state: 'inconclusive', reason: `http_${status}`, chain, hosts, finalUrl: inspected.href }
        }
      } catch {
        return { state: 'inconclusive', reason: 'fetch_failed', chain, hosts, finalUrl: null }
      } finally {
        clearTimeout(timer)
      }
    }

    if (!next) {
      return { state: 'pass', reason: 'resolved', chain, hosts, finalUrl: inspected.href, ips }
    }
    if (hop === maxRedirects) {
      return { state: 'inconclusive', reason: 'redirect_limit', chain, hosts, finalUrl: null }
    }
    try {
      current = new URL(next, inspected.href).href
    } catch {
      return { state: 'fail', reason: 'bad_redirect', chain, hosts, finalUrl: null }
    }
  }

  return { state: 'inconclusive', reason: 'redirect_limit', chain, hosts, finalUrl: null }
}
