const NOW = new Date('2026-01-15T00:00:00.000Z')

/**
 * Offline network doubles. Unknown domains have no RDAP date.
 * @param {{
 *   domainAgeDays?: Record<string, number>,
 *   dns?: Record<string, string[]>,
 *   redirects?: Record<string, string>,
 *   fetchImpl?: typeof fetch | null,
 *   resolver?: (host: string) => Promise<string[]>,
 * }} [extra]
 */
export function offlineOptions(extra = {}) {
  const ages = extra.domainAgeDays || {}
  const dns = extra.dns || {}
  return {
    now: NOW,
    allowLiveHttp: false,
    allowLiveRdap: false,
    redirects: extra.redirects || {},
    fetchImpl: extra.fetchImpl === undefined ? null : extra.fetchImpl,
    resolver: extra.resolver || (async (host) => dns[host] || ['203.0.113.50']),
    rdapLookup: async (host) => {
      if (!Object.hasOwn(ages, host)) return { unknown: true, reason: 'no_rdap_fixture' }
      return { registrationDate: new Date(NOW.getTime() - ages[host] * 86_400_000).toISOString() }
    },
  }
}

/**
 * @param {number} status
 * @param {Record<string, string>} [headers]
 * @param {unknown} [body]
 */
export function fakeResponse(status, headers = {}, body = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        const key = Object.keys(headers).find(header => header.toLowerCase() === name.toLowerCase())
        return key ? headers[key] : null
      },
    },
    json: async () => body,
  }
}
