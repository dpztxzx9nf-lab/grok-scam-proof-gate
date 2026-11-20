import { extractPhones, normalizeHost } from './extract.js'

/**
 * Published consumer-support numbers used only as a mismatch allowlist.
 * The list is incomplete on purpose. It is not a phone directory.
 * Confirm any number on the organization's own site before calling.
 * @type {ReadonlyArray<{
 *   id: string,
 *   name: string,
 *   domains: string[],
 *   phones: string[],
 *   tokens: string[],
 *   body: RegExp,
 *   display: RegExp,
 *   prefix: RegExp,
 * }>}
 */
export const BRANDS = Object.freeze([
  brand('chase', 'Chase', ['chase.com', 'jpmorganchase.com'], ['8009359935', '8004323117'], ['chase', 'jpmorgan', 'jpmorganchase'], {
    body: /\b(?:chase bank|jpmorgan(?:\s+chase)?|chase\.com|chase (?:fraud|security|account|card|customer|debit|credit|online))\b/i,
    display: /\b(?:chase|jpmorgan)\b/i,
    prefix: /^\s*(?:chase|jpmorgan(?:\s+chase)?)\s*:/i,
  }),
  brand('bankofamerica', 'Bank of America', ['bankofamerica.com', 'bofa.com'], ['8004321000'], ['bankofamerica', 'bofa'], {
    body: /\b(?:bank of america|\bbofa\b)\b/i,
    display: /\b(?:bank of america|\bbofa\b)\b/i,
    prefix: /^\s*(?:bank of america|bofa)\s*:/i,
  }),
  brand('wellsfargo', 'Wells Fargo', ['wellsfargo.com'], ['8008693557'], ['wellsfargo'], {
    body: /\bwells\s*fargo\b/i,
    display: /\bwells\s*fargo\b/i,
    prefix: /^\s*wells\s*fargo\s*:/i,
  }),
  brand('citi', 'Citi', ['citi.com', 'citibank.com'], ['8003749700'], ['citibank', 'citi'], {
    body: /\b(?:citibank|\bciti\b)\b/i,
    display: /\b(?:citibank|\bciti\b)\b/i,
    prefix: /^\s*(?:citibank|citi)\s*:/i,
  }),
  brand('capitalone', 'Capital One', ['capitalone.com'], ['8002274825'], ['capitalone'], {
    body: /\bcapital\s*one\b/i,
    display: /\bcapital\s*one\b/i,
    prefix: /^\s*capital\s*one\s*:/i,
  }),
  brand('usbank', 'U.S. Bank', ['usbank.com'], ['8008722657'], ['usbank'], {
    body: /\b(?:u\.?s\.?\s*bank|usbank)\b/i,
    display: /\b(?:u\.?s\.?\s*bank|usbank)\b/i,
    prefix: /^\s*(?:u\.?s\.?\s*bank|usbank)\s*:/i,
  }),
  brand('pnc', 'PNC', ['pnc.com'], ['8887622265'], ['pnc'], {
    body: /\bpnc(?:\s+bank)?\b/i,
    display: /\bpnc(?:\s+bank)?\b/i,
    prefix: /^\s*pnc(?:\s+bank)?\s*:/i,
  }),
  brand('amex', 'American Express', ['americanexpress.com'], ['8005284800'], ['americanexpress', 'amex'], {
    body: /\b(?:american express|\bamex\b)\b/i,
    display: /\b(?:american express|\bamex\b)\b/i,
    prefix: /^\s*(?:american express|amex)\s*:/i,
  }),
  brand('apple', 'Apple', ['apple.com', 'icloud.com'], ['8002752273', '8006927753'], ['apple', 'icloud'], {
    body: /\b(?:apple id|apple support|apple pay|apple card|\bicloud\b|apple\.com|(?:the )?apple (?:account|security|store))\b/i,
    display: /\b(?:apple|icloud)\b/i,
    prefix: /^\s*(?:apple|icloud)\s*:/i,
  }),
  brand('microsoft', 'Microsoft', ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'windows.com'], ['8006427676'], ['microsoft', 'windows', 'outlook', 'office365'], {
    body: /\b(?:microsoft|windows defender|outlook|office 365|office365)\b/i,
    display: /\b(?:microsoft|outlook)\b/i,
    prefix: /^\s*(?:microsoft|outlook)\s*:/i,
  }),
  brand('amazon', 'Amazon', ['amazon.com'], ['8882804331'], ['amazon'], {
    body: /\bamazon\b/i,
    display: /\bamazon\b/i,
    prefix: /^\s*amazon\s*:/i,
  }),
  brand('irs', 'IRS', ['irs.gov'], ['8008291040', '8008294933'], ['irs'], {
    body: /\b(?:\birs\b|internal revenue service)\b/i,
    display: /\b(?:\birs\b|internal revenue)\b/i,
    prefix: /^\s*(?:irs|internal revenue service)\s*:/i,
  }),
  brand('ssa', 'Social Security Administration', ['ssa.gov'], ['8007721213'], ['ssa'], {
    body: /\b(?:SSA\b|Social Security Administration|ssa\.gov)\b/,
    display: /\b(?:SSA\b|Social Security)\b/,
    prefix: /^\s*(?:SSA|Social Security)\s*:/,
  }),
  brand('medicare', 'Medicare', ['medicare.gov', 'cms.gov'], ['8006334227'], ['medicare'], {
    body: /\bmedicare\b/i,
    display: /\bmedicare\b/i,
    prefix: /^\s*medicare\s*:/i,
  }),
  brand('usps', 'USPS', ['usps.com'], ['8002758777'], ['usps'], {
    body: /\b(?:usps|u\.s\. postal service|united states postal)\b/i,
    display: /\b(?:usps|u\.s\. postal)\b/i,
    prefix: /^\s*(?:usps|u\.s\. postal service)\s*:/i,
  }),
  brand('fedex', 'FedEx', ['fedex.com'], ['8004633339'], ['fedex'], {
    body: /\b(?:fedex|federal express)\b/i,
    display: /\b(?:fedex|federal express)\b/i,
    prefix: /^\s*(?:fedex|federal express)\s*:/i,
  }),
  brand('ups', 'UPS', ['ups.com'], ['8007425877'], ['ups'], {
    body: /\bUPS\b|\bUnited Parcel Service\b/,
    display: /\bUPS\b|\bUnited Parcel\b/,
    prefix: /^\s*UPS\s*:/,
  }),
  brand('geeksquad', 'Geek Squad', ['geeksquad.com', 'bestbuy.com'], ['8004335778'], ['geeksquad'], {
    body: /\bgeek\s*squad\b/i,
    display: /\bgeek\s*squad\b/i,
    prefix: /^\s*geek\s*squad\s*:/i,
  }),
  brand('norton', 'Norton', ['norton.com', 'lifelock.com'], ['8009273991'], ['norton', 'lifelock'], {
    body: /\b(?:norton|lifelock)\b/i,
    display: /\b(?:norton|lifelock)\b/i,
    prefix: /^\s*(?:norton|lifelock)\s*:/i,
  }),
  brand('mcafee', 'McAfee', ['mcafee.com'], ['8666223911'], ['mcafee'], {
    body: /\bmcafee\b/i,
    display: /\bmcafee\b/i,
    prefix: /^\s*mcafee\s*:/i,
  }),
  brand('xfinity', 'Xfinity', ['xfinity.com', 'comcast.com'], ['8009346489'], ['xfinity', 'comcast'], {
    body: /\b(?:xfinity|comcast)\b/i,
    display: /\b(?:xfinity|comcast)\b/i,
    prefix: /^\s*(?:xfinity|comcast)\s*:/i,
  }),
  brand('verizon', 'Verizon', ['verizon.com', 'verizonwireless.com'], ['8009220204', '8338374966'], ['verizon'], {
    body: /\bverizon\b/i,
    display: /\bverizon\b/i,
    prefix: /^\s*verizon\s*:/i,
  }),
])

const RESERVED_DOMAINS = Object.freeze(['example.com', 'example.org', 'example.net'])

const COMPOUND_TAILS = new Set([
  'login', 'secure', 'security', 'alert', 'alerts', 'support', 'account', 'accounts',
  'online', 'verify', 'update', 'service', 'services', 'help', 'pay', 'payment',
  'refund', 'hold', 'delivery', 'tracking', 'billing', 'renew', 'renewal', 'unlock',
  'signin', 'auth', 'notice', 'notify', 'locked', 'fraud', 'card', 'bank', 'assist',
  'assistant', 'redelivery', 'fee', 'fees', 'invoice', 'id',
])

const GLUE_PREFIXES = new Set(['not', 'my', 'the', 'get'])

/**
 * @param {string} id
 * @param {string} name
 * @param {string[]} domains
 * @param {string[]} phones
 * @param {string[]} tokens
 * @param {{ body: RegExp, display: RegExp, prefix: RegExp }} patterns
 */
function brand(id, name, domains, phones, tokens, patterns) {
  return Object.freeze({ id, name, domains, phones, tokens, ...patterns })
}

/**
 * @param {string} value
 * @returns {string}
 */
export function confusableFold(value) {
  return value.toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
}

/**
 * @param {string} left
 * @param {string} right
 * @returns {number}
 */
function levenshtein(left, right) {
  if (Math.abs(left.length - right.length) > 1) return 2
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index)
  for (let i = 1; i <= left.length; i += 1) {
    const current = [i]
    let rowMin = i
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left.charCodeAt(i - 1) === right.charCodeAt(j - 1) ? 0 : 1
      const value = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
      current[j] = value
      if (value < rowMin) rowMin = value
    }
    if (rowMin > 1) return 2
    previous = current
  }
  return previous[right.length]
}

/**
 * @param {string} label
 * @param {string} token
 * @returns {boolean}
 */
export function labelSignalsBrand(label, token) {
  const folded = confusableFold(label)
  const pieces = folded.split(/[^a-z0-9]+/).filter(Boolean)
  const candidates = pieces.length ? pieces : [folded]
  for (const piece of candidates) {
    if (piece === token) return true
    const stripped = piece.replace(/^\d+|\d+$/g, '')
    if (stripped === token) return true
    if (token.length >= 4 && piece.startsWith(token)) {
      const rest = piece.slice(token.length)
      if (rest.length === 0 || COMPOUND_TAILS.has(rest)) return true
    }
    if (token.length >= 5 && piece.endsWith(token)) {
      const prefix = piece.slice(0, piece.length - token.length)
      if (GLUE_PREFIXES.has(prefix)) return true
    }
    if (token.length >= 5 && piece.length >= 5 && Math.abs(piece.length - token.length) <= 1 && levenshtein(piece, token) === 1) {
      return true
    }
  }
  return false
}

/**
 * @param {string} host
 * @param {string[]} domains
 * @returns {boolean}
 */
export function isOfficialHost(host, domains) {
  const normalized = normalizeHost(host)
  return domains.some(domain => normalized === domain || normalized.endsWith(`.${domain}`))
}

/**
 * @param {string} host
 * @param {string} domain
 * @returns {boolean}
 */
export function hostEmbedsBrandDomain(host, domain) {
  const normalized = normalizeHost(host)
  const brandDomain = domain.toLowerCase()
  if (normalized === brandDomain || normalized.endsWith(`.${brandDomain}`)) return false
  const foldedHost = confusableFold(normalized)
  const foldedDomain = confusableFold(brandDomain)
  return foldedHost.includes(`${foldedDomain}.`)
}

/**
 * @param {string} host
 * @returns {{ kind: 'official' | 'lookalike' | 'punycode' | 'reserved' | 'other', brands: string[] }}
 */
export function classifyHost(host) {
  const normalized = normalizeHost(host)
  if (!normalized) return { kind: 'other', brands: [] }
  const official = []
  for (const entry of BRANDS) {
    if (isOfficialHost(normalized, entry.domains)) official.push(entry.id)
  }
  if (official.length) return { kind: 'official', brands: official }

  const spoofed = []
  const labels = normalized.split('.').filter(Boolean)
  for (const entry of BRANDS) {
    const embedded = entry.domains.some(domain => hostEmbedsBrandDomain(normalized, domain))
    const labeled = labels.some(label => entry.tokens.some(token => labelSignalsBrand(label, token)))
    const squashed = labels.some(label => squashedSignals(confusableFold(label), entry.tokens))
    if (embedded || labeled || squashed) spoofed.push(entry.id)
  }
  if (spoofed.length) return { kind: 'lookalike', brands: spoofed }
  if (labels.some(label => label.startsWith('xn--'))) return { kind: 'punycode', brands: [] }
  if (RESERVED_DOMAINS.some(domain => normalized === domain || normalized.endsWith(`.${domain}`))) {
    return { kind: 'reserved', brands: [] }
  }
  return { kind: 'other', brands: [] }
}

/**
 * @param {string} label
 * @param {string[]} tokens
 * @returns {boolean}
 */
function squashedSignals(label, tokens) {
  const squashed = label.replace(/[^a-z0-9]/g, '')
  for (const token of tokens) {
    if (!squashed.startsWith(token)) continue
    const rest = squashed.slice(token.length)
    if (rest.length === 0 || COMPOUND_TAILS.has(rest)) return true
  }
  return false
}

/**
 * @param {(typeof BRANDS)[number]} entry
 * @param {string} text
 * @param {string} displayName
 * @returns {boolean}
 */
function claimsBrand(entry, text, displayName) {
  if (displayName && entry.display.test(displayName)) return true
  if (entry.body.test(text)) return true
  if (entry.prefix.test(text)) return true
  return false
}

/**
 * @param {string} host
 * @param {Array<(typeof BRANDS)[number]>} claims
 * @returns {boolean}
 */
function hostAuthorized(host, claims) {
  return claims.every(entry => isOfficialHost(host, entry.domains))
}

/**
 * @param {string} before
 * @param {string} channel
 * @param {boolean} hasClaims
 * @returns {boolean}
 */
function isSupportContext(before, channel, hasClaims) {
  if (/\b(?:call|text|phone|ring)\s+me\b/i.test(before)) return false
  if (channel === 'sms' && hasClaims) return true
  if (/\b(?:support|helpline|fraud|customer service|toll[- ]?free|agent|officer|call us|call now|dial|contact us|text us|phone us)\b/i.test(before)) {
    return true
  }
  if (hasClaims && /\b(?:call|dial|text|phone)\b/i.test(before)) return true
  return false
}

/**
 * @param {{
 *   text: string,
 *   displayName?: string,
 *   senderHost?: string | null,
 *   hosts?: string[],
 *   channel?: string,
 * }} input
 */
export function analyzeBrand(input) {
  const text = input.text || ''
  const displayName = input.displayName || ''
  const channel = input.channel || ''
  const claims = BRANDS.filter(entry => claimsBrand(entry, text, displayName))
  const hosts = []
  const seen = new Set()
  for (const host of [input.senderHost, ...(input.hosts || [])]) {
    if (!host) continue
    const normalized = normalizeHost(host)
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    hosts.push(normalized)
  }

  /** @type {Array<{ id: string, severity: 'caution' | 'likely_scam', host?: string, brands?: string[] }>} */
  const findings = []
  const lookalikes = []
  for (const host of hosts) {
    const classified = classifyHost(host)
    if (classified.kind === 'lookalike') {
      lookalikes.push(host)
      findings.push({ id: 'lookalike_domain', severity: 'likely_scam', host, brands: classified.brands })
      continue
    }
    if (classified.kind === 'punycode') {
      findings.push({
        id: 'punycode_host',
        severity: claims.length ? 'likely_scam' : 'caution',
        host,
      })
      continue
    }
    if (claims.length && !hostAuthorized(host, claims)) {
      findings.push({
        id: 'brand_domain_mismatch',
        severity: 'likely_scam',
        host,
        brands: claims.map(entry => entry.id),
      })
    }
  }

  let phonesOk = true
  const phones = extractPhones(text)
  for (const phone of phones) {
    const before = text.slice(Math.max(0, phone.index - 80), phone.index)
    if (!isSupportContext(before, channel, claims.length > 0)) continue
    if (!claims.length) continue
    const allowed = claims.some(entry => entry.phones.includes(phone.digits))
    if (allowed) continue
    phonesOk = false
    const catalogued = claims.some(entry => entry.phones.length > 0)
    findings.push({
      id: catalogued ? 'unofficial_support_phone' : 'unverified_support_phone',
      severity: catalogued ? 'likely_scam' : 'caution',
    })
  }

  const identityVerified = claims.length > 0
    && hosts.length > 0
    && lookalikes.length === 0
    && hosts.every(host => hostAuthorized(host, claims))

  return {
    claims: claims.map(entry => entry.id),
    findings,
    identityVerified,
    phonesOk,
    lookalikes,
  }
}
