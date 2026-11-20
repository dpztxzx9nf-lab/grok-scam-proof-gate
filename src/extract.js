const URL_RE = /\bhttps?:\/\/[^\s<>"'`{}|\\^]+/gi
const PHONE_RE = /(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/g
const EMAIL_RE = /\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})\b/g

/**
 * @param {string} url
 * @returns {string}
 */
export function trimUrl(url) {
  return url.replace(/[),.;:!?\]>'"]+$/g, '')
}

/**
 * @param {string} text
 * @returns {string[]}
 */
export function extractUrls(text) {
  const found = []
  for (const match of String(text).matchAll(URL_RE)) {
    const url = trimUrl(match[0])
    if (url) found.push(url)
  }
  return found
}

/**
 * @param {string} value
 * @returns {string}
 */
export function digitsOnly(value) {
  return String(value).replace(/\D/g, '')
}

/**
 * Last 10 digits of a NANP number, or null when the digit count is not 10 or 11.
 * @param {string} value
 * @returns {string | null}
 */
export function normalizePhone(value) {
  const digits = digitsOnly(value)
  if (digits.length === 10) return digits
  if (digits.length === 11 && digits.startsWith('1')) return digits.slice(1)
  return null
}

/**
 * @param {string} text
 * @returns {Array<{ raw: string, digits: string, index: number }>}
 */
export function extractPhones(text) {
  const found = []
  for (const match of String(text).matchAll(PHONE_RE)) {
    const digits = normalizePhone(match[0])
    if (!digits) continue
    found.push({ raw: match[0], digits, index: match.index ?? 0 })
  }
  return found
}

/**
 * @param {string} email
 * @returns {string | null}
 */
export function emailHost(email) {
  if (!email) return null
  const match = String(email).trim().match(/^[^@\s]+@([^@\s]+)$/)
  if (!match) return null
  return normalizeHost(match[1])
}

/**
 * @param {string} text
 * @returns {Array<{ email: string, local: string, host: string, index: number }>}
 */
export function extractEmails(text) {
  const found = []
  for (const match of String(text).matchAll(EMAIL_RE)) {
    found.push({
      email: match[0],
      local: match[1],
      host: match[2].toLowerCase(),
      index: match.index ?? 0,
    })
  }
  return found
}

/**
 * @param {string} host
 * @returns {string}
 */
export function normalizeHost(host) {
  let value = String(host).trim().toLowerCase()
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1)
  while (value.endsWith('.')) value = value.slice(0, -1)
  return value
}

/**
 * @param {string[]} values
 * @returns {string[]}
 */
export function unique(values) {
  const seen = new Set()
  const out = []
  for (const value of values) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}
