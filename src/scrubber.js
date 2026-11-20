const LETTER = 'ACDEFGHJKMNPQRTUVWXY'
const LETTER_OR_DIGIT = `${LETTER}0-9`
const MBI_CORE = `[1-9][${LETTER}][${LETTER_OR_DIGIT}]\\d[${LETTER}][${LETTER_OR_DIGIT}]\\d[${LETTER}][${LETTER}]\\d\\d`
const MBI_DASHED = `[1-9][${LETTER}][${LETTER_OR_DIGIT}]\\d-[${LETTER}][${LETTER_OR_DIGIT}]\\d-[${LETTER}][${LETTER}]\\d\\d`

/**
 * @param {string} digits
 * @returns {boolean}
 */
export function passesLuhn(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false
  let sum = 0
  let alternate = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = digits.charCodeAt(index) - 48
    if (alternate) {
      value *= 2
      if (value > 9) value -= 9
    }
    sum += value
    alternate = !alternate
  }
  return sum % 10 === 0
}

/**
 * @param {string} digits
 * @returns {boolean}
 */
export function passesAba(digits) {
  if (!/^\d{9}$/.test(digits) || digits === '000000000') return false
  const values = digits.split('').map(Number)
  const sum = 3 * (values[0] + values[3] + values[6])
    + 7 * (values[1] + values[4] + values[7])
    + (values[2] + values[5] + values[8])
  return sum !== 0 && sum % 10 === 0
}

/**
 * @param {string} text
 * @param {RegExp} regex
 * @param {(match: RegExpMatchArray) => { type: string, placeholder: string, group?: number, priority: number } | null} accept
 * @param {Array<{ start: number, end: number, type: string, placeholder: string, priority: number }>} found
 */
function collect(text, regex, accept, found) {
  const flags = `${regex.flags.includes('g') ? '' : 'g'}${regex.flags.includes('d') ? '' : 'd'}${regex.flags}`
  const re = new RegExp(regex.source, flags)
  for (const match of text.matchAll(re)) {
    const accepted = accept(match)
    if (!accepted) continue
    const group = accepted.group ?? 0
    const indices = match.indices?.[group]
    if (!indices) continue
    const [start, end] = indices
    if (end <= start) continue
    found.push({ start, end, type: accepted.type, placeholder: accepted.placeholder, priority: accepted.priority })
  }
}

/**
 * Redact SSNs, payment numbers, Medicare IDs, secrets, and other sensitive
 * identifiers before a model call or a log line.
 * @param {string} input
 * @returns {{ scrubbedText: string, redactions: Array<{ type: string, start: number, end: number, placeholder: string }> }}
 */
export function scrubText(input) {
  const text = String(input ?? '')
  /** @type {Array<{ start: number, end: number, type: string, placeholder: string, priority: number }>} */
  const found = []

  collect(text, /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/gi, (match) => {
    const digits = match[0].replace(/\D/g, '')
    if (!passesLuhn(digits)) return null
    return { type: 'card', placeholder: '[REDACTED_CARD]', priority: 1 }
  }, found)

  collect(text, new RegExp(`\\b(?:${MBI_CORE}|${MBI_DASHED})\\b`, 'gi'), () => ({
    type: 'mbi',
    placeholder: '[REDACTED_MBI]',
    priority: 2,
  }), found)

  collect(text, /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g, () => ({
    type: 'ssn',
    placeholder: '[REDACTED_SSN]',
    priority: 3,
  }), found)

  collect(text, /(?<!\d)\d{3}\s\d{2}\s\d{4}(?!\d)/g, () => ({
    type: 'ssn',
    placeholder: '[REDACTED_SSN]',
    priority: 3,
  }), found)

  collect(text, /\b(?:routing|aba|rtn)(?:\s*(?:number|no\.?|#))?\s*[:=]?\s*(\d{9})\b/gi, () => ({
    type: 'routing',
    placeholder: '[REDACTED_ROUTING]',
    group: 1,
    priority: 4,
  }), found)

  collect(text, /\b\d{9}\b/g, (match) => {
    if (!passesAba(match[0])) return null
    const around = text.slice(Math.max(0, (match.index ?? 0) - 40), (match.index ?? 0) + match[0].length + 40)
    if (!/\b(?:routing|aba|rtn|bank)\b/i.test(around)) return null
    return { type: 'routing', placeholder: '[REDACTED_ROUTING]', priority: 4 }
  }, found)

  collect(text, /\b(?:bank\s+)?(?:account|acct)\s*(?:number|no\.?|#)?\s*[:=]?\s*(\d[\d -]{4,22}\d)/gi, (match) => {
    const digits = match[1].replace(/\D/g, '')
    if (digits.length < 6 || digits.length > 17) return null
    return { type: 'account', placeholder: '[REDACTED_ACCOUNT]', group: 1, priority: 5 }
  }, found)

  collect(text, /\b(?:password|passcode|passwd|pwd|pin|otp|one-?time(?:\s+(?:password|code|pin))?)\b\s*(?:is|was|:|=|of)?\s*["']?([A-Za-z0-9!@#$%^&*._-]{3,64})/gi, () => ({
    type: 'secret',
    placeholder: '[REDACTED_SECRET]',
    group: 1,
    priority: 6,
  }), found)

  collect(text, /\b(?:cvv|cvc|security code)\b\s*[:=]?\s*(\d{3,4})\b/gi, () => ({
    type: 'cvv',
    placeholder: '[REDACTED_CVV]',
    group: 1,
    priority: 7,
  }), found)

  collect(text, /\b(?:dob|date of birth|birth date)\b\s*(?:is|:|=)?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})/gi, () => ({
    type: 'dob',
    placeholder: '[REDACTED_DOB]',
    group: 1,
    priority: 8,
  }), found)

  collect(text, /\b(?:driver'?s? licen[sc]e(?:\s*(?:number|no\.?|#))?|dl\s*[#:])\s*[:=]?\s*([A-Z0-9][A-Z0-9-]{3,19})\b/gi, () => ({
    type: 'dl',
    placeholder: '[REDACTED_DL]',
    group: 1,
    priority: 9,
  }), found)

  collect(text, /\b(?:mother'?s? maiden name)\b\s*(?:is|:|=)?\s*([A-Za-z][A-Za-z' -]{1,40})/gi, () => ({
    type: 'maiden',
    placeholder: '[REDACTED_MAIDEN]',
    group: 1,
    priority: 10,
  }), found)

  collect(text, /\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})\b/gi, () => ({
    type: 'email',
    placeholder: '[REDACTED_EMAIL]',
    group: 1,
    priority: 11,
  }), found)

  found.sort((left, right) => left.start - right.start || left.priority - right.priority || (right.end - right.start) - (left.end - left.start))
  /** @type {typeof found} */
  const chosen = []
  for (const candidate of found) {
    if (chosen.some(item => candidate.start < item.end && candidate.end > item.start)) continue
    chosen.push(candidate)
  }
  chosen.sort((left, right) => left.start - right.start)

  let scrubbedText = ''
  let cursor = 0
  const redactions = []
  for (const item of chosen) {
    scrubbedText += text.slice(cursor, item.start) + item.placeholder
    redactions.push({
      type: item.type,
      start: item.start,
      end: item.end,
      placeholder: item.placeholder,
    })
    cursor = item.end
  }
  scrubbedText += text.slice(cursor)
  return { scrubbedText, redactions }
}
