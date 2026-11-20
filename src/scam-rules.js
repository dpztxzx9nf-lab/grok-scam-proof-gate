/**
 * High-precision elder-scam patterns. A hit is a floor, never a ceiling.
 * Soft rules can be suppressed only when the channel is positively on-brand.
 * @type {ReadonlyArray<{ id: string, severity: 'caution' | 'likely_scam', soft: boolean, match: (text: string) => boolean }>}
 */
export const SCAM_RULES = Object.freeze([
  {
    id: 'remote_access_tool',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:anydesk|teamviewer|ultraviewer|logmein|log-me-in)\b/i.test(text),
  },
  {
    id: 'gift_card_payment',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\bgift\s*cards?\b/i.test(text)
      && /\b(?:buy|purchase|scratch|codes?|pins?|cvs|walgreens|walmart|target|google play|steam|itunes|read (?:me |the |those )|pay with|payment)\b/i.test(text),
  },
  {
    id: 'crypto_atm',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:bitcoin|btc|crypto(?:currency)?)\b/i.test(text)
      && /\b(?:atm|wallet address|qr code|send (?:the )?(?:bitcoin|btc|crypto))\b/i.test(text),
  },
  {
    id: 'isolation_secrecy',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /(?:do not|don't|dont)\s+(?:tell|talk to|speak (?:to|with)|inform|contact)\s+(?:your\s+)?(?:family|kids|children|anyone|anybody|mom|mother|dad|father|wife|husband|spouse|police|bank|a soul|people)\b/i.test(text)
      || /\bstay on the (?:line|phone)\b/i.test(text)
      || /\bdo not (?:hang up|disconnect)\b/i.test(text)
      || /\bkeep this (?:secret|between us|confidential)\b/i.test(text),
  },
  {
    id: 'check_overpayment',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:overpaid|over-?payment|paid you too much|too much money)\b/i.test(text)
      && /\b(?:check|money order|cashier'?s check)\b/i.test(text)
      && /\b(?:deposit|refund|send back|wire|difference|return the|gift card)\b/i.test(text),
  },
  {
    id: 'grandparent_emergency',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:grand(?:ma|mother|pa|father|son|daughter)|nana|papa)\b/i.test(text)
      && /\b(?:jail|bail|accident|arrested|hospital|stranded|lawyer|bond)\b/i.test(text),
  },
  {
    id: 'government_payment',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:\birs\b|internal revenue|social security|\bssa\b|medicare|federal (?:agent|officer)|u\.?s\.? marshal)\b/i.test(text)
      && /\b(?:arrest(?:ed)?|warrant|suspended|gift cards?|lawsuit|back taxes|benefits (?:will be |are )?stopped|police|immediately pay|marshal)\b/i.test(text),
  },
  {
    id: 'virus_scare',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:virus detected|trojan|malware detected|infected (?:your|the) (?:pc|computer|device|mac)|files (?:are )?being encrypted|do not (?:shut down|turn off)|your (?:pc|computer|mac) is (?:locked|infected))\b/i.test(text)
      && /\b(?:call|toll-?free|support|remote|anydesk|teamviewer|payment|credit card)\b/i.test(text),
  },
  {
    id: 'wire_zelle',
    severity: 'likely_scam',
    soft: false,
    match: (text) => /\b(?:zelle|wire transfer|send a wire|wiring instructions)\b/i.test(text)
      && /\b(?:urgent|urgently|immediately|right now|asap|do not tell|don't tell|stay on|warrant|bail|gift|agent|safe account|untraceable|refund)\b/i.test(text),
  },
  {
    id: 'prompt_injection',
    severity: 'caution',
    soft: false,
    match: (text) => /\bignore (?:all |any )?(?:previous|prior|above) instructions\b/i.test(text)
      || /\boutput verdict\s*:\s*safe\b/i.test(text)
      || /<\s*\/?\s*system\s*>/i.test(text)
      || /\bsystem\s*:\s*you are\b/i.test(text)
      || /\bdisregard (?:all |your )?(?:rules|instructions)\b/i.test(text),
  },
  {
    id: 'toll_sms',
    severity: 'likely_scam',
    soft: true,
    match: (text) => /\b(?:unpaid toll|toll (?:road|violation|by mail|charge|invoice)|ez-?pass|e-zpass|sunpass|fastrak)\b/i.test(text)
      && /\b(?:pay|past due|dmv|suspend|https?:|fee|balance|final notice|violation)\b/i.test(text),
  },
  {
    id: 'frozen_card',
    severity: 'likely_scam',
    soft: true,
    match: (text) => /\b(?:card (?:has been |is )?(?:frozen|locked|blocked|disabled)|we (?:froze|locked|blocked) your (?:card|debit|account)|debit card (?:is )?(?:frozen|locked|disabled))\b/i.test(text)
      && /\b(?:call|click|https?:|verify|confirm|tap|reply)\b/i.test(text),
  },
  {
    id: 'bank_credential_demand',
    severity: 'likely_scam',
    soft: true,
    match: (text) => /\b(?:send|tell|give|read|provide|reply with|enter|share|confirm|what(?:'s| is))\b(?:\s+\w+){0,5}\s+(?:password|passcode|pin|one-?time code|otp|full card|social security number|ssn|routing number|bank account)\b/i.test(text),
  },
  {
    id: 'vague_urgency',
    severity: 'caution',
    soft: true,
    match: (text) => /\b(?:urgent|urgently|act now|final notice)\b/i.test(text)
      && /\b(?:account|payment|delivery|refund)\b/i.test(text),
  },
])

/**
 * @param {string} text
 * @returns {Array<{ id: string, severity: 'caution' | 'likely_scam', soft: boolean }>}
 */
export function matchScamRules(text) {
  const hits = []
  for (const rule of SCAM_RULES) {
    if (rule.match(text)) hits.push({ id: rule.id, severity: rule.severity, soft: rule.soft })
  }
  return hits
}
