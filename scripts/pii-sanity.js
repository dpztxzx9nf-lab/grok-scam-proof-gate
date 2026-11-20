#!/usr/bin/env node
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { BRANDS } from '../src/brands.js'
import { extractEmails, extractPhones, normalizeHost } from '../src/extract.js'
import { passesLuhn } from '../src/scrubber.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SKIP = new Set(['.git', 'node_modules', 'reports'])
const SECRET_PATTERNS = [
  { id: 'private_key', pattern: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/ },
  { id: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/ },
  { id: 'github_token', pattern: /ghp_[A-Za-z0-9]{20,}/ },
  { id: 'xai_key', pattern: /xai-[A-Za-z0-9]{20,}/ },
  { id: 'sk_key', pattern: /sk-(?:proj-)?[A-Za-z0-9]{20,}/ },
]
const BANNED_MAIL_HOSTS = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'proton.me', 'aol.com']
const MBI = /\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d-?[ACDEFGHJKMNPQRTUVWXY]{2}\d{2}\b/

/**
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const found = []
  for (const entry of entries) {
    if (SKIP.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) found.push(...await files(full))
    else if (entry.isFile()) found.push(full)
  }
  return found
}

/**
 * @param {string} host
 * @returns {boolean}
 */
export function datasetEmailAllowed(host) {
  const normalized = normalizeHost(host)
  const documentation = ['example.com', 'example.org', 'example.net', 'example.test']
  if (documentation.some(domain => normalized === domain || normalized.endsWith(`.${domain}`))) return true
  return BRANDS.some(entry => entry.domains.some(domain => normalized === domain || normalized.endsWith(`.${domain}`)))
}

/**
 * @param {string} text
 * @param {string} file
 * @returns {string[]}
 */
export function scanText(text, file) {
  /** @type {string[]} */
  const problems = []
  for (const secret of SECRET_PATTERNS) {
    if (secret.pattern.test(text)) problems.push(`${file}: secret pattern ${secret.id}`)
  }
  const relative = path.relative(ROOT, file)
  if (!relative.startsWith('datasets/')) return problems

  let dataset
  try {
    dataset = JSON.parse(text)
  } catch {
    problems.push(`${file}: dataset is not valid JSON`)
    return problems
  }
  if (dataset.synthetic !== true || dataset.customerData !== false) {
    problems.push(`${file}: dataset must set synthetic true and customerData false`)
  }
  const blob = JSON.stringify(dataset.cases ?? [])
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(blob)) problems.push(`${file}: SSN-shaped number in dataset`)
  if (MBI.test(blob)) problems.push(`${file}: Medicare ID pattern in dataset`)
  for (const email of extractEmails(blob)) {
    if (BANNED_MAIL_HOSTS.some(host => email.host === host || email.host.endsWith(`.${host}`))) {
      problems.push(`${file}: banned mailbox host ${email.host}`)
    }
    if (!datasetEmailAllowed(email.host)) problems.push(`${file}: email host not synthetic or allowlisted (${email.host})`)
  }
  for (const phone of extractPhones(blob)) {
    if (!/^\d{3}55501\d{2}$/.test(phone.digits)) {
      problems.push(`${file}: phone ${phone.raw} is outside the fictional 555-01xx range`)
    }
  }
  for (const match of blob.matchAll(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g) ) {
    const digits = match[0].replace(/\D/g, '')
    if (passesLuhn(digits)) problems.push(`${file}: Luhn-valid card number in dataset`)
  }
  return problems
}

/**
 * @param {string} [root]
 * @returns {Promise<string[]>}
 */
export async function scanRepo(root = ROOT) {
  const problems = []
  for (const file of await files(root)) {
    if (file.endsWith('.png') || file.endsWith('.jpg') || file.endsWith('.zip')) continue
    const text = await readFile(file, 'utf8')
    problems.push(...scanText(text, file))
  }
  return problems
}

async function main() {
  const problems = await scanRepo(ROOT)
  if (problems.length) {
    for (const problem of problems) console.error(problem)
    process.exitCode = 1
    return
  }
  console.log('pii-sanity: ok')
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href
if (invokedDirectly) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 2
  })
}
