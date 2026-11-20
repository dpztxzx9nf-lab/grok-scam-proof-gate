import assert from 'node:assert/strict'
import test from 'node:test'
import { expandUrl, isBlockedIp } from '../src/ssrf.js'
import { fakeResponse } from './helpers.js'

const resolver = async () => ['203.0.113.50']

test('blocks private, loopback, link-local, metadata, and IPv6 ULA addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.20', '172.16.0.4', '169.254.169.254', '100.64.1.1', '0.0.0.0', '255.255.255.255', '224.0.0.1', '::1', 'fd12:3456:789a::1', 'fe80::1', '::ffff:7f00:1']) {
    assert.equal(isBlockedIp(ip), true, ip)
  }
  for (const ip of ['203.0.113.50', '198.51.100.10', '8.8.8.8', '2001:db8::1']) {
    assert.equal(isBlockedIp(ip), false, ip)
  }
})

test('refuses non-http schemes, credentials, and obfuscated loopback without fetching them', async () => {
  let calls = 0
  const fetchImpl = async () => {
    calls += 1
    return fakeResponse(200)
  }
  const cases = [
    'file:///etc/passwd',
    'ftp://files.example/a',
    'http://127.0.0.1/latest',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://0x7f000001/',
    'http://[::1]/',
    'http://[fd00::1]/',
    'http://localhost/admin',
    'http://foo.localhost/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'https://user:pass@evil.example/a',
    'https://chase.com@evil.example/a',
  ]
  for (const url of cases) {
    const result = await expandUrl(url, { resolver, fetchImpl, allowLiveHttp: true })
    assert.notEqual(result.state, 'pass', url)
    assert.equal(calls, 0, url)
  }
})

test('does not follow a redirect onto a private address', async () => {
  const seen = []
  const fetchImpl = async (url) => {
    seen.push(String(url))
    return fakeResponse(302, { location: 'http://169.254.169.254/latest' })
  }
  const result = await expandUrl('https://start.example/go', { resolver, fetchImpl, allowLiveHttp: true })
  assert.equal(result.state, 'fail')
  assert.equal(result.reason, 'blocked_ip')
  assert.deepEqual(seen, ['https://start.example/go'])
})

test('stops at the redirect limit and can use an offline redirect fixture', async () => {
  let calls = 0
  const fetchImpl = async (url) => {
    calls += 1
    return fakeResponse(302, { location: `https://hop-${calls}.example/next` })
  }
  const limited = await expandUrl('https://start.example/a', {
    resolver,
    fetchImpl,
    allowLiveHttp: true,
    maxRedirects: 2,
  })
  assert.equal(limited.state, 'inconclusive')
  assert.equal(limited.reason, 'redirect_limit')
  assert.equal(calls, 3)

  const offline = await expandUrl('https://track.example.test/r', {
    resolver,
    allowLiveHttp: false,
    fetchImpl,
    redirects: { 'https://track.example.test/r': 'https://usps-redelivery.example.test/fee' },
  })
  assert.equal(offline.state, 'pass')
  assert.deepEqual(offline.hosts, ['track.example.test', 'usps-redelivery.example.test'])
  assert.equal(calls, 3)
})

test('a public https URL passes when DNS is public and HTTP is disabled', async () => {
  const result = await expandUrl('https://www.chase.com/statements', {
    resolver,
    allowLiveHttp: false,
  })
  assert.equal(result.state, 'pass')
  assert.deepEqual(result.hosts, ['www.chase.com'])
})
