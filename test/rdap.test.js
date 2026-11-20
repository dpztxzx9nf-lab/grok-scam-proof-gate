import assert from 'node:assert/strict'
import test from 'node:test'
import { ageBand, checkDomainAge, liveRdapLookup, registrationDateFromRdap } from '../src/rdap.js'
import { fakeResponse } from './helpers.js'

test('reads a registration event and bands the age', () => {
  assert.equal(registrationDateFromRdap({ events: [{ eventAction: 'registration', eventDate: '2000-01-01T00:00:00Z' }] }), '2000-01-01T00:00:00Z')
  assert.equal(ageBand(10), 'very_young')
  assert.equal(ageBand(90), 'young')
  assert.equal(ageBand(400), 'established')
})

test('allowlisted and reserved domains pass without a fixture; unknown domains do not', async () => {
  const now = new Date('2026-01-15T00:00:00.000Z')
  const official = await checkDomainAge('www.chase.com', {
    now,
    official: true,
    rdapLookup: async () => ({ unknown: true }),
  })
  assert.equal(official.state, 'pass')
  const reserved = await checkDomainAge('photos.example.com', {
    now,
    reserved: true,
    rdapLookup: async () => ({ unknown: true }),
  })
  assert.equal(reserved.state, 'pass')
  const unknown = await checkDomainAge('picnic-photos.example.test', {
    now,
    rdapLookup: async () => ({ unknown: true }),
  })
  assert.equal(unknown.state, 'inconclusive')
  const young = await checkDomainAge('picnic-photos.example.test', {
    now,
    rdapLookup: async () => ({ registrationDate: '2026-01-01T00:00:00.000Z' }),
  })
  assert.equal(young.band, 'very_young')
  assert.equal(young.state, 'fail')
})

test('live RDAP refuses a redirect to a metadata address', async () => {
  const seen = []
  const fetchImpl = async (url) => {
    seen.push(String(url))
    if (String(url).includes('127.0.0.1')) return fakeResponse(200, {}, { events: [] })
    return fakeResponse(302, { location: 'http://127.0.0.1/latest' })
  }
  const result = await liveRdapLookup('example.com', {
    fetchImpl,
    resolver: async () => ['203.0.113.20'],
  })
  assert.equal(result.inconclusive, true)
  assert.equal(seen.some(url => url.includes('127.0.0.1')), false)
})
