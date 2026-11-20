import assert from 'node:assert/strict'
import test from 'node:test'
import { passesAba, passesLuhn, scrubText } from '../src/scrubber.js'

test('redacts SSNs, Luhn cards, Medicare IDs, secrets, and email local-parts', () => {
  const input = [
    'SSN 123-45-6789 and 219 09 9999.',
    'Card 4111 1111 1111 1111 / 4111-1111-1111-1111 / 4111111111111111.',
    'Not a card 4111111111111112.',
    'Routing number 021000021 account number 123456789012.',
    'MBI 1EG4-TE5-MK73 and 1EG4TE5MK73.',
    'password: hunter2 PIN is 9876.',
    'DOB: 03/14/1948 DL: A1234567.',
    'mother\'s maiden name is Exampleton.',
    'CVV: 123.',
    'Write Jordan.Example@example.test after this.',
    'We will never ask for your password by email.',
  ].join(' ')
  const { scrubbedText, redactions } = scrubText(input)
  assert.equal(scrubbedText.includes('123-45-6789'), false)
  assert.equal(scrubbedText.includes('219 09 9999'), false)
  assert.equal(scrubbedText.includes('4111 1111 1111 1111'), false)
  assert.equal(scrubbedText.includes('4111-1111-1111-1111'), false)
  assert.equal(scrubbedText.includes('4111111111111111'), false)
  assert.equal(scrubbedText.includes('4111111111111112'), true)
  assert.equal(scrubbedText.includes('021000021'), false)
  assert.equal(scrubbedText.includes('123456789012'), false)
  assert.equal(scrubbedText.includes('1EG4'), false)
  assert.equal(scrubbedText.includes('hunter2'), false)
  assert.equal(scrubbedText.includes('9876'), false)
  assert.equal(scrubbedText.includes('03/14/1948'), false)
  assert.equal(scrubbedText.includes('A1234567'), false)
  assert.equal(scrubbedText.includes('Exampleton'), false)
  assert.equal(scrubbedText.includes('Jordan.Example'), false)
  assert.match(scrubbedText, /\[REDACTED_EMAIL\]@example\.test/)
  assert.match(scrubbedText, /password by email/)
  assert.ok(redactions.some(item => item.type === 'ssn'))
  assert.ok(redactions.some(item => item.type === 'card'))
  assert.ok(redactions.some(item => item.type === 'mbi'))
  assert.ok(redactions.some(item => item.type === 'routing'))
  assert.ok(redactions.some(item => item.type === 'account'))
  assert.ok(passesLuhn('4111111111111111'))
  assert.equal(passesLuhn('4111111111111112'), false)
  assert.equal(passesAba('021000021'), true)
})

test('does not treat an unlabeled routing-shaped number as a routing number', () => {
  const { scrubbedText } = scrubText('The reference is 021000021 today.')
  assert.match(scrubbedText, /021000021/)
})
