import {
  getDomain,
  getRedactedEmailAddress,
  normalize,
  removeDisplayName,
  splitToParts,
  validate,
  validateForProvisioning,
} from '../../../src/email/emailAddressParsing'

describe('emailAddressParsing', () => {
  describe('validate', () => {
    describe('accepts valid addresses', () => {
      it.each([
        'john.doe@example.com',
        'a@b.co',
        'user+tag@example.com',
        'user_name@sub.domain.example.com',
        "o'brien@example.com",
        'first.last@example.co.uk',
      ])('%s', (email) => {
        expect(validate(email)).toBe(true)
      })
    })

    describe('rejects invalid addresses', () => {
      it.each([
        ['empty string', ''],
        ['no @', 'plainaddress'],
        ['no domain dot', 'user@localhost'],
        ['missing local part', '@example.com'],
        ['missing domain', 'user@'],
        ['two @ symbols', 'user@@example.com'],
        ['two @ with domains', 'a@b@example.com'],
        ['whitespace in local', 'us er@example.com'],
        ['whitespace in domain', 'user@exa mple.com'],
        ['leading whitespace', ' user@example.com'],
        ['trailing whitespace', 'user@example.com '],
      ])('%s', (_desc, email) => {
        expect(validate(email)).toBe(false)
      })
    })

    it('rejects an address longer than 256 characters', () => {
      const longLocal = 'a'.repeat(250)
      const email = `${longLocal}@example.com`
      expect(email.length).toBeGreaterThan(256)
      expect(validate(email)).toBe(false)
    })

    it('rejects a local part longer than 64 characters', () => {
      const email = `${'a'.repeat(65)}@example.com`
      expect(validate(email)).toBe(false)
    })

    it('accepts a local part of exactly 64 characters', () => {
      const email = `${'a'.repeat(64)}@example.com`
      expect(validate(email)).toBe(true)
    })

    it('rejects a domain label longer than 63 characters', () => {
      const email = `user@${'a'.repeat(64)}.com`
      expect(validate(email)).toBe(false)
    })

    it('accepts a domain label of exactly 63 characters', () => {
      const email = `user@${'a'.repeat(63)}.com`
      expect(validate(email)).toBe(true)
    })

    it('uses a provided custom regex', () => {
      const onlyAcme = /^[^\s@]+@acme\.com$/
      expect(validate('user@acme.com', onlyAcme)).toBe(true)
      expect(validate('user@example.com', onlyAcme)).toBe(false)
    })
  })

  describe('validateForProvisioning', () => {
    describe('accepts provisionable addresses', () => {
      it.each([
        'john@example.com',
        'john.doe@example.com',
        'john_doe@example.com',
        'john-doe@example.com',
        'user@sub.example.com',
      ])('%s', (email) => {
        expect(validateForProvisioning(email)).toBe(true)
      })
    })

    describe('rejects non-provisionable addresses', () => {
      it.each([
        ['leading dot in local part', '.john@example.com'],
        ['plus tag not allowed', 'user+tag@example.com'],
        ['leading dot in domain', 'user@.example.com'],
        ['single label tld too short', 'user@example.c'],
        ['empty', ''],
      ])('%s', (_desc, email) => {
        expect(validateForProvisioning(email)).toBe(false)
      })
    })

    it('is stricter than the general validator', () => {
      // valid generally (plus addressing) but not provisionable
      expect(validate('user+tag@example.com')).toBe(true)
      expect(validateForProvisioning('user+tag@example.com')).toBe(false)
    })
  })

  describe('splitToParts', () => {
    it('splits a valid address into local part and domain', () => {
      expect(splitToParts('john.doe@example.com')).toEqual({
        localPart: 'john.doe',
        domain: 'example.com',
      })
    })

    it('returns undefined for an invalid address', () => {
      expect(splitToParts('not-an-email')).toBeUndefined()
      expect(splitToParts('')).toBeUndefined()
    })
  })

  describe('normalize', () => {
    it('lowercases the address', () => {
      expect(normalize('John.Doe@Example.COM')).toBe('john.doe@example.com')
    })

    it('returns the normalized address unchanged when already lowercase', () => {
      expect(normalize('john@example.com')).toBe('john@example.com')
    })

    it('returns undefined for an invalid address', () => {
      expect(normalize('invalid')).toBeUndefined()
      expect(normalize('')).toBeUndefined()
    })
  })

  describe('removeDisplayName', () => {
    it('extracts the address from a display name form', () => {
      expect(removeDisplayName('John Doe <john@example.com>')).toBe(
        'john@example.com',
      )
    })

    it('returns the original string when no display name is present', () => {
      expect(removeDisplayName('john@example.com')).toBe('john@example.com')
    })

    it('extracts content inside the first/last angle brackets', () => {
      expect(removeDisplayName('<john@example.com>')).toBe('john@example.com')
    })

    it('returns the original string when there is no closing bracket', () => {
      expect(removeDisplayName('John <john@example.com')).toBe(
        'John <john@example.com',
      )
    })
  })

  describe('getDomain', () => {
    it('returns the domain for a bare domain string', () => {
      expect(getDomain('example.com')).toBe('example.com')
    })

    it('extracts the hostname from a URL', () => {
      expect(getDomain('https://sub.example.com/path')).toBe('sub.example.com')
    })

    it('returns undefined when no hostname can be parsed', () => {
      expect(getDomain('')).toBeUndefined()
    })
  })

  describe('getRedactedEmailAddress', () => {
    it('redacts the middle characters of local part and domain', () => {
      expect(getRedactedEmailAddress('john@example.com')).toBe(
        'j**n@e*********m',
      )
    })

    it('masks a segment fully when it is two characters or fewer', () => {
      // local part "jo" (<= 2 chars) is fully masked; domain "ab.de" keeps ends
      expect(getRedactedEmailAddress('jo@ab.de')).toBe('**@a***e')
    })

    it('returns undefined for an invalid address', () => {
      expect(getRedactedEmailAddress('not-an-email')).toBeUndefined()
      expect(getRedactedEmailAddress('')).toBeUndefined()
    })
  })
})
