import {
  extractDomain,
  isSubdomainOf,
  parseListUnsubscribe,
} from '../../../src/email/emailHeaderParsing'

describe('emailHeaderParsing', () => {
  describe('extractDomain', () => {
    it('should extract domain from standard "Name <email>" format', () => {
      expect(extractDomain('John Doe <john@example.com>')).toBe('example.com')
    })

    it('should extract domain from bare email address', () => {
      expect(extractDomain('user@github.com')).toBe('github.com')
    })

    it('should extract domain from angle-bracket only format', () => {
      expect(extractDomain('<admin@netflix.com>')).toBe('netflix.com')
    })

    it('should return lowercase domain', () => {
      expect(extractDomain('User <user@GitHub.COM>')).toBe('github.com')
    })

    it('should handle email with subdomain', () => {
      expect(extractDomain('Notifications <no-reply@mail.github.com>')).toBe(
        'mail.github.com',
      )
    })

    it('should return undefined for string without @ symbol', () => {
      expect(extractDomain('no email here')).toBeUndefined()
    })

    it('should return undefined for empty string', () => {
      expect(extractDomain('')).toBeUndefined()
    })

    it('should handle email with multiple @ (take last)', () => {
      expect(extractDomain('"user@local" <actual@domain.com>')).toBe(
        'domain.com',
      )
    })

    it('should handle whitespace in bare email', () => {
      expect(extractDomain('  user@example.org  ')).toBe('example.org')
    })

    it('should preserve a deep subdomain under a multi-part public suffix', () => {
      expect(extractDomain('Support <help@mail.sub.example.co.uk>')).toBe(
        'mail.sub.example.co.uk',
      )
    })
  })

  describe('isSubdomainOf', () => {
    it('should return true when domainA is a subdomain of domainB', () => {
      expect(isSubdomainOf('accounts.google.com', 'google.com')).toBe(true)
    })

    it('should return true for deep subdomains', () => {
      expect(isSubdomainOf('mail.accounts.google.com', 'google.com')).toBe(true)
    })

    it('should return false when domains are unrelated', () => {
      expect(isSubdomainOf('netflix.com', 'google.com')).toBe(false)
    })

    it('should return false when domains are the same', () => {
      expect(isSubdomainOf('google.com', 'google.com')).toBe(false)
    })

    it('should return false for partial string matches', () => {
      expect(isSubdomainOf('notgoogle.com', 'google.com')).toBe(false)
    })

    it('should handle co.uk style domains', () => {
      expect(isSubdomainOf('mail.amazon.co.uk', 'amazon.co.uk')).toBe(true)
    })
  })

  describe('parseListUnsubscribe', () => {
    it('returns undefined when no header is present', () => {
      expect(parseListUnsubscribe(undefined)).toBeUndefined()
    })

    it('returns undefined when the header has no usable URI', () => {
      expect(parseListUnsubscribe('not a uri')).toBeUndefined()
    })

    it('extracts a landing-page HTTPS url (no one-click directive) and a mailto', () => {
      const result = parseListUnsubscribe(
        '<https://example.com/unsub?id=1>, <mailto:unsub@example.com>',
      )
      expect(result).toEqual({
        landingPageUrl: 'https://example.com/unsub?id=1',
        mailto: 'mailto:unsub@example.com',
      })
    })

    it('extracts a mailto-only target', () => {
      const result = parseListUnsubscribe('<mailto:unsub@example.com>')
      expect(result).toEqual({
        mailto: 'mailto:unsub@example.com',
      })
    })

    it('routes the HTTPS url to oneClickUrl when the One-Click post directive is present', () => {
      const result = parseListUnsubscribe(
        '<https://example.com/unsub>, <mailto:unsub@example.com>',
        'List-Unsubscribe=One-Click',
      )
      expect(result).toEqual({
        oneClickUrl: 'https://example.com/unsub',
        mailto: 'mailto:unsub@example.com',
      })
    })

    it('does not set oneClickUrl for a mailto-only target even with the post directive', () => {
      const result = parseListUnsubscribe(
        '<mailto:unsub@example.com>',
        'List-Unsubscribe=One-Click',
      )
      expect(result?.oneClickUrl).toBeUndefined()
      expect(result?.mailto).toBe('mailto:unsub@example.com')
    })

    it('ignores non-HTTPS (e.g. http) URLs for the url slots', () => {
      const result = parseListUnsubscribe('<http://example.com/unsub>')
      expect(result).toBeUndefined()
    })

    it('rejects an unsafe one-click HTTPS target (SSRF) and captures nothing', () => {
      const result = parseListUnsubscribe(
        '<https://169.254.169.254/latest/meta-data/>',
        'List-Unsubscribe=One-Click',
      )
      expect(result).toBeUndefined()
    })

    it('rejects an unsafe landing-page HTTPS target (internal host)', () => {
      const result = parseListUnsubscribe('<https://192.168.0.1/unsub>')
      expect(result).toBeUndefined()
    })

    it('skips an unsafe HTTPS uri and captures a safe HTTPS alternative in the same header', () => {
      const result = parseListUnsubscribe(
        '<https://127.0.0.1/unsub>, <https://example.com/unsub?id=1>',
        'List-Unsubscribe=One-Click',
      )
      expect(result).toEqual({
        oneClickUrl: 'https://example.com/unsub?id=1',
      })
    })

    it('still captures a mailto when the only HTTPS uri is unsafe', () => {
      const result = parseListUnsubscribe(
        '<https://10.0.0.1/unsub>, <mailto:unsub@example.com>',
      )
      expect(result).toEqual({ mailto: 'mailto:unsub@example.com' })
    })
  })
})
