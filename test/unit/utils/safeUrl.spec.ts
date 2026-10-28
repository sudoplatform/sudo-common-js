import { isSafeOutboundUrl } from '../../../src/utils/safeUrl'

describe('isSafeOutboundUrl', () => {
  describe('accepts', () => {
    it.each([
      'https://unsubscribe.example.com/oneclick',
      'https://mail.acme.co.uk/u/abc123?token=xyz',
      'https://sub.domain.example.com:8443/path',
      'https://203.0.113.10/unsub', // routable public IPv4
    ])('%s', (url) => {
      expect(isSafeOutboundUrl(url)).toBe(true)
    })
  })

  describe('rejects', () => {
    it.each([
      // Non-HTTPS schemes
      ['http (not https)', 'http://example.com/unsub'],
      ['file scheme', 'file:///etc/passwd'],
      ['ftp scheme', 'ftp://example.com/x'],
      ['data scheme', 'data:text/plain,hi'],
      ['gopher scheme', 'gopher://example.com/'],
      // Malformed
      ['not a url', 'not-a-url'],
      ['empty', ''],
      // Embedded credentials
      ['userinfo', 'https://user:pass@example.com/unsub'],
      // Loopback / unspecified
      ['localhost', 'https://localhost/unsub'],
      ['localhost subdomain', 'https://api.localhost/unsub'],
      ['127.0.0.1', 'https://127.0.0.1/unsub'],
      ['127.x loopback', 'https://127.9.9.9/unsub'],
      ['0.0.0.0', 'https://0.0.0.0/unsub'],
      ['ipv6 loopback', 'https://[::1]/unsub'],
      // Link-local + cloud metadata
      ['metadata ip', 'https://169.254.169.254/latest/meta-data/'],
      ['link-local range', 'https://169.254.1.1/x'],
      ['ipv6 link-local', 'https://[fe80::1]/x'],
      // Private ranges
      ['10/8', 'https://10.1.2.3/unsub'],
      ['172.16/12', 'https://172.20.0.1/unsub'],
      ['192.168/16', 'https://192.168.1.1/unsub'],
      ['ipv6 unique-local', 'https://[fd00::1]/x'],
      // IPv4-mapped IPv6 pointing at loopback
      ['ipv4-mapped loopback', 'https://[::ffff:127.0.0.1]/x'],
      // Unqualified internal name (no dot)
      ['bare hostname', 'https://internal-service/unsub'],
    ])('%s', (_desc, url) => {
      expect(isSafeOutboundUrl(url)).toBe(false)
    })
  })
})
