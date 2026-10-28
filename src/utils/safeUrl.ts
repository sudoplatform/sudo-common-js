/**
 * Validation for outbound URLs that originate from untrusted input — notably the
 * `List-Unsubscribe` target extracted from a received email, which the sender
 * controls. Without this check a malicious sender could point the unsubscribe
 * POST at an internal or non-HTTP endpoint (an SSRF vector).
 *
 * `isSafeOutboundUrl` accepts only an HTTPS URL to a routable public host: it
 * rejects non-HTTPS schemes, embedded credentials, and hosts that are loopback,
 * link-local (including the cloud instance-metadata address), private, or
 * otherwise non-routable.
 *
 * This is a syntactic guard on the URL as written. It does not resolve DNS, so
 * it does not defend against a public hostname that resolves to a private
 * address (DNS rebinding); network-level egress controls are the defence for
 * that.
 */

/** IPv4 octet ranges that are loopback, link-local, private, or unspecified. */
function isBlockedIpv4(host: string): boolean {
  const parts = host.split('.')
  if (parts.length !== 4) {
    return false
  }
  const octets = parts.map((p) => Number(p))
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    // Not a well-formed dotted-quad; treated as a hostname elsewhere.
    return false
  }
  const [a, b] = octets
  if (a === 0) return true // 0.0.0.0/8 "this network"
  if (a === 10) return true // 10.0.0.0/8 private
  if (a === 127) return true // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true // 169.254.0.0/16 link-local (incl. 169.254.169.254 metadata)
  if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true // 192.168.0.0/16 private
  return false
}

/** IPv6 literals that are loopback, unspecified, link-local, or unique-local. */
function isBlockedIpv6(host: string): boolean {
  // URL hostnames wrap IPv6 literals in brackets.
  const inner =
    host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  const lower = inner.toLowerCase()
  if (lower === '::1' || lower === '::') return true // loopback / unspecified
  if (lower.startsWith('fe80:')) return true // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true // fc00::/7 unique-local
  // IPv4-mapped/compatible IPv6 (e.g. ::ffff:127.0.0.1, which the URL parser may
  // compress to ::ffff:7f00:1). These embed an IPv4 address and are a known
  // SSRF-bypass notation; a legitimate unsubscribe link would not use them, so
  // reject the whole class rather than trying to decode the embedded address.
  if (lower.startsWith('::ffff:') || lower.startsWith('::')) return true
  return false
}

/**
 * Whether `url` is a safe outbound target: a syntactically valid HTTPS URL, with
 * no embedded credentials, to a host that is not loopback, link-local, private,
 * or an unqualified internal name.
 */
export function isSafeOutboundUrl(url: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }

  if (parsed.protocol !== 'https:') {
    return false
  }

  // Credentials in the URL (user:pass@host) are never expected on an unsubscribe
  // link and are a classic way to disguise the real host.
  if (parsed.username !== '' || parsed.password !== '') {
    return false
  }

  const host = parsed.hostname.toLowerCase()
  if (host === '' || host === 'localhost' || host.endsWith('.localhost')) {
    return false
  }

  // An unqualified name (no dot, not an IP literal) resolves via internal search
  // domains — treat as internal and reject.
  const isIpv6 = host.includes(':') || parsed.hostname.startsWith('[')
  if (!isIpv6 && !host.includes('.')) {
    return false
  }

  if (isBlockedIpv4(host) || isBlockedIpv6(parsed.hostname)) {
    return false
  }

  return true
}
