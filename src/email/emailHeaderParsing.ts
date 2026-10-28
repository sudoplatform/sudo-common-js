import { isSafeOutboundUrl } from '../utils/safeUrl'
import { getDomain, removeDisplayName } from './emailAddressParsing'

/**
 * Extract the full domain from an email "From" header value.
 * The display name is stripped first, then `tldts` parses the hostname.
 * e.g. `Instagram <test@priority.instagram.com>` → `priority.instagram.com`.
 */
export function extractDomain(fromHeader: string): string | undefined {
  const email = removeDisplayName(fromHeader)
  return email ? getDomain(email) : undefined
}

/**
 * Check if domainA is a subdomain of domainB.
 * e.g. isSubdomainOf('mail.netflix.com', 'netflix.com') → true
 */
export function isSubdomainOf(domainA: string, domainB: string): boolean {
  return domainA.endsWith('.' + domainB)
}

/**
 * Parsed unsubscribe target extracted from `List-Unsubscribe` /
 * `List-Unsubscribe-Post` header values.
 */
export interface ParsedUnsubscribe {
  oneClickUrl?: string
  landingPageUrl?: string
  mailto?: string
}

/**
 * Parse RFC 2369 `List-Unsubscribe` and RFC 8058 `List-Unsubscribe-Post`
 * header values into a structured unsubscribe target.
 *
 * The `List-Unsubscribe` value is a comma-separated list of angle-bracketed
 * URIs offering alternative mechanisms for the same unsubscribe, e.g.
 * `<https://host/unsub?id=1>, <mailto:unsub@host>`. The first `mailto:` URI is
 * captured as `mailto`. The first HTTPS URI that passes outbound-safety
 * validation (see {@link isSafeOutboundUrl}) is captured as either `oneClickUrl`
 * — when the `List-Unsubscribe-Post` value contains `List-Unsubscribe=One-Click`
 * (RFC 8058), so it is safe to POST automatically — or otherwise as
 * `landingPageUrl`, an RFC 2369 page the user opens to complete the unsubscribe.
 *
 * The header value is sender-controlled, so an HTTPS URI that targets an
 * internal, loopback, link-local, or otherwise non-routable host (an SSRF
 * vector) is rejected here and never captured; scanning continues so a safe
 * HTTPS alternative in the same header is still used. Additional same-kind URIs
 * are dropped and non-HTTPS URLs (e.g. `http://`) are ignored. Returns undefined
 * when no usable target can be extracted.
 */
export function parseListUnsubscribe(
  listUnsubscribe: string | undefined,
  listUnsubscribePost?: string,
): ParsedUnsubscribe | undefined {
  if (!listUnsubscribe) {
    return undefined
  }

  const uris = [...listUnsubscribe.matchAll(/<([^>]+)>/g)].map((m) =>
    m[1].trim(),
  )

  const supportsOneClickPost =
    listUnsubscribePost?.toLowerCase().includes('list-unsubscribe=one-click') ??
    false

  let httpsUri: string | undefined
  let mailto: string | undefined
  for (const uri of uris) {
    const lower = uri.toLowerCase()
    if (!mailto && lower.startsWith('mailto:')) {
      mailto = uri
      continue
    }
    // Capture the first HTTPS URI that is a safe outbound target. Unsafe URIs
    // (internal/non-routable hosts, embedded credentials) are skipped so a safe
    // alternative later in the same header can still be used.
    if (!httpsUri && lower.startsWith('https://') && isSafeOutboundUrl(uri)) {
      httpsUri = uri
    }
  }

  // The HTTPS URL is one-click only when the sender also declares the RFC 8058
  // one-click POST directive; otherwise it is a landing page the user opens.
  const oneClickUrl = httpsUri && supportsOneClickPost ? httpsUri : undefined
  const landingPageUrl =
    httpsUri && !supportsOneClickPost ? httpsUri : undefined

  if (!oneClickUrl && !landingPageUrl && !mailto) {
    return undefined
  }

  return {
    ...(oneClickUrl !== undefined && { oneClickUrl }),
    ...(landingPageUrl !== undefined && { landingPageUrl }),
    ...(mailto !== undefined && { mailto }),
  }
}
