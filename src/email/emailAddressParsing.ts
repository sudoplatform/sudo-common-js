import { getHostname } from 'tldts'

/**
 *  Regex that is used to check if a string is an email address that is valid to be provisioned as a
 * Sudo Platform email address. Stricter than the {@link generalRegex}
 */
const provisioningRegex =
  /^[a-zA-Z0-9_-](?:\.?[-_a-zA-Z0-9])*@[a-zA-Z0-9](?:-*\.?[a-zA-Z0-9])*\.[a-zA-Z](?:-?[a-zA-Z0-9])+$/

/**
 * Regex for validating email addresses generally
 * Essentially:
 *  - A string of non-whitespace characters, excluding '@'
 *  - A single '@'
 *  - Another string of non-whitespace characters, excluding '@'
 *  - A single '.'
 *  - Another string of non-whitespace characters, excluding '@'
 * All with no whitespace and only one '@'
 * Less strict than {@link provisioningRegex}
 */
const generalRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

interface EmailAddressParts {
  localPart: string
  domain: string
}

/**
 * Validates an email address.
 *
 * @param {string} email Address to validate.
 * @param {RegExp} regex Optional regex to validate against. Defaults to {@link generalRegex}
 * @returns {boolean} true if input `email` is valid.
 */
export function validate(email: string, regex: RegExp = generalRegex): boolean {
  if (email.length > 256) return false
  if (!regex.test(email)) return false

  const [localPart, address] = email.split('@')
  if (localPart.length > 64) return false
  const domainParts = address.split('.')
  if (
    domainParts.some(function (part) {
      return part.length > 63
    })
  )
    return false

  return true
}

/**
 * Validates and email address for provisioning as a Sudo Platform email address.
 *
 * @param {string} email address to validate.
 * @returns {boolean} true if input `email` is valid.
 */
export function validateForProvisioning(email: string): boolean {
  return validate(email, provisioningRegex)
}

export function splitToParts(email: string): EmailAddressParts | undefined {
  if (!validate(email)) {
    return undefined
  }
  const [localPart, domain] = email.split('@')

  return {
    localPart,
    domain,
  }
}

/**
 * Normalize an email address per platform policy.
 *
 * @param {string} email Complete address `<localpart>@<domain>`
 * @returns {string} normalized email address or undefined if invalid
 */
export function normalize(email: string): string | undefined {
  const parts = splitToParts(email.toLowerCase()) // split local part from domain

  if (!parts) {
    return undefined
  }

  return `${parts.localPart}@${parts.domain}`
}

/**
 * If present, remove display name from an email address string and return only localpart@domain
 *
 * @param {string} address the email address string which may contain a display name, expected to be of the form 'phrase <localpart@domain>'
 * @returns {string} localpart@domain, or the original string if no display name present or string is not the correct format
 * @memberof EmailAddressParser
 */
export function removeDisplayName(address: string): string {
  const addressOnlyRegex = /<(.*)>/
  const noDisplayName = addressOnlyRegex.exec(address)
  return noDisplayName ? noDisplayName[1] : address
}

/**
 * Get the domain from an email address.
 * @param {string} address The email address.
 * @returns {string | undefined} The domain, or undefined if not present.
 * @memberof EmailAddressParser
 */
export function getDomain(address: string): string | undefined {
  return getHostname(address) ?? undefined
}

/**
 * Redacts the email address. Useful for logging
 * @param address
 * @returns redacted address
 */
export function getRedactedEmailAddress(address: string): string | undefined {
  const parts = splitToParts(address)
  if (!parts) {
    return
  }
  return [parts.localPart, parts.domain]
    .map((s) =>
      s.length > 2
        ? s.charAt(0) + '*'.repeat(s.length - 2) + s.charAt(s.length - 1)
        : '*'.repeat(s.length),
    )
    .join('@')
}
