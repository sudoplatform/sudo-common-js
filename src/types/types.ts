/**
 * Generic type for paginated results from list queries
 */
export interface ListOutput<T> {
  items: T[]
  nextToken?: string
}

/**
 * Cache policy that determines how data is accessed when performing a query method
 * from the Email Service.
 */
export enum CachePolicy {
  // Use the device cached data.
  CacheOnly = 'cache-only',
  // Query and use the data on the server.
  RemoteOnly = 'network-only',
}

export interface Owner {
  id: string
  issuer: string
}

/**
 * A filter to use on string fields when listing items in a repository
 */
export interface StringFilter {
  ne?: string
  eq?: string
  beginsWith?: string
}

/**
 * A filter to use on string fields when listing items in a repository
 */
export interface BooleanFilter {
  eq?: boolean
  ne?: boolean
}

/**
 * Encryption algorithm names that are
 * supported by the Sudo Platform and can be used
 * between devices.
 */
export enum EncryptionAlgorithm {
  AesCbcPkcs7Padding = 'AES/CBC/PKCS7Padding',
  RsaOaepSha1 = 'RSA/OAEPWithSHA-1',
}
