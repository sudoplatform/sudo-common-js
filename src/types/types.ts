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
  AesGcmNoPadding = 'AES/GCM/NoPadding',
  RsaOaepSha1 = 'RSA/OAEPWithSHA-1',
}

export type Subset<T, S> = Pick<T, keyof T & keyof S>

/**
 * Status of the list operation result.
 */
export enum ListOperationResultStatus {
  /**
   * The operation completed successfully.
   */
  Success = 'Success',
  /**
   * The operation completed but some items had errors during
   * processing.
   */
  Partial = 'Partial',
  /**
   * The operation failed and no list item could be returned.
   */
  Failure = 'Failure',
}

export interface ListOperationSuccessResult<T> {
  /**
   * Operation status.
   */
  status: ListOperationResultStatus.Success
  /**
   * List of items that were successfully processed.
   */
  items: T[]
  /**
   * Pagination token.
   */
  nextToken?: string
}

export interface ListOperationFailureResult {
  /**
   * Operation status.
   */
  status: ListOperationResultStatus.Failure
  /**
   * The error that caused the failure.
   */
  cause: Error
}

export interface ListOperationPartialResult<T, S extends Subset<S, T>> {
  /**
   * Operation status.
   */
  status: ListOperationResultStatus.Partial
  /**
   * List of items that were successfully processed.
   */
  items: T[]
  /**
   * List of items that failed to be processed and the error
   * that caused the failure.
   */
  failed: { item: Omit<T, keyof S>; cause: Error }[]
  /**
   * Pagination token.
   */
  nextToken?: string
}

/**
 * Result of a list operation. T is the expected item type and
 * S is a subset of T's properties that won't be present if the
 * additional processing after the item has been fetched fails.
 */
export type ListOperationResult<T, S extends Subset<S, T> = T> =
  | ListOperationSuccessResult<T>
  | ListOperationFailureResult
  | ListOperationPartialResult<T, S>

/**
 * Representation of opaque of application defined JSON data values
 * as used and returned by Sudo Platform SDKs.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | Array<JsonValue>
  | { [key: string]: JsonValue }
