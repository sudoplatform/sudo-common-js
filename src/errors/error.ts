import { GraphQLError } from 'graphql'
import { ApolloError } from 'apollo-client'

export type AppSyncError = GraphQLError & {
  errorType?: string | null
}
export type AppSyncNetworkError = Error & {
  networkError: Error & {
    statusCode?: number
  }
}

export function isAppSyncNetworkError(u: Error): u is AppSyncNetworkError {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return !!(u as ApolloError).networkError
}

/**
 * Indicates the GraphQL API returned an error that's not recognized by
 * the client.
 */
export class UnknownGraphQLError extends Error {
  constructor(cause: unknown) {
    const maybeAppSyncError = cause as AppSyncError
    let message: string
    if (maybeAppSyncError?.errorType) {
      message = `type: ${maybeAppSyncError.errorType}, message: ${maybeAppSyncError.message}`
    } else if (maybeAppSyncError?.message) {
      message = maybeAppSyncError?.message
    } else if (maybeAppSyncError?.name) {
      message = maybeAppSyncError.name
    } else {
      message = 'unknown cause'
    }
    super(message)

    this.name = 'UnknownGraphQLError'
  }
}

/**
 * The configuration set was not found by the given key
 */
export class ConfigurationSetNotFoundError extends Error {
  constructor(key?: string) {
    super('Configuration set not found.')
    if (key) {
      this.message += ` Key: ${key}`
    }
    this.name = 'ConfigurationSetNotFoundError'
  }
}

/**
 * The configuration has not been set on the ConfigurationManager
 * before trying operations that need it
 */
export class ConfigurationNotSetError extends Error {
  constructor() {
    super('Configuration has not been set.')
    this.name = 'ConfigurationNotSetError'
  }
}

/**
 * A decode error message
 */
export class DecodeError extends Error {
  constructor(message?: string) {
    super(message)
    this.name = 'DecodeError'
  }
}

/**
 * An error occurred during the authentication process. This may be due to invalid credentials
 * being supplied, or authentication tokens not able to be retrieved from storage.
 */
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthenticationError'
  }
}

/**
 * An error occurred during the sign out process.
 */
export class SignOutError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SignOutError'
  }
}

/**
 * An error occurred during the registration process.
 * This may be due to the client already being registered.
 */
export class RegisterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RegisterError'
  }
}

/**
 * An error occurred indicating that the user is not registered.
 */
export class NotRegisteredError extends Error {
  constructor(message?: string) {
    super(message ?? 'User is not registered.')
    this.name = 'NotRegisteredError'
  }
}

/**
 * The user is not authorized to perform the requested operation. This maybe
 * due to specifying the wrong key deriving key or password.
 */
export class NotAuthorizedError extends Error {
  constructor(message?: string) {
    super(message ?? 'User is not authorized perform the requested operation.')
    this.name = 'NotAuthorizedError'
  }
}

/**
 * Indicates the operation requires the user to be signed in but the user is
 * currently not signed in.
 */
export class NotSignedInError extends Error {
  constructor() {
    super('Not signed in.')
    this.name = 'NotSignedInError'
  }
}

/**
 * Indicates that the user was registered but is not confirmed due to not
 * passing all the required validation.
 */
export class UserNotConfirmedError extends Error {
  constructor() {
    super('User not confirmed.')
    this.name = 'UserNotConfirmedError'
  }
}

/**
 * The version of the vault that's being updated does not match the version
 * stored in the backed. It is likely that another client updated the vault
 * first so the caller should reconcile the changes before attempting to
 * update the vault.
 */
export class VersionMismatchError extends Error {
  constructor() {
    super('Expected object version does not match the actual object version.')
    this.name = 'VersionMismatchError'
  }
}

/**
 * Indicates that the ownership proof was invalid.
 */
export class InvalidOwnershipProofError extends Error {
  constructor() {
    super('Ownership proof was invalid.')
    this.name = 'InvalidOwnershipProofError'
  }
}

/**
 * Indicates that the user does not have sufficient entitlements to perform
 * the requested operation.
 */
export class InsufficientEntitlementsError extends Error {
  constructor() {
    super(
      'The user does not have sufficient entitlements to perform the requested operation.',
    )
    this.name = 'InsufficientEntitlementsError'
  }
}

/**
 * Indicates the requested operation failed because the user account is locked.
 */
export class AccountLockedError extends Error {
  constructor() {
    super('The requested operation failed because the user account is locked.')
    this.name = 'AccountLockedError'
  }
}

/**
 * Indicates that an internal server error caused the operation to fail. The error
 * is possibly transient and retrying at a later time may cause the operation to
 * complete successfully.
 */
export class ServiceError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ServiceError'
  }
}

/**
 * Error when expected arguments are missing or invalid
 */
export class IllegalArgumentError extends Error {
  constructor(message?: string) {
    super(message ?? 'Invalid arguments were specified')
    this.name = 'IllegalArgumentError'
  }
}

/**
 * Error when the state of the program is expecting a value to
 * be set or available and it is not.
 */
export class IllegalStateError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'IllegalStateError'
  }
}

/**
 * Operation failed due to it exceeding some limits imposed for the API. For example,
 * this error can occur if the resource size exceeds the database record size limit.
 */
export class LimitExceededError extends Error {
  constructor() {
    super('API limit exceeded.')
    this.name = 'LimitExceededError'
  }
}

/**
 * API request failed due to network error or unexpected server error.
 */
export class RequestFailedError extends Error {
  /**
   * Underlying error that cause the request to fail.
   */
  public cause?: Error
  /**
   * HTTP status code if a valid response was received with unexpected
   * status code.
   */
  public statusCode?: number

  constructor(cause?: Error, statusCode?: number) {
    super(
      `API request failed. cause: ${cause?.message ?? '<none>'}, statusCode: ${
        statusCode ?? '<none>'
      }`,
    )
    this.name = 'RequestFailedError'
    this.cause = cause
    this.statusCode = statusCode
  }
}

/**
 * An unexpected error was encountered. This may result from programmatic error
 * and is unlikley to be user recoverable.
 */
export class FatalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FatalError'
  }
}

/**
 * No entitlements assigned to user.
 */
export class NoEntitlementsError extends Error {
  constructor() {
    super('No entitlements assigned to user.')
    this.name = 'NoEntitlementsError'
  }
}

/**
 * Token presented was not valid for the purpose.
 */
export class InvalidTokenError extends Error {
  constructor() {
    super('Invalid token.')
    this.name = 'InvalidTokenError'
  }
}

/**
 * Key not found from store when using cryptoProvider
 */
export class KeyNotFoundError extends Error {
  constructor(message?: string) {
    super(message ?? 'Key not found.')
    this.name = 'KeyNotFoundError'
  }
}

/**
 * Underlying secure key store does not support key export
 */
export class KeyStoreNotExportableError extends Error {
  constructor(message?: string) {
    super(message ?? 'Key store not exportable.')
    this.name = 'KeyStoreNotExportableError'
  }
}

/**
 * No key archive provided prior to unarchiving
 */
export class KeyArchiveMissingError extends Error {
  constructor(message?: string) {
    super(message ?? 'No key archive provided prior to unarchiving')
    this.name = 'KeyArchiveMissingError'
  }
}

/**
 * No password provided to unarchive secure archive
 */
export class KeyArchivePasswordRequiredError extends Error {
  constructor(message?: string) {
    super(message ?? 'No password provided to unarchive secure archive')
    this.name = 'KeyArchivePasswordRequiredError'
  }
}

/**
 * No password required to unarchive insecure archive
 */
export class KeyArchiveNoPasswordRequiredError extends Error {
  constructor(message?: string) {
    super(message ?? 'No password required to unarchive insecure archive')
    this.name = 'KeyArchiveNoPasswordRequiredError'
  }
}

/**
 * Key archive data could not be decoded as expected
 */
export class KeyArchiveDecodingError extends Error {
  constructor(message?: string) {
    super(message ?? 'Key archive data could not be decoded as expected')
    this.name = 'KeyArchiveDecodingError'
  }
}

/**
 * Key archive was unable to be decrypted using the provided password
 */
export class KeyArchiveIncorrectPasswordError extends Error {
  constructor(message?: string) {
    super(
      message ??
        'Key archive was unable to be decrypted using the provided password',
    )
    this.name = 'KeyArchiveIncorrectPasswordError'
  }
}

/**
 * Key archive type is not supported
 */
export class KeyArchiveTypeError extends Error {
  constructor(keyArchiveType: string) {
    super(`Key archive type ${keyArchiveType} is not supported`)
    this.name = 'KeyArchiveTypeError'
  }
}

/**
 * Key archive version is not supported
 */
export class KeyArchiveVersionError extends Error {
  constructor(version: number) {
    super(`Key archive version ${version} is not supported`)
    this.name = 'KeyArchiveVersionError'
  }
}

/**
 * Key archive key type is not recognized
 */
export class KeyArchiveUnknownKeyTypeError extends Error {
  constructor(message?: string) {
    super(message ?? 'Key type is not recognized')
    this.name = 'KeyArchiveUnknownKeyTypeError'
  }
}

/**
 * Operation not implemented
 */
export class OperationNotImplementedError extends Error {
  constructor(message?: string) {
    super(message ?? 'Operation is not implemented')
    this.name = 'OperationNotImplementedError'
  }
}

/**
 * Encryption algorithm is not recognized
 */
export class UnrecognizedAlgorithmError extends Error {
  constructor(message?: string) {
    super(message ?? 'Unrecognized encryption algorithm name.')
    this.name = 'UnrecognizedAlgorithmError'
  }
}

/**
 * Helper method for mapping an App Sync error to common errors.
 *
 * For consumption by other Sudo Platform SDKs
 *
 * @param error The App Sync error to map
 * @returns The mapped error
 */
export function mapGraphQLToClientError(error: AppSyncError): Error {
  switch (error.errorType) {
    case 'sudoplatform.AccountLockedError':
      return new AccountLockedError()
    case 'sudoplatform.InsufficientEntitlementsError':
      return new InsufficientEntitlementsError()
    case 'sudoplatform.InvalidTokenError':
      return new InvalidTokenError()
    case 'sudoplatform.InvalidArgumentError':
      return new IllegalArgumentError()
    case 'sudoplatform.NoEntitlementsError':
      return new NoEntitlementsError()
    case 'sudoplatform.ServiceError':
      return new ServiceError(error.message)
    default:
      return new UnknownGraphQLError(error)
  }
}

/**
 * Call this in error handling when testing with isAppSyncNetworkError on
 * a caught error from an AppSync operation returns true.
 *
 * @param error AppSyncNetworkError to map
 *
 * @returns Mapped error
 */
export function mapNetworkErrorToClientError(
  error: AppSyncNetworkError,
): Error {
  const networkError = error.networkError
  switch (networkError.statusCode) {
    case 401:
      return new NotAuthorizedError()
    default:
      return new RequestFailedError(networkError, networkError.statusCode)
  }
}
