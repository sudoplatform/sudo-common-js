import { GraphQLError } from 'graphql'

export type AppSyncError = GraphQLError & {
  errorType?: string | null
}

/**
 * Indicates the GraphQL API returned an error that's not recognized by the client.
 */
export class UnknownGraphQLError extends Error {
  constructor(cause: AppSyncError) {
    super(`type: ${cause.errorType}, message: ${cause.message}`)
    this.name = 'GraphQLError'
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
  constructor(message: string) {
    super(message)
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
 * the requested operation. This error may also be thrown if the request
 * has violated a service specific policy, e.g rate limit.
 */
export class PolicyError extends Error {
  constructor() {
    super(
      'Service policy prevented the requested operation from completing. This may be due to the user having insufficient entitlements or service specific limits.',
    )
    this.name = 'PolicyError'
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
 * An unexpected error was encountered. This may result from programmatic error
 * and is unlikley to be user recoverable.
 */
export class FatalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FatalError'
  }
}
