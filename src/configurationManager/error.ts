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
