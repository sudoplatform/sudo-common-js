import { BunyanLogger, createBunyanLogger } from './bunyanLogger'

/**
 * Interface encapsulating logger functions.
 */
export interface Logger {
  /**
   * Will log the given message with the logger implementation using the TRACE level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  trace(message: string, fields?: Record<string, unknown>): void
  /**
   * Will log the given message with the logger implementation using the DEBUG level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  debug(message: string, fields?: Record<string, unknown>): void
  /**
   * Will log the given message with the logger implementation using the INFO level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  info(message: string, fields?: Record<string, unknown>): void
  /**
   * Will log the given message with the logger implementation using the WARN level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  warn(message: string, fields?: Record<string, unknown>): void
  /**
   * Will log the given message with the logger implementation using the ERROR level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  error(message: string, fields?: Record<string, unknown>): void
  /**
   * Will log the given message with the logger implementation using the FATAL level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  fatal(message: string, fields?: Record<string, unknown>): void
}

export class DefaultLogger implements Logger {
  private logger: BunyanLogger

  /**
   * The default logger implementation which wraps browser-bunyan
   *
   * @param identifier the name of the module
   * @param logLevel the log level for the module
   */
  constructor(identifier?: string, logLevel?: string) {
    this.logger = createBunyanLogger(identifier, logLevel)
  }

  trace(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.trace({ obj: fields }, message)
    } else {
      this.logger.trace(message)
    }
  }

  debug(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.debug({ obj: fields }, message)
    } else {
      this.logger.debug(message)
    }
  }

  info(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.info({ obj: fields }, message)
    } else {
      this.logger.info(message)
    }
  }

  warn(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.warn({ obj: fields }, message)
    } else {
      this.logger.warn(message)
    }
  }

  error(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.error({ obj: fields }, message)
    } else {
      this.logger.error(message)
    }
  }

  fatal(message: string, fields?: Record<string, unknown>): void {
    if (fields) {
      this.logger.fatal({ obj: fields }, message)
    } else {
      this.logger.fatal(message)
    }
  }
}
