/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { BunyanLogger, createBunyanLogger } from './bunyanLogger'

/**
 * Interface encapsulating logger functions.
 */
export interface Logger {
  /**
   * @returns Whether or not trace level logging is enabled
   */
  trace(): boolean

  /**
   * Will log the given message with the logger implementation using the TRACE level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  trace(message: string, fields?: Record<string, unknown>): void

  /**
   * @returns Whether or not debug level logging is enabled
   */
  debug(): boolean

  /**
   * Will log the given message with the logger implementation using the DEBUG level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  debug(message: string, fields?: Record<string, unknown>): void

  /**
   * @returns Whether or not info level logging is enabled
   */
  info(): boolean

  /**
   * Will log the given message with the logger implementation using the INFO level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  info(message: string, fields?: Record<string, unknown>): void

  /**
   * @returns Whether or not warn level logging is enabled
   */
  warn(): boolean

  /**
   * Will log the given message with the logger implementation using the WARN level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  warn(message: string, fields?: Record<string, unknown>): void

  /**
   * @returns Whether or not error level logging is enabled
   */
  error(): boolean

  /**
   * Will log the given message with the logger implementation using the ERROR level
   * @param message the message to be logged
   * @param fields optional fields that represent an object
   */
  error(message: string, fields?: Record<string, unknown>): void

  /**
   * @returns Whether or not fatal level logging is enabled
   */
  fatal(): boolean

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

  trace(): boolean
  trace(message: string, fields?: Record<string, unknown>): void
  trace(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.trace()

    if (fields) {
      this.logger.trace({ obj: fields }, message)
    } else {
      this.logger.trace(message)
    }
  }

  debug(): boolean
  debug(message: string, fields?: Record<string, unknown>): void
  debug(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.debug()

    if (fields) {
      this.logger.debug({ obj: fields }, message)
    } else {
      this.logger.debug(message)
    }
  }

  info(): boolean
  info(message: string, fields?: Record<string, unknown>): void
  info(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.info()

    if (fields) {
      this.logger.info({ obj: fields }, message)
    } else {
      this.logger.info(message)
    }
  }

  warn(): boolean
  warn(message: string, fields?: Record<string, unknown>): void
  warn(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.warn()

    if (fields) {
      this.logger.warn({ obj: fields }, message)
    } else {
      this.logger.warn(message)
    }
  }

  error(): boolean
  error(message: string, fields?: Record<string, unknown>): void
  error(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.error()

    if (fields) {
      this.logger.error({ obj: fields }, message)
    } else {
      this.logger.error(message)
    }
  }

  fatal(): boolean
  fatal(message: string, fields?: Record<string, unknown>): void
  fatal(message?: string, fields?: Record<string, unknown>): boolean | void {
    if (message === undefined) return this.logger.fatal()

    if (fields) {
      this.logger.fatal({ obj: fields }, message)
    } else {
      this.logger.fatal(message)
    }
  }
}
