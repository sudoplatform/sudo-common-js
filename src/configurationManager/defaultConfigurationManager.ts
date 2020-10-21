import { fold, left } from 'fp-ts/lib/Either'
import { pipe } from 'fp-ts/lib/pipeable'
import * as t from 'io-ts'
import { PathReporter } from 'io-ts/lib/PathReporter'
import {
  ConfigurationNotSetError,
  DecodeError,
  ConfigurationSetNotFoundError,
} from './error'

/**
 * Interface that encapsulates the APIs common to all configuration manager implementations.
 * A configuration manager should be a singleton that holds reference to a parsed config
 * and returns the configuration set specific to a given namespace.
 */
export interface ConfigurationManager {
  /**
   * Set config that will be parsed as JSON
   *
   * @param config A string representation of configuration
   *
   * @returns ConfigurationManager
   */
  setConfig(config: string): ConfigurationManager

  /**
   * Get a subset of configuration by namespace
   *
   * @param namespace The key for the nested json object
   *
   * @returns Configuration set specific to a given namespace
   *
   * @throws {@link ConfigurationNotSetError}
   */
  getConfigSet(namespace?: string): string | undefined

  /**
   * Decode a configuration set to a given type
   *
   * @param configSet Configuration set specific to a given namespace
   * @param codec The codec to bind the configuration set to
   *
   * @returns Configuration as a given type
   *
   * @throws {@link DecodeError}
   */
  bind<T>(configSet: unknown, codec: t.Mixed): T

  /**
   * Get a configuration by namespace and decode and validate
   * that configuration set to a given type.  If no namespace
   * provided, try and use the whole configuration object
   * to bind to the given type.
   *
   * @param namespace The key for the nested json object or undefined
   * @param codec The codec to bind the configuration set to
   *
   * @returns Configuration as a given type
   *
   * @throws {@link ConfigurationNotSetError}
   * @throws {@link ConfigurationSetNotFoundError}
   * @throws {@link DecodeError}
   */
  bindConfigSet<T>(codec: t.Mixed, namespace?: string): T
}

/**
 * Singleton to manage configuration
 */
export class DefaultConfigurationManager implements ConfigurationManager {
  private static instance: DefaultConfigurationManager

  private _config: string | undefined

  private constructor() {
    // Do Nothing.
  }

  public static getInstance(): DefaultConfigurationManager {
    if (!DefaultConfigurationManager.instance) {
      DefaultConfigurationManager.instance = new DefaultConfigurationManager()
    }

    return DefaultConfigurationManager.instance
  }

  public setConfig(config: string): DefaultConfigurationManager {
    this._config = config

    return DefaultConfigurationManager.instance
  }

  public getConfigSet(namespace?: string): string {
    if (!this._config) {
      throw new ConfigurationNotSetError()
    }

    const configSet = !namespace
      ? JSON.parse(this._config)
      : JSON.parse(this._config)[namespace]

    return configSet
  }

  public bind<T>(configSet: unknown, codec: t.Mixed): T {
    // Decode and validate config
    return pipe(
      codec.decode(configSet),
      fold(
        (errors: t.Errors): T => {
          throw new DecodeError(PathReporter.report(left(errors)).join('\n'))
        },
        (v: T): T => v,
      ),
    )
  }

  public bindConfigSet<T>(codec: t.Mixed, namespace?: string): T {
    const configSet = this.getConfigSet(namespace)

    if (!configSet) {
      throw new ConfigurationSetNotFoundError(namespace)
    }

    return this.bind<T>(configSet, codec)
  }
}
