/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { fold, left } from 'fp-ts/lib/Either'
import { pipe } from 'fp-ts/lib/pipeable'
import * as t from 'io-ts'
import { PathReporter } from 'io-ts/lib/PathReporter'
import {
  ConfigurationNotSetError,
  DecodeError,
  ConfigurationSetNotFoundError,
  FatalError,
} from '../errors/error'
import {
  S3Client,
  ListObjectsCommand,
  GetObjectCommand,
} from '@aws-sdk/client-s3'
import { bodyToString } from '../utils/stream'

/**
 * Service compatibility information.
 */
export interface ServiceCompatibilityInfo {
  /**
   * The name of the service associated with the compatibility info. This matches one of the
   * service name present in sudoplatformconfig.json.
   */
  name: string
  /**
   * The version of the service config present in sudoplatformconfig.json. It defaults
   * to 1 if not present.
   */
  configVersion: number
  /**
   * The minimum supported service config version currently supported by the backend.
   */
  minSupportedVersion?: number
  /**
   * Any service config version less than or equal to this version is considered deprecated
   * and the backend may remove the support for those versions after a grace period.
   */
  deprecatedVersion?: number
  /**
   * After this time any deprecated service config versions will no longer be compatible
   * with the backend. It is recommended to warn the user prior to the deprecation grace.
   */
  deprecationGrace?: Date
}

/**
 * Result returned by `validateConfig` API if an incompatible client config is found when compared
 * to the deployed backend services.
 */
export interface ValidationResult {
  /**
   * The list of incompatible services. The client must be upgraded to the latest
   * version in order to use these services.
   */
  incompatible: ServiceCompatibilityInfo[]
  /**
   * The list of services that will be made incompatible with the current version of the
   * client. The users should be warned that after the specified grace period these services will be
   * made incompatible.
   */
  deprecated: ServiceCompatibilityInfo[]
}

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

  /**
   * Validates the client configuration (sudoplatformconfig.json) against the currently deployed set of
   * backend services. If the client configuration is valid, i.e. the client is compatible will all deployed
   * backend services, then the call will complete with `success` result. If any part of the client
   * configuration is incompatible then a detailed information on the incompatible service will be
   * returned in `failure` result. See `SudoConfigManagerError.compatibilityIssueFound` for more details.
   *
   * @return validation result with the details of incompatible or deprecated service configurations.
   */
  validateConfig(): Promise<ValidationResult>
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

    const parsed = JSON.parse(this._config)
    const configSet = namespace ? parsed[namespace] : parsed

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

  public async validateConfig(): Promise<ValidationResult> {
    if (!this._config) {
      return { incompatible: [], deprecated: [] }
    }

    const config = JSON.parse(this._config)

    const region = config.identityService?.region
    const bucket = config.identityService?.serviceInfoBucket

    if (!(region && bucket)) {
      return { incompatible: [], deprecated: [] }
    }

    const s3Client = new S3Client({
      region: region,
      // We want these request to be unauthenticated
      // so we provide a no-op signer for the requests
      signer: { sign: (request: any) => Promise.resolve(request) },
      credentials: { accessKeyId: '', secretAccessKey: '' },
    })

    const incompatible: ServiceCompatibilityInfo[] = []
    const deprecated: ServiceCompatibilityInfo[] = []

    const listObjectsCommand = new ListObjectsCommand({
      Bucket: bucket,
    })

    const objects = await s3Client.send(listObjectsCommand)
    if (!objects.Contents?.length) {
      return { incompatible: [], deprecated: [] }
    }

    const keys = objects.Contents.map((object: any) => object.Key)

    // Only fetch the service info docs for the services that are present in client config
    // to minimize the network calls.
    const keysToFetch = keys.filter(
      (key: string) =>
        key.endsWith('.json') && config[key.replace('.json', '')],
    )

    for (const key of keysToFetch) {
      const getObject = new GetObjectCommand({
        Key: key,
        Bucket: bucket,
      })
      const object = await s3Client.send(getObject)
      if (!object.Body) {
        throw new FatalError('No S3 object body')
      }
      const body = await bodyToString(object.Body)
      const json = JSON.parse(body)
      const serviceName = key.replace('.json', '')
      const serviceInfo: any = json[serviceName]
      const serviceConfig: any = config[serviceName]
      if (serviceInfo && serviceConfig) {
        const currentVersion: number = serviceConfig.version ?? 1
        const deprecationGrace: number = serviceInfo.deprecationGrace ?? -1
        const compatibilityInfo: ServiceCompatibilityInfo = {
          name: serviceName,
          configVersion: currentVersion,
          minSupportedVersion: serviceInfo.minVersion,
          deprecatedVersion: serviceInfo.deprecated,
          deprecationGrace:
            deprecationGrace != -1 ? new Date(deprecationGrace) : undefined,
        }

        // If the service config in `sudoplatformconfig.json` is less than the
        // minimum supported version then the client is incompatible.
        if (currentVersion < (compatibilityInfo.minSupportedVersion ?? 0)) {
          incompatible.push(compatibilityInfo)
        }

        // If the service config is less than or equal to the deprecated version
        // then it will be made incompatible after the deprecation grace.
        if (currentVersion <= (compatibilityInfo.deprecatedVersion ?? 0)) {
          deprecated.push(compatibilityInfo)
        }
      }
    }

    return { incompatible, deprecated }
  }
}
