import { DefaultConfigurationManager } from '../../../src/configurationManager/defaultConfigurationManager'
import * as t from 'io-ts'
import { ConfigurationSetNotFoundError } from '../../../src/errors/error'
import AWS from 'aws-sdk'

describe('configuration manager', () => {
  const config = {
    federatedSignIn: {
      appClientId: '120q904mra9d5l4psmvdbrgm49',
      signInRedirectUri: 'http://localhost:3000/callback',
      signOutRedirectUri: 'http://localhost:3000/',
      webDomain: 'id-dev-fsso-sudoplatform.auth.us-east-1.amazoncognito.com',
      identityProvider: 'Auth0',
    },
    apiService: {
      apiUrl:
        'https://xy7zw5ys7rahrponv7h26vjn6y.appsync-api.us-east-1.amazonaws.com/graphql',
      region: 'us-east-1',
    },
    identityService: {
      region: 'us-east-1',
      poolId: 'us-east-1_ZiPDToF73',
      clientId: '120q904mra9d5l4psmvdbrgm49',
      identityPoolId: 'us-east-1:8fe6d8ed-cd77-4622-b1bb-3f0c147638ad',
      apiUrl:
        'https://mqn7cjrzcrd75jpsma3xw4744a.appsync-api.us-east-1.amazonaws.com/graphql',
      apiKey: 'da2-xejsa343urfifmzkycmz3rqdom',
      bucket: 'ids-userdata-id-dev-fsso-userdatabucket2d841c35-j9x47k5042fk',
      transientBucket:
        'ids-userdata-id-dev-fsso-transientuserdatabucket0-1enoeyoho1sjl',
    },
    secureVaultService: {
      region: 'us-east-1',
      poolId: 'us-east-1_6NalHLdlq',
      clientId: 'pcg1ma18cluamqrif79viaj04',
      apiUrl:
        'https://u2ysyzwojzaahbsq5toulhdt4e.appsync-api.us-east-1.amazonaws.com/graphql',
      pbkdfRounds: 100000,
    },
  }

  const IdentityServiceConfig = t.type({
    region: t.string,
    poolId: t.string,
    clientId: t.string,
    apiUrl: t.string,
  })

  const ApiServiceConfig = t.type({
    apiUrl: t.string,
    region: t.string,
  })

  const SdkConfig = t.type({
    identityService: IdentityServiceConfig,
    apiService: ApiServiceConfig,
  })

  type IdentityServiceConfig = t.TypeOf<typeof IdentityServiceConfig>
  type ApiServiceConfig = t.TypeOf<typeof ApiServiceConfig>
  type SdkConfig = t.TypeOf<typeof SdkConfig>

  describe('getConfigSet', () => {
    it('should return entire config set when empty namespace supplied', () => {
      const configSet = DefaultConfigurationManager.getInstance()
        .setConfig(JSON.stringify(config))
        .getConfigSet()

      expect(configSet).toStrictEqual(config)
    })

    it('should return subset of configuration when matching namespace supplied', () => {
      const expected = {
        region: 'us-east-1',
        poolId: 'us-east-1_ZiPDToF73',
        clientId: '120q904mra9d5l4psmvdbrgm49',
        identityPoolId: 'us-east-1:8fe6d8ed-cd77-4622-b1bb-3f0c147638ad',
        apiUrl:
          'https://mqn7cjrzcrd75jpsma3xw4744a.appsync-api.us-east-1.amazonaws.com/graphql',
        apiKey: 'da2-xejsa343urfifmzkycmz3rqdom',
        bucket: 'ids-userdata-id-dev-fsso-userdatabucket2d841c35-j9x47k5042fk',
        transientBucket:
          'ids-userdata-id-dev-fsso-transientuserdatabucket0-1enoeyoho1sjl',
      }

      const configSet = DefaultConfigurationManager.getInstance()
        .setConfig(JSON.stringify(config))
        .getConfigSet('identityService')

      expect(configSet).toStrictEqual(expected)
    })

    it('should return nothing when no matching namespace supplied', () => {
      const configSet = DefaultConfigurationManager.getInstance()
        .setConfig(JSON.stringify(config))
        .getConfigSet('randomNoMatchingNamespace')

      expect(configSet).toBeFalsy()
    })
  })

  describe('bindConfigSet<T>', () => {
    it('should find config set then bind to given type', () => {
      const result = DefaultConfigurationManager.getInstance()
        .setConfig(JSON.stringify(config))
        .bindConfigSet<IdentityServiceConfig>(
          IdentityServiceConfig,
          'identityService',
        )

      expect(result).toBeTruthy()
      expect(result['apiUrl']).toBeTruthy()
    })

    it('should throw when configuration set not found', () => {
      expect(() => {
        DefaultConfigurationManager.getInstance()
          .setConfig(JSON.stringify(config))
          .bindConfigSet<IdentityServiceConfig>(
            IdentityServiceConfig,
            'randomNamespace',
          )
      }).toThrow(ConfigurationSetNotFoundError)
    })

    it('should still bind when no nampespace provided', () => {
      const result = DefaultConfigurationManager.getInstance()
        .setConfig(JSON.stringify(config))
        .bindConfigSet<SdkConfig>(SdkConfig)

      expect(result).toBeTruthy()
      expect(result['identityService'].apiUrl).toBeTruthy()
    })
  })

  describe('validateConfig', () => {
    it('should return empty result when config not set', async () => {
      const manager = DefaultConfigurationManager.getInstance()

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return empty result when config does not have identity service config', async () => {
      const badConfig = {
        bad: 'bad',
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(badConfig),
      )

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return empty result when config does not have service info bucket name', async () => {
      const badConfig = {
        identityService: {
          region: 'dummy_region',
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(badConfig),
      )

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return empty result when service info document does not have .json extension', async () => {
      const config = {
        identityService: {
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'identityService' }],
                })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return empty result when service info document does not match the client config', async () => {
      const config = {
        identityService: {
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'sudoService' }],
                })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return empty result when there is no service info document', async () => {
      const config = {
        identityService: {
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [],
                })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return incompatible service info if less than min version', async () => {
      const config = {
        identityService: {
          version: 1,
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const serviceInfo = {
        identityService: {
          minVersion: 2,
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation, params) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'identityService.json' }],
                })
              },
            }
          } else if (
            params.Key === 'identityService.json' &&
            params.Bucket === 'dummy_bucket'
          ) {
            return {
              promise() {
                return Promise.resolve({ Body: JSON.stringify(serviceInfo) })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [
          {
            configVersion: 1,
            minSupportedVersion: 2,
            name: 'identityService',
          },
        ],
      })
    })

    it('should return empty result if greater than min version', async () => {
      const config = {
        identityService: {
          version: 3,
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const serviceInfo = {
        identityService: {
          minVersion: 2,
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation, params) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'identityService.json' }],
                })
              },
            }
          } else if (
            params.Key === 'identityService.json' &&
            params.Bucket === 'dummy_bucket'
          ) {
            return {
              promise() {
                return Promise.resolve({ Body: JSON.stringify(serviceInfo) })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [],
        incompatible: [],
      })
    })

    it('should return deprecated service info if equal to deprecated version', async () => {
      const config = {
        identityService: {
          version: 2,
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const serviceInfo = {
        identityService: {
          minVersion: 1,
          deprecated: 2,
          deprecationGrace: 1,
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation, params) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'identityService.json' }],
                })
              },
            }
          } else if (
            params.Key === 'identityService.json' &&
            params.Bucket === 'dummy_bucket'
          ) {
            return {
              promise() {
                return Promise.resolve({ Body: JSON.stringify(serviceInfo) })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [
          {
            configVersion: 2,
            minSupportedVersion: 1,
            deprecatedVersion: 2,
            deprecationGrace: new Date(1),
            name: 'identityService',
          },
        ],
        incompatible: [],
      })
    })

    it('should return deprecated service info if less than deprecated version', async () => {
      const config = {
        identityService: {
          version: 2,
          region: 'us-east-1',
          serviceInfoBucket: 'dummy_bucket',
        },
      }

      const serviceInfo = {
        identityService: {
          minVersion: 1,
          deprecated: 3,
          deprecationGrace: 1,
        },
      }

      const manager = DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify(config),
      )

      jest.mock('aws-sdk')

      AWS.Service.prototype.makeUnauthenticatedRequest = jest
        .fn()
        .mockImplementation((operation, params) => {
          if (operation === 'listObjects') {
            return {
              promise() {
                return Promise.resolve({
                  Contents: [{ Key: 'identityService.json' }],
                })
              },
            }
          } else if (
            params.Key === 'identityService.json' &&
            params.Bucket === 'dummy_bucket'
          ) {
            return {
              promise() {
                return Promise.resolve({ Body: JSON.stringify(serviceInfo) })
              },
            }
          }
        })

      await expect(manager.validateConfig()).resolves.toEqual({
        deprecated: [
          {
            configVersion: 2,
            minSupportedVersion: 1,
            deprecatedVersion: 3,
            deprecationGrace: new Date(1),
            name: 'identityService',
          },
        ],
        incompatible: [],
      })
    })
  })
})
