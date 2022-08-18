import { DefaultConfigurationManager } from '../../src/configurationManager/defaultConfigurationManager'
import { readFileSync, existsSync } from 'fs'
import { TextEncoder, TextDecoder } from 'util'

require('isomorphic-fetch')

global.TextEncoder = TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

describe('configuration manager', () => {
  const configFilePath = 'config/sudoplatformconfig.json'

  beforeEach(() => {
    delete process.env.AWS_PROFILE
    delete process.env.AWS_ACCESS_KEY_ID
    delete process.env.AWS_SECRET_ACCESS_KEY
    delete process.env.AWS_SESSION_TOKEN
  })

  if (existsSync(configFilePath)) {
    const config = readFileSync(configFilePath, 'utf-8')
    const json = JSON.parse(config)

    describe('validateConfig', () => {
      it('should return deprecated service info if equal to deprecated version', async () => {
        const config = {
          identityService: {
            region: json.identityService.region,
            serviceInfoBucket: json.identityService.serviceInfoBucket,
          },
          vcService: {
            version: 3,
          },
        }

        const manager = DefaultConfigurationManager.getInstance().setConfig(
          JSON.stringify(config),
        )

        await expect(manager.validateConfig()).resolves.toEqual({
          deprecated: [
            {
              configVersion: 3,
              minSupportedVersion: 2,
              deprecatedVersion: 3,
              name: 'vcService',
            },
          ],
          incompatible: [],
        })
      })

      it('should return incompatible service info if less than min version', async () => {
        const config = {
          identityService: {
            region: json.identityService.region,
            serviceInfoBucket: json.identityService.serviceInfoBucket,
          },
          vcService: {
            version: 1,
          },
        }

        const manager = DefaultConfigurationManager.getInstance().setConfig(
          JSON.stringify(config),
        )

        await expect(manager.validateConfig()).resolves.toEqual({
          deprecated: [
            {
              configVersion: 1,
              minSupportedVersion: 2,
              deprecatedVersion: 3,
              name: 'vcService',
            },
          ],
          incompatible: [
            {
              configVersion: 1,
              minSupportedVersion: 2,
              deprecatedVersion: 3,
              name: 'vcService',
            },
          ],
        })
      })
    })
  } else {
    it('Skip all tests.', () => {
      console.log(
        'No sudoplatformconfig.json, test key and test key ID file found. Skipping all integration tests.',
      )
    })
  }
})
