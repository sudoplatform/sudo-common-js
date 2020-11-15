import { getLogger } from '../util/logging'

describe('Logging utility test suite', () => {
  it('should log with custom logger name at custom level', async () => {
    process.env.PROJECT_NAME = 'TestProject'
    process.env.LOG_LEVEL = 'warn'
    expect(getLogger().warn()).toBeTruthy()
    getLogger().warn('Custom logger name with custom level')
  })

  it('should not be able to change the logging level ', async () => {
    process.env.LOG_LEVEL = 'info'
    expect(getLogger().info()).toBeFalsy()
  })
})
