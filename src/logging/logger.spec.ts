import { DefaultLogger } from './logger'

afterEach(() => {
  jest.clearAllMocks()
})

const fooBar = {
  foo: 'bar',
}

describe('Logging utility test suite', () => {
  it('should log with custom logger name at custom level', async () => {
    const logger = new DefaultLogger('TestProject', 'error')
    console.log = jest.fn()
    logger.error('Custom logger name with custom level', fooBar)

    expect(console.log).toBeCalledTimes(2)
    expect(console.log).toBeCalledWith(
      expect.stringContaining(
        'ERROR: TestProject: Custom logger name with custom level',
      ),
    )
    expect(console.log).toBeCalledWith(
      expect.objectContaining({
        foo: 'bar',
      }),
    )
  })

  it('should log with default logger name at default level', async () => {
    const logger = new DefaultLogger()
    console.log = jest.fn()
    logger.info('Default logger name with default level', fooBar)
    expect(console.log).toBeCalledTimes(2)
    expect(console.log).toBeCalledWith(
      expect.stringContaining(
        'INFO: rootLogger: Default logger name with default level',
      ),
    )
    expect(console.log).toBeCalledWith(
      expect.objectContaining({
        foo: 'bar',
      }),
    )
  })

  it('should log with logger name at level set by environment variables', async () => {
    process.env.PROJECT_NAME = 'DummyProject'
    process.env.LOG_LEVEL = 'debug'
    const logger = new DefaultLogger()
    console.log = jest.fn()
    logger.debug('logger name at level set by environment variables')
    expect(console.log).toBeCalledTimes(1)
    expect(console.log).toBeCalledWith(
      expect.stringContaining(
        'DEBUG: DummyProject: logger name at level set by environment variables',
      ),
    )
  })
})
