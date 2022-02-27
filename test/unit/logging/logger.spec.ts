import { DefaultLogger } from '../../../src/logging/logger'

afterEach(() => {
  jest.clearAllMocks()
})

const fooBar = {
  foo: 'bar',
}

describe('Logging utility test suite', () => {
  it('should log with custom logger name at custom level', () => {
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

  it('should log with default logger name at default level', () => {
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

  it('should log with logger name at level set by environment variables', () => {
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

  it('should log with logger name at level set by environment variables', () => {
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

  it.each`
    level      | traceEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${false}
    ${'info'}  | ${false}
    ${'warn'}  | ${false}
    ${'error'} | ${false}
    ${'fatal'} | ${false}
  `(
    'should return trace enabled $traceEnabled when level is $level',
    ({ level, traceEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.trace()).toEqual(traceEnabled)
    },
  )

  it.each`
    level      | debugEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${true}
    ${'info'}  | ${false}
    ${'warn'}  | ${false}
    ${'error'} | ${false}
    ${'fatal'} | ${false}
  `(
    'should return debug enabled $debugEnabled when level is $level',
    ({ level, debugEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.debug()).toEqual(debugEnabled)
    },
  )

  it.each`
    level      | infoEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${true}
    ${'info'}  | ${true}
    ${'warn'}  | ${false}
    ${'error'} | ${false}
    ${'fatal'} | ${false}
  `(
    'should return info enabled $infoEnabled when level is $level',
    ({ level, infoEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.info()).toEqual(infoEnabled)
    },
  )

  it.each`
    level      | warnEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${true}
    ${'info'}  | ${true}
    ${'warn'}  | ${true}
    ${'error'} | ${false}
    ${'fatal'} | ${false}
  `(
    'should return warn enabled $warnEnabled when level is $level',
    ({ level, warnEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.warn()).toEqual(warnEnabled)
    },
  )

  it.each`
    level      | errorEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${true}
    ${'info'}  | ${true}
    ${'warn'}  | ${true}
    ${'error'} | ${true}
    ${'fatal'} | ${false}
  `(
    'should return error enabled $errorEnabled when level is $level',
    ({ level, errorEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.error()).toEqual(errorEnabled)
    },
  )

  it.each`
    level      | fatalEnabled
    ${'trace'} | ${true}
    ${'debug'} | ${true}
    ${'info'}  | ${true}
    ${'warn'}  | ${true}
    ${'error'} | ${true}
    ${'fatal'} | ${true}
  `(
    'should return fatal enabled $fatalEnabled when level is $level',
    ({ level, fatalEnabled }) => {
      process.env.PROJECT_NAME = 'DummyProject'
      process.env.LOG_LEVEL = level
      const logger = new DefaultLogger()
      expect(logger.fatal()).toEqual(fatalEnabled)
    },
  )
})
