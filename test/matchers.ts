export {}

function match(
  context: jest.MatcherContext,
  caught: Error | undefined,
  error: {
    name: string | RegExp | undefined
    message?: string | RegExp | undefined | null
  },
): { pass: boolean; message: () => string } {
  const failures: string[] = []
  if (caught) {
    if (error.name instanceof RegExp) {
      let pass: boolean
      if (
        caught.name !== undefined &&
        caught.name !== null &&
        typeof caught.name === 'string'
      ) {
        pass = error.name.exec(caught.name) != null
      } else {
        pass = false
      }
      if (!pass) {
        failures.push(
          `name '${caught.name}' does not match regexp ${error.name.source}`,
        )
      }
    } else if (error.name !== undefined) {
      if (caught.name !== error.name) {
        failures.push(`name '${caught.name}' does not match '${error.name}'`)
      }
    }

    if (error.message instanceof RegExp) {
      let pass: boolean
      if (
        caught.message !== undefined &&
        caught.message !== null &&
        typeof caught.message === 'string'
      ) {
        pass = error.message.exec(caught.message) != null
      } else {
        pass = false
      }
      if (!pass) {
        failures.push(
          `message '${caught.message}' does not match regexp ${error.message.source}`,
        )
      }
    } else if (error.message !== undefined) {
      if (caught.message !== error.message) {
        failures.push(
          `message '${caught.message} does not match '${error.message}'`,
        )
      }
    }
  } else {
    failures.push(`no error thrown`)
  }

  if (failures.length === 0 || context.isNot) {
    return {
      pass: true,
      message: () => 'matched',
    }
  } else {
    if (context.isNot) {
      failures.push(`expected ${caught} not to match ${error} but does`)
    }

    return {
      pass: false,
      message: () => {
        return `Failures: ${JSON.stringify(failures, undefined, 2)}`
      },
    }
  }
}

declare global {
  namespace jest {
    interface Matchers<R> {
      toThrowErrorMatching(error: {
        name: string | RegExp | undefined | null
        message?: string | RegExp | undefined | null
      }): R
      toMatchError(error: {
        name: string | RegExp | undefined | null
        message?: string | RegExp | undefined | null
      }): R
    }
  }
}

expect.extend({
  toThrowErrorMatching(
    operation: () => unknown,
    error: {
      name: string | RegExp | undefined
      message?: string | RegExp | undefined | null
    },
  ) {
    let caught: Error | undefined
    try {
      operation()
    } catch (err) {
      caught = err as Error
    }

    return match(this, caught, error)
  },
  toMatchError(
    caught: Error,
    error: {
      name: string | RegExp | undefined
      message?: string | RegExp | undefined | null
    },
  ) {
    return match(this, caught, error)
  },
})
