import {
  AppSyncError,
  AppSyncNetworkError,
  IllegalArgumentError,
  InsufficientEntitlementsError,
  InvalidTokenError,
  isAppSyncNetworkError,
  mapGraphQLToClientError,
  mapNetworkErrorToClientError,
  NoEntitlementsError,
  NotAuthorizedError,
  RequestFailedError,
  ServiceError,
  UnknownGraphQLError,
} from './error'

describe('error', () => {
  const message = 'graphql-error'
  describe('mapGraphQLToClientError', () => {
    it.each`
      code                                            | error
      ${'sudoplatform.InsufficientEntitlementsError'} | ${new InsufficientEntitlementsError()}
      ${'sudoplatform.InvalidTokenError'}             | ${new InvalidTokenError()}
      ${'sudoplatform.InvalidArgumentError'}          | ${new IllegalArgumentError()}
      ${'sudoplatform.NoEntitlementsError'}           | ${new NoEntitlementsError()}
      ${'sudoplatform.ServiceError'}                  | ${new ServiceError(message)}
    `('should map common error $code properly', ({ code, error }) => {
      expect(
        mapGraphQLToClientError({
          message,
          path: [],
          locations: [],
          nodes: [],
          positions: [],
          source: undefined,
          originalError: undefined,
          extensions: [],
          name: code,
          errorType: code,
        }),
      ).toEqual(error)
    })

    it('should map an unrecognized error to UnknownGraphQLError', () => {
      const unrecognized: AppSyncError = {
        message,
        path: [],
        locations: [],
        nodes: [],
        positions: [],
        source: undefined,
        originalError: undefined,
        extensions: [],
        name: 'unrecognized',
        errorType: 'unrecognized',
      }
      expect(mapGraphQLToClientError(unrecognized)).toEqual(
        new UnknownGraphQLError(unrecognized),
      )
    })
  })

  describe('isAppSyncNetworkError', () => {
    const normalNetworkError = {
      name: 'name',
      message: 'message',
      networkError: {
        name: 'name',
        message: 'message',
        statusCode: 401,
      },
    }

    const noStatusCodeNetworkError = {
      name: 'name',
      message: 'message',
      networkError: {
        name: 'name',
        message: 'message',
      },
    }

    const nullNetworkError = {
      name: 'name',
      message: 'message',
      networkError: null,
    }

    const undefinedNetworkError = {
      name: 'name',
      message: 'message',
    }

    it.each`
      error                       | networkError
      ${normalNetworkError}       | ${true}
      ${noStatusCodeNetworkError} | ${true}
      ${undefinedNetworkError}    | ${false}
      ${nullNetworkError}         | ${false}
    `('should return $networkError for $error', ({ error, networkError }) => {
      expect(isAppSyncNetworkError(error)).toEqual(networkError)
    })
  })

  describe('mapNetworkErrorToClientError', () => {
    it.each`
      statusCode   | error
      ${401}       | ${new NotAuthorizedError()}
      ${500}       | ${'default'}
      ${undefined} | ${'default'}
    `('maps network error $statusCode to $error', ({ statusCode, error }) => {
      const networkError: AppSyncNetworkError = {
        name: 'error ' + statusCode,
        message: 'error ' + statusCode,
        networkError: {
          name: 'error ' + statusCode,
          message: 'error ' + statusCode,
          statusCode,
        },
      }
      if (error === 'default') {
        error = new RequestFailedError(networkError, statusCode)
      }

      expect(mapNetworkErrorToClientError(networkError)).toEqual(error)
    })
  })
})
