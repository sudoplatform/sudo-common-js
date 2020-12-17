import {
  AppSyncError,
  InsufficientEntitlementsError,
  InvalidTokenError,
  mapGraphQLToClientError,
  NoEntitlementsError,
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
})
