import { isLeft, isRight } from 'fp-ts/lib/Either'
import {
  KeyArchiveKeyType,
  KeyArchiveKeyTypeCodec,
} from '../../src/sudoKeyArchive/keyType'

describe('KeyArchiveKeyType tests', () => {
  describe('KeyArchiveKeyTypeCodec', () => {
    it.each`
      input                             | encoded
      ${KeyArchiveKeyType.Password}     | ${'password'}
      ${KeyArchiveKeyType.PrivateKey}   | ${'privateKey'}
      ${KeyArchiveKeyType.PublicKey}    | ${'publicKey'}
      ${KeyArchiveKeyType.SymmetricKey} | ${'symmetricKey'}
    `('should encode $input to $encoded', ({ input, encoded }) => {
      expect(KeyArchiveKeyTypeCodec.encode(input)).toEqual(encoded)
    })

    it.each`
      input              | decoded
      ${'password'}      | ${KeyArchiveKeyType.Password}
      ${'privateKey'}    | ${KeyArchiveKeyType.PrivateKey}
      ${'privatekey'}    | ${KeyArchiveKeyType.PrivateKey}
      ${'private_key'}   | ${KeyArchiveKeyType.PrivateKey}
      ${'publicKey'}     | ${KeyArchiveKeyType.PublicKey}
      ${'publickey'}     | ${KeyArchiveKeyType.PublicKey}
      ${'public_key'}    | ${KeyArchiveKeyType.PublicKey}
      ${'symmetricKey'}  | ${KeyArchiveKeyType.SymmetricKey}
      ${'symmetrickey'}  | ${KeyArchiveKeyType.SymmetricKey}
      ${'symmetric_key'} | ${KeyArchiveKeyType.SymmetricKey}
    `('should decode $input to $decoded', ({ input, decoded }) => {
      const result = KeyArchiveKeyTypeCodec.decode(input)
      expect(isRight(result)).toEqual(true)
      if (!isRight(result)) {
        fail('result unexpectedly not right')
      }
      expect(result.right).toEqual(decoded)
    })

    it.each`
      invalid
      ${'password_'}
      ${'symmetric__key'}
      ${'foo'}
      ${'1'}
      ${1}
      ${null}
      ${undefined}
    `('it should detect $invalid as invalid', ({ invalid }) => {
      const result = KeyArchiveKeyTypeCodec.decode(invalid)
      expect(isLeft(result)).toEqual(true)
    })
  })
})
