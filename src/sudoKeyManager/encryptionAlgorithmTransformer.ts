import { EncryptionAlgorithm } from '../types/types'

/**
 * A utility function to convert between a Sudo Platform
 * algorithm name to a WebCrypto API algorithm name
 *
 * @param algorithm The Sudo Platform algorithm name
 * @returns The WebCrypto API algorithm name
 */
export function CryptoAlgorithmName(
  algorithm: EncryptionAlgorithm,
): string | undefined {
  switch (algorithm) {
    case EncryptionAlgorithm.AesCbcPkcs7Padding:
      return 'AES-CBC'
    case EncryptionAlgorithm.RsaOaepSha1:
      return 'RSA-OAEP'
    default:
      return undefined
  }
}
