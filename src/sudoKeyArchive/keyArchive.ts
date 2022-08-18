import * as t from 'io-ts'
import { KeyArchiveKeyInfoCodec } from './keyInfo'

export const CURRENT_ARCHIVE_VERSION = 3

const CommonKeyArchiveRequiredProps = {
  /**
   * Version this archive format.
   */
  Version: t.literal(CURRENT_ARCHIVE_VERSION),

  /**
   * Metainfo user is able to associate with the archive.
   */
  MetaInfo: t.record(t.string, t.string),
}

export const InsecureKeyArchiveType = 'Insecure'

const InsecureKeyArchiveRequiredProps = {
  ...CommonKeyArchiveRequiredProps,
  /**
   * Discriminant for InsecureKeyArchive type.
   */
  Type: t.literal(InsecureKeyArchiveType),

  /**
   * Array of exported keys in clear text.
   */
  Keys: t.array(KeyArchiveKeyInfoCodec),
}

export const InsecureKeyArchiveCodec = t.type(
  InsecureKeyArchiveRequiredProps,
  'InsecureKeyArchive',
)

export type InsecureKeyArchive = t.TypeOf<typeof InsecureKeyArchiveCodec>

export const SecureKeyArchiveType = 'Secure'

const SecureKeyArchiveRequiredProps = {
  ...CommonKeyArchiveRequiredProps,
  /**
   * Discriminant for SecureKeyArchive type.
   */
  Type: t.literal(SecureKeyArchiveType),

  /**
   * Format is:
   *
   * base64(gzip(encrypt(stringify(array of KeyArchiveKeyInfo)))
   *
   * Encrypt is 256-bit AES-CBC using symmetric key derived from
   * password and IV specified by IV property.
   */
  Keys: t.string,

  /**
   * Rounds of PBKDF2 applied to password to derive symmetric key.
   */
  Rounds: t.number,

  /**
   * Salt passed to PBKDF2 to derive symmetric key.
   */
  Salt: t.string,

  /**
   * IV used for AES encryption of keys.
   */
  IV: t.string,
}

const UnrecognizedKeyArchiveProps = {
  Version: t.number,
  Type: t.string,
}

export const UnrecognizedKeyArchiveCodec = t.partial(
  UnrecognizedKeyArchiveProps,
)
export type UnrecognizedKeyArchive = t.TypeOf<
  typeof UnrecognizedKeyArchiveCodec
>

export const SecureKeyArchiveCodec = t.type(
  SecureKeyArchiveRequiredProps,
  'SecureKeyArchive',
)
export type SecureKeyArchive = t.TypeOf<typeof SecureKeyArchiveCodec>

export const KeyArchiveCodec = t.union(
  [
    SecureKeyArchiveCodec,
    InsecureKeyArchiveCodec,

    // Leave UnrecognizedKeyArchiveCodec last so it's tried last
    UnrecognizedKeyArchiveCodec,
  ],
  'KeyArchive',
)

export type KeyArchive = t.TypeOf<typeof KeyArchiveCodec>

export function isSecureKeyArchive(
  keyArchive: KeyArchive,
): keyArchive is SecureKeyArchive {
  return keyArchive.Type === SecureKeyArchiveType
}

export function isInsecureKeyArchive(
  keyArchive: KeyArchive,
): keyArchive is InsecureKeyArchive {
  return keyArchive.Type === InsecureKeyArchiveType
}

export function isUnrecognizedKeyArchive(
  keyArchive: KeyArchive,
): keyArchive is UnrecognizedKeyArchive {
  return !isSecureKeyArchive(keyArchive) && !isInsecureKeyArchive(keyArchive)
}
