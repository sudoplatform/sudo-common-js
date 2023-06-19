/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as t from 'io-ts'
import { KeyArchiveKeyInfoCodec } from './keyInfo'

export const PREGZIP_ARCHIVE_VERSION = 2
export const CURRENT_ARCHIVE_VERSION = 3

const CommonKeyArchiveRequiredProps = {
  /**
   * Version this archive format.
   */
  Version: t.union([
    t.literal(CURRENT_ARCHIVE_VERSION),
    t.literal(PREGZIP_ARCHIVE_VERSION),
  ]),

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

const InsecureKeyArchiveV2RequiredProps = {
  ...CommonKeyArchiveRequiredProps,
  /**
   * Archive type.
   */
  Type: t.union([
    t.literal(InsecureKeyArchiveType),
    t.literal(SecureKeyArchiveType),
  ]),

  /**
   * Base64 encoded exported keys.
   */
  Keys: t.string,
}

// Existing V2 insecure key archives produced by iOS and Android
// has a different structure to V3 insecure key archive so we
// need a separate type and codec to process those. This is an
// incompatibility in addition to V3 archives being zipped.
export const InsecureKeyArchiveV2Codec = t.type(
  InsecureKeyArchiveV2RequiredProps,
  'InsecureKeyArchiveV2',
)

export type InsecureKeyArchiveV2 = t.TypeOf<typeof InsecureKeyArchiveV2Codec>

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
    InsecureKeyArchiveV2Codec,

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
  return (
    keyArchive.Type === InsecureKeyArchiveType &&
    keyArchive.Version !== PREGZIP_ARCHIVE_VERSION
  )
}

export function isInsecureKeyArchiveV2(
  keyArchive: KeyArchive,
): keyArchive is InsecureKeyArchiveV2 {
  return (
    keyArchive.Type === InsecureKeyArchiveType &&
    keyArchive.Version === PREGZIP_ARCHIVE_VERSION
  )
}

export function isUnrecognizedKeyArchive(
  keyArchive: KeyArchive,
): keyArchive is UnrecognizedKeyArchive {
  return (
    !isSecureKeyArchive(keyArchive) &&
    !isInsecureKeyArchive(keyArchive) &&
    !isInsecureKeyArchiveV2(keyArchive)
  )
}
