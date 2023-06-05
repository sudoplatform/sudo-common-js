/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as t from 'io-ts'

/**
 * Key types supported in key archives
 *
 * These form part of the interoperable secure key archive format.
 */
export enum KeyArchiveKeyType {
  // Byte array of secret data - to be stored and retrievable using *Password
  // methods on key managers
  Password = 'password',

  // PKCS8 PrivateKey encoded RSA private key
  PrivateKey = 'privateKey',

  // SPKI encoded RSA public key
  PublicKey = 'publicKey',

  // Byte array of AES symmetric key
  SymmetricKey = 'symmetricKey',
}

// Android is tolerating the following case insensitive alias key type
// names so we will do the same
const keyArchiveKeyTypeAlternatives: Record<string, KeyArchiveKeyType> = {
  password: KeyArchiveKeyType.Password,
  privatekey: KeyArchiveKeyType.PrivateKey,
  private_key: KeyArchiveKeyType.PrivateKey,
  publickey: KeyArchiveKeyType.PublicKey,
  public_key: KeyArchiveKeyType.PublicKey,
  symmetrickey: KeyArchiveKeyType.SymmetricKey,
  symmetric_key: KeyArchiveKeyType.SymmetricKey,
}

const failureMessage = `Key type is not one of: ${Object.keys(
  keyArchiveKeyTypeAlternatives,
).join(',')}` // eslint-disable-line tree-shaking/no-side-effects-in-initialization

const isKeyArchiveKeyType = (u: unknown): u is KeyArchiveKeyType =>
  t.string.is(u) && keyArchiveKeyTypeAlternatives[u.toLowerCase()] !== undefined

export const KeyArchiveKeyTypeCodec = new t.Type<KeyArchiveKeyType, string>(
  'KeyArchiveKeyType',
  isKeyArchiveKeyType,
  (u, c) =>
    isKeyArchiveKeyType(u)
      ? t.success(keyArchiveKeyTypeAlternatives[u.toLowerCase()])
      : t.failure(u, c, failureMessage),
  t.identity,
)
