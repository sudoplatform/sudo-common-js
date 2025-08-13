/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as t from 'io-ts'

import { KeyArchiveKeyTypeCodec } from './keyType'

const KeyArchiveKeyInfoRequiredProps = {
  Name: t.string,
  Type: KeyArchiveKeyTypeCodec,
  Data: t.string,
  Synchronizable: t.boolean,
  NameSpace: t.string,
}

const KeyArchiveKeyInfoOptionalProps = {
  Exportable: t.boolean,
}

// eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
export const KeyArchiveKeyInfoCodec = t.intersection(
  [
    t.type(KeyArchiveKeyInfoRequiredProps),
    t.partial(KeyArchiveKeyInfoOptionalProps),
  ],
  'KeyArchiveKeyInfo',
)

export const KeyArchiveKeyInfoArrayCodec = t.array(
  KeyArchiveKeyInfoCodec,
  'KeyArchiveKeyInfoArray',
)

/**
 * Record of key in a key archive
 *
 * @property NameSpace
 *     NameSpace to which the key belongs.
 *
 * @property Name
 *     Name of the key within the namespace
 *
 * @property Type
 *     Type of the key (also implies key format)
 *
 * @property Data
 *     Base64 encoded key data
 *
 * @property Synchronizable
 *     Whether key should be synced out of band of archiving.
 *     For future use - always false for now.
 *
 * @property Exportable
 *     Whether restored key should be exportable. Always true on archive.
 *     For future use on unarchive.
 */
export type KeyArchiveKeyInfo = t.TypeOf<typeof KeyArchiveKeyInfoCodec>
