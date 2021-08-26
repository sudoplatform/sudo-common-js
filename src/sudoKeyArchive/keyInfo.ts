import * as t from 'io-ts'

import { KeyArchiveKeyTypeCodec } from './keyType'

const KeyArchiveKeyInfoRequiredProps = {
  Name: t.string,
  Type: KeyArchiveKeyTypeCodec,
  Data: t.string,
  Synchronizable: t.boolean,
  Exportable: t.boolean,
  NameSpace: t.string,
}

export const KeyArchiveKeyInfoCodec = t.type(
  KeyArchiveKeyInfoRequiredProps,
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
