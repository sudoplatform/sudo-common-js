/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { gunzipSync, gzipSync } from 'fflate'
import { isLeft } from 'fp-ts/lib/Either'

import {
  IllegalArgumentError,
  KeyArchiveDecodingError,
  KeyArchiveIncorrectPasswordError,
  KeyArchiveMissingError,
  KeyArchiveNoPasswordRequiredError,
  KeyArchivePasswordRequiredError,
  KeyArchiveTypeError,
  KeyArchiveUnknownKeyTypeError,
  KeyArchiveVersionError,
  KeyNotFoundError,
} from '../errors/error'
import { KeyData, KeyDataKeyType } from '../sudoKeyManager'
import { SudoCryptoProviderDefaults } from '../sudoKeyManager/sudoCryptoProvider'
import { SudoKeyManager } from '../sudoKeyManager/sudoKeyManager'
import { Base64 } from '../utils/base64'
import { Buffer as BufferUtil } from '../utils/buffer'
import {
  CURRENT_ARCHIVE_VERSION,
  PREGZIP_ARCHIVE_VERSION,
  InsecureKeyArchive,
  InsecureKeyArchiveType,
  isSecureKeyArchive,
  isUnrecognizedKeyArchive,
  KeyArchive,
  KeyArchiveCodec,
  SecureKeyArchive,
  SecureKeyArchiveType,
  isInsecureKeyArchive,
  InsecureKeyArchiveV2,
} from './keyArchive'
import { KeyArchiveKeyInfo, KeyArchiveKeyInfoArrayCodec } from './keyInfo'
import { KeyArchiveKeyType } from './keyType'

export interface SudoKeyArchive {
  /**
   * Loads keys from the secure store into the archive.
   */
  loadKeys(): Promise<void>

  /**
   * Saves the keys in this archive to the secure store.
   */
  saveKeys(): Promise<void>

  /**
   * Archives and encrypts the keys loaded into this archive.
   *
   * @param password
   *   The password to use to encrypt the archive. Or undefined if no password.
   *   Choice to have no password must be explicit.
   *
   * @returns Binary archive data.
   */
  archive(password: ArrayBuffer | undefined): Promise<ArrayBuffer>

  /**
   * Decrypts and unarchives the keys in this archive.
   *
   * @param password
   *    The password to use to decrypt the archive if its a secure archive
   *    otherwise must be undefined.
   *
   * @throws {@link KeyArchiveDecodingError}
   *    If the archive is unable to be decoding according to the
   *    required structure.
   *
   * @throws {@link KeyArchiveIncorrectPasswordError}
   *    If the archive is a secure archive and the password is unable to be
   *    used to decrypt the encrypted keys.
   *
   * @throws {@link KeyArchivePasswordRequiredError}
   *    If the archive is a secure archive but no password is provided.
   *
   * @throws {@link KeyArchiveNoPasswordRequiredError}
   *    If the archive is an insecure archive but a password is provided.
   */
  unarchive(password: ArrayBuffer | undefined): Promise<void>

  /**
   * Resets the archive by clearing loaded keys and archive data.
   */
  reset(): void

  /**
   * Determines whether or not the archive contains the key with the
   * specified name and type. The archive must be unarchived before the
   * key can be searched.
   *
   * @param namespace the namespace of the key
   * @param name the key name.
   * @param type the key type.
   *
   * @return true if the specified key exists in the archive.
   */
  containsKey(namespace: string, name: string, type: KeyArchiveKeyType): boolean

  /**
   * Retrieves the specified key data from the archive. The archive must
   * be unarchived before the key data can be retrieved.
   *
   * @param namespace the namespace of the key
   * @param name the key name
   * @param type the key type
   *
   * @return a byte array containing the specified key data or null if it was not found.
   *
   * @throws {@link KeyNotFoundError}
   *     If key is not present in the archive.
   */
  getKeyData(
    namespace: string,
    name: string,
    type: KeyArchiveKeyType,
  ): ArrayBuffer

  /** @return the key types to exclude from the archive in an unmodifiable set. */
  getExcludedKeyTypes(): ReadonlySet<KeyArchiveKeyType>

  /** @return the key names to exclude from the archive in an unmodifiable set. */
  getExcludedKeys(): ReadonlySet<string>

  /** @return the meta-information associated with this archive in an unmodifiable map. */
  getMetaInfo(): ReadonlyMap<string, string>
}

export type KeyArchiveKeyInfoDecoded = KeyArchiveKeyInfo & {
  Decoded: ArrayBuffer
}

export class DefaultSudoKeyArchive implements SudoKeyArchive {
  /**
   * Version 2 format is not gzipped is what's currently generated
   * by iOS and Android. We may want to add support for importing
   * such archives.
   */
  public static readonly PREGZIP_ARCHIVE_VERSION = PREGZIP_ARCHIVE_VERSION

  /**
   * Version 3 format permits both secure and insecure key archives.
   *
   * Insecure key archives are used where the archive will be stored
   * in an otherwise known secure way e.g. via secure-vault-service
   * where the encryption of the archive would then be handled by
   * clients of that service.
   *
   * Secure key archives are password protected (via PBKDF2) a la version
   * 2 format.
   *
   * Insecure format detail is:
   *
   *     gzip(JSON.stringify(InsecureKeyArchive))
   *
   * Secure format detail is:
   *
   *     gzip(JSON.stringify(SecureKeyArchive))
   *
   * where Keys property of SecureKeyArchive is:
   *
   *     base64(encrypt(gzip(JSON.stringify(array of keys))))
   *
   * Where encrypt operation is 256-bit AES CBC-mode with IV SecureKeyArchive.IV
   * and key generated by SecureKeyArchive.Rounds of PBKDF2 on the password
   * salted with SecureKeyArchive.Salt.
   */
  public static readonly CURRENT_ARCHIVE_VERSION = CURRENT_ARCHIVE_VERSION

  private readonly defaultKeyManager: SudoKeyManager
  private readonly keyManagers: Record<string, SudoKeyManager> = {}
  private keyArchive:
    | SecureKeyArchive
    | InsecureKeyArchive
    | InsecureKeyArchiveV2
    | undefined
  private readonly excludedKeys: Set<string> = new Set<string>()
  private readonly excludedKeyTypes: Set<KeyArchiveKeyType> =
    new Set<KeyArchiveKeyType>()
  private readonly metaInfo: Map<string, string> = new Map<string, string>()

  private readonly keys: Map<string, KeyArchiveKeyInfoDecoded> = new Map<
    string,
    KeyArchiveKeyInfoDecoded
  >()

  private readonly zip: boolean

  /**
   * Construct SudoKeyArchive
   *
   *
   * @param keyManagers
   *     Key manager or array of key managers to either restore archive in to
   *     or construct archive from
   *
   * @param archiveData
   *     Array buffer of binary archive data to restore.
   *
   * @param excludedKeys
   *     Set of key names to exclude from archive or restore operation.
   *     Default: None
   *
   * @param excludedKeyTypes
   *     Set of key types to exclude from archive or restore operation.
   *     Default: {@link KeyArchiveKeyType.PublicKey}
   *
   * @param metaInfo
   *     Meta information to include with the key archive
   *
   * @param zip
   * If the archive is created for importing keys, it specifies whether the provided data is
   * zipped. If the archive is created for exporting keys, specifies whether the output should
   * be zipped.
   *
   * @throws {@link IllegalArgumentError}
   *     If no key managers are provided
   *
   * @throws {@link IllegalArgumentError}
   *     If multiple key managers are provided with the same namespace
   *
   * @throws {@link KeyArchiveDecodingError}
   *     If archiveData is provided and its binary data cannot be decoded
   *
   * @throws {@link KeyArchiveTypeError}
   *     If archiveData is provided and decodes to an unsupported archive
   *     type.
   *
   * @throws {@link KeyArchiveVersionError}
   *     If archiveData is provided and decodes to an unsupported archive
   *     version.
   */
  public constructor(
    keyManagers: SudoKeyManager | SudoKeyManager[],
    options?: {
      archiveData?: ArrayBuffer
      excludedKeys?: ReadonlySet<string>
      excludedKeyTypes?: ReadonlySet<KeyArchiveKeyType>
      metaInfo?: ReadonlyMap<string, string>
      zip?: boolean
    },
  ) {
    if (Array.isArray(keyManagers)) {
      if (keyManagers.length === 0) {
        throw new IllegalArgumentError('Must provide at least one key manager')
      }

      keyManagers.forEach((keyManager) => {
        if (this.keyManagers[keyManager.namespace]) {
          throw new IllegalArgumentError(
            `Multiple key managers provided with namespace ${keyManager.namespace}`,
          )
        }
        this.keyManagers[keyManager.namespace] = keyManager
      })
      this.defaultKeyManager = keyManagers[0]
    } else {
      this.keyManagers[keyManagers.namespace] = keyManagers
      this.defaultKeyManager = keyManagers
    }

    if (options?.archiveData) {
      this.keyArchive = this.loadArchive(options.archiveData, options.zip)
    }

    // We take copies of the input parameters so we own the data
    if (options?.excludedKeys) {
      options?.excludedKeys.forEach((excludedKey) =>
        this.excludedKeys.add(excludedKey),
      )
    }

    if (options?.excludedKeyTypes) {
      options?.excludedKeyTypes.forEach((excludedKeyType) =>
        this.excludedKeyTypes.add(excludedKeyType),
      )
    }

    if (options?.metaInfo?.size) {
      for (const [key, value] of options?.metaInfo?.entries()) {
        this.metaInfo.set(key, value)
      }
    }

    this.zip = options?.zip ?? true
  }

  /**
   * Reads the binary data and converts it to JSON and then deserialises it
   * into a KeyArchive
   */
  private loadArchive(
    archiveData: ArrayBuffer,
    zip: boolean = true,
  ): SecureKeyArchive | InsecureKeyArchive {
    let jsonData: ArrayBuffer

    try {
      if (zip) {
        jsonData = gunzipSync(new Uint8Array(archiveData))
      } else {
        jsonData = archiveData
      }
    } catch (err) {
      throw new KeyArchiveDecodingError()
    }

    let keyArchive: KeyArchive
    try {
      const decoded = KeyArchiveCodec.decode(
        JSON.parse(BufferUtil.toString(jsonData)),
      )
      if (isLeft(decoded)) {
        throw new KeyArchiveDecodingError()
      }
      keyArchive = decoded.right
    } catch (err) {
      throw new KeyArchiveDecodingError()
    }
    if (isUnrecognizedKeyArchive(keyArchive)) {
      if (
        keyArchive.Type &&
        keyArchive.Type !== SecureKeyArchiveType &&
        keyArchive.Type !== InsecureKeyArchiveType
      ) {
        throw new KeyArchiveTypeError(keyArchive.Type)
      }

      // Only support DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION and PREGZIP_ARCHIVE_VERSION
      // for now.
      if (
        keyArchive.Version !== undefined &&
        keyArchive.Version !== DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION &&
        keyArchive.Version !== DefaultSudoKeyArchive.PREGZIP_ARCHIVE_VERSION
      ) {
        throw new KeyArchiveVersionError(keyArchive.Version)
      }

      throw new KeyArchiveDecodingError()
    }

    return keyArchive
  }

  private keyArchiveInfoFromKeyData(
    keyData: KeyData,
  ): KeyArchiveKeyInfoDecoded {
    let rawKey: ArrayBuffer = keyData.data
    // If we are not using compression then we are creating v2
    // archive. We need to perform some key format conversion
    // in order ensure interoperability with other platforms.
    if (!this.zip) {
      switch (keyData.type) {
        case KeyDataKeyType.RSAPrivateKey:
          rawKey = Object.values(
            this.keyManagers,
          )[0].privateKeyInfoToRSAPrivateKey(keyData.data)
          break
        case KeyDataKeyType.RSAPublicKey:
          rawKey = Object.values(
            this.keyManagers,
          )[0].publicKeyInfoToRSAPublicKey(keyData.data)
          break
        default:
          break
      }
    }

    return {
      NameSpace: keyData.namespace,
      Name: keyData.name,
      Type: keyArchiveKeyTypeFromKeyDataKeyType(keyData.type),
      Data: Base64.encode(rawKey),
      Decoded: keyData.data,
      Synchronizable: false,
      Exportable: true,
    }
  }

  async loadKeys(): Promise<void> {
    for (const keyManager of Object.values(this.keyManagers)) {
      await keyManager.exportKeys().then((exported) => {
        exported.forEach((data) => {
          const keyArchiveInfoDecoded = this.keyArchiveInfoFromKeyData(data)
          if (
            !this.excludedKeyTypes.has(keyArchiveInfoDecoded.Type) &&
            !this.excludedKeys.has(data.name)
          ) {
            this.keys.set(
              `${keyArchiveInfoDecoded.NameSpace}:${keyArchiveInfoDecoded.Type}:${keyArchiveInfoDecoded.Name}`,
              keyArchiveInfoDecoded,
            )
          }
        })
      })
    }
  }

  async saveKeys(): Promise<void> {
    for (const info of this.keys.values()) {
      const keyManager = this.keyManagers[info.NameSpace]
      if (!keyManager) continue
      if (this.excludedKeyTypes.has(info.Type)) continue
      if (this.excludedKeys.has(info.Name)) continue

      const keyData = info.Decoded
      switch (info.Type) {
        case KeyArchiveKeyType.Password:
          await keyManager.addPassword(keyData, info.Name)
          break
        case KeyArchiveKeyType.PrivateKey:
          if (this.keyArchive?.Version === PREGZIP_ARCHIVE_VERSION) {
            await keyManager.importPrivateKeyFromRSAPrivateKey(
              info.Name,
              keyData,
            )
          } else {
            await keyManager.addPrivateKey(keyData, info.Name)
          }
          break
        case KeyArchiveKeyType.PublicKey:
          if (this.keyArchive?.Version === PREGZIP_ARCHIVE_VERSION) {
            await keyManager.importPublicKeyFromRSAPublicKey(info.Name, keyData)
          } else {
            await keyManager.addPublicKey(keyData, info.Name)
          }
          break
        case KeyArchiveKeyType.SymmetricKey:
          await keyManager.addSymmetricKey(keyData, info.Name)
          break
        default:
          throw new KeyArchiveUnknownKeyTypeError(
            `Key archive key type ${info.Type as string} is not recognized`,
          )
      }
    }
  }

  async archive(password: ArrayBuffer | undefined): Promise<ArrayBuffer> {
    const keys: KeyArchiveKeyInfo[] = []
    for (const key of this.keys.values()) {
      keys.push({
        NameSpace: key.NameSpace,
        Name: key.Name,
        Data: key.Data,
        Type: key.Type,
        Synchronizable: key.Synchronizable,
        Exportable: key.Exportable,
      })
    }

    let keyArchive: SecureKeyArchive | InsecureKeyArchive | InsecureKeyArchiveV2
    if (!password) {
      if (this.zip) {
        // Zipped archive is only supported by V3 archive.
        const insecureKeyArchive: InsecureKeyArchive = {
          Type: 'Insecure',
          MetaInfo: {},
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          Keys: keys,
        }
        keyArchive = insecureKeyArchive
      } else {
        // Need this for backward compatibility and interoperability
        // since other platforms only support V2 archive.
        const insecureKeyArchive: InsecureKeyArchiveV2 = {
          Type: 'Insecure',
          MetaInfo: {},
          Version: DefaultSudoKeyArchive.PREGZIP_ARCHIVE_VERSION,
          Keys: Base64.encode(new TextEncoder().encode(JSON.stringify(keys))),
        }
        keyArchive = insecureKeyArchive
      }
    } else {
      const salt = await this.defaultKeyManager.generateRandomData(
        SudoCryptoProviderDefaults.pbkdfSaltSize,
      )
      const b64Salt = Base64.encode(salt)
      const key = await this.defaultKeyManager.generateSymmetricKeyFromPassword(
        password,
        salt,
        {
          rounds: SudoCryptoProviderDefaults.pbkdfRounds,
        },
      )

      const serializedKeys = JSON.stringify(keys)
      const compressedSerializedKeys = gzipSync(
        BufferUtil.fromString(serializedKeys),
        {
          level: 9,
        },
      )

      // Don't strictly need a randomly generated IV here but no harm either
      const iv = await this.defaultKeyManager.generateRandomData(
        SudoCryptoProviderDefaults.aesIVSize,
      )
      const encryptedKeys =
        await this.defaultKeyManager.encryptWithSymmetricKey(
          key,
          compressedSerializedKeys,
          { iv },
        )
      const secureKeyArchive: SecureKeyArchive = {
        Type: 'Secure',
        Version: this.zip
          ? DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION
          : DefaultSudoKeyArchive.PREGZIP_ARCHIVE_VERSION,
        MetaInfo: {},
        Salt: b64Salt,
        Rounds: SudoCryptoProviderDefaults.pbkdfRounds,
        Keys: Base64.encode(encryptedKeys),
        IV: Base64.encode(iv),
      }

      keyArchive = secureKeyArchive
    }

    for (const [key, value] of this.metaInfo.entries()) {
      keyArchive.MetaInfo[key] = value
    }

    const archiveString = JSON.stringify(keyArchive)
    const archiveData = BufferUtil.fromString(archiveString)

    // While this double Gzips the SecureKeyArchive, it allows us to roughly
    // recover the space consumed by Base64 encoding the cipher text. Otherwise
    // we would end up having a fully binary data structure for the archive.
    // If the time to compute becomes prohibitive we can look at a binary, non-JSON
    // base format for the archive.
    return this.zip
      ? gzipSync(archiveData, {
          level: 9,
        })
      : archiveData
  }

  async unarchive(password: ArrayBuffer | undefined): Promise<void> {
    if (!this.keyArchive) {
      throw new KeyArchiveMissingError()
    }

    let keys: KeyArchiveKeyInfo[]

    if (isSecureKeyArchive(this.keyArchive)) {
      if (!password) {
        throw new KeyArchivePasswordRequiredError()
      }

      let iv: ArrayBuffer
      let encryptedKeys: ArrayBuffer
      let key: ArrayBuffer
      try {
        const salt = Base64.decode(this.keyArchive.Salt)
        iv = Base64.decode(this.keyArchive.IV)
        encryptedKeys = Base64.decode(this.keyArchive.Keys)
        key = await this.defaultKeyManager.generateSymmetricKeyFromPassword(
          password,
          salt,
          { rounds: this.keyArchive.Rounds },
        )
      } catch (err) {
        throw new KeyArchiveDecodingError()
      }

      let compressedSerializedKeys: ArrayBuffer
      try {
        compressedSerializedKeys =
          await this.defaultKeyManager.decryptWithSymmetricKey(
            key,
            encryptedKeys,
            { iv },
          )
      } catch (err) {
        throw new KeyArchiveIncorrectPasswordError()
      }
      try {
        const serializedKeys =
          this.keyArchive.Version === PREGZIP_ARCHIVE_VERSION
            ? compressedSerializedKeys
            : gunzipSync(new Uint8Array(compressedSerializedKeys))
        const decoded = KeyArchiveKeyInfoArrayCodec.decode(
          JSON.parse(BufferUtil.toString(serializedKeys)),
        )
        if (isLeft(decoded)) {
          throw new KeyArchiveDecodingError()
        }
        keys = decoded.right
      } catch (err) {
        throw new KeyArchiveDecodingError()
      }
    } else if (isInsecureKeyArchive(this.keyArchive)) {
      if (password) {
        throw new KeyArchiveNoPasswordRequiredError()
      }
      keys = this.keyArchive.Keys
    } else {
      // Process V2 insecure key archive. V2 archive's `Keys` attribute
      // is always base64 encoded string.
      const serializedKeys = Base64.decode(this.keyArchive.Keys)
      try {
        const decoded = KeyArchiveKeyInfoArrayCodec.decode(
          JSON.parse(BufferUtil.toString(serializedKeys)),
        )
        if (isLeft(decoded)) {
          throw new KeyArchiveDecodingError()
        }
        keys = decoded.right
      } catch (err) {
        throw new KeyArchiveDecodingError()
      }
    }

    keys.forEach((key) => {
      const keyKey = `${key.NameSpace}:${key.Type}:${key.Name}`
      let decoded: ArrayBuffer
      try {
        decoded = Base64.decode(key.Data)
      } catch (err) {
        throw new KeyArchiveDecodingError(`Unable to decode key ${keyKey}`)
      }
      this.keys.set(keyKey, { ...key, Decoded: decoded })
    })
  }

  reset(): void {
    this.keys.clear()
  }

  containsKey(
    namespace: string,
    name: string,
    type: KeyArchiveKeyType,
  ): boolean {
    return this.keys.has(`${namespace}:${type}:${name}`)
  }

  getKeyData(
    namespace: string,
    name: string,
    type: KeyArchiveKeyType,
  ): ArrayBuffer {
    const keyInfo = this.keys.get(`${namespace}:${type}:${name}`)
    if (!keyInfo) {
      throw new KeyNotFoundError()
    }

    return keyInfo.Decoded
  }

  getExcludedKeys(): ReadonlySet<string> {
    return this.excludedKeys
  }

  getExcludedKeyTypes(): ReadonlySet<KeyArchiveKeyType> {
    return this.excludedKeyTypes
  }

  getMetaInfo(): ReadonlyMap<string, string> {
    return this.metaInfo
  }
}

export function keyArchiveKeyTypeFromKeyDataKeyType(
  keyDataKeyType: KeyDataKeyType,
): KeyArchiveKeyType {
  switch (keyDataKeyType) {
    case KeyDataKeyType.Password:
      return KeyArchiveKeyType.Password
    case KeyDataKeyType.RSAPrivateKey:
      return KeyArchiveKeyType.PrivateKey
    case KeyDataKeyType.RSAPublicKey:
      return KeyArchiveKeyType.PublicKey
    case KeyDataKeyType.SymmetricKey:
      return KeyArchiveKeyType.SymmetricKey
  }
}
