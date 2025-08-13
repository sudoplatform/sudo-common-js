import { isLeft, isRight } from 'fp-ts/lib/Either'
import * as t from 'io-ts'
import {
  anything,
  capture,
  deepEqual,
  instance,
  mock,
  reset,
  verify,
  when,
} from 'ts-mockito'

import {
  IllegalArgumentError,
  KeyArchiveDecodingError,
  KeyArchiveIncorrectPasswordError,
  KeyArchiveMissingError,
  KeyArchiveNoPasswordRequiredError,
  KeyArchivePasswordRequiredError,
  KeyArchiveTypeError,
  KeyArchiveVersionError,
  KeyNotFoundError,
} from '../../src/errors/error'
import {
  InsecureKeyArchive,
  InsecureKeyArchiveCodec,
  InsecureKeyArchiveV2Codec,
  SecureKeyArchive,
  SecureKeyArchiveCodec,
} from '../../src/sudoKeyArchive/keyArchive'
import {
  KeyArchiveKeyInfo,
  KeyArchiveKeyInfoCodec,
} from '../../src/sudoKeyArchive/keyInfo'
import { KeyArchiveKeyType } from '../../src/sudoKeyArchive/keyType'
import { DefaultSudoKeyArchive } from '../../src/sudoKeyArchive/sudoKeyArchive'
import {
  KeyData,
  KeyDataKeyFormat,
  KeyDataKeyType,
  SudoCryptoProviderDefaults,
} from '../../src/sudoKeyManager'
import { SudoKeyManager } from '../../src/sudoKeyManager/sudoKeyManager'
import { Base64 } from '../../src/utils/base64'
import { Buffer as BufferUtil } from '../../src/utils/buffer'
import { TextEncoder, TextDecoder } from 'node:util'
import '../matchers'
import { Gzip } from '../../src/utils/gzip'

global.TextEncoder = TextEncoder as typeof global.TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

describe('DefaultSudoKeyArchive tests', () => {
  const mockKeyManager1 = mock<SudoKeyManager>()
  const mockKeyManager2 = mock<SudoKeyManager>()
  const keyManager1Namespace = 'key-manager-1'
  const keyManager2Namespace = 'key-manager-2'
  const password = BufferUtil.fromString('password')

  beforeEach(() => {
    reset(mockKeyManager1)
    reset(mockKeyManager2)

    when(mockKeyManager1.namespace).thenReturn(keyManager1Namespace)
    when(mockKeyManager1.addPassword(anything(), anything())).thenResolve()
    when(mockKeyManager1.addPrivateKey(anything(), anything())).thenResolve()
    when(mockKeyManager1.addPublicKey(anything(), anything())).thenResolve()
    when(mockKeyManager1.addSymmetricKey(anything(), anything())).thenResolve()

    when(mockKeyManager2.namespace).thenReturn(keyManager2Namespace)
    when(mockKeyManager2.addPassword(anything(), anything())).thenResolve()
    when(mockKeyManager2.addPrivateKey(anything(), anything())).thenResolve()
    when(mockKeyManager2.addPublicKey(anything(), anything())).thenResolve()
    when(mockKeyManager2.addSymmetricKey(anything(), anything())).thenResolve()
  })

  const iv = BufferUtil.fromString('iv')
  const ivB64 = Base64.encode(iv)
  const salt = BufferUtil.fromString('salt')
  const saltB64 = Base64.encode(salt)
  const symmetricKey = BufferUtil.fromString('symmetric-key')

  describe('constructor', () => {
    describe('with no options parameter and one key manager', () => {
      it('should succeed', () => {
        new DefaultSudoKeyArchive(instance(mockKeyManager1))
        verify(mockKeyManager1.namespace).atLeast(1)
      })

      it('should create a sudo key archive with no meta info', () => {
        const sudoKeyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
        )
        expect(sudoKeyArchive.getMetaInfo()).toEqual(new Map<string, string>())
        verify(mockKeyManager1.namespace).atLeast(1)
      })

      it('should create a sudo key archive with no excluded keys', () => {
        const sudoKeyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
        )
        expect(sudoKeyArchive.getExcludedKeys()).toEqual(new Set<string>())
        verify(mockKeyManager1.namespace).atLeast(1)
      })

      it('should create a sudo key archive with no excluded key types', () => {
        const sudoKeyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
        )
        expect(sudoKeyArchive.getExcludedKeyTypes()).toEqual(
          new Set<KeyArchiveKeyType>(),
        )
        verify(mockKeyManager1.namespace).atLeast(1)
      })
    })

    describe('with no options parameter and array of key managers', () => {
      it('should succeed', () => {
        new DefaultSudoKeyArchive([
          instance(mockKeyManager1),
          instance(mockKeyManager2),
        ])
        verify(mockKeyManager1.namespace).atLeast(1)
        verify(mockKeyManager2.namespace).atLeast(1)
      })

      it('should throw an IllegalArgumentError if key manager array is empty', () => {
        expect(() => new DefaultSudoKeyArchive([])).toThrowErrorMatching(
          new IllegalArgumentError('Must provide at least one key manager'),
        )
      })

      it('should throw an IllegalArgumentError if key manager array has key managers with same namespace', () => {
        expect(
          () =>
            new DefaultSudoKeyArchive([
              instance(mockKeyManager1),
              instance(mockKeyManager1),
            ]),
        ).toThrowErrorMatching(
          new IllegalArgumentError(
            `Multiple key managers provided with namespace ${keyManager1Namespace}`,
          ),
        )
      })
    })

    describe('with fully populated options parameter but no archive', () => {
      let metaInfo: ReadonlyMap<string, string>
      let excludedKeyTypes: ReadonlySet<KeyArchiveKeyType>
      let excludedKeys: ReadonlySet<string>

      beforeAll(() => {
        const newMetaInfo = new Map<string, string>()
        newMetaInfo.set('meta-1', 'value-1')
        newMetaInfo.set('meta-2', 'value-2')
        metaInfo = newMetaInfo

        const newExcludedKeyTypes = new Set<KeyArchiveKeyType>()
        newExcludedKeyTypes.add(KeyArchiveKeyType.PublicKey)
        excludedKeyTypes = newExcludedKeyTypes

        const newExcludedKeys = new Set<string>()
        newExcludedKeys.add('excluded-key-1')
        excludedKeys = newExcludedKeys
      })

      it('should succeed', () => {
        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            metaInfo,
            excludedKeys,
            excludedKeyTypes,
          },
        )
        verify(mockKeyManager1.namespace).once()

        expect(keyArchive.getExcludedKeys()).toEqual(excludedKeys)
        expect(keyArchive.getExcludedKeyTypes()).toEqual(excludedKeyTypes)
        expect(keyArchive.getMetaInfo()).toEqual(metaInfo)
      })
    })

    describe('with archiveData provided', () => {
      it('throws KeyArchiveDecodingError if archive data is not gzip data', () => {
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: BufferUtil.fromString('not gzipped'),
            }),
        ).toThrowErrorMatching(new KeyArchiveDecodingError())
      })

      it('should succeed if archive data is not gzip data but zip parameter set to false', () => {
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: BufferUtil.fromString('not gzipped'),
              zip: false,
            }),
        ).toBeTruthy()
      })

      it('throws KeyArchiveDecodingError if archive data is not gzipped JSON data', () => {
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: Gzip.compress(BufferUtil.fromString('not JSON')),
            }),
        ).toThrowErrorMatching(new KeyArchiveDecodingError())
      })

      it('throws KeyArchiveDecodingError if archive data is gzipped JSON data without a Type or Version field', () => {
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: Gzip.compress(
                BufferUtil.fromString(JSON.stringify({ Some: 'JSON' })),
              ),
            }),
        ).toThrowErrorMatching(new KeyArchiveDecodingError())
      })

      it('throws KeyArchiveTypeError if archive data is gzipped JSON data with Type property of unrecognized value', () => {
        const unsupportedType = 'Unsupported'
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: Gzip.compress(
                BufferUtil.fromString(
                  JSON.stringify({ Type: unsupportedType }),
                ),
              ),
            }),
        ).toThrowErrorMatching(new KeyArchiveTypeError(unsupportedType))
      })

      it('throws KeyArchiveVersionError if archive data is gzipped JSON data with Type property of unrecognized value', () => {
        const unsupportedVersion =
          DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION + 1
        expect(
          () =>
            new DefaultSudoKeyArchive(instance(mockKeyManager1), {
              archiveData: Gzip.compress(
                BufferUtil.fromString(
                  JSON.stringify({ Version: unsupportedVersion }),
                ),
              ),
            }),
        ).toThrowErrorMatching(new KeyArchiveVersionError(unsupportedVersion))
      })
    })
  })

  describe('unarchive', () => {
    const keys: KeyArchiveKeyInfo[] = [
      {
        Name: 'key-1-password',
        NameSpace: keyManager1Namespace,
        Data: Base64.encode(BufferUtil.fromString('key-1-password-data')),
        Exportable: true,
        Synchronizable: false,
        Type: KeyArchiveKeyType.Password,
      },
      {
        Name: 'key-2-key-pair',
        NameSpace: keyManager1Namespace,
        Data: Base64.encode(BufferUtil.fromString('key-2-public-key-data')),
        Exportable: true,
        Synchronizable: false,
        Type: KeyArchiveKeyType.PublicKey,
      },
      {
        Name: 'key-2-key-pair',
        NameSpace: keyManager1Namespace,
        Data: Base64.encode(BufferUtil.fromString('key-2-private-key-data')),
        Exportable: true,
        Synchronizable: false,
        Type: KeyArchiveKeyType.PrivateKey,
      },
      {
        Name: 'key-3-symmetric',
        NameSpace: keyManager1Namespace,
        Data: Base64.encode(BufferUtil.fromString('key-3-symmetric-data')),
        Exportable: true,
        Synchronizable: false,
        Type: KeyArchiveKeyType.SymmetricKey,
      },
    ]

    it('throws KeyArchiveMissingError if constructed without archive data', async () => {
      const keyArchive = new DefaultSudoKeyArchive(instance(mockKeyManager1))
      await expect(keyArchive.unarchive(undefined)).rejects.toMatchError(
        new KeyArchiveMissingError(),
      )
    })

    it('throws KeyArchiveDecodingError if key data cannot be decoded', async () => {
      const keyArchive = new DefaultSudoKeyArchive(instance(mockKeyManager1), {
        archiveData: Gzip.compress(
          BufferUtil.fromString(
            JSON.stringify({
              Type: 'Insecure',
              Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
              Keys: [
                {
                  Data: 'not base64',
                  Type: KeyArchiveKeyType.Password,
                  Name: 'not-base64',
                  NameSpace: keyManager1Namespace,
                },
              ],
            }),
          ),
        ),
      })

      await expect(keyArchive.unarchive(undefined)).rejects.toMatchError(
        new KeyArchiveDecodingError(
          `Unable to decode key ${keyManager1Namespace}:${KeyArchiveKeyType.Password}:not-base64`,
        ),
      )
    })

    describe('with insecure archive', () => {
      it('throws KeyArchiveNoPasswordRequiredError if a password is provided', async () => {
        const insecureArchive: InsecureKeyArchive = {
          Type: 'Insecure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          Keys: [],
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(insecureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveNoPasswordRequiredError(),
        )
      })

      it('succeeds with no keys', async () => {
        const insecureArchive: InsecureKeyArchive = {
          Type: 'Insecure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          Keys: [],
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(insecureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()

        verify(mockKeyManager1.addPassword(anything(), anything())).never()
        verify(mockKeyManager1.addPrivateKey(anything(), anything())).never()
        verify(mockKeyManager1.addPublicKey(anything(), anything())).never()
        verify(mockKeyManager1.addSymmetricKey(anything(), anything())).never()
      })

      it('succeeds with keys of different types', async () => {
        const insecureArchive: InsecureKeyArchive = {
          Type: 'Insecure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          Keys: keys,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(insecureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()

        keys.forEach((Key) =>
          expect(
            keyArchive.getKeyData(keyManager1Namespace, Key.Name, Key.Type),
          ).toEqual(Base64.decode(Key.Data)),
        )
      })
    })

    describe('with secure archive', () => {
      const emptyKeys: KeyArchiveKeyInfo[] = []
      const serializedEmptyKeys = JSON.stringify(emptyKeys)
      const compressedSerializedEmptyKeys = Gzip.compress(
        BufferUtil.fromString(serializedEmptyKeys),
      )
      const serializedKeys = JSON.stringify(keys)
      const compressedSerializedKeys = Gzip.compress(
        BufferUtil.fromString(serializedKeys),
      )
      const encryptedEmptyKeys = BufferUtil.fromString('encrypted-empty-keys')
      const encryptedEmptyKeysB64 = Base64.encode(encryptedEmptyKeys)
      const encryptedKeys = BufferUtil.fromString('encrypted-keys')
      const encryptedKeysB64 = Base64.encode(encryptedKeys)

      beforeEach(() => {
        when(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).thenResolve(symmetricKey)
        when(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            deepEqual(encryptedEmptyKeys),
            anything(),
          ),
        ).thenResolve(compressedSerializedEmptyKeys)
        when(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            deepEqual(encryptedKeys),
            anything(),
          ),
        ).thenResolve(compressedSerializedKeys)
      })

      it('throws KeyArchivePasswordRequiredError if no password is provided', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(undefined)).rejects.toMatchError(
          new KeyArchivePasswordRequiredError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
      })

      it('throws KeyArchiveDecodingError if Salt is not decodable as base 64', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: 'not base64',
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
      })

      it('throws KeyArchiveDecodingError if IV is not decodable as base 64', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: 'not base64',
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
      })

      it('throws KeyArchiveDecodingError if Keys is not decodable as base 64', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: 'not base64',
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
      })

      it('throws KeyArchiveDecodingError if symmetric key is unable to be generated', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        when(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).thenReject(new Error('symmetric key generation failed'))

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).never()
      })

      it('throws KeyArchiveIncorrectPasswordError if encrypted compressed serialized keys are unable to be decrypted', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        when(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).thenReject(new Error('decryption failed'))

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveIncorrectPasswordError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedEmptyKeys)
        expect(symmetricOptions).toBeDefined()
        expect(symmetricOptions?.iv).toEqual(iv)
      })

      it('throws KeyArchiveDecodingError if compressed serialized keys are unable to be uncompressed', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        when(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).thenResolve(BufferUtil.fromString('not compressed'))

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedEmptyKeys)
        expect(symmetricOptions).toBeDefined()
        expect(symmetricOptions?.iv).toEqual(iv)
      })

      it('throws KeyArchiveDecodingError if serialized keys are unable to be deserialized', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        when(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).thenResolve(Gzip.compress(BufferUtil.fromString('not JSON')))

        await expect(keyArchive.unarchive(password)).rejects.toMatchError(
          new KeyArchiveDecodingError(),
        )

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedEmptyKeys)
        expect(symmetricOptions).toBeDefined()
        expect(symmetricOptions?.iv).toEqual(iv)
      })

      it('succeeds with an empty key array', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedEmptyKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).resolves.toBeUndefined()

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedEmptyKeys)
        expect(symmetricOptions?.iv).toEqual(iv)
      })

      it('succeeds with an non-empty key array', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).resolves.toBeUndefined()

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedKeys)
        expect(symmetricOptions?.iv).toEqual(iv)

        keys.forEach((key) =>
          expect(
            keyArchive.getKeyData(keyManager1Namespace, key.Name, key.Type),
          ).toEqual(Base64.decode(key.Data)),
        )
      })
      it('succeeds with an non-empty key array', async () => {
        const secureArchive: SecureKeyArchive = {
          Type: 'Secure',
          Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
          IV: ivB64,
          Salt: saltB64,
          Rounds: 1,
          Keys: encryptedKeysB64,
          MetaInfo: {},
        }

        const keyArchive = new DefaultSudoKeyArchive(
          instance(mockKeyManager1),
          {
            archiveData: Gzip.compress(
              BufferUtil.fromString(JSON.stringify(secureArchive)),
            ),
          },
        )

        await expect(keyArchive.unarchive(password)).resolves.toBeUndefined()

        verify(
          mockKeyManager1.generateSymmetricKeyFromPassword(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualPassword, actualSalt, actualOptions] = capture(
          mockKeyManager1.generateSymmetricKeyFromPassword,
        ).first()
        expect(actualPassword).toEqual(password)
        expect(actualSalt).toEqual(salt)
        expect(actualOptions).toEqual({ rounds: secureArchive.Rounds })

        verify(
          mockKeyManager1.decryptWithSymmetricKey(
            anything(),
            anything(),
            anything(),
          ),
        ).once()
        const [actualKey, actualData, symmetricOptions] = capture(
          mockKeyManager1.decryptWithSymmetricKey,
        ).first()
        expect(actualKey).toEqual(symmetricKey)
        expect(actualData).toEqual(encryptedKeys)
        expect(symmetricOptions?.iv).toEqual(iv)

        keys.forEach((key) =>
          expect(
            keyArchive.getKeyData(keyManager1Namespace, key.Name, key.Type),
          ).toEqual(Base64.decode(key.Data)),
        )
      })
    })
  })

  type AddFn = (data: ArrayBuffer, name: string) => Promise<void>
  function getAddFn(key: KeyArchiveKeyInfo): AddFn {
    switch (key.Type) {
      case KeyArchiveKeyType.Password:
        return key.NameSpace === keyManager1Namespace
          ? mockKeyManager1.addPassword
          : mockKeyManager2.addPassword
      case KeyArchiveKeyType.PublicKey:
        return key.NameSpace === keyManager1Namespace
          ? mockKeyManager1.addPublicKey
          : mockKeyManager2.addPublicKey
      case KeyArchiveKeyType.PrivateKey:
        return key.NameSpace === keyManager1Namespace
          ? mockKeyManager1.addPrivateKey
          : mockKeyManager2.addPrivateKey
      case KeyArchiveKeyType.SymmetricKey:
        return key.NameSpace === keyManager1Namespace
          ? mockKeyManager1.addSymmetricKey
          : mockKeyManager2.addSymmetricKey
    }
  }

  const password1: KeyArchiveKeyInfo = {
    Name: 'key-1-password',
    NameSpace: keyManager1Namespace,
    Data: Base64.encode(BufferUtil.fromString('1-key-1-password-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.Password,
  }
  const publicKey1: KeyArchiveKeyInfo = {
    Name: 'key-2-key-pair',
    NameSpace: keyManager1Namespace,
    Data: Base64.encode(BufferUtil.fromString('1-key-2-public-key-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.PublicKey,
  }
  const privateKey1: KeyArchiveKeyInfo = {
    Name: 'key-2-key-pair',
    NameSpace: keyManager1Namespace,
    Data: Base64.encode(BufferUtil.fromString('1-key-2-private-key-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.PrivateKey,
  }
  const symmetricKey1: KeyArchiveKeyInfo = {
    Name: 'key-3-symmetric',
    NameSpace: keyManager1Namespace,
    Data: Base64.encode(BufferUtil.fromString('1-key-3-symmetric-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.SymmetricKey,
  }
  const password2: KeyArchiveKeyInfo = {
    Name: 'key-1-password',
    NameSpace: keyManager2Namespace,
    Data: Base64.encode(BufferUtil.fromString('2-key-1-password-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.Password,
  }
  const publicKey2: KeyArchiveKeyInfo = {
    Name: 'key-2-key-pair',
    NameSpace: keyManager2Namespace,
    Data: Base64.encode(BufferUtil.fromString('2-key-2-public-key-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.PublicKey,
  }
  const privateKey2: KeyArchiveKeyInfo = {
    Name: 'key-2-key-pair',
    NameSpace: keyManager2Namespace,
    Data: Base64.encode(BufferUtil.fromString('2-key-2-private-key-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.PrivateKey,
  }

  const symmetricKey2: KeyArchiveKeyInfo = {
    Name: 'key-3-symmetric',
    NameSpace: keyManager2Namespace,
    Data: Base64.encode(BufferUtil.fromString('2-key-3-symmetric-data')),
    Exportable: true,
    Synchronizable: false,
    Type: KeyArchiveKeyType.SymmetricKey,
  }
  const keys: KeyArchiveKeyInfo[] = [
    password1,
    publicKey1,
    privateKey1,
    symmetricKey1,
    password2,
    publicKey2,
    privateKey2,
    symmetricKey2,
  ]

  function keyArchiveKeyTypeToKeyDataKeyType(
    keyArchiveInfoKeyType: KeyArchiveKeyType,
  ): KeyDataKeyType {
    switch (keyArchiveInfoKeyType) {
      case KeyArchiveKeyType.Password:
        return KeyDataKeyType.Password
      case KeyArchiveKeyType.PrivateKey:
        return KeyDataKeyType.RSAPrivateKey
      case KeyArchiveKeyType.PublicKey:
        return KeyDataKeyType.RSAPublicKey
      case KeyArchiveKeyType.SymmetricKey:
        return KeyDataKeyType.SymmetricKey
    }
  }
  function keyArchiveInfoToKeyData(keyInfo: KeyArchiveKeyInfo): KeyData {
    let format: KeyDataKeyFormat
    switch (keyInfo.Type) {
      case KeyArchiveKeyType.Password:
        format = KeyDataKeyFormat.Raw
        break
      case KeyArchiveKeyType.PublicKey:
        format = KeyDataKeyFormat.SPKI
        break
      case KeyArchiveKeyType.PrivateKey:
        format = KeyDataKeyFormat.PKCS8
        break
      case KeyArchiveKeyType.SymmetricKey:
        format = KeyDataKeyFormat.Raw
        break
    }
    return {
      namespace: keyInfo.NameSpace,
      name: keyInfo.Name,
      type: keyArchiveKeyTypeToKeyDataKeyType(keyInfo.Type),
      data: Base64.decode(keyInfo.Data),
      format,
    }
  }

  describe('saveKeys', () => {
    let insecureKeyArchiveData: ArrayBuffer

    beforeEach(() => {
      const insecureArchive: InsecureKeyArchive = {
        Type: 'Insecure',
        Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
        Keys: keys,
        MetaInfo: {},
      }

      insecureKeyArchiveData = Gzip.compress(
        BufferUtil.fromString(JSON.stringify(insecureArchive)),
      )
    })

    it('should save keys to correct key manager in correct way', async () => {
      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1), instance(mockKeyManager2)],
        { archiveData: insecureKeyArchiveData },
      )
      await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()
      await expect(keyArchive.saveKeys()).resolves.toBeUndefined()

      verify(mockKeyManager1.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager1.addPublicKey(anything(), anything())).once()
      verify(mockKeyManager1.addPrivateKey(anything(), anything())).once()
      verify(mockKeyManager1.addPassword(anything(), anything())).once()
      verify(mockKeyManager2.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager2.addPublicKey(anything(), anything())).once()
      verify(mockKeyManager2.addPrivateKey(anything(), anything())).once()
      verify(mockKeyManager2.addPassword(anything(), anything())).once()

      for (const key of keys) {
        const addFn = getAddFn(key)
        const [actualData, actualName] = capture(addFn).first()
        expect(actualData).toEqual(Base64.decode(key.Data))
        expect(actualName).toEqual(key.Name)
      }
    })

    it('should omit excluded key types', async () => {
      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1), instance(mockKeyManager2)],
        {
          archiveData: insecureKeyArchiveData,
          excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
        },
      )
      await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()
      await expect(keyArchive.saveKeys()).resolves.toBeUndefined()

      verify(mockKeyManager1.addPublicKey(anything(), anything())).never()
      verify(mockKeyManager2.addPublicKey(anything(), anything())).never()

      verify(mockKeyManager1.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager1.addPrivateKey(anything(), anything())).once()
      verify(mockKeyManager1.addPassword(anything(), anything())).once()
      verify(mockKeyManager2.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager2.addPrivateKey(anything(), anything())).once()
      verify(mockKeyManager2.addPassword(anything(), anything())).once()

      for (const key of keys) {
        if (key.Type === KeyArchiveKeyType.PublicKey) continue

        const addFn = getAddFn(key)
        const [actualData, actualName] = capture(addFn).first()
        expect(actualData).toEqual(Base64.decode(key.Data))
        expect(actualName).toEqual(key.Name)
      }
    })

    it('should omit excluded key names', async () => {
      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1), instance(mockKeyManager2)],
        {
          archiveData: insecureKeyArchiveData,
          excludedKeys: new Set([password1.Name]),
        },
      )
      await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()
      await expect(keyArchive.saveKeys()).resolves.toBeUndefined()

      verify(mockKeyManager1.addPassword(anything(), anything())).never()
      verify(mockKeyManager2.addPassword(anything(), anything())).never()

      verify(mockKeyManager1.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager1.addPublicKey(anything(), anything())).once()
      verify(mockKeyManager1.addPrivateKey(anything(), anything())).once()
      verify(mockKeyManager2.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager2.addPublicKey(anything(), anything())).once()
      verify(mockKeyManager2.addPrivateKey(anything(), anything())).once()

      for (const key of keys) {
        if (key.Name === password1.Name) continue

        const addFn = getAddFn(key)
        const [actualData, actualName] = capture(addFn).first()
        expect(actualData).toEqual(Base64.decode(key.Data))
        expect(actualName).toEqual(key.Name)
      }
    })

    it('should omit keys without a matching key manager namespace', async () => {
      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1)],
        {
          archiveData: insecureKeyArchiveData,
        },
      )
      await expect(keyArchive.unarchive(undefined)).resolves.toBeUndefined()
      await expect(keyArchive.saveKeys()).resolves.toBeUndefined()

      verify(mockKeyManager1.addPassword(anything(), anything())).once()
      verify(mockKeyManager1.addSymmetricKey(anything(), anything())).once()
      verify(mockKeyManager1.addPublicKey(anything(), anything())).once()
      verify(mockKeyManager1.addPrivateKey(anything(), anything())).once()

      verify(mockKeyManager2.addPassword(anything(), anything())).never()
      verify(mockKeyManager2.addSymmetricKey(anything(), anything())).never()
      verify(mockKeyManager2.addPublicKey(anything(), anything())).never()
      verify(mockKeyManager2.addPrivateKey(anything(), anything())).never()

      for (const key of keys) {
        if (key.NameSpace === keyManager2Namespace) continue

        const addFn = getAddFn(key)
        const [actualData, actualName] = capture(addFn).first()
        expect(actualData).toEqual(Base64.decode(key.Data))
        expect(actualName).toEqual(key.Name)
      }
    })
  })

  describe('loadKeys', () => {
    it('should load keys from all key managers', async () => {
      when(mockKeyManager1.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager1Namespace)
          .map(keyArchiveInfoToKeyData),
      )
      when(mockKeyManager2.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager2Namespace)
          .map(keyArchiveInfoToKeyData),
      )

      const keyArchive = new DefaultSudoKeyArchive([
        instance(mockKeyManager1),
        instance(mockKeyManager2),
      ])

      await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

      keys.forEach((key) =>
        expect(
          keyArchive.containsKey(key.NameSpace, key.Name, key.Type),
        ).toEqual(true),
      )

      verify(mockKeyManager1.exportKeys()).once()
      verify(mockKeyManager2.exportKeys()).once()
    })

    it('should omit keys from excluded key types', async () => {
      when(mockKeyManager1.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager1Namespace)
          .map(keyArchiveInfoToKeyData),
      )
      when(mockKeyManager2.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager2Namespace)
          .map(keyArchiveInfoToKeyData),
      )

      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1), instance(mockKeyManager2)],
        {
          excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
        },
      )

      await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

      keys.forEach((key) =>
        expect(
          keyArchive.containsKey(key.NameSpace, key.Name, key.Type),
        ).toEqual(key.Type !== KeyArchiveKeyType.PublicKey),
      )

      verify(mockKeyManager1.exportKeys()).once()
      verify(mockKeyManager2.exportKeys()).once()
    })

    it('should omit keys with excluded names', async () => {
      when(mockKeyManager1.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager1Namespace)
          .map(keyArchiveInfoToKeyData),
      )
      when(mockKeyManager2.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager2Namespace)
          .map(keyArchiveInfoToKeyData),
      )

      const keyArchive = new DefaultSudoKeyArchive(
        [instance(mockKeyManager1), instance(mockKeyManager2)],
        {
          excludedKeys: new Set([password1.Name]),
        },
      )

      await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

      keys.forEach((key) =>
        expect(
          keyArchive.containsKey(key.NameSpace, key.Name, key.Type),
        ).toEqual(key.Name !== password1.Name),
      )

      verify(mockKeyManager1.exportKeys()).once()
      verify(mockKeyManager2.exportKeys()).once()
    })
  })

  describe('archive', () => {
    const metaInfoRecord = { some: 'meta', info: 'provided' }
    const metaInfo = new Map<string, string>(
      Object.entries(metaInfoRecord).map(([k, v]) => [k, v]),
    )

    beforeEach(() => {
      when(mockKeyManager1.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager1Namespace)
          .map(keyArchiveInfoToKeyData),
      )
      when(mockKeyManager2.exportKeys()).thenResolve(
        keys
          .filter((key) => key.NameSpace === keyManager2Namespace)
          .map(keyArchiveInfoToKeyData),
      )
    })

    describe('without password', () => {
      it.each`
        name                  | withMetaInfo
        ${'with MetaInfo'}    | ${true}
        ${'without MetaInfo'} | ${false}
      `(
        'should produce an insecure archive $name',
        async ({ withMetaInfo }) => {
          const keyArchive = new DefaultSudoKeyArchive(
            [instance(mockKeyManager1), instance(mockKeyManager2)],
            { metaInfo: withMetaInfo ? metaInfo : undefined },
          )

          await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

          const archive = await keyArchive.archive(undefined)
          const unzipped = Gzip.decompress(archive)
          const string = BufferUtil.toString(unzipped)
          const deserialized = JSON.parse(string)
          const decoded = InsecureKeyArchiveCodec.decode(deserialized)
          expect(isRight(decoded)).toEqual(true)
          if (!isRight(decoded)) throw new Error('decoded unexpectedly lefty')
          const insecureKeyArchive = decoded.right
          expect(insecureKeyArchive).toMatchObject({
            Type: 'Insecure',
            Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
            MetaInfo: withMetaInfo ? metaInfoRecord : {},
          })
          expect(insecureKeyArchive.Keys).toHaveLength(keys.length)
          keys.forEach((key) =>
            expect(insecureKeyArchive.Keys).toContainEqual(key),
          )
        },
      )

      it.each`
        name                  | withMetaInfo
        ${'with MetaInfo'}    | ${true}
        ${'without MetaInfo'} | ${false}
      `(
        'should produce an insecure archive $name without compression',
        async ({ withMetaInfo }) => {
          const keyArchive = new DefaultSudoKeyArchive(
            [instance(mockKeyManager1), instance(mockKeyManager2)],
            { metaInfo: withMetaInfo ? metaInfo : undefined, zip: false },
          )

          when(
            mockKeyManager1.publicKeyInfoToRSAPublicKey(anything()),
          ).thenCall((publicKey: ArrayBuffer) => {
            return publicKey
          })
          when(
            mockKeyManager1.privateKeyInfoToRSAPrivateKey(anything()),
          ).thenCall((privateKey: ArrayBuffer) => {
            return privateKey
          })

          await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

          const archive = await keyArchive.archive(undefined)
          const string = BufferUtil.toString(archive)
          const deserialized = JSON.parse(string)
          const decoded = InsecureKeyArchiveV2Codec.decode(deserialized)
          expect(isRight(decoded)).toEqual(true)
          if (!isRight(decoded)) throw new Error('decoded unexpectedly lefty')
          const insecureKeyArchive = decoded.right
          expect(insecureKeyArchive).toMatchObject({
            Type: 'Insecure',
            Version: DefaultSudoKeyArchive.PREGZIP_ARCHIVE_VERSION,
            MetaInfo: withMetaInfo ? metaInfoRecord : {},
          })
          const keysData = Base64.decode(insecureKeyArchive.Keys)
          const keyList = JSON.parse(new TextDecoder().decode(keysData))
          expect(keyList).toHaveLength(keys.length)
          keys.forEach((key) => expect(keyList).toContainEqual(key))
        },
      )
    })

    describe('with password', () => {
      const encryptedKeys = BufferUtil.fromString('encrypted-keys')

      it.each`
        name                  | withMetaInfo
        ${'with MetaInfo'}    | ${true}
        ${'without MetaInfo'} | ${false}
      `(
        'should produce an insecure archive $name',
        async ({ withMetaInfo }) => {
          const keyArchive = new DefaultSudoKeyArchive(
            [instance(mockKeyManager1), instance(mockKeyManager2)],
            { metaInfo: withMetaInfo ? metaInfo : undefined },
          )

          await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

          when(mockKeyManager1.generateRandomData(anything())).thenResolve(
            salt,
            iv,
          )
          when(
            mockKeyManager1.generateSymmetricKeyFromPassword(
              anything(),
              anything(),
              anything(),
            ),
          ).thenResolve(symmetricKey)
          when(
            mockKeyManager1.encryptWithSymmetricKey(
              anything(),
              anything(),
              anything(),
            ),
          ).thenResolve(encryptedKeys)

          const archive = await keyArchive.archive(password)

          const unzipped = Gzip.decompress(archive)
          const string = BufferUtil.toString(unzipped)
          const deserialized = JSON.parse(string)
          const decoded = SecureKeyArchiveCodec.decode(deserialized)
          expect(isRight(decoded)).toEqual(true)
          if (!isRight(decoded)) throw new Error('decoded unexpectedly lefty')
          const secureKeyArchive = decoded.right
          expect(secureKeyArchive).toEqual({
            Type: 'Secure',
            Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
            IV: ivB64,
            Salt: saltB64,
            Rounds: SudoCryptoProviderDefaults.pbkdfRounds,
            Keys: Base64.encode(encryptedKeys),
            MetaInfo: withMetaInfo ? metaInfoRecord : {},
          })

          verify(mockKeyManager1.exportKeys()).once()
          verify(mockKeyManager2.exportKeys()).once()

          verify(mockKeyManager1.generateRandomData(anything())).twice()
          const [actualSaltSize] = capture(
            mockKeyManager1.generateRandomData,
          ).first()
          expect(actualSaltSize).toEqual(
            SudoCryptoProviderDefaults.pbkdfSaltSize,
          )
          const [actualIVSize] = capture(
            mockKeyManager1.generateRandomData,
          ).second()
          expect(actualIVSize).toEqual(SudoCryptoProviderDefaults.aesIVSize)

          verify(
            mockKeyManager1.generateSymmetricKeyFromPassword(
              anything(),
              anything(),
              anything(),
            ),
          ).once()
          const [actualPassword, actualSalt, actualOptions] = capture(
            mockKeyManager1.generateSymmetricKeyFromPassword,
          ).first()
          expect(actualPassword).toEqual(password)
          expect(actualSalt).toEqual(salt)
          expect(actualOptions).toEqual({
            rounds: SudoCryptoProviderDefaults.pbkdfRounds,
          })

          verify(
            mockKeyManager1.encryptWithSymmetricKey(
              anything(),
              anything(),
              anything(),
            ),
          ).once()
          const [actualKey, actualData, symmetricOptions] = capture(
            mockKeyManager1.encryptWithSymmetricKey,
          ).first()
          expect(actualKey).toEqual(symmetricKey)
          expect(symmetricOptions?.iv).toEqual(iv)

          const uncompressedData = Gzip.decompress(actualData)
          const deserializedData = JSON.parse(
            BufferUtil.toString(uncompressedData),
          )
          const decodedData = t
            .array(KeyArchiveKeyInfoCodec)
            .decode(deserializedData)
          expect(isRight(decodedData)).toEqual(true)
          if (isLeft(decodedData)) {
            throw new Error('decodedData unexpectedly lefty')
          }
          const actualKeys = decodedData.right
          expect(actualKeys).toHaveLength(keys.length)
          keys.forEach((key) => expect(actualKeys).toContainEqual(key))
        },
      )

      it.each`
        name                  | withMetaInfo
        ${'with MetaInfo'}    | ${true}
        ${'without MetaInfo'} | ${false}
      `(
        'should produce an insecure archive $name without compression',
        async ({ withMetaInfo }) => {
          const keyArchive = new DefaultSudoKeyArchive(
            [instance(mockKeyManager1), instance(mockKeyManager2)],
            { metaInfo: withMetaInfo ? metaInfo : undefined, zip: false },
          )

          when(
            mockKeyManager1.publicKeyInfoToRSAPublicKey(anything()),
          ).thenCall((publicKey: ArrayBuffer) => {
            return publicKey
          })
          when(
            mockKeyManager1.privateKeyInfoToRSAPrivateKey(anything()),
          ).thenCall((privateKey: ArrayBuffer) => {
            return privateKey
          })

          await expect(keyArchive.loadKeys()).resolves.toBeUndefined()

          when(mockKeyManager1.generateRandomData(anything())).thenResolve(
            salt,
            iv,
          )
          when(
            mockKeyManager1.generateSymmetricKeyFromPassword(
              anything(),
              anything(),
              anything(),
            ),
          ).thenResolve(symmetricKey)
          when(
            mockKeyManager1.encryptWithSymmetricKey(
              anything(),
              anything(),
              anything(),
            ),
          ).thenResolve(encryptedKeys)

          const archive = await keyArchive.archive(password)

          const string = BufferUtil.toString(archive)
          const deserialized = JSON.parse(string)
          const decoded = SecureKeyArchiveCodec.decode(deserialized)
          expect(isRight(decoded)).toEqual(true)
          if (!isRight(decoded)) throw new Error('decoded unexpectedly lefty')
          const secureKeyArchive = decoded.right
          expect(secureKeyArchive).toEqual({
            Type: 'Secure',
            Version: DefaultSudoKeyArchive.PREGZIP_ARCHIVE_VERSION,
            IV: ivB64,
            Salt: saltB64,
            Rounds: SudoCryptoProviderDefaults.pbkdfRounds,
            Keys: Base64.encode(encryptedKeys),
            MetaInfo: withMetaInfo ? metaInfoRecord : {},
          })

          verify(mockKeyManager1.exportKeys()).once()
          verify(mockKeyManager2.exportKeys()).once()

          verify(mockKeyManager1.generateRandomData(anything())).twice()
          const [actualSaltSize] = capture(
            mockKeyManager1.generateRandomData,
          ).first()
          expect(actualSaltSize).toEqual(
            SudoCryptoProviderDefaults.pbkdfSaltSize,
          )
          const [actualIVSize] = capture(
            mockKeyManager1.generateRandomData,
          ).second()
          expect(actualIVSize).toEqual(SudoCryptoProviderDefaults.aesIVSize)

          verify(
            mockKeyManager1.generateSymmetricKeyFromPassword(
              anything(),
              anything(),
              anything(),
            ),
          ).once()
          const [actualPassword, actualSalt, actualOptions] = capture(
            mockKeyManager1.generateSymmetricKeyFromPassword,
          ).first()
          expect(actualPassword).toEqual(password)
          expect(actualSalt).toEqual(salt)
          expect(actualOptions).toEqual({
            rounds: SudoCryptoProviderDefaults.pbkdfRounds,
          })

          verify(
            mockKeyManager1.encryptWithSymmetricKey(
              anything(),
              anything(),
              anything(),
            ),
          ).once()
          const [actualKey, actualData, symmetricOptions] = capture(
            mockKeyManager1.encryptWithSymmetricKey,
          ).first()
          expect(actualKey).toEqual(symmetricKey)
          expect(symmetricOptions?.iv).toEqual(iv)

          const uncompressedData = Gzip.decompress(actualData)
          const deserializedData = JSON.parse(
            BufferUtil.toString(uncompressedData),
          )
          const decodedData = t
            .array(KeyArchiveKeyInfoCodec)
            .decode(deserializedData)
          expect(isRight(decodedData)).toEqual(true)
          if (isLeft(decodedData)) {
            throw new Error('decodedData unexpectedly lefty')
          }
          const actualKeys = decodedData.right
          expect(actualKeys).toHaveLength(keys.length)
          keys.forEach((key) => expect(actualKeys).toContainEqual(key))
        },
      )
    })
  })

  describe('getKeyData', () => {
    it('should throw a KeyNotFoundError if archive does not contain requested key', () => {
      const insecureArchive: InsecureKeyArchive = {
        Type: 'Insecure',
        Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
        Keys: [],
        MetaInfo: {},
      }

      const keyArchive = new DefaultSudoKeyArchive(instance(mockKeyManager1), {
        archiveData: Gzip.compress(
          BufferUtil.fromString(JSON.stringify(insecureArchive)),
        ),
      })

      expect(() =>
        keyArchive.getKeyData(
          keyManager1Namespace,
          'not-found',
          KeyArchiveKeyType.Password,
        ),
      ).toThrowErrorMatching(new KeyNotFoundError())
    })

    it('should return keys from the archive', async () => {
      const insecureArchive: InsecureKeyArchive = {
        Type: 'Insecure',
        Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
        Keys: keys,
        MetaInfo: {},
      }

      const keyArchive = new DefaultSudoKeyArchive(instance(mockKeyManager1), {
        archiveData: Gzip.compress(
          BufferUtil.fromString(JSON.stringify(insecureArchive)),
        ),
      })

      await keyArchive.unarchive(undefined)

      keys.forEach((key) =>
        expect(
          keyArchive.getKeyData(key.NameSpace, key.Name, key.Type),
        ).toEqual(Base64.decode(key.Data)),
      )
    })
  })

  describe('reset', () => {
    it('should clear out keys from the archive', async () => {
      const insecureArchive: InsecureKeyArchive = {
        Type: 'Insecure',
        Version: DefaultSudoKeyArchive.CURRENT_ARCHIVE_VERSION,
        Keys: keys,
        MetaInfo: {},
      }

      const keyArchive = new DefaultSudoKeyArchive(instance(mockKeyManager1), {
        archiveData: Gzip.compress(
          BufferUtil.fromString(JSON.stringify(insecureArchive)),
        ),
      })

      await keyArchive.unarchive(undefined)

      keys.forEach((key) =>
        expect(
          keyArchive.containsKey(key.NameSpace, key.Name, key.Type),
        ).toEqual(true),
      )
      keyArchive.reset()
      keys.forEach((key) =>
        expect(
          keyArchive.containsKey(key.NameSpace, key.Name, key.Type),
        ).toEqual(false),
      )
    })
  })
})
