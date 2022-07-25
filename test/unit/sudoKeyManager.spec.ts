import {
  anything,
  capture,
  instance,
  mock,
  reset,
  verify,
  when,
} from 'ts-mockito'
import {
  KeyData,
  KeyDataKeyFormat,
  KeyDataKeyType,
} from '../../src/sudoKeyManager/keyData'
import { PublicKey, PublicKeyFormat } from '../../src/sudoKeyManager/publicKey'
import { SudoCryptoProvider } from '../../src/sudoKeyManager/sudoCryptoProvider'
import { DefaultSudoKeyManager } from '../../src/sudoKeyManager/sudoKeyManager'
import { EncryptionAlgorithm } from '../../src/types/types'
import { Buffer as BufferUtil } from '../../src/utils/buffer'

const sudoCryptoProviderMock: SudoCryptoProvider = mock()

const sudoKeyManager = new DefaultSudoKeyManager(
  instance(sudoCryptoProviderMock),
)

afterEach(() => {
  reset(sudoCryptoProviderMock)
})

describe('DefaultSudoKeyManager', () => {
  const encrypted = BufferUtil.fromString('encrypted')
  const iv = BufferUtil.fromString('iv')
  const salt = BufferUtil.fromString('salt')
  const decrypted = BufferUtil.fromString('decrypted')
  const symmetricKey = BufferUtil.fromString('14A9B3C3540142A11E70ACBB1BD8969F')
  const hash = BufferUtil.fromString('hash')
  const data = BufferUtil.fromString('data')
  const privateKey = BufferUtil.fromString('privateKey')
  const publicKey: PublicKey = {
    keyData: BufferUtil.fromString('publickey'),
    keyFormat: PublicKeyFormat.SPKI,
  }
  const password = BufferUtil.fromString('password')
  const serviceName = 'service-name'
  const namespace = 'name-space'

  beforeEach(() => {
    when(sudoCryptoProviderMock.getNamespace()).thenReturn(namespace)
  })

  describe('namespace', () => {
    it('calls provider correctly when accessing namespace', () => {
      when(sudoCryptoProviderMock.getNamespace()).thenReturn(namespace)

      expect(sudoKeyManager.namespace).toEqual(namespace)

      verify(sudoCryptoProviderMock.getNamespace()).once()
    })
  })

  describe('serviceName', () => {
    it('calls provider correctly when accessing service name', () => {
      when(sudoCryptoProviderMock.getServiceName()).thenReturn(serviceName)

      expect(sudoKeyManager.serviceName).toEqual(serviceName)

      verify(sudoCryptoProviderMock.getServiceName()).once()
    })
  })

  describe('addPassword', () => {
    it('calls provider correctly when adding password', async () => {
      when(
        sudoCryptoProviderMock.addPassword(anything(), anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.addPassword(password, 'VpnPassword'),
      ).resolves.toBeUndefined()
      const [actualPassword, actualKey] = capture(
        sudoCryptoProviderMock.addPassword,
      ).first()
      expect(actualPassword).toStrictEqual(password)
      expect(actualKey).toStrictEqual('VpnPassword')

      verify(sudoCryptoProviderMock.addPassword(anything(), anything())).once()
    })
  })

  describe('addSymmetricKey', () => {
    it('calls provider correctly when adding a symmetric key', async () => {
      when(
        sudoCryptoProviderMock.addSymmetricKey(anything(), anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.addSymmetricKey(symmetricKey, 'VpnSymmetric'),
      ).resolves.toBeUndefined()
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualKeyName).toStrictEqual('VpnSymmetric')

      verify(
        sudoCryptoProviderMock.addSymmetricKey(anything(), anything()),
      ).once()
    })
  })

  describe('getPassword', () => {
    it('should call crypto provider getPassword', async () => {
      when(sudoCryptoProviderMock.getPassword(anything())).thenResolve(password)

      await expect(sudoKeyManager.getPassword('VpnPassword')).resolves.toEqual(
        password,
      )

      const [actualKey] = capture(sudoCryptoProviderMock.getPassword).first()
      expect(actualKey).toStrictEqual('VpnPassword')

      verify(sudoCryptoProviderMock.getPassword(anything())).once()
    })
  })

  describe('deletePassword', () => {
    it('should call crypto provider deletePassword', async () => {
      when(sudoCryptoProviderMock.deletePassword(anything())).thenResolve()

      await expect(
        sudoKeyManager.deletePassword('VpnPassword'),
      ).resolves.toBeUndefined()
      const [actualKey] = capture(sudoCryptoProviderMock.deletePassword).first()
      expect(actualKey).toStrictEqual('VpnPassword')

      verify(sudoCryptoProviderMock.deletePassword(anything())).once()
    })
  })

  describe('updatePassword', () => {
    it('should call crypto provider updatePassword', async () => {
      when(
        sudoCryptoProviderMock.updatePassword(anything(), anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.updatePassword(password, 'VpnPassword'),
      ).resolves.toBeUndefined()
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.updatePassword,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnPassword')
      expect(actualKey).toStrictEqual(password)

      verify(
        sudoCryptoProviderMock.updatePassword(anything(), anything()),
      ).once()
    })
  })

  describe('getSymmetricKey', () => {
    it('should call crypto provider getSymmetricKey', async () => {
      when(sudoCryptoProviderMock.getSymmetricKey(anything())).thenResolve(
        symmetricKey,
      )

      await expect(sudoKeyManager.getSymmetricKey('VpnKey')).resolves.toEqual(
        symmetricKey,
      )
      const [actualKey] = capture(
        sudoCryptoProviderMock.getSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual('VpnKey')

      verify(sudoCryptoProviderMock.getSymmetricKey(anything())).once()
    })
  })

  describe('doesSymmetricKeyExist', () => {
    it('should call crypto provider doesSymmetricKeyExist', async () => {
      when(
        sudoCryptoProviderMock.doesSymmetricKeyExist(anything()),
      ).thenResolve(true)

      await expect(
        sudoKeyManager.doesSymmetricKeyExist('VpnKey'),
      ).resolves.toEqual(true)
      const [actualKey] = capture(
        sudoCryptoProviderMock.doesSymmetricKeyExist,
      ).first()
      expect(actualKey).toStrictEqual('VpnKey')

      verify(sudoCryptoProviderMock.doesSymmetricKeyExist(anything())).once()
    })
  })

  describe('deleteSymmetricKey', () => {
    it('should call crypto provider deleteSymmetricKey', async () => {
      when(sudoCryptoProviderMock.deleteSymmetricKey(anything())).thenResolve()

      await expect(
        sudoKeyManager.deleteSymmetricKey('VpnKey'),
      ).resolves.toBeUndefined()
      const [actualKey] = capture(
        sudoCryptoProviderMock.deleteSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual('VpnKey')

      verify(sudoCryptoProviderMock.deleteSymmetricKey(anything())).once()
    })
  })

  describe('generateKeyPair', () => {
    it('should call crypto provider generateKeyPair', async () => {
      when(sudoCryptoProviderMock.generateKeyPair(anything())).thenResolve()

      await expect(
        sudoKeyManager.generateKeyPair('VpnKeyPair'),
      ).resolves.toBeUndefined()
      const [actualKey] = capture(
        sudoCryptoProviderMock.generateKeyPair,
      ).first()
      expect(actualKey).toStrictEqual('VpnKeyPair')

      verify(sudoCryptoProviderMock.generateKeyPair(anything())).once()
    })
  })

  describe('deleteKeyPair', () => {
    it('should call crypto provider deleteKeyPair', async () => {
      when(sudoCryptoProviderMock.deleteKeyPair(anything())).thenResolve()

      await expect(
        sudoKeyManager.deleteKeyPair('KeyPair'),
      ).resolves.toBeUndefined()
      const [actualKey] = capture(sudoCryptoProviderMock.deleteKeyPair).first()
      expect(actualKey).toStrictEqual('KeyPair')

      verify(sudoCryptoProviderMock.deleteKeyPair(anything())).once()
    })
  })

  describe('addPrivateKey', () => {
    it('should call crypto provider addPrivateKey', async () => {
      when(
        sudoCryptoProviderMock.addPrivateKey(anything(), anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.addPrivateKey(privateKey, 'VpnKeyPair'),
      ).resolves.toBeUndefined()
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addPrivateKey,
      ).first()
      expect(actualKey).toStrictEqual(privateKey)
      expect(actualKeyName).toStrictEqual('VpnKeyPair')

      verify(
        sudoCryptoProviderMock.addPrivateKey(anything(), anything()),
      ).once()
    })
  })

  describe('getPrivateKey', () => {
    it('should call crypto provider getPrivateKey', async () => {
      when(sudoCryptoProviderMock.getPrivateKey(anything())).thenResolve(
        privateKey,
      )

      await expect(sudoKeyManager.getPrivateKey('VpnKeyPair')).resolves.toEqual(
        privateKey,
      )

      const [actualKeyName] = capture(
        sudoCryptoProviderMock.getPrivateKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKeyPair')

      verify(sudoCryptoProviderMock.getPrivateKey(anything())).once()
    })
  })

  describe('doesPrivateKeyExist', () => {
    it('should call crypto provider doesPrivateKeyExist', async () => {
      when(sudoCryptoProviderMock.doesPrivateKeyExist(anything())).thenResolve(
        true,
      )

      await expect(
        sudoKeyManager.doesPrivateKeyExist('VpnKeyPair'),
      ).resolves.toBeTruthy()

      const [actualKeyName] = capture(
        sudoCryptoProviderMock.doesPrivateKeyExist,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKeyPair')

      verify(sudoCryptoProviderMock.doesPrivateKeyExist(anything())).once()
    })
  })

  describe('addPublicKey', () => {
    it('should call crypto provider addPublicKey', async () => {
      when(
        sudoCryptoProviderMock.addPublicKey(anything(), anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.addPublicKey(publicKey.keyData, 'VpnKeyPair'),
      ).resolves.toBeUndefined()
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addPublicKey,
      ).first()
      expect(actualKey).toStrictEqual(publicKey.keyData)
      expect(actualKeyName).toStrictEqual('VpnKeyPair')

      verify(sudoCryptoProviderMock.addPublicKey(anything(), anything())).once()
    })
  })

  describe('getPublicKey', () => {
    it('should call crypto provider getPublicKey', async () => {
      when(sudoCryptoProviderMock.getPublicKey(anything())).thenResolve(
        publicKey,
      )

      await expect(sudoKeyManager.getPublicKey('VpnKeyPair')).resolves.toEqual(
        publicKey,
      )

      const [actualKeyName] = capture(
        sudoCryptoProviderMock.getPublicKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKeyPair')

      verify(sudoCryptoProviderMock.getPublicKey(anything())).once()
    })
  })

  describe('removeAllKeys', () => {
    it('should call crypto provider removeAllKeys', async () => {
      when(sudoCryptoProviderMock.removeAllKeys()).thenResolve()
      await sudoKeyManager.removeAllKeys()
      verify(sudoCryptoProviderMock.removeAllKeys()).once()
    })
  })

  describe('encryptWithSymmetricKeyName', () => {
    it('should call crypto provider encryptWithSymmetricKeyName without iv or algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(encrypted)

      await sudoKeyManager.encryptWithSymmetricKeyName('VpnKey', decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(decrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider encryptWithSymmetricKeyName with iv and no algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(encrypted)

      await sudoKeyManager.encryptWithSymmetricKeyName('VpnKey', decrypted, {
        iv,
      })

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(decrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(iv)
      expect(actualOptions!.algorithm).toBeUndefined()

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider encryptWithSymmetricKeyName with iv and algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(encrypted)

      const options = {
        iv,
        algorithm: EncryptionAlgorithm.AesCbcPkcs7Padding,
      }
      await sudoKeyManager.encryptWithSymmetricKeyName(
        'VpnKey',
        decrypted,
        options,
      )

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(decrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(options.iv)
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('encryptWithSymmetricKey', () => {
    it('should call crypto provider encryptWithSymmetricKey without iv or algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      await expect(
        sudoKeyManager.encryptWithSymmetricKey(symmetricKey, encrypted),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider encryptWithSymmetricKey with iv and no algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      await expect(
        sudoKeyManager.encryptWithSymmetricKey(symmetricKey, encrypted, { iv }),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(iv)
      expect(actualOptions!.algorithm).toBeUndefined()

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider encryptWithSymmetricKey with algorithm and no iv', async () => {
      when(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        algorithm: EncryptionAlgorithm.AesCbcPkcs7Padding,
      }
      await expect(
        sudoKeyManager.encryptWithSymmetricKey(
          symmetricKey,
          encrypted,
          options,
        ),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toBeUndefined()
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('decryptWithSymmetricKeyName', () => {
    it('should call crypto provider decryptWithSymmetricKeyName without iv and algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      await expect(
        sudoKeyManager.decryptWithSymmetricKeyName('VpnKey', encrypted),
      ).resolves.toEqual(decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider decryptWithSymmetricKeyName with iv and no algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        iv,
      }
      await expect(
        sudoKeyManager.decryptWithSymmetricKeyName(
          'VpnKey',
          encrypted,
          options,
        ),
      ).resolves.toEqual(decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(options.iv)
      expect(actualOptions!.algorithm).toBeUndefined()

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider decryptWithSymmetricKeyName with iv and algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        iv,
        algorithm: EncryptionAlgorithm.AesCbcPkcs7Padding,
      }
      await expect(
        sudoKeyManager.decryptWithSymmetricKeyName(
          'VpnKey',
          encrypted,
          options,
        ),
      ).resolves.toEqual(decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(options.iv)
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('decryptWithSymmetricKey', () => {
    it('should call crypto provider decryptWithSymmetricKey without iv or algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      await expect(
        sudoKeyManager.decryptWithSymmetricKey(symmetricKey, encrypted),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider decryptWithSymmetricKey with iv and no algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        iv,
      }
      await expect(
        sudoKeyManager.decryptWithSymmetricKey(
          symmetricKey,
          encrypted,
          options,
        ),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(iv)
      expect(actualOptions!.algorithm).toBeUndefined()

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider decryptWithSymmetricKey with iv and algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        iv,
        algorithm: EncryptionAlgorithm.AesCbcPkcs7Padding,
      }
      await expect(
        sudoKeyManager.decryptWithSymmetricKey(
          symmetricKey,
          encrypted,
          options,
        ),
      ).resolves.toEqual(decrypted)

      const [actualKey, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.iv).toStrictEqual(iv)
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('encryptWithPublicKey', () => {
    it('should call crypto provider encryptWithPublicKey', async () => {
      when(
        sudoCryptoProviderMock.encryptWithPublicKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(encrypted)

      await expect(
        sudoKeyManager.encryptWithPublicKey('VpnKey', decrypted),
      ).resolves.toEqual(encrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithPublicKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(decrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.encryptWithPublicKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider encryptWithPublicKey with algorithm', async () => {
      when(
        sudoCryptoProviderMock.encryptWithPublicKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(encrypted)

      const options = {
        algorithm: EncryptionAlgorithm.RsaOaepSha1,
      }
      await expect(
        sudoKeyManager.encryptWithPublicKey('VpnKey', decrypted, options),
      ).resolves.toEqual(encrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.encryptWithPublicKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(decrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.encryptWithPublicKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('decryptWithPrivateKey', () => {
    it('should call crypto provider decryptWithPrivateKey', async () => {
      when(
        sudoCryptoProviderMock.decryptWithPrivateKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      await expect(
        sudoKeyManager.decryptWithPrivateKey('VpnKey', encrypted),
      ).resolves.toEqual(decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithPrivateKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.decryptWithPrivateKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })

    it('should call crypto provider decryptWithPrivateKey with algorithm', async () => {
      when(
        sudoCryptoProviderMock.decryptWithPrivateKey(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(decrypted)

      const options = {
        algorithm: EncryptionAlgorithm.RsaOaepSha1,
      }
      await expect(
        sudoKeyManager.decryptWithPrivateKey('VpnKey', encrypted, options),
      ).resolves.toEqual(decrypted)

      const [actualKeyName, actualData, actualOptions] = capture(
        sudoCryptoProviderMock.decryptWithPrivateKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(encrypted)
      expect(actualOptions).toBeDefined()
      expect(actualOptions!.algorithm).toStrictEqual(options.algorithm)

      verify(
        sudoCryptoProviderMock.decryptWithPrivateKey(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('generateSymmetricKey', () => {
    it('should call crypto provider generateSymmetricKey', async () => {
      when(
        sudoCryptoProviderMock.generateSymmetricKey(anything()),
      ).thenResolve()

      await expect(
        sudoKeyManager.generateSymmetricKey('VpnKey'),
      ).resolves.toBeUndefined()

      const [actualKeyName] = capture(
        sudoCryptoProviderMock.generateSymmetricKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')

      verify(sudoCryptoProviderMock.generateSymmetricKey(anything())).once()
    })
  })

  describe('generateSymmetricKeyFromPassword', () => {
    it('should call crypto provider generateSymmetricKeyFromPassword without options', async () => {
      when(
        sudoCryptoProviderMock.generateSymmetricKeyFromPassword(
          anything(),
          anything(),
          anything(),
        ),
      ).thenResolve(symmetricKey)

      await expect(
        sudoKeyManager.generateSymmetricKeyFromPassword(password, salt),
      ).resolves.toEqual(symmetricKey)

      const [actualPassword, actualSalt, actualOptions] = capture(
        sudoCryptoProviderMock.generateSymmetricKeyFromPassword,
      ).first()
      expect(actualPassword).toStrictEqual(password)
      expect(actualSalt).toStrictEqual(salt)
      expect(actualOptions).toBeUndefined()

      verify(
        sudoCryptoProviderMock.generateSymmetricKeyFromPassword(
          anything(),
          anything(),
          anything(),
        ),
      ).once()
    })
  })

  describe('generateHash', () => {
    it('should call crypto provider generateHash', async () => {
      when(sudoCryptoProviderMock.generateHash(anything())).thenResolve(hash)

      await expect(sudoKeyManager.generateHash(data)).resolves.toEqual(hash)

      const [actualData] = capture(sudoCryptoProviderMock.generateHash).first()
      expect(actualData).toStrictEqual(data)

      verify(sudoCryptoProviderMock.generateHash(anything())).once()
    })
  })

  describe('generateRandomData', () => {
    it('should call crypto provider generateRandomData', async () => {
      when(sudoCryptoProviderMock.generateRandomData(anything())).thenResolve(
        new Uint8Array(),
      )

      const size = 100
      await sudoKeyManager.generateRandomData(size)

      const [actualSize] = capture(
        sudoCryptoProviderMock.generateRandomData,
      ).first()
      expect(actualSize).toStrictEqual(size)

      verify(sudoCryptoProviderMock.generateRandomData(anything())).once()
    })
  })

  describe('exportKeys', () => {
    const keyData: KeyData[] = [
      {
        name: 'password',
        type: KeyDataKeyType.Password,
        data: password,
        namespace,
        format: KeyDataKeyFormat.Raw,
      },
      {
        name: 'symmetric',
        type: KeyDataKeyType.SymmetricKey,
        data: symmetricKey,
        namespace,
        format: KeyDataKeyFormat.Raw,
      },
      {
        name: 'private',
        type: KeyDataKeyType.RSAPrivateKey,
        data: privateKey,
        namespace,
        format: KeyDataKeyFormat.PKCS8,
      },
      {
        name: 'public',
        type: KeyDataKeyType.RSAPublicKey,
        data: publicKey.keyData,
        namespace,
        format: KeyDataKeyFormat.SPKI,
      },
    ]

    const exportedKeyData: KeyData[] = [
      {
        name: 'password',
        type: KeyDataKeyType.Password,
        data: password,
        namespace,
        format: KeyDataKeyFormat.Raw,
      },
      {
        name: 'symmetric',
        type: KeyDataKeyType.SymmetricKey,
        data: symmetricKey,
        namespace,
        format: KeyDataKeyFormat.Raw,
      },
      {
        name: 'private',
        type: KeyDataKeyType.RSAPrivateKey,
        data: privateKey,
        namespace,
        format: KeyDataKeyFormat.PKCS8,
      },
      {
        name: 'public',
        type: KeyDataKeyType.RSAPublicKey,
        data: publicKey.keyData,
        namespace,
        format: KeyDataKeyFormat.SPKI,
      },
    ]

    it('should call crypto provider exportKeys', async () => {
      when(sudoCryptoProviderMock.exportKeys()).thenResolve(keyData)

      const actualExportedKeyData = await sudoKeyManager.exportKeys()

      expect(actualExportedKeyData).toHaveLength(exportedKeyData.length)
      actualExportedKeyData.forEach((k) =>
        expect(exportedKeyData).toContainEqual(k),
      )
    })
  })
})
