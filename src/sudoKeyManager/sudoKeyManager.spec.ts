import { DefaultSudoKeyManager } from './sudoKeyManager'
import { mock, instance, reset, capture, when, verify } from 'ts-mockito'
import { SudoCryptoProvider } from './sudoCryptoProvider'

const sudoCryptoProviderMock: SudoCryptoProvider = mock()

const sudoKeyManager = new DefaultSudoKeyManager(
  instance(sudoCryptoProviderMock),
)

beforeEach(() => {
  when(sudoCryptoProviderMock.getNamespace()).thenReturn('randomNamespace')
})

afterEach(() => {
  reset(sudoCryptoProviderMock)
})

describe('DefaultSudoKeyManager', () => {
  describe('addPassword', () => {
    it('calls provider correctly when adding password', async () => {
      const password = new TextEncoder().encode('am@z1ing')

      await sudoKeyManager.addPassword(password, 'VpnPassword')
      const [actualPassword, actualKey] = capture(
        sudoCryptoProviderMock.addPassword,
      ).first()
      expect(actualPassword).toStrictEqual(password)
      expect(actualKey).toStrictEqual('VpnPassword')
    })
  })

  describe('addSymmetricKey', () => {
    it('calls provider correctly when adding a symmetric key', async () => {
      const symmetricKey = new TextEncoder().encode(
        '14A9B3C3540142A11E70ACBB1BD8969F',
      )
      await sudoKeyManager.addSymmetricKey(symmetricKey, 'VpnSymmetric')
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualKeyName).toStrictEqual('VpnSymmetric')
    })
  })

  describe('getPassword', () => {
    it('should call crypto provider getPassword', async () => {
      await sudoKeyManager.getPassword('VpnPassword')
      const [actualKey] = capture(sudoCryptoProviderMock.getPassword).first()
      expect(actualKey).toStrictEqual('VpnPassword')
    })
  })

  describe('deletePassword', () => {
    it('should call crypto provider deletePassword', async () => {
      await sudoKeyManager.deletePassword('VpnPassword')
      const [actualKey] = capture(sudoCryptoProviderMock.deletePassword).first()
      expect(actualKey).toStrictEqual('VpnPassword')
    })
  })

  describe('updatePassword', () => {
    it('should call crypto provider updatePassword', async () => {
      const newPassword = new TextEncoder().encode('newPassword')
      await sudoKeyManager.updatePassword(newPassword, 'VpnPassword')
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.updatePassword,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnPassword')
      expect(actualKey).toStrictEqual(newPassword)
    })
  })

  describe('getSymmetricKey', () => {
    it('should call crypto provider getSymmetricKey', async () => {
      await sudoKeyManager.getSymmetricKey('VpnKey')
      const [actualKey] = capture(
        sudoCryptoProviderMock.getSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual('VpnKey')
    })
  })

  describe('deleteSymmetricKey', () => {
    it('should call crypto provider deleteSymmetricKey', async () => {
      await sudoKeyManager.deleteSymmetricKey('VpnKey')
      const [actualKey] = capture(
        sudoCryptoProviderMock.deleteSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual('VpnKey')
    })
  })

  describe('generateKeyPair', () => {
    it('should call crypto provider generateKeyPair', async () => {
      await sudoKeyManager.generateKeyPair('VpnKeyPair')
      const [actualKey] = capture(
        sudoCryptoProviderMock.generateKeyPair,
      ).first()
      expect(actualKey).toStrictEqual('VpnKeyPair')
    })
  })

  describe('addPrivateKey', () => {
    it('should call crypto provider addPrivateKey', async () => {
      const privateKey = new TextEncoder().encode('')
      await sudoKeyManager.addPrivateKey(privateKey, 'VpnKeyPair')
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addPrivateKey,
      ).first()
      expect(actualKey).toStrictEqual(privateKey)
      expect(actualKeyName).toStrictEqual('VpnKeyPair')
    })
  })

  describe('getPrivateKey', () => {
    it('should call crypto provider getPrivateKey', async () => {
      await sudoKeyManager.getPrivateKey('VpnKeyPair')
      const [actualKeyName] = capture(
        sudoCryptoProviderMock.getPrivateKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKeyPair')
    })
  })

  describe('addPublicKey', () => {
    it('should call crypto provider addPublicKey', async () => {
      const publicKey = new TextEncoder().encode('')
      await sudoKeyManager.addPublicKey(publicKey, 'VpnKeyPair')
      const [actualKey, actualKeyName] = capture(
        sudoCryptoProviderMock.addPublicKey,
      ).first()
      expect(actualKey).toStrictEqual(publicKey)
      expect(actualKeyName).toStrictEqual('VpnKeyPair')
    })
  })

  describe('getPublicKey', () => {
    it('should call crypto provider getPublicKey', async () => {
      await sudoKeyManager.getPublicKey('VpnKeyPair')
      const [actualKeyName] = capture(
        sudoCryptoProviderMock.getPublicKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKeyPair')
    })
  })

  describe('removeAllKeys', () => {
    it('should call crypto provider removeAllKeys', async () => {
      await sudoKeyManager.removeAllKeys()
      verify(sudoCryptoProviderMock.removeAllKeys()).called()
    })
  })

  describe('encryptWithSymmetricKeyName', () => {
    it('should call crypto provider encryptWithSymmetricKeyName', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.encryptWithSymmetricKeyName('VpnKey', key)
      const [actualKeyName, actualKey] = capture(
        sudoCryptoProviderMock.encryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualKey).toStrictEqual(key)
    })
  })

  describe('decryptWithSymmetricKeyName', () => {
    it('should call crypto provider decryptWithSymmetricKeyName', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.decryptWithSymmetricKeyName('VpnKey', key)
      const [actualKeyName, actualKey] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualKey).toStrictEqual(key)
    })
  })

  describe('decryptWithSymmetricKey', () => {
    it('should call crypto provider decryptWithSymmetricKey', async () => {
      const symmetricKey = new TextEncoder().encode(
        '14A9B3C3540142A11E70ACBB1BD8969F',
      )
      const data = new ArrayBuffer(8)

      await sudoKeyManager.decryptWithSymmetricKey(symmetricKey, data)
      const [actualKey, actualData] = capture(
        sudoCryptoProviderMock.decryptWithSymmetricKey,
      ).first()
      expect(actualKey).toStrictEqual(symmetricKey)
      expect(actualData).toStrictEqual(data)
    })
  })

  describe('encryptWithPublicKey', () => {
    it('should call crypto provider encryptWithPublicKey', async () => {
      const data = new TextEncoder().encode('data')
      await sudoKeyManager.encryptWithPublicKey('VpnKey', data)
      const [actualKeyName, actualData] = capture(
        sudoCryptoProviderMock.encryptWithPublicKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(data)
    })
  })

  describe('decryptWithPrivateKey', () => {
    it('should call crypto provider decryptWithPrivateKey', async () => {
      const data = new TextEncoder().encode('')
      await sudoKeyManager.decryptWithPrivateKey('VpnKey', data)
      const [actualKeyName, actualData] = capture(
        sudoCryptoProviderMock.decryptWithPrivateKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
      expect(actualData).toStrictEqual(data)
    })
  })

  describe('generateSymmetricKey', () => {
    it('should call crypto provider generateSymmetricKey', async () => {
      await sudoKeyManager.generateSymmetricKey('VpnKey')
      const [actualKeyName] = capture(
        sudoCryptoProviderMock.generateSymmetricKey,
      ).first()
      expect(actualKeyName).toStrictEqual('VpnKey')
    })
  })

  describe('generateHash', () => {
    it('should call crypto provider generateHash', async () => {
      const data = new TextEncoder().encode('')
      await sudoKeyManager.generateHash(data)
      const [actualData] = capture(sudoCryptoProviderMock.generateHash).first()
      expect(actualData).toStrictEqual(data)
    })
  })
})
