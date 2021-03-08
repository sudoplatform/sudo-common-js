import { DefaultSudoKeyManager } from './sudoKeyManager'
import { mock, instance, verify, reset } from 'ts-mockito'
import { SudoCryptoProvider } from './sudoCryptoProvider'

const sudoCryptoProviderMock: SudoCryptoProvider = mock()

const sudoKeyManager = new DefaultSudoKeyManager(
  'randomNamespace',
  instance(sudoCryptoProviderMock),
)

afterEach(() => {
  reset(sudoCryptoProviderMock)
})

describe('DefaultSudoKeyManager', () => {
  describe('addPassword', () => {
    it('should format namespace of key correctly when adding password', async () => {
      const password = new TextEncoder().encode('am@z1ing')

      await sudoKeyManager.addPassword(password, 'VpnPassword')

      verify(
        sudoCryptoProviderMock.addPassword(
          password,
          'randomNamespace.VpnPassword.password',
        ),
      ).called()
    })
  })

  describe('addSymmetricKey', () => {
    it('should format namespace of key correctly when adding a symmetric key', async () => {
      const symmetricKey = new TextEncoder().encode(
        '14A9B3C3540142A11E70ACBB1BD8969F',
      )

      await sudoKeyManager.addSymmetricKey(symmetricKey, 'VpnSymmetric')

      verify(
        sudoCryptoProviderMock.addSymmetricKey(
          symmetricKey,
          'randomNamespace.VpnSymmetric.symmetric',
        ),
      ).called()
    })
  })

  describe('getPassword', () => {
    it('should call crypto provider getPassword', async () => {
      await sudoKeyManager.getPassword('VpnPassword')
      verify(
        sudoCryptoProviderMock.getPassword(
          'randomNamespace.VpnPassword.password',
        ),
      ).called()
    })
  })

  describe('deletePassword', () => {
    it('should call crypto provider deletePassword', async () => {
      await sudoKeyManager.deletePassword('VpnPassword')
      verify(
        sudoCryptoProviderMock.deletePassword(
          'randomNamespace.VpnPassword.password',
        ),
      ).called()
    })
  })

  describe('updatePassword', () => {
    it('should call crypto provider updatePassword', async () => {
      const newPassword = new TextEncoder().encode('newPassword')
      await sudoKeyManager.updatePassword(newPassword, 'VpnPassword')
      verify(
        sudoCryptoProviderMock.updatePassword(
          newPassword,
          'randomNamespace.VpnPassword.password',
        ),
      ).called()
    })
  })

  describe('getSymmetricKey', () => {
    it('should call crypto provider getSymmetricKey', async () => {
      await sudoKeyManager.getSymmetricKey('VpnKey')
      verify(
        sudoCryptoProviderMock.getSymmetricKey(
          'randomNamespace.VpnKey.symmetric',
        ),
      ).called()
    })
  })

  describe('deleteSymmetricKey', () => {
    it('should call crypto provider deleteSymmetricKey', async () => {
      await sudoKeyManager.deleteSymmetricKey('VpnKey')
      verify(
        sudoCryptoProviderMock.deleteSymmetricKey(
          'randomNamespace.VpnKey.symmetric',
        ),
      ).called()
    })
  })

  describe('generateKeyPair', () => {
    it('should call crypto provider generateKeyPair', async () => {
      await sudoKeyManager.generateKeyPair('VpnKeyPair')
      verify(
        sudoCryptoProviderMock.generateKeyPair(
          'randomNamespace.VpnKeyPair.keyPair',
        ),
      ).called()
    })
  })

  describe('addPrivateKey', () => {
    it('should call crypto provider addPrivateKey', async () => {
      const privateKey = new TextEncoder().encode('')
      await sudoKeyManager.addPrivateKey(privateKey, 'VpnKeyPair')
      verify(
        sudoCryptoProviderMock.addPrivateKey(
          privateKey,
          'randomNamespace.VpnKeyPair.keyPair',
        ),
      ).called()
    })
  })

  describe('getPrivateKey', () => {
    it('should call crypto provider getPrivateKey', async () => {
      await sudoKeyManager.getPrivateKey('VpnKeyPair')
      verify(
        sudoCryptoProviderMock.getPrivateKey(
          'randomNamespace.VpnKeyPair.keyPair',
        ),
      ).called()
    })
  })

  describe('addPublicKey', () => {
    it('should call crypto provider addPublicKey', async () => {
      const publicKey = new TextEncoder().encode('')
      await sudoKeyManager.addPublicKey(publicKey, 'VpnKeyPair')
      verify(
        sudoCryptoProviderMock.addPublicKey(
          publicKey,
          'randomNamespace.VpnKeyPair.keyPair',
        ),
      ).called()
    })
  })

  describe('getPublicKey', () => {
    it('should call crypto provider getPublicKey', async () => {
      await sudoKeyManager.getPublicKey('VpnKeyPair')
      verify(
        sudoCryptoProviderMock.getPublicKey(
          'randomNamespace.VpnKeyPair.keyPair',
        ),
      ).called()
    })
  })

  describe('removeAllKeys', () => {
    it('should call crypto provider removeAllKeys', async () => {
      await sudoKeyManager.removeAllKeys()
      verify(sudoCryptoProviderMock.removeAllKeys()).called()
    })
  })

  describe('encryptWithSymmetricKey', () => {
    it('should call crypto provider encryptWithSymmetricKey', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.encryptWithSymmetricKey('VpnKey', key)
      verify(
        sudoCryptoProviderMock.encryptWithSymmetricKey(
          'randomNamespace.VpnKey.symmetric',
          key,
          undefined,
        ),
      ).called()
    })
  })

  describe('decryptWithSymmetricKeyName', () => {
    it('should call crypto provider decryptWithSymmetricKeyName', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.decryptWithSymmetricKeyName('VpnKey', key)
      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKeyName(
          'randomNamespace.VpnKey.symmetric',
          key,
          undefined,
        ),
      ).called()
    })
  })

  describe('decryptWithSymmetricKey', () => {
    it('should call crypto provider decryptWithSymmetricKey', async () => {
      const symmetricKey = new TextEncoder().encode(
        '14A9B3C3540142A11E70ACBB1BD8969F',
      )
      const data = new ArrayBuffer(8)

      await sudoKeyManager.decryptWithSymmetricKey(symmetricKey, data)
      verify(
        sudoCryptoProviderMock.decryptWithSymmetricKey(
          symmetricKey,
          data,
          undefined,
        ),
      ).called()
    })
  })

  describe('encryptWithPublicKey', () => {
    it('should call crypto provider encryptWithPublicKey', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.encryptWithPublicKey('VpnKey', key)
      verify(
        sudoCryptoProviderMock.encryptWithPublicKey(
          'randomNamespace.VpnKey.keyPair',
          key,
        ),
      ).called()
    })
  })

  describe('decryptWithPrivateKey', () => {
    it('should call crypto provider decryptWithPrivateKey', async () => {
      const key = new TextEncoder().encode('')
      await sudoKeyManager.decryptWithPrivateKey('VpnKey', key)
      verify(
        sudoCryptoProviderMock.decryptWithPrivateKey(
          'randomNamespace.VpnKey.keyPair',
          key,
        ),
      ).called()
    })
  })

  describe('generateSymmetricKey', () => {
    it('should call crypto provider generateSymmetricKey', async () => {
      await sudoKeyManager.generateSymmetricKey('VpnKey')
      verify(
        sudoCryptoProviderMock.generateSymmetricKey(
          'randomNamespace.VpnKey.symmetric',
        ),
      ).called()
    })
  })

  describe('generateHash', () => {
    it('should call crypto provider generateHash', async () => {
      const data = new TextEncoder().encode('')
      await sudoKeyManager.generateHash(data)
      verify(sudoCryptoProviderMock.generateHash(data)).called()
    })
  })
})
