import { Buffer as BufferUtil } from '../utils/buffer'
import { KeyData } from './keyData'
import { PublicKey } from './publicKey'
import {
  AsymmetricEncryptionOptions,
  SudoCryptoProvider,
  SymmetricEncryptionOptions,
} from './sudoCryptoProvider'

/**
 * Interface for a set of methods for securely storing keys and performing
 * cryptographic operations.
 */
export interface SudoKeyManager {
  readonly namespace: string
  readonly serviceName: string
  /**
   * Adds as password to the secure store.
   *
   * @param password
   * @param name
   */
  addPassword(password: ArrayBuffer, name: string): Promise<void>

  /**
   * Retrieves a password from the secure store.
   *
   * @param name The name of the password to retrieve
   *
   * @returns The password or undefined if the password was not found.
   */
  getPassword(name: string): Promise<ArrayBuffer | undefined>

  /**
   * Deletes a password from the secure store.
   *
   * @param name
   */
  deletePassword(name: string): Promise<void>

  /**
   * Updates a password stored in the secure store.
   *
   * @param password
   * @param name
   */
  updatePassword(password: ArrayBuffer, name: string): Promise<void>

  /**
   * Adds a symmetric key to the secure store.
   *
   * @param key The symmetric key.
   * @param name The name for the symmetric key.
   */
  addSymmetricKey(key: ArrayBuffer, name: string): Promise<void>

  /**
   * Retrieves a symmetric key from the secure store.
   *
   * @param name The name of the symmetric key.
   *
   * @returns The symmetric key or undefined if not found.
   */
  getSymmetricKey(name: string): Promise<ArrayBuffer | undefined>

  /**
   * Checks to see if the specified symmetric key exists.
   *
   * @param name The name of the symmetric key.
   */
  doesSymmetricKeyExist(name: string): Promise<boolean>

  /**
   * Deletes a symmetric key from the secure store.
   *
   * @param name The name of the symmetric key.
   */
  deleteSymmetricKey(name: string): Promise<void>

  /**
   * Adds a private key to the secure store.
   *
   * @param key The private key to store securely.
   * @param name The name of the private key to be stored.
   */
  addPrivateKey(key: ArrayBuffer, name: string): Promise<void>

  /**
   * Retrieves a private key from the secure store.
   *
   * @param name The name of the private key to be retrieved.
   *
   * @returns Requested private key or undefined if the key was not found.
   */
  getPrivateKey(name: string): Promise<ArrayBuffer | undefined>

  /**
   * Checks to see if the specified private key exists.
   *
   * @param name The name of the private key.
   */
  doesPrivateKeyExist(name: string): Promise<boolean>

  /**
   * Adds a public key to the secure store.
   *
   * The format of the public key should be SubjectPublicKeyInfo (spki)
   *
   * @param key The public key to store securely.
   * @param name The name of the public key to be stored.
   */
  addPublicKey(key: ArrayBuffer, name: string): Promise<void>

  /**
   * Deletes the specified public key from the secure store.
   *
   * @param name The name of the public key to be removed.
   */
  deletePublicKey(name: string): Promise<void>

  /**
   * Retrieves the public key from the secure store.
   *
   * The format of the public key is SubjectPublicKeyInfo (spki)
   *
   * @param name The name of the public key.
   *
   * @returns The public key or undefined if the key was not found.
   */
  getPublicKey(name: string): Promise<PublicKey | undefined>

  /**
   * Deletes a key pair from the secure store.
   *
   * @param name The name of the key pair to be deleted.
   */
  deleteKeyPair(name: string): Promise<void>

  /**
   * Generates a signature for the given data with the specified private key.
   *
   * @param name The name of the private key to use for generation.
   * @param data The data to sign.
   *
   * @returns Data signature or undefined if the private key is not found.
   */
  generateSignatureWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Verifies the given data against the provided signature using the specified public key.
   *
   * @param name The name of the public key to use for validation.
   * @param data The data to verify
   * @param signature The signature to verify against
   *
   * @returns True if the data and signature could be successfully verified
   */
  verifySignatureWithPublicKey(
    name: string,
    data: ArrayBuffer,
    signature: ArrayBuffer,
  ): Promise<boolean>

  /**
   * @deprecated Use version with `options` param.
   *
   * Encrypts the given data with the specified key
   *
   * @param name The name of the symmetric key to use to encrypt.
   * @param data Data to encrypt.
   * @param iv Optional Initialization Vector.
   *
   * @returns Encrypted data and IV
   */
  encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Encrypts the given data with the specified key
   *
   * @param name The name of the symmetric key to use to encrypt.
   * @param data Data to encrypt.
   *
   * @returns Encrypted data and IV
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    options?: SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  /**
   * @deprecated Use version with `options` param.
   *
   * Decrypt the given data with the given symmetric key
   *
   * @param key The symmetric key to use to decrypt the data.
   * @param encryptedData The encrypted data.
   * @param iv Optional Initialization Vector.
   *
   * @returns Decrypted data
   */
  decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Decrypt the given data with the given symmetric key
   *
   * @param key The symmetric key to use to decrypt the data.
   * @param encryptedData The encrypted data.
   *
   * @returns Decrypted data
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    options?: SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  /**
   * @deprecated Use version with `options` param.
   *
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
   * @param iv Optional Initialization Vector.
   *
   * @returns Decrypted data
   */
  encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
   *
   * @returns Decrypted data
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    options?: SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  /**
   * @deprecated Use version with `options` param.
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
   * @param iv Optional Initialization Vector.
   *
   * @returns Decrypted data
   */
  decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
   *
   * @returns Decrypted data
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    options?: SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  /**
   * Encrypts the given data with the specified public key.
   *
   * @param name The name of the public key to use for encryption.
   * @param data The data to encrypt.
   *
   * @returns Encrypted data
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  /**
   * Decrypts the given data with the specified private key.
   *
   * @param name The name of the private key to use for decryption.
   * @param data The data to decrypt.
   *
   * @returns Decrypted data or undefined if the private key is not found.
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer | undefined>

  /**
   * Remove all keys associated with this `SudoKeyManager`
   */
  removeAllKeys(): Promise<void>

  /**
   * Generates and securely stores a symmetric key.
   *
   * @param name The name of the symmetric key.
   */
  generateSymmetricKey(name: string): Promise<void>

  /**
   * Generates a symmetric key, derived from a password using PBKDF2.
   *
   * @param name The name to store the symmetric key as
   * @param password The password from which to generate the symmetric key
   * @param salt Salt to use in generation of the key
   * @param rounds The number of rounds of PBKDF2 to perform. Default: per getDefaultPBKDF2Rounds
   *
   * @returns The generated symmetric key.
   */
  generateSymmetricKeyFromPassword(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    options?: { rounds?: number },
  ): Promise<ArrayBuffer>

  /**
   * Generate random bytes using a secure random number generator.
   *
   * @param size Number of random bytes to generate
   *
   * @returns ArrayBuffer containing the random bytes.
   */
  generateRandomData(size: number): Promise<ArrayBuffer>

  /**
   * Creates a SHA256 hash of the specified data.
   *
   * @param data Data to hash.
   */
  generateHash(data: ArrayBuffer): Promise<ArrayBuffer>

  /**
   * Generates and securely stores a key pair for public key cryptography.
   *
   * The public key is exported as `SubjectPublicKeyInfo (spki)
   * The private key is exported as `pkcs8`
   *
   * @param name The name of the key pair to be generated.
   */
  generateKeyPair(name: string): Promise<void>

  /**
   * Export all contents of the key manager as an array of KeyArchiveKeyInfo
   * ready for archive.
   */
  exportKeys(): Promise<KeyData[]>
}

export class DefaultSudoKeyManager implements SudoKeyManager {
  /**
   * @param namespace A namespace to use as part of the key name.  If a namespace is specified then
   * a unique identifier for each key will be `<namespace>.<keyName>`. Namespace cannot be an empty string.
   * @param sudoCryptoProvider
   */
  constructor(private readonly sudoCryptoProvider: SudoCryptoProvider) {}

  public get serviceName(): string {
    return this.sudoCryptoProvider.getServiceName()
  }

  public get namespace(): string {
    return this.sudoCryptoProvider.getNamespace()
  }

  public addPassword(password: ArrayBuffer, name: string): Promise<void> {
    return this.sudoCryptoProvider.addPassword(password, name)
  }

  public getPassword(name: string): Promise<ArrayBuffer | undefined> {
    return this.sudoCryptoProvider.getPassword(name)
  }

  public deletePassword(name: string): Promise<void> {
    return this.sudoCryptoProvider.deletePassword(name)
  }

  public updatePassword(password: ArrayBuffer, name: string): Promise<void> {
    return this.sudoCryptoProvider.updatePassword(password, name)
  }

  public addSymmetricKey(key: ArrayBuffer, name: string): Promise<void> {
    return this.sudoCryptoProvider.addSymmetricKey(key, name)
  }

  public getSymmetricKey(name: string): Promise<ArrayBuffer | undefined> {
    return this.sudoCryptoProvider.getSymmetricKey(name)
  }

  public doesSymmetricKeyExist(name: string): Promise<boolean> {
    return this.sudoCryptoProvider.doesSymmetricKeyExist(name)
  }

  public deleteSymmetricKey(name: string): Promise<void> {
    return this.sudoCryptoProvider.deleteSymmetricKey(name)
  }

  public generateKeyPair(name: string): Promise<void> {
    return this.sudoCryptoProvider.generateKeyPair(name)
  }

  public addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    return this.sudoCryptoProvider.addPrivateKey(key, name)
  }

  public getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    return this.sudoCryptoProvider.getPrivateKey(name)
  }

  public doesPrivateKeyExist(name: string): Promise<boolean> {
    return this.sudoCryptoProvider.doesPrivateKeyExist(name)
  }

  public addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    return this.sudoCryptoProvider.addPublicKey(key, name)
  }

  public deletePublicKey(name: string): Promise<void> {
    return this.sudoCryptoProvider.deletePublicKey(name)
  }

  public getPublicKey(name: string): Promise<PublicKey | undefined> {
    return this.sudoCryptoProvider.getPublicKey(name)
  }

  public deleteKeyPair(name: string): Promise<void> {
    return this.sudoCryptoProvider.deleteKeyPair(name)
  }

  public generateSignatureWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.generateSignatureWithPrivateKey(name, data)
  }

  verifySignatureWithPublicKey(
    name: string,
    data: ArrayBuffer,
    signature: ArrayBuffer,
  ): Promise<boolean> {
    return this.sudoCryptoProvider.verifySignatureWithPublicKey(
      name,
      data,
      signature,
    )
  }

  public encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (BufferUtil.isArrayBuffer(ivOrOptions)) {
      return this.sudoCryptoProvider.encryptWithSymmetricKey(key, data, {
        iv: ivOrOptions,
      })
    } else {
      return this.sudoCryptoProvider.encryptWithSymmetricKey(
        key,
        data,
        ivOrOptions,
      )
    }
  }

  public decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (BufferUtil.isArrayBuffer(ivOrOptions)) {
      return this.sudoCryptoProvider.decryptWithSymmetricKey(key, data, {
        iv: ivOrOptions,
      })
    } else {
      return this.sudoCryptoProvider.decryptWithSymmetricKey(
        key,
        data,
        ivOrOptions,
      )
    }
  }

  public encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (BufferUtil.isArrayBuffer(ivOrOptions)) {
      return this.sudoCryptoProvider.encryptWithSymmetricKeyName(name, data, {
        iv: ivOrOptions,
      })
    } else {
      return this.sudoCryptoProvider.encryptWithSymmetricKeyName(
        name,
        data,
        ivOrOptions,
      )
    }
  }

  public decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (BufferUtil.isArrayBuffer(ivOrOptions)) {
      return this.sudoCryptoProvider.decryptWithSymmetricKeyName(name, data, {
        iv: ivOrOptions,
      })
    } else {
      return this.sudoCryptoProvider.decryptWithSymmetricKeyName(
        name,
        data,
        ivOrOptions,
      )
    }
  }

  public encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.encryptWithPublicKey(name, data, options)
  }

  public decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer | undefined> {
    return this.sudoCryptoProvider.decryptWithPrivateKey(name, data, options)
  }

  public removeAllKeys(): Promise<void> {
    return this.sudoCryptoProvider.removeAllKeys()
  }

  public generateSymmetricKey(name: string): Promise<void> {
    return this.sudoCryptoProvider.generateSymmetricKey(name)
  }

  public generateSymmetricKeyFromPassword(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    options?: { rounds?: number },
  ): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.generateSymmetricKeyFromPassword(
      password,
      salt,
      options,
    )
  }

  public generateRandomData(size: number): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.generateRandomData(size)
  }

  public generateHash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.generateHash(data)
  }

  public exportKeys(): Promise<KeyData[]> {
    return this.sudoCryptoProvider.exportKeys()
  }
}
