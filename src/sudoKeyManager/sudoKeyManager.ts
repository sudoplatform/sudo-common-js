import { PublicKey } from './publicKey'
import { SudoCryptoProvider } from './sudoCryptoProvider'

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
   * Adds a public key to the secure store.
   *
   * The format of the public key should be SubjectPublicKeyInfo (spki)
   *
   * @param key The public key to store securely.
   * @param name The name of the public key to be stored.
   */
  addPublicKey(key: ArrayBuffer, name: string): Promise<void>

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
   * Encrypts the given data with the specified public key.
   *
   * @param name The name of the public key to use for encryption.
   * @param data The data to encrypt.
   *
   * @returns Encrypted data
   */
  encryptWithPublicKey(name: string, data: ArrayBuffer): Promise<ArrayBuffer>

  /**
   * Decrypts the given data with the specified private key.
   *
   * @param name The name of the private key to use for decryption.
   * @param data The data to decrypt.
   *
   * @returns Decrypted data or undefined if the private key is not found.
   */
  decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
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
}

export class DefaultSudoKeyManager implements SudoKeyManager {
  /**
   * @param namespace A namespace to use as part of the key name.  If a namespace is specified then
   * a unique identifier for each key will be `<namespace>.<keyName>`. Namespace cannot be an empty string.
   * @param sudoCryptoProvider
   */
  constructor(private sudoCryptoProvider: SudoCryptoProvider) {}

  public get serviceName(): string {
    return this.sudoCryptoProvider.getServiceName()
  }

  public get namespace(): string {
    return this.sudoCryptoProvider.getNamespace()
  }

  public async addPassword(password: ArrayBuffer, name: string): Promise<void> {
    await this.sudoCryptoProvider.addPassword(password, name)
  }

  public async getPassword(name: string): Promise<ArrayBuffer | undefined> {
    return await this.sudoCryptoProvider.getPassword(name)
  }

  public async deletePassword(name: string): Promise<void> {
    await this.sudoCryptoProvider.deletePassword(name)
  }

  public async updatePassword(
    password: ArrayBuffer,
    name: string,
  ): Promise<void> {
    await this.sudoCryptoProvider.updatePassword(password, name)
  }

  public async addSymmetricKey(key: ArrayBuffer, name: string): Promise<void> {
    await this.sudoCryptoProvider.addSymmetricKey(key, name)
  }

  public async getSymmetricKey(name: string): Promise<ArrayBuffer | undefined> {
    return await this.sudoCryptoProvider.getSymmetricKey(name)
  }

  public async deleteSymmetricKey(name: string): Promise<void> {
    await this.sudoCryptoProvider.deleteSymmetricKey(name)
  }

  public async generateKeyPair(name: string): Promise<void> {
    await this.sudoCryptoProvider.generateKeyPair(name)
  }

  public async addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    return await this.sudoCryptoProvider.addPrivateKey(key, name)
  }

  public async getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    return await this.sudoCryptoProvider.getPrivateKey(name)
  }

  public async addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    return await this.sudoCryptoProvider.addPublicKey(key, name)
  }

  public async getPublicKey(name: string): Promise<PublicKey | undefined> {
    return await this.sudoCryptoProvider.getPublicKey(name)
  }

  public async deleteKeyPair(name: string): Promise<void> {
    return await this.sudoCryptoProvider.deleteKeyPair(name)
  }

  public async encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.encryptWithSymmetricKey(key, data, iv)
  }

  public async decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.decryptWithSymmetricKey(key, data, iv)
  }

  public async encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.encryptWithSymmetricKeyName(
      name,
      data,
      iv,
    )
  }

  public async decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.decryptWithSymmetricKeyName(
      name,
      data,
      iv,
    )
  }

  public async encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.encryptWithPublicKey(name, data)
  }

  public async decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer | undefined> {
    return await this.sudoCryptoProvider.decryptWithPrivateKey(name, data)
  }

  public async removeAllKeys(): Promise<void> {
    return await this.sudoCryptoProvider.removeAllKeys()
  }

  public async generateSymmetricKey(name: string): Promise<void> {
    return await this.sudoCryptoProvider.generateSymmetricKey(name)
  }

  public async generateHash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return await this.sudoCryptoProvider.generateHash(data)
  }
}
