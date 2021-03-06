import { PublicKey } from './publicKey'

/**
 * CryptoProvider instance interface
 */
export interface SudoCryptoProvider {
  getNamespace(): string
  getServiceName(): string
  /**
   * Adds as password to the secure store.
   *
   * @param password The password to store.
   * @param name The name of the password.
   */
  addPassword(password: ArrayBuffer, name: string): Promise<void>
  /**
   * Retrieves a password from the secure store.
   *
   * @param name The name of the password to retrieve.
   *
   * @returns The password or undefined if a password with the given name was not found.
   */
  getPassword(name: string): Promise<ArrayBuffer | undefined>
  /**
   * Deletes a password from the secure store.
   *
   * @param name The name of the password to delete.
   */
  deletePassword(name: string): Promise<void>
  /**
   * Updates a password stored in the secure store.
   *
   * @param password The new password.
   * @param name The name of the password to update.
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
   * Generates a symmetric key and stores it securely.
   *
   * @param name The name for the symmetric key.
   */
  generateSymmetricKey(name: string): Promise<void>
  /**
   * Deletes a key pair from the secure store.
   *
   * @param name The name of the key pair to be deleted.
   */
  deleteKeyPair(name: string): Promise<void>
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
   * @param key The public key to store securely.
   * @param name The name of the public key to be stored.
   */
  addPublicKey(key: ArrayBuffer, name: string): Promise<void>
  /**
   * Retrieves the public key from the secure store.
   *
   * @param name The name of the public key.
   *
   * @returns The public key or undefined if the key was not found.
   */
  getPublicKey(name: string): Promise<PublicKey | undefined>
  /**
   * Clear all types of keys
   */
  removeAllKeys(): Promise<void>
  /**
   * Encrypts the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to encrypt.
   * @param data Data to encrypt.
   * @param iv Optional Initialization Vector.
   *
   * @returns Encrypted data and IV
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
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
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
   * Encrypts the given data with the specified public key.
   *
   * @param name The name of the public key to use for encryption.
   * @param data The data to encrypt.
   * @param algorithm The encryption algorithm to use.
   *
   * @returns Encrypted data
   */
  encryptWithPublicKey(name: string, data: ArrayBuffer): Promise<ArrayBuffer>
  /**
   * Decrypts the given data with the specified private key.
   *
   * @param name The name of the private key to use for decryption.
   * @param data The data to decrypt.
   * @param algorithm The algorithm used for decryption.
   *
   * @returns Decrypted data or undefined if the private key is not found.
   */
  decryptWithPrivateKey(name: string, data: ArrayBuffer): Promise<ArrayBuffer>
  /**
   * Generates and securely stores a key pair for public key cryptography.
   *
   * @param name The name of the key pair to be generated.
   */
  generateKeyPair(name: string): Promise<void>
  /**
   * Creates a SHA256 hash of the specified data.
   *
   * @param data Data to hash.
   */
  generateHash(data: ArrayBuffer): Promise<ArrayBuffer>
}
