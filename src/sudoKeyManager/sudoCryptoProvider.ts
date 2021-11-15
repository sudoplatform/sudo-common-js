import { EncryptionAlgorithm } from '../types/types'
import { KeyData } from './keyData'
import { PublicKey } from './publicKey'

export class SudoCryptoProviderDefaults {
  public static readonly aesIVSize = 16
  public static readonly aesKeySize = 256
  public static readonly pbkdfRounds = 10000
  public static readonly pbkdfSaltSize = 16
}

/**
 * Optional arguments for symmetric encryption..
 */
export interface SymmetricEncryptionOptions {
  // Initialization Vector
  iv?: ArrayBuffer
  // Algorithm to use to encrypt data.
  // Defaulted to `AES/CBC/PKCS7Padding`
  algorithm?: EncryptionAlgorithm
}

/**
 * Optional arguments for public key encryption.
 */
export interface AsymmetricEncryptionOptions {
  // Algorithm used to encrypt data.
  // Defaulted to RSA/OAEPSHA-1
  algorithm?: EncryptionAlgorithm
}

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
   * Checks to see if the specified symmetric key exists.
   *
   * @param name The name of the symmetric key.
   */
  doesSymmetricKeyExists(name: string): Promise<boolean>

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
   * Generates a symmetric key from a password using PBKDF2.
   *
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
   * Checks to see if the specified private key exists.
   *
   * @param name The name of the private key.
   */
  doesPrivateKeyExists(name: string): Promise<boolean>

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
   * @deprecated Use version with `options` param.
   *
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
   * Encrypts the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to encrypt.
   * @param data Data to encrypt.
   *
   *
   * @returns Encrypted data and IV
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
   *
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
   * Decrypt the given data with the specified symmetric key stored in the secure store.
   *
   * @param name The name of the symmetric key to use to decrypt.
   * @param data The data to decrypt.
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
  ): Promise<ArrayBuffer>

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
   *
   * @returns The SHA256 hash of data
   */
  generateHash(data: ArrayBuffer): Promise<ArrayBuffer>

  /**
   * Export all keys and passwords from the key store as an
   * array of KeyData items.
   *
   * @returns Array of exported keys and passwords
   */
  exportKeys(): Promise<KeyData[]>
}
