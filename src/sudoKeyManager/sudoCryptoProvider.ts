import { KeyNotFoundError } from '../errors/error'

export enum KeyType {
  Symmetric = 'symmetric',
  Password = 'password',
  KeyPair = 'keyPair',
}

export enum KeyFormat {
  Raw = 'raw',
  Jwk = 'jwk', // public or private
  Spki = 'spki', // public only
  Pkcs8 = 'pkcs8', // private only
}

export enum SecretType {
  Symmetric,
  Password,
  KeyPair,
  PrivateKey,
  PublicKey,
}

export interface KeyPair {
  publicKey: ArrayBuffer | undefined
  privateKey: ArrayBuffer | undefined
}

export interface SudoCryptoProvider {
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
  getPublicKey(name: string): Promise<ArrayBuffer | undefined>

  /**
   * Clear all types of keys
   */
  removeAllKeys(): Promise<void>

  /**
   * Creates random data used mainly for generating symmetric keys.
   *
   * @param size The size (in bytes) of the random data to create.
   *
   * @returns Random data
   */
  createRandomData(size: number): ArrayBuffer

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
   *
   * @param key The symmetric key to decrypt data with.
   * @param data The encrypted data to decrypt.
   * @param iv Optional Initialization Vector.
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
  decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer | undefined>

  /**
   * Creates a SHA256 hash of the specified data.
   *
   * @param data Data to hash.
   */
  generateHash(data: ArrayBuffer): Promise<ArrayBuffer>

  /**
   * Generates and securely stores a key pair for public key cryptography.
   *
   * @param name The name of the key pair to be generated.
   */
  generateKeyPair(name: string): Promise<void>
}

export class DefaultSudoCryptoProvider implements SudoCryptoProvider {
  private static readonly Constants = {
    ivSize: 16,
    publicKeyEncryptionAlgorithm: 'RSA-OAEP',
    symmetricKeyEncryptionAlgorithm: 'AES-CBC',
    hashingAlgorithm: 'SHA-1',
  }

  #passwords: Record<string, ArrayBuffer> = {}
  #symmetricKeys: Record<string, ArrayBuffer> = {}
  #keyPairs: Record<string, KeyPair> = {}

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public async addPassword(password: ArrayBuffer, name: string): Promise<void> {
    this.#passwords[name] = password
    return Promise.resolve()
  }

  public async getPassword(name: string): Promise<ArrayBuffer | undefined> {
    return Promise.resolve(this.#passwords[name])
  }

  public async deletePassword(name: string): Promise<void> {
    delete this.#passwords[name]
    return Promise.resolve()
  }

  public async updatePassword(
    password: ArrayBuffer,
    name: string,
  ): Promise<void> {
    if (this.#passwords[name]) {
      this.#passwords[name] = password
    } else {
      throw new KeyNotFoundError()
    }
    return Promise.resolve()
  }

  public async addSymmetricKey(key: ArrayBuffer, name: string): Promise<void> {
    this.#symmetricKeys[name] = key
    return Promise.resolve()
  }

  public async getSymmetricKey(name: string): Promise<ArrayBuffer | undefined> {
    return Promise.resolve(this.#symmetricKeys[name])
  }

  public async deleteSymmetricKey(name: string): Promise<void> {
    delete this.#symmetricKeys[name]
    return Promise.resolve()
  }

  public async generateSymmetricKey(name: string): Promise<void> {
    const cryptoKey = await crypto.subtle.generateKey(
      {
        name:
          DefaultSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const formattedKey = await crypto.subtle.exportKey(KeyFormat.Raw, cryptoKey)

    this.#symmetricKeys[name] = formattedKey
  }

  public async deleteKeyPair(name: string): Promise<void> {
    delete this.#keyPairs[name]
    Promise.resolve()
  }

  public async addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    this.#keyPairs[name] = { privateKey: key, publicKey: undefined }
    Promise.resolve()
  }

  public async getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    return Promise.resolve(this.#keyPairs[name]?.privateKey)
  }

  public async addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    this.#keyPairs[name] = { privateKey: undefined, publicKey: key }
    Promise.resolve()
  }

  public async getPublicKey(name: string): Promise<ArrayBuffer | undefined> {
    return Promise.resolve(this.#keyPairs[name]?.publicKey)
  }

  public async removeAllKeys(): Promise<void> {
    this.#passwords = {}
    this.#symmetricKeys = {}
    this.#keyPairs = {}
    return Promise.resolve()
  }

  public createRandomData(size: number): ArrayBuffer {
    const buffer = new ArrayBuffer(size)
    crypto.getRandomValues(new Uint8Array(buffer))
    return buffer
  }

  public async encryptWithSymmetricKey(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const key = this.#symmetricKeys[name]
    if (!key) {
      throw new KeyNotFoundError()
    }

    if (!iv) {
      iv = new ArrayBuffer(DefaultSudoCryptoProvider.Constants.ivSize)
    }

    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      DefaultSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
      false,
      ['encrypt'],
    )

    const encrypted = await crypto.subtle.encrypt(
      {
        name:
          DefaultSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )

    return encrypted
  }

  public async decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const key = this.#symmetricKeys[name]
    if (!key) {
      throw new KeyNotFoundError()
    }

    return await this.decryptWithSymmetricKey(key, data, iv)
  }

  public async decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!iv) {
      iv = new ArrayBuffer(DefaultSudoCryptoProvider.Constants.ivSize)
    }

    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      DefaultSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
      false,
      ['decrypt'],
    )

    const decrypted = await crypto.subtle.decrypt(
      {
        name:
          DefaultSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )

    return decrypted
  }

  public async encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const publicKey = this.#keyPairs[name]?.publicKey
    if (!publicKey) {
      throw new KeyNotFoundError()
    }

    const formattedPublicKey = await crypto.subtle.importKey(
      KeyFormat.Spki,
      publicKey,
      {
        name: DefaultSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: { name: DefaultSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['encrypt'],
    )

    const encrypted = await crypto.subtle.encrypt(
      {
        name: DefaultSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      formattedPublicKey,
      data,
    )

    return encrypted
  }

  public async decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const privateKey = this.#keyPairs[name]?.privateKey
    if (!privateKey) {
      throw new KeyNotFoundError()
    }

    const formattedPrivateKey = await crypto.subtle.importKey(
      KeyFormat.Pkcs8,
      privateKey,
      {
        name: DefaultSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: { name: DefaultSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['decrypt'],
    )

    const decrypted = await crypto.subtle.decrypt(
      {
        name: DefaultSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      formattedPrivateKey,
      data,
    )

    return decrypted
  }

  public async generateHash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return await crypto.subtle.digest(
      DefaultSudoCryptoProvider.Constants.hashingAlgorithm,
      data,
    )
  }

  public async generateKeyPair(name: string): Promise<void> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: DefaultSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: DefaultSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const publicKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Spki,
      keyPair.publicKey,
    )

    const privateKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Pkcs8,
      keyPair.privateKey,
    )

    const newKeyPair = {
      privateKey: privateKeyBits,
      publicKey: publicKeyBits,
    }

    this.#keyPairs[name] = newKeyPair
  }
}
