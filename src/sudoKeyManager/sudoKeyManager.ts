/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { IllegalArgumentError } from '../errors/error'
import { Base64 } from '../utils/base64'
import { Buffer as BufferUtil } from '../utils/buffer'
import { KeyData } from './keyData'
import { PublicKey, PublicKeyFormat } from './publicKey'
import {
  AsymmetricEncryptionOptions,
  SignatureOptions,
  SudoCryptoProvider,
  SymmetricEncryptionOptions,
} from './sudoCryptoProvider'

/**
 * ASN.1 OIDs.
 */
enum OID {
  rsaEncryption = '1.2.840.113549.1.1.1',
}

/**
 * PEM headers.
 */
enum PEMHeader {
  rsaPublicKey = '-----BEGIN RSA PUBLIC KEY-----',
  publicKey = '-----BEGIN PUBLIC KEY-----',
}

/**
 * PEM footers.
 */
enum PEMFooter {
  rsaPublicKey = '-----END RSA PUBLIC KEY-----',
  publicKey = '-----END PUBLIC KEY-----',
}

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
   * Exports the public key from the secure store as PEM encoded
   * string.
   *
   * @param name The name of the public key.
   * @param format The key format to use.
   *
   * @returns The public key or undefined if the key was not found.
   */
  exportPublicKeyAsPEM(
    name: string,
    format: PublicKeyFormat,
  ): Promise<string | undefined>

  /**
   * Imports a PEM encoded public key into the secure store.
   *
   * @param name The name of the public key.
   * @param publicKey The public key to import.
   */
  importPublicKeyFromPEM(name: string, publicKey: string): Promise<void>

  /**
   * Exports the private key from the secure store as RSAPrivateKey.
   *
   * @param name The name of the private key.
   *
   * @returns The private key or undefined if the key was not found.
   */
  exportPrivateKeyAsRSAPrivateKey(
    name: string,
  ): Promise<ArrayBuffer | undefined>

  /**
   * Imports a RSAPrivateKey into the secure store.
   *
   * @param name The name of the private key.
   * @param privateKey The private key to import.
   */
  importPrivateKeyFromRSAPrivateKey(
    name: string,
    privateKey: ArrayBuffer,
  ): Promise<void>

  /**
   * Exports the public key from the secure store as RSAPublicKey.
   *
   * @param name The name of the public key.
   *
   * @returns The public key or undefined if the key was not found.
   */
  exportPublicKeyAsRSAPublicKey(name: string): Promise<ArrayBuffer | undefined>

  /**
   * Imports a RSAPublicKey into the secure store.
   *
   * @param name The name of the public key.
   * @param publicKey The public key to import.
   */
  importPublicKeyFromRSAPublicKey(
    name: string,
    publicKey: ArrayBuffer,
  ): Promise<void>

  /**
   * Converts PKCS#8 PrivateKeyInfo (RFC5280) to RSAPrivateKey (RFC3447).
   *
   * @param privateKey private key to convert.
   */
  privateKeyInfoToRSAPrivateKey(privateKey: ArrayBuffer): ArrayBuffer

  /**
   * Converts SubjectPubicKeyInfo (RFC5280) to RSAPublicKey (RFC3447).
   *
   * @param publicKey public key to convert.
   */
  publicKeyInfoToRSAPublicKey(publicKey: ArrayBuffer): ArrayBuffer

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
   * @param options Signature options. Defaults to \{ algorithm: SignatureAlgorithm.RsaPkcs15Sha256 \}
   *
   * @returns Data signature or undefined if the private key is not found.
   */
  generateSignatureWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<ArrayBuffer>

  /**
   * Verifies the given data against the provided signature using the specified public key.
   *
   * @param name The name of the public key to use for validation.
   * @param data The data to verify
   * @param signature The signature to verify against
   * @param options Signature options. Defaults to \{ algorithm: SignatureAlgorithm.RsaPkcs15Sha256 \}
   *
   * @returns True if the data and signature could be successfully verified
   */
  verifySignatureWithPublicKey(
    name: string,
    data: ArrayBuffer,
    signature: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<boolean>

  /**
   * @deprecated Use version with `options` param.
   *
   * Encrypts the given data with the specified key
   *
   * @param key The symmetric key to use to encrypt.
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
   * @param key The symmetric key to use to encrypt.
   * @param data Data to encrypt.
   * @param options SymmetricEncryptionOptions to use.
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
   * @param data The encrypted data.
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
   * @param data The encrypted data.
   * @param options SymmetricEncryptionOptions to use.
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
   * Encrypts the given data with the specified public key.
   *
   * @param {ArrayBuffer} key Raw key bytes of the public key to use for encryption.
   * @param {ArrayBuffer} data The data to encrypt.
   *
   * @returns Encrypted data
   *
   * @throws {@link UnrecognizedAlgorithmError}
   */
  encryptWithPublicKey(
    key: ArrayBuffer,
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
   * @param password The password from which to generate the symmetric key
   * @param salt Salt to use in generation of the key
   * @param options.rounds The number of rounds of PBKDF2 to perform. Default: per getDefaultPBKDF2Rounds
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

  public async exportPublicKeyAsPEM(
    name: string,
    format: PublicKeyFormat,
  ): Promise<string | undefined> {
    const publicKey = await this.getPublicKey(name)

    if (!publicKey) {
      return undefined
    }

    if (publicKey.keyFormat === PublicKeyFormat.RSAPublicKey) {
      if (format === PublicKeyFormat.RSAPublicKey) {
        return this.publicKeyToPEM(publicKey.keyData, format)
      } else {
        // Convert RSAPublicKey (RFC3447) to SPKI (RFC5280).
        const spki = new pkijs.PublicKeyInfo()
        spki.algorithm = new pkijs.AlgorithmIdentifier({
          algorithmId: OID.rsaEncryption,
          algorithmParams: new asn1js.Null(),
        })
        spki.subjectPublicKey = new asn1js.BitString({
          valueHex: publicKey.keyData,
        })

        return this.publicKeyToPEM(spki.toSchema().toBER(), format)
      }
    } else {
      if (format === PublicKeyFormat.SPKI) {
        return this.publicKeyToPEM(publicKey.keyData, format)
      } else {
        // Convert SPKI (RFC5280) to RSAPublicKey (RFC3447).
        const publicKeyInfo = pkijs.PublicKeyInfo.fromBER(publicKey.keyData)
        const keyData = publicKeyInfo.subjectPublicKey.valueBlock.valueHexView
        return this.publicKeyToPEM(keyData, format)
      }
    }
  }

  public async importPublicKeyFromPEM(
    name: string,
    publicKey: string,
  ): Promise<void> {
    let format: PublicKeyFormat
    if (
      publicKey.includes(PEMHeader.rsaPublicKey) &&
      publicKey.includes(PEMFooter.rsaPublicKey)
    ) {
      format = PublicKeyFormat.RSAPublicKey
    } else if (
      publicKey.includes(PEMHeader.publicKey) &&
      publicKey.includes(PEMFooter.publicKey)
    ) {
      format = PublicKeyFormat.SPKI
    } else {
      throw new IllegalArgumentError()
    }
    const keyData = this.publicKeyAsSpki(publicKey, format)
    await this.sudoCryptoProvider.addPublicKey(keyData, name)
  }

  public async exportPrivateKeyAsRSAPrivateKey(
    name: string,
  ): Promise<ArrayBuffer | undefined> {
    const privateKey = await this.getPrivateKey(name)

    if (!privateKey) {
      return undefined
    }

    return this.privateKeyInfoToRSAPrivateKey(privateKey)
  }

  public async importPrivateKeyFromRSAPrivateKey(
    name: string,
    privateKey: ArrayBuffer,
  ): Promise<void> {
    // Web Crypto Provider currently only accepts PrivateKeyInfo.
    const pki = new pkijs.PrivateKeyInfo()
    pki.privateKeyAlgorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: OID.rsaEncryption,
      algorithmParams: new asn1js.Null(),
    })
    pki.privateKey = new asn1js.OctetString({
      valueHex: privateKey,
    })
    const keyData = pki.toSchema().toBER()

    await this.sudoCryptoProvider.addPrivateKey(keyData, name)
  }

  public async exportPublicKeyAsRSAPublicKey(
    name: string,
  ): Promise<ArrayBuffer | undefined> {
    const publicKey = await this.getPublicKey(name)

    if (!publicKey) {
      return undefined
    }

    switch (publicKey.keyFormat) {
      case PublicKeyFormat.RSAPublicKey:
        return publicKey.keyData
      case PublicKeyFormat.SPKI:
        return this.publicKeyInfoToRSAPublicKey(publicKey.keyData)
    }
  }

  public async importPublicKeyFromRSAPublicKey(
    name: string,
    publicKey: ArrayBuffer,
  ): Promise<void> {
    // Web Crypto Provider currently only accepts SPKI and
    // none of the native providers support adding a public
    // key so we will need to convert RSAPublicKey (RFC3447)
    // to SPKI (RFC5280).
    const spki = new pkijs.PublicKeyInfo()
    spki.algorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: OID.rsaEncryption,
      algorithmParams: new asn1js.Null(),
    })
    spki.subjectPublicKey = new asn1js.BitString({
      valueHex: publicKey,
    })
    const keyData = spki.toSchema().toBER()

    await this.sudoCryptoProvider.addPublicKey(keyData, name)
  }

  public deleteKeyPair(name: string): Promise<void> {
    return this.sudoCryptoProvider.deleteKeyPair(name)
  }

  public generateSignatureWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    return this.sudoCryptoProvider.generateSignatureWithPrivateKey(
      name,
      data,
      options,
    )
  }

  verifySignatureWithPublicKey(
    name: string,
    data: ArrayBuffer,
    signature: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<boolean> {
    return this.sudoCryptoProvider.verifySignatureWithPublicKey(
      name,
      data,
      signature,
      options,
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
  ): Promise<ArrayBuffer>

  public encryptWithPublicKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  public encryptWithPublicKey(
    key: ArrayBuffer | string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (typeof key === 'string') {
      return this.sudoCryptoProvider.encryptWithPublicKeyName(
        key,
        data,
        options,
      )
    }

    let keyToUse = key
    const formatToUse =
      options?.publicKeyFormat ??
      (BufferUtil.toString(key).startsWith(this.getSpkiHeaderBytes())
        ? PublicKeyFormat.SPKI
        : PublicKeyFormat.RSAPublicKey)
    if (formatToUse !== PublicKeyFormat.SPKI) {
      keyToUse = this.publicKeyAsSpki(
        BufferUtil.toString(key),
        PublicKeyFormat.RSAPublicKey,
      )
    }
    return this.sudoCryptoProvider.encryptWithPublicKey(keyToUse, data, {
      ...options,
      publicKeyFormat: PublicKeyFormat.SPKI,
    })
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

  public privateKeyInfoToRSAPrivateKey(privateKey: ArrayBuffer): ArrayBuffer {
    const privateKeyInfo = pkijs.PrivateKeyInfo.fromBER(privateKey)
    const privateKeyData = privateKeyInfo.parsedKey?.toSchema().toBER()
    if (!privateKeyData) {
      throw new IllegalArgumentError('Private key cannot be converted.')
    }
    return privateKeyData
  }

  public publicKeyInfoToRSAPublicKey(publicKey: ArrayBuffer): ArrayBuffer {
    const publicKeyInfo = pkijs.PublicKeyInfo.fromBER(publicKey)
    return publicKeyInfo.subjectPublicKey.valueBlock.valueHexView
  }

  private publicKeyAsSpki(
    publicKey: string,
    format: PublicKeyFormat,
  ): ArrayBuffer {
    const stripped = publicKey
      .replace(/-{5}(BEGIN|END) .*-{5}/gm, '')
      .replace(/\s/gm, '')
    let keyData = Base64.decode(stripped)
    if (format === PublicKeyFormat.RSAPublicKey) {
      // Convert RSAPublicKey (RFC3447) to SPKI (RFC5280).
      const spki = new pkijs.PublicKeyInfo()
      spki.algorithm = new pkijs.AlgorithmIdentifier({
        algorithmId: OID.rsaEncryption,
        algorithmParams: new asn1js.Null(),
      })
      spki.subjectPublicKey = new asn1js.BitString({
        valueHex: keyData,
      })
      keyData = spki.toSchema().toBER()
    }
    return keyData
  }

  private getSpkiHeaderBytes(length: number = 24): string {
    const spki = new pkijs.PublicKeyInfo()
    spki.algorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: OID.rsaEncryption,
      algorithmParams: new asn1js.Null(),
    })
    spki.subjectPublicKey = new asn1js.BitString({
      valueHex: new ArrayBuffer(270),
    })
    const encoded = Base64.encode(spki.toSchema().toBER())
    return encoded.substring(0, length)
  }

  private publicKeyToPEM(key: ArrayBuffer, format: PublicKeyFormat): string {
    const encoded = Base64.encode(key)
    const lines = encoded.match(/.{1,64}/g)
    if (!lines) {
      throw new IllegalArgumentError()
    }
    const formatted = lines.join('\n')
    return (
      '-----BEGIN ' +
      (format === PublicKeyFormat.RSAPublicKey ? 'RSA ' : '') +
      'PUBLIC KEY-----\n' +
      formatted +
      '\n-----END ' +
      (format === PublicKeyFormat.RSAPublicKey ? 'RSA ' : '') +
      'PUBLIC KEY-----'
    )
  }
}
