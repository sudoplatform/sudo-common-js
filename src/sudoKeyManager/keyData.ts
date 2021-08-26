/**
 * Type of key
 */
export enum KeyDataKeyType {
  SymmetricKey = 'SymmetricKey',
  RSAPublicKey = 'RSAPublicKey',
  RSAPrivateKey = 'RSAPrivateKey',
  Password = 'Password',
}

export enum KeyDataKeyFormat {
  /**
   * Raw key format.
   *
   * For SymmetricKey and Password types this means the raw bytes
   * of the key/password.
   *
   * For RSAPublicKey this means RSAPublicKey binary format.
   * For RSAPrivateKey this means RSAPrivateKey binary format.
   * "RSA PUBLIC KEY" or "RSA PRIVATE KEY" in PEM speak
   */
  Raw = 'Raw',

  /**
   * SPKI public key format.
   *
   * Applies to public keys (currently only RSAPublicKey)
   * and means they are formated using SPKI.
   *
   * "PUBLIC KEY" in PEM speak
   */
  SPKI = 'SPKI',

  /**
   * PKCS8 private key format.
   *
   * Applies to private keys (currently only RSAPrivateKey)
   * and means they are formated using unencrypted PKCS8.
   *
   * "PRIVATE KEY" in PEM speak
   */
  PKCS8 = 'PKCS8',
}

/**
 * Record of key in a key archive
 *
 * @property name name of the key within the namespace
 * @property namespace namespace of the key manager for this key
 * @property data raw binary data of the key
 * @property type type of the key
 * @property format format of the raw binary data
 */
export interface KeyData {
  name: string
  namespace: string
  data: ArrayBuffer
  type: KeyDataKeyType
  format: KeyDataKeyFormat
}
