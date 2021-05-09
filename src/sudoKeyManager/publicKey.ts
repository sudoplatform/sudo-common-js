export enum PublicKeyFormat {
  RSAPublicKey,
  SPKI,
}

export interface PublicKey {
  readonly keyData: ArrayBuffer
  readonly keyFormat: PublicKeyFormat
}
