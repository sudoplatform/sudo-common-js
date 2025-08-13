/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export enum PublicKeyFormat {
  RSAPublicKey,
  SPKI,
}

export interface PublicKey {
  readonly keyData: ArrayBuffer
  readonly keyFormat: PublicKeyFormat
}
