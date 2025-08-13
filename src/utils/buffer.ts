/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Utility class for operating on ArrayBuffer.
 */
export class Buffer {
  /**
   * Converts a Uint8Array to an ArrayBuffer
   */
  static toArrayBuffer(uint8Array: Uint8Array): ArrayBuffer {
    const arrayBuffer = new ArrayBuffer(uint8Array.length)
    new Uint8Array(arrayBuffer).set(uint8Array)
    return arrayBuffer
  }

  static concat(lhs: ArrayBuffer, rhs: ArrayBuffer): ArrayBuffer {
    const combined = new Uint8Array(lhs.byteLength + rhs.byteLength)
    combined.set(new Uint8Array(lhs), 0)
    combined.set(new Uint8Array(rhs), lhs.byteLength)
    return combined.buffer
  }

  static split(
    buffer: ArrayBuffer,
    lhsLength: number,
  ): { lhs: ArrayBuffer; rhs: ArrayBuffer } {
    const array = new Uint8Array(buffer)
    const lhsSlice = array.slice(0, lhsLength)
    const rhsSlice = array.slice(lhsLength, array.length)

    return {
      lhs: Buffer.toArrayBuffer(lhsSlice),
      rhs: Buffer.toArrayBuffer(rhsSlice),
    }
  }

  static toString(input: ArrayBuffer | Uint8Array): string {
    if (Buffer.isArrayBuffer(input)) {
      input = new Uint8Array(input)
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(input)
  }

  static fromString(s: string): ArrayBuffer {
    const uint8Array = new TextEncoder().encode(s)
    return Buffer.toArrayBuffer(uint8Array)
  }

  static isArrayBuffer(u: unknown): u is ArrayBuffer {
    return ArrayBuffer.isView(u)
  }

  static toBinaryString(input: ArrayBuffer | Uint8Array): string {
    if (Buffer.isArrayBuffer(input)) {
      input = new Uint8Array(input)
    }
    const bytes = new Uint8Array(input)
    let s = ''
    bytes.forEach((b) => (s += String.fromCharCode(b)))
    return s
  }

  static fromBinaryString(s: string): ArrayBuffer {
    const uint8Array = Uint8Array.from(s, (c) => c.charCodeAt(0))
    return Buffer.toArrayBuffer(uint8Array)
  }
}
