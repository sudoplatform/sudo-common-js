/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer as BufferUtil } from './buffer'
/**
 * Utility class for Base64 encoding and decoding.
 */
export class Base64 {
  private static URLSafeEncodeTransform(input: string): string {
    return input
      .replace(/\+/g, '-') // Convert '+' to '-'
      .replace(/\//g, '_') // Convert '/' to '_'
      .replace(/=+$/, '') // Remove ending '='
  }
  private static URLSafeDecodeTransform(input: string): string {
    return input
      .replace(/\-/g, '+') // Convert '-' to '+'
      .replace(/\_/g, '/') // Convert '_' to '/'
  }

  static decode(encoded: string): ArrayBuffer {
    return BufferUtil.fromBinaryString(atob(encoded))
  }

  static encode(buffer: ArrayBuffer): string {
    return btoa(BufferUtil.toBinaryString(buffer))
  }

  static decodeString(encoded: string): string {
    return atob(encoded)
  }

  static encodeString(string: string): string {
    return btoa(string)
  }

  /**
   * Encode a URL safe ArrayBuffer
   * @param {ArrayBuffer} input buffer to be encoded
   * @returns {string} encoded string
   */
  static urlSafeEncode({ input }: { input: ArrayBuffer }): string {
    return this.URLSafeEncodeTransform(this.encode(input))
  }

  /**
   * Decode into a URL safe ArrayBuffer
   * @param {string} input string to be decoded
   * @returns {ArrayBuffer} decoded ArrayBuffer
   */
  static urlSafeDecode({ encoded }: { encoded: string }): ArrayBuffer {
    encoded = this.URLSafeDecodeTransform(encoded)
    return this.decode(encoded)
  }

  /**
   * Encode a URL safe string
   * @param {string} input string to be encoded
   * @returns {string} encoded string
   */
  static urlSafeEncodeString({ input }: { input: string }): string {
    return this.URLSafeEncodeTransform(this.encodeString(input))
  }

  /**
   * Decode a URL safe string
   * @param {string} input string to be decoded
   * @returns {string} decoded string
   */
  static urlSafeDecodeString({ encoded }: { encoded: string }): string {
    encoded = this.URLSafeDecodeTransform(encoded)
    return Buffer.from(this.decode(encoded)).toString('utf8')
  }

  static UrlSafeValidate(encoded: string): boolean {
    return /^[A-Za-z0-9\-_]+$/.test(encoded)
  }
}
