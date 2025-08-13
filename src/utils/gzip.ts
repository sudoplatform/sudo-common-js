/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { gunzipSync, gzipSync, GzipOptions } from 'fflate'
import { Buffer as BufferUtil } from './buffer'

/**
 * Utility class for gzip compression/decompression with proper type handling.
 */
export class Gzip {
  /**
   * Compresses data using gzip and returns an ArrayBuffer
   * @param data The data to compress (ArrayBuffer)
   * @param options Optional compression options
   * @returns Compressed data as ArrayBuffer
   */
  static compress(data: ArrayBuffer, options?: GzipOptions): ArrayBuffer {
    const uint8Array = new Uint8Array(data)
    const compressed = gzipSync(uint8Array, options)
    return BufferUtil.toArrayBuffer(compressed)
  }

  /**
   * Decompresses gzip data and returns an ArrayBuffer
   * @param data The compressed data to decompress (ArrayBuffer)
   * @returns Decompressed data as ArrayBuffer
   */
  static decompress(data: ArrayBuffer): ArrayBuffer {
    const uint8Array = new Uint8Array(data)
    const decompressed = gunzipSync(uint8Array)
    return BufferUtil.toArrayBuffer(decompressed)
  }
}
