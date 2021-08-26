import { Buffer as BufferUtil } from './buffer'
/**
 * Utility class for Base64 encoding and decoding.
 */
export class Base64 {
  static decode(encoded: string): ArrayBuffer {
    return BufferUtil.fromString(atob(encoded))
  }

  static encode(buffer: ArrayBuffer): string {
    return btoa(BufferUtil.toString(buffer))
  }

  static decodeString(encoded: string): string {
    return atob(encoded)
  }

  static encodeString(string: string): string {
    return btoa(string)
  }
}
