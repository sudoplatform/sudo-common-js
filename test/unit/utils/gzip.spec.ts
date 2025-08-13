import { Gzip } from '../../../src/utils/gzip'
import { Buffer as BufferUtil } from '../../../src/utils/buffer'
import { TextEncoder, TextDecoder } from 'node:util'

global.TextEncoder = TextEncoder as typeof global.TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

describe('Gzip utility test suite', () => {
  // Use a long, repetitive string to ensure compression is effective
  const text = 'The quick brown fox jumps over the lazy dog. '.repeat(100)
  const data = BufferUtil.fromString(text)

  describe('compress', () => {
    it('should compress a string to an ArrayBuffer', () => {
      const compressed = Gzip.compress(data)
      expect(compressed).toBeInstanceOf(ArrayBuffer)
      // Should be smaller than original for this text
      expect(compressed.byteLength).toBeLessThanOrEqual(data.byteLength)
    })
  })

  describe('decompress', () => {
    it('should decompress a compressed ArrayBuffer to the original', () => {
      const compressed = Gzip.compress(data)
      const decompressed = Gzip.decompress(compressed)
      expect(decompressed).toBeInstanceOf(ArrayBuffer)
      // Should match original string
      const result = BufferUtil.toString(decompressed)
      expect(result).toBe(text)
    })

    it('should throw if input is not valid gzip data', () => {
      const invalid = BufferUtil.fromString('not gzip')
      expect(() => Gzip.decompress(invalid)).toThrow()
    })
  })

  describe('roundtrip', () => {
    it('should compress and decompress binary data', () => {
      const binary = new Uint8Array([0, 255, 127, 128, 1, 2, 3, 4]).buffer
      const compressed = Gzip.compress(binary)
      const decompressed = Gzip.decompress(compressed)
      expect(decompressed).toStrictEqual(binary)
    })

    it('should compress and decompress a string (roundtrip)', () => {
      const original =
        'Hello, gzip roundtrip! 1234567890 abcdefghijklmnopqrstuvwxyz'
      const arr = BufferUtil.fromString(original)
      const compressed = Gzip.compress(arr)
      const decompressed = Gzip.decompress(compressed)
      const result = BufferUtil.toString(decompressed)
      expect(result).toBe(original)
    })
  })
})
