import { Buffer as BufferUtil } from '../../../src/utils/buffer'
import { TextEncoder, TextDecoder } from 'node:util'
import '../../matchers'

global.TextEncoder = TextEncoder as typeof global.TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

describe('Buffer', () => {
  it('split()', () => {
    const buffer = BufferUtil.fromString('1234567')
    const { lhs, rhs } = BufferUtil.split(buffer, 3)
    expect(Buffer.from(lhs).toString('utf8')).toBe('123')
    expect(Buffer.from(rhs).toString('utf8')).toBe('4567')
  })

  it('concat()', () => {
    const lhs = BufferUtil.fromString('123')
    const rhs = BufferUtil.fromString('4567')
    const buffer = BufferUtil.concat(lhs, rhs)
    expect(Buffer.from(buffer).toString('utf8')).toBe('1234567')
  })

  describe('fromString', () => {
    it('constructs a buffer from a string correctly', () => {
      expect(BufferUtil.fromString('abcd')).toEqual(
        new Uint8Array([
          'a'.charCodeAt(0),
          'b'.charCodeAt(0),
          'c'.charCodeAt(0),
          'd'.charCodeAt(0),
        ]).buffer,
      )
    })

    it('constructs a buffer from a multi-byte string correctly', () => {
      expect(BufferUtil.fromString('😎abcd😎efgh😎')).toEqual(
        new Uint8Array([
          0xf0,
          0x9f,
          0x98,
          0x8e,
          'a'.charCodeAt(0),
          'b'.charCodeAt(0),
          'c'.charCodeAt(0),
          'd'.charCodeAt(0),
          0xf0,
          0x9f,
          0x98,
          0x8e,
          'e'.charCodeAt(0),
          'f'.charCodeAt(0),
          'g'.charCodeAt(0),
          'h'.charCodeAt(0),
          0xf0,
          0x9f,
          0x98,
          0x8e,
        ]).buffer,
      )
    })

    it('accepts output of BufferUtil.toString', () => {
      const data = BufferUtil.toArrayBuffer(
        new Uint8Array([
          0xf0,
          0x9f,
          0x98,
          0x8e,
          'a'.charCodeAt(0),
          'b'.charCodeAt(0),
          'c'.charCodeAt(0),
          'd'.charCodeAt(0),
          0xf0,
          0x9f,
          0x98,
          0x8e,
          'e'.charCodeAt(0),
          'f'.charCodeAt(0),
          'g'.charCodeAt(0),
          'h'.charCodeAt(0),
          0xf0,
          0x9f,
          0x98,
          0x8e,
        ]),
      )
      const dataString = BufferUtil.toString(data)
      expect(BufferUtil.fromString(dataString)).toEqual(data)
    })
  })

  describe('toString', () => {
    it('constructs a string from a buffer correctly', () => {
      expect(
        BufferUtil.toString(
          new Uint8Array([
            'a'.charCodeAt(0),
            'b'.charCodeAt(0),
            'c'.charCodeAt(0),
            'd'.charCodeAt(0),
          ]),
        ),
      ).toEqual('abcd')
    })

    it('constructs a multi-byte string from a buffer correctly', () => {
      expect(
        BufferUtil.toString(
          new Uint8Array([
            0xf0,
            0x9f,
            0x98,
            0x8e,
            'a'.charCodeAt(0),
            'b'.charCodeAt(0),
            'c'.charCodeAt(0),
            'd'.charCodeAt(0),
            0xf0,
            0x9f,
            0x98,
            0x8e,
            'e'.charCodeAt(0),
            'f'.charCodeAt(0),
            'g'.charCodeAt(0),
            'h'.charCodeAt(0),
            0xf0,
            0x9f,
            0x98,
            0x8e,
          ]),
        ),
      ).toEqual('😎abcd😎efgh😎')
    })

    it('accepts output of BufferUtil.fromString', () => {
      expect(
        BufferUtil.toString(BufferUtil.fromString('😎abcd😎efgh😎')),
      ).toEqual('😎abcd😎efgh😎')
    })
  })

  describe('toArrayBuffer', () => {
    it('constructs an ArrayBuffer from a buffer correctly', () => {
      const uint8Array = new Uint8Array([1, 2, 3, 4])
      const arrayBuffer = BufferUtil.toArrayBuffer(uint8Array)
      expect(arrayBuffer).toEqual(uint8Array.buffer)
      expect(BufferUtil.toString(arrayBuffer)).toEqual(
        BufferUtil.toString(uint8Array.buffer),
      )
    })
  })

  describe('toBinaryString and fromBinaryString', () => {
    /*
     * Since these methods rely on violating the rule that javascript strings
     * are utf-8 strings in order to use browser atob and btoa functions,
     * best way to test is to verify that what we put in we
     * get out when we start with binary data.
     *
     * Note, that there's no way to express the reverse symmetric operation
     * in javascript.
     */
    it('is not lossy', () => {
      const data: number[] = []
      for (let i = 0; i < 2048; ++i) {
        data.push(Math.floor(Math.random() * 256))
      }
      const dataBuffer = new Uint8Array(data)

      expect(
        BufferUtil.fromBinaryString(
          BufferUtil.toBinaryString(BufferUtil.toArrayBuffer(dataBuffer)),
        ),
      ).toEqual(dataBuffer.buffer)
    })
  })
})
