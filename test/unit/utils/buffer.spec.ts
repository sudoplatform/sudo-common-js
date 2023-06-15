import { Buffer as BufferUtil } from '../../../src/utils/buffer'
import { TextEncoder, TextDecoder } from 'node:util'
import '../../matchers'

global.TextEncoder = TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

describe('Buffer', () => {
  it('split()', () => {
    const buffer = Buffer.from('1234567', 'utf8')
    const { lhs, rhs } = BufferUtil.split(buffer, 3)
    expect(Buffer.from(lhs).toString('utf8')).toBe('123')
    expect(Buffer.from(rhs).toString('utf8')).toBe('4567')
  })

  it('concat()', () => {
    const lhs = Buffer.from('123', 'utf8')
    const rhs = Buffer.from('4567', 'utf8')
    const buffer = BufferUtil.concat(lhs, rhs)
    expect(Buffer.from(buffer).toString('utf8')).toBe('1234567')
  })

  describe('fromString', () => {
    it('constructs a buffer from a string correctly', () => {
      expect(BufferUtil.fromString('abcd')).toEqualUint8Array(
        new Uint8Array([
          'a'.charCodeAt(0),
          'b'.charCodeAt(0),
          'c'.charCodeAt(0),
          'd'.charCodeAt(0),
        ]),
      )
    })

    it('constructs a buffer from a multi-byte string correctly', () => {
      expect(BufferUtil.fromString('😎abcd😎efgh😎')).toEqualUint8Array(
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
    })

    it('accepts output of BufferUtil.toString', () => {
      const data = new Uint8Array([
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
      ])
      expect(
        BufferUtil.fromString(BufferUtil.toString(data)),
      ).toEqualUint8Array(data)
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
        BufferUtil.fromBinaryString(BufferUtil.toBinaryString(dataBuffer)),
      ).toEqualUint8Array(dataBuffer)
    })
  })
})
