import {
  bodyToString,
  isBodyBlob,
  isBodyReadable,
  isBodyReadableStream,
} from '../../../src/utils/stream'
import { ReadableStream } from 'node:stream/web'
import { Readable } from 'node:stream'
import { TextEncoder, TextDecoder } from 'node:util'
import { Buffer as BufferUtil } from '../../../src/utils/buffer'

global.TextEncoder = TextEncoder as typeof global.TextEncoder
global.TextDecoder = TextDecoder as typeof global.TextDecoder

function toReadable(s: string): Readable {
  const readable = new Readable()
  readable.push(s)
  readable.push(null)
  return readable
}

class StringReadableStreamDefaultReader implements ReadableStreamDefaultReader<any> {
  private done = false
  private closeCallback:
    | ((value: PromiseLike<undefined> | undefined) => void)
    | undefined = undefined

  private close() {
    if (!this.done) {
      this.done = true
      this.closeCallback?.(undefined)
    }
  }

  public constructor(public readonly s: string) {}

  read(): Promise<ReadableStreamReadResult<any>> {
    if (!this.done) {
      this.close()
      return Promise.resolve({ value: Buffer.from(this.s), done: false })
    } else {
      return Promise.resolve({ value: undefined, done: true })
    }
  }

  releaseLock(): void {
    throw new Error('Method not implemented.')
  }

  closed: Promise<undefined> = new Promise((resolve) => {
    if (this.done) {
      resolve(undefined)
    } else {
      this.closeCallback = resolve
    }
  })

  cancel(): Promise<void> {
    throw new Error('Method not implemented.')
  }
}

class StringReadableStream extends ReadableStream<any> {
  private reader: StringReadableStreamDefaultReader

  public constructor(public readonly s: string) {
    super()
    this.reader = new StringReadableStreamDefaultReader(s)
  }

  getReader(): ReadableStreamDefaultReader<any> {
    return this.reader
  }
}

function toReadableStream(s: string): ReadableStream<Uint8Array> {
  return new StringReadableStream(s)
}

function toBlob(s: string): Blob {
  return {
    size: s.length,
    type: 'text/plain',
    arrayBuffer: () => {
      const arrayBuffer = BufferUtil.fromString(s)
      return Promise.resolve(arrayBuffer)
    },
    bytes: () => {
      throw new Error('Not implemented')
    },
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    stream: () => toReadableStream(s) as any,
    slice: () => {
      throw new Error('Not implemented')
    },
    text: () => Promise.resolve(s),
  }
}

describe('stream utils test suite', () => {
  const s = 'the string'

  describe('isBodyReadableStream', () => {
    it('should return true for a ReadableStream', () => {
      expect(isBodyReadableStream(toReadableStream(s) as any)).toEqual(true)
    })

    it('should return false for a Readable', () => {
      expect(isBodyReadableStream(toReadable(s))).toEqual(false)
    })

    it('should return false for a Blob', () => {
      expect(isBodyReadableStream(toBlob(s))).toEqual(false)
    })
  })

  describe('isBodyReadable', () => {
    it('should return false for a ReadableStream', () => {
      expect(isBodyReadable(toReadableStream(s) as any)).toEqual(false)
    })

    it('should return true for a Readable', () => {
      expect(isBodyReadable(toReadable(s))).toEqual(true)
    })

    it('should return false for a Blob', () => {
      expect(isBodyReadable(toBlob(s))).toEqual(false)
    })
  })

  describe('isBodyBlob', () => {
    it('should return false for a ReadableStream', () => {
      expect(isBodyBlob(toReadableStream(s) as any)).toEqual(false)
    })

    it('should return true for a Readable', () => {
      expect(isBodyBlob(toReadable(s))).toEqual(false)
    })

    it('should return false for a Blob', () => {
      expect(isBodyBlob(toBlob(s))).toEqual(true)
    })
  })

  describe('bodyToString', () => {
    it('should read a ReadableString', async () => {
      await expect(bodyToString(toReadableStream(s) as any)).resolves.toEqual(s)
    })

    it('should read a Readable', async () => {
      await expect(bodyToString(toReadable(s))).resolves.toEqual(s)
    })

    it('should read a Blob', async () => {
      await expect(bodyToString(toBlob(s))).resolves.toEqual(s)
    })
  })
})
