/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Readable } from 'stream'
import { FatalError } from '../errors/error'

/**
 * Read a ReadableStream in to a string.
 *
 * This is used in browser environments
 *
 * @param stream The ReadableStream to read
 *
 * @returns The string
 */
const readableStreamToString = async (
  stream: ReadableStream,
): Promise<string> => {
  const reader = stream.getReader()

  const decoder = new TextDecoder('utf-8')
  let string = ''
  while (true) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    string += decoder.decode(value, { stream: true })
  }
  string += decoder.decode()
  return string
}

/**
 * Read a Readable in to a string.
 *
 * This is used in node environments
 *
 * @param readable The Readable to read
 *
 * @returns The string
 */
const readableToString = (readable: Readable): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = []
    readable.on('data', (chunk: Uint8Array) => chunks.push(chunk))
    readable.on('error', reject)
    readable.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  })

export function isBodyReadableStream(
  body: ReadableStream | Readable | Blob,
): body is ReadableStream {
  return typeof (body as ReadableStream).getReader === 'function'
}

export function isBodyBlob(
  body: ReadableStream | Readable | Blob,
): body is Blob {
  return typeof body === 'object' && body.hasOwnProperty('size')
}

export function isBodyReadable(
  body: ReadableStream | Readable | Blob,
): body is Readable {
  return !isBodyReadableStream(body) && !isBodyBlob(body)
}

export const bodyToString = async (
  body: ReadableStream | Readable | Blob,
): Promise<string> => {
  if (isBodyReadableStream(body)) {
    return readableStreamToString(body)
  }

  if (isBodyReadable(body)) {
    return readableToString(body)
  }

  if (isBodyBlob(body)) {
    return body.text()
  }

  throw new FatalError('Unknown body type')
}
