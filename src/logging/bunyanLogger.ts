import { createLogger, stdSerializers } from 'browser-bunyan'
import { ConsolePlainStream } from '@browser-bunyan/console-plain-stream'
import * as t from 'io-ts'
import { pipe } from 'fp-ts/lib/pipeable'
import { fold } from 'fp-ts/lib/Either'

export const Level = t.union([
  t.literal('trace'),
  t.literal('debug'),
  t.literal('info'),
  t.literal('warn'),
  t.literal('error'),
  t.literal('fatal'),
])

export type Level = t.TypeOf<typeof Level>

export function getLogLevel(level: string | undefined): Level | undefined {
  if (!level) {
    return undefined
  }

  return pipe(
    Level.decode(level),
    fold(
      () => undefined,
      (v) => v,
    ),
  )
}

export function createBunyanLogger(
  identifier?: string,
  logLevel?: string,
): BunyanLogger {
  const level =
    getLogLevel(process.env.LOG_LEVEL) || getLogLevel(logLevel) || 'info'
  const log = createLogger({
    name: process.env.PROJECT_NAME || identifier || 'rootLogger',
    level,
    serializers: stdSerializers,
    stream: new ConsolePlainStream(),
  })
  return log
}

export type BunyanLogger = ReturnType<typeof createLogger>
