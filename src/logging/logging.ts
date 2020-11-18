import { createLogger, stdSerializers } from 'browser-bunyan'
import { ConsolePlainStream } from '@browser-bunyan/console-plain-stream'
import * as t from 'io-ts'
import { pipe } from 'fp-ts/lib/pipeable'
import { fold } from 'fp-ts/lib/Either'

const Level = t.union([
  t.literal('trace'),
  t.literal('debug'),
  t.literal('info'),
  t.literal('warn'),
  t.literal('error'),
  t.literal('fatal'),
])

type Level = t.TypeOf<typeof Level>

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

let log: Logger | undefined
export function getLogger(): Logger {
  const level = getLogLevel(process.env.LOG_LEVEL) || 'info'
  log =
    log ||
    createLogger({
      name: process.env.PROJECT_NAME || 'rootLogger',
      level,
      serializers: stdSerializers,
      stream: new ConsolePlainStream(),
    })
  return log
}

export type Logger = ReturnType<typeof createLogger>
