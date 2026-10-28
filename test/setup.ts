/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Global Jest setup, run before each test file.
 *
 * The jsdom test environment does not expose TextEncoder/TextDecoder as
 * globals. Newer AWS SDK (@smithy/*) builds reference them at module load
 * time, so they must exist before any spec imports those modules. Polyfill
 * them from Node's `util` module.
 */
import { TextEncoder, TextDecoder } from 'node:util'

if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = TextEncoder
}

if (typeof globalThis.TextDecoder === 'undefined') {
  globalThis.TextDecoder = TextDecoder as typeof globalThis.TextDecoder
}
