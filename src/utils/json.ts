/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { JsonValue } from '../types/types'

/**
 * Type guard for JsonValue
 *
 * @param {unknown} u Value to test for compliance with JsonValue type
 */
export function isJsonValue(u: unknown): u is JsonValue {
  if (u === undefined) return false
  if (u === null) return true

  if (typeof u === 'string') return true
  if (typeof u === 'number') return true
  if (typeof u === 'boolean') return true

  let values: unknown[] | undefined = undefined
  if (Array.isArray(u)) {
    values = u
  } else if (typeof u === 'object') {
    values = Object.values(u)
  }

  if (values) {
    return values.every(isJsonValue)
  }

  return false
}

export function isJsonRecord(u: unknown): u is Record<string, JsonValue> {
  if (u === undefined) return false
  if (u === null) return false
  if (Array.isArray(u)) return false

  if (typeof u === 'object') {
    return Object.values(u).every(isJsonValue)
  }

  return false
}
