import { expectTypeOf } from 'expect-type'
import { RequireOnlyOne } from '../../../src/types/types'

describe('Types Tests', () => {
  describe('RequireOnlyOne', () => {
    type TwoOptionsRequireOnlyOneTestType = RequireOnlyOne<
      {
        a: string
        b: number
        c: boolean
      },
      'a' | 'b'
    >
    type ThreeOptionsRequireOnlyOneTestType = RequireOnlyOne<
      {
        a: string[]
        b: number
        c: boolean
        d: string
      },
      'a' | 'b' | 'c'
    >

    it('should allow object with only first of two keys', () => {
      expectTypeOf<{ a: string; c: boolean }>({
        a: 'test',
        c: false,
      }).toExtend<TwoOptionsRequireOnlyOneTestType>()
    })

    it('should allow object with only second of two keys', () => {
      expectTypeOf<{ b: number; c: boolean }>({
        b: 123,
        c: true,
      }).toExtend<TwoOptionsRequireOnlyOneTestType>()
    })

    it('should not allow object with both of two keys', () => {
      expectTypeOf<{ a: string; b: number; c: boolean }>({
        a: 'test',
        b: 123,
        c: false,
      }).not.toExtend<TwoOptionsRequireOnlyOneTestType>()
    })

    it('should not allow object with neither of two keys', () => {
      expectTypeOf<{ c: boolean }>({
        c: true,
      }).not.toExtend<TwoOptionsRequireOnlyOneTestType>()
    })

    it('should allow object with only first of three keys', () => {
      expectTypeOf<{ a: string[]; d: string }>({
        a: ['test1', 'test2'],
        d: 'test',
      }).toExtend<ThreeOptionsRequireOnlyOneTestType>()
    })

    it('should allow object with only second of three keys', () => {
      expectTypeOf<{ b: number; d: string }>({
        b: 456,
        d: 'test',
      }).toExtend<ThreeOptionsRequireOnlyOneTestType>()
    })

    it('should allow object with only third of three keys', () => {
      expectTypeOf<{ c: boolean; d: string }>({
        c: false,
        d: 'test',
      }).toExtend<ThreeOptionsRequireOnlyOneTestType>()
    })

    it('should not allow object with more than one of three keys', () => {
      expectTypeOf<{ a: string[]; b: number; d: string }>({
        a: ['test1'],
        b: 789,
        d: 'test',
      }).not.toExtend<ThreeOptionsRequireOnlyOneTestType>()
    })

    it('should not allow object with none of three keys', () => {
      expectTypeOf<{ d: string }>({
        d: 'test',
      }).not.toExtend<ThreeOptionsRequireOnlyOneTestType>()
    })
  })
})
