import {
  ListOperationResult,
  ListOperationResultStatus,
} from '../../src/types/types'

type Item = {
  id: string
  createdAt: Date
  updatedAt: Date
} & SealedAttributes
type SealedAttributes = {
  secret: string
}
type ListItemResult = ListOperationResult<Item, SealedAttributes>

describe('ListOperationResult', () => {
  it('should successfully assign success result', () => {
    const obj: ListItemResult = {
      status: ListOperationResultStatus.Success,
      items: [
        {
          id: 'dummy_id',
          createdAt: new Date(1),
          updatedAt: new Date(2),
          secret: 'dummy_secret',
        },
      ],
      nextToken: 'dummy_token',
    }
    expect(obj.status).toBe('Success')
    expect(obj.nextToken).toBe('dummy_token')
    expect(obj.items.length).toBe(1)
    expect(obj.items[0].id).toBe('dummy_id')
    expect(obj.items[0].createdAt).toEqual(new Date(1))
    expect(obj.items[0].updatedAt).toEqual(new Date(2))
    expect(obj.items[0].secret).toBe('dummy_secret')
  })

  it('should successfully assign failure result', () => {
    const obj: ListItemResult = {
      status: ListOperationResultStatus.Failure,
      cause: new Error('dummy_error'),
    }
    expect(obj.status).toBe('Failure')
    expect(obj.cause.message).toBe('dummy_error')
  })

  it('should successfully assign partial result', () => {
    const obj: ListItemResult = {
      status: ListOperationResultStatus.Partial,
      items: [
        {
          id: 'dummy_id',
          createdAt: new Date(1),
          updatedAt: new Date(2),
          secret: 'dummy_secret',
        },
      ],
      failed: [
        {
          item: {
            id: 'dummy_id',
            createdAt: new Date(1),
            updatedAt: new Date(2),
          },
          cause: new Error('dummy_error'),
        },
      ],
      nextToken: 'dummy_token',
    }
    expect(obj.status).toBe('Partial')
    expect(obj.nextToken).toBe('dummy_token')
    expect(obj.items.length).toBe(1)
    expect(obj.items[0].id).toBe('dummy_id')
    expect(obj.items[0].createdAt).toEqual(new Date(1))
    expect(obj.items[0].updatedAt).toEqual(new Date(2))
    expect(obj.items[0].secret).toBe('dummy_secret')
    expect(obj.items.length).toBe(1)
    expect(obj.failed[0].item.id).toBe('dummy_id')
    expect(obj.failed[0].item.createdAt).toEqual(new Date(1))
    expect(obj.failed[0].item.updatedAt).toEqual(new Date(2))
    expect(obj.failed[0].cause.message).toBe('dummy_error')
  })
})
