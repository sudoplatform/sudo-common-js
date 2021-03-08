import { Base64 } from './base64'
global.btoa = (b) => Buffer.from(b).toString('base64')
global.atob = (a) => Buffer.from(a, 'base64').toString()

describe('Base64', () => {
  it('Base 64 encode and decode.', () => {
    const encoded = Base64.encode(Buffer.from('dummy_data', 'utf8'))
    const decoded = Base64.decode(encoded)
    expect(Buffer.from(decoded).toString('utf8')).toBe('dummy_data')
  })
})
