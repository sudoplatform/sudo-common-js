import { Base64 } from '../../src/utils/base64'

describe('Base64', () => {
  const dummyDataB64 = 'ZHVtbXlfZGF0YQ==' // b64(dummy_data)

  it('Base 64 encodes and decodes its own results', () => {
    const encoded = Base64.encode(Buffer.from('dummy_data', 'utf8'))
    const decoded = Base64.decode(encoded)
    expect(Buffer.from(decoded).toString('utf8')).toBe('dummy_data')
  })

  it('Base 64 encodes the same as other encoders', () => {
    expect(Base64.encode(Buffer.from('dummy_data', 'utf8'))).toEqual(
      dummyDataB64,
    )
  })

  it('Base 64 decodes the same as other decoders', () => {
    expect(Base64.decode(dummyDataB64)).toEqual(
      new Uint8Array(Buffer.from('dummy_data', 'utf8')),
    )
  })

  const encodedPK =
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt88ya9gRqtqPA75DyRMY13SkDIHveCqCpngTnMUmLpRvd7HigAIkVEfKWqxG7+QdUPUUr2heBkG3WoGgljGXkMRNdcZek4LZ3+W7o2vCrp6h/19bmPxgQDRSasT1Br7zFk2yKmV/WBwI+9SoIqNU/oxO9ucdK6D0jL/Po32UfCFs+zsNE7Hg3gXNR/fihqnlE+oZETlFmF7QkxXtTaPv+acTQCrWT1V4f+hMQ4JBFKDORZ2Agb0L3Fn45R0rsXofkyvUNMxRztffbZm1m6pqysRRgOgHEQGULCGxlO6VgkhJFhxfQd1iLyK0cYRyg53t5dr9aO1tRAM2S2Bn65sKewIDAQAB'
  const decodedPKBuffer = Buffer.from(encodedPK, 'base64')
  it('should encode like buffer encode/decode', () => {
    expect(Base64.encode(decodedPKBuffer)).toEqual(encodedPK)
  })
})
