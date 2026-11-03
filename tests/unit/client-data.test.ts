/**
 * clientDataJSON must match WebAuthn Level 3 §5.8.1.1 byte for byte, so the
 * expected values below are the spec's own test vectors (§16), which were
 * produced by that serialization.
 */

import { serializeClientData } from '../../src/background/client-data';
import { fromHex } from '../helpers/bytes';

const text = (hex: string) => new TextDecoder().decode(fromHex(hex));

describe('serializeClientData', () => {
  it('reproduces the §16.2 authentication clientDataJSON', () => {
    const vector = text(
      '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    );

    expect(
      serializeClientData({
        type: 'webauthn.get',
        challenge: 'OcDnUhQXulTUPo3JUXT0I97pvzzYBP9tZchXyav01Ag',
        origin: 'https://example.org',
        crossOrigin: false,
      })
    ).toBe(vector);
  });

  it('reproduces the §16.5 registration clientDataJSON from a cross-origin iframe', () => {
    const vector = text(
      '7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d'
    );

    expect(
      serializeClientData({
        type: 'webauthn.create',
        challenge: 'Th9MYZhpnjPBTxkhU_Sdfg6ONXfVrEFsXzrckqQfJ-U',
        origin: 'https://example.org',
        crossOrigin: true,
        topOrigin: 'https://example.com',
      })
    ).toBe(vector);
  });

  it('never writes topOrigin for a same-origin call', () => {
    expect(
      serializeClientData({
        type: 'webauthn.get',
        challenge: 'AA',
        origin: 'https://a.example',
        crossOrigin: false,
        topOrigin: 'https://b.example',
      })
    ).toBe(
      '{"type":"webauthn.get","challenge":"AA","origin":"https://a.example","crossOrigin":false}'
    );
  });

  it('escapes control characters with lower-case \\u escapes, as CCDToString does', () => {
    const out = serializeClientData({
      type: 'webauthn.get',
      challenge: 'a"b\\c\n\u001f',
      origin: 'https://x',
      crossOrigin: false,
    });

    expect(out).toContain('"challenge":"a\\"b\\\\c\\u000a\\u001f"');
  });

  it('refuses to serialize without a challenge or origin', () => {
    expect(() =>
      serializeClientData({
        type: 'webauthn.get',
        challenge: undefined as unknown as string,
        origin: 'https://x',
        crossOrigin: false,
      })
    ).toThrow(TypeError);
    expect(() =>
      serializeClientData({
        type: 'webauthn.get',
        challenge: 'AA',
        origin: undefined as unknown as string,
        crossOrigin: false,
      })
    ).toThrow(TypeError);
  });
});
