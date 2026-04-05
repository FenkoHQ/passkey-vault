/**
 * Base64 and Base64URL encoding/decoding utilities.
 * Single source of truth — do not duplicate these elsewhere.
 */

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] & 0xff);
  }
  return btoa(binary);
}

export function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
  return arrayBufferToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64urlToBase64(base64url: string): string {
  if (!base64url || typeof base64url !== 'string') {
    throw new Error('base64urlToBase64 requires a string input');
  }
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (base64.length % 4)) % 4;
  if (padding > 0) {
    base64 += '='.repeat(padding);
  }
  return base64;
}

export function base64URLToArrayBuffer(input: unknown): ArrayBuffer {
  if (input instanceof ArrayBuffer) return input;
  if (input instanceof Uint8Array) return input.buffer as ArrayBuffer;
  if (ArrayBuffer.isView(input)) return (input as ArrayBufferView).buffer as ArrayBuffer;
  if (
    input != null &&
    typeof input === 'object' &&
    'type' in input &&
    (input as { type: string }).type === 'Buffer' &&
    'data' in input &&
    Array.isArray((input as { data: unknown }).data)
  ) {
    return new Uint8Array((input as { data: number[] }).data).buffer;
  }
  if (input == null) throw new TypeError('Unsupported base64 input type: null/undefined');

  const str = typeof input === 'string' ? input : String(input);
  if (str.length === 0) throw new Error('Empty base64 string provided');

  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }
  return bytes.buffer;
}

/**
 * Flexible base64 decoder that tries base64url first, then standard base64.
 */
export function decodeBase64Flexible(value: unknown): ArrayBuffer {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) return (value as ArrayBufferView).buffer as ArrayBuffer;
  if (
    value != null &&
    typeof value === 'object' &&
    'type' in value &&
    (value as { type: string }).type === 'Buffer' &&
    'data' in value &&
    Array.isArray((value as { data: unknown }).data)
  ) {
    return new Uint8Array((value as { data: number[] }).data).buffer;
  }
  if (typeof value !== 'string') throw new TypeError('Invalid base64 input type');

  try {
    return base64URLToArrayBuffer(value);
  } catch {
    /* fall through to standard base64 */
  }

  const padded = value.length % 4 === 0 ? value : value + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }
  return bytes.buffer;
}

export function uint8ArrayToBase64(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

export function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
