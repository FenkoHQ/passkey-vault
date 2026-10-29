/**
 * A deliberately unforgiving CBOR decoder for checking what the vault emits.
 *
 * WebAuthn RPs decode attestation objects and COSE keys with all kinds of
 * CBOR libraries; the safest output is the CTAP2 canonical form, which every
 * one of them accepts (CTAP 2.2 §8 "Message Encoding", RFC 8949 §4.2.3):
 *
 *   - integers, lengths and simple values in their shortest form
 *   - definite lengths only
 *   - map keys unique and sorted length-first, then bytewise
 *   - text strings valid UTF-8
 *   - no tags, no floats, no trailing bytes (unless the caller expects them)
 *
 * Maps decode to `Map` so integer and text keys stay distinct, byte strings
 * to Uint8Array.
 */

export class CborError extends Error {
  constructor(
    message: string,
    readonly offset: number
  ) {
    super(`CBOR @${offset}: ${message}`);
    this.name = 'CborError';
  }
}

export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>;

export interface DecodeOptions {
  /** Enforce CTAP2 canonical encoding (default true). */
  canonical?: boolean;
  /** Allow bytes after the first item; `end` says where it stopped. */
  allowTrailing?: boolean;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

export function decodeCbor(
  input: Uint8Array | ArrayBuffer,
  options: DecodeOptions = {}
): { value: CborValue; end: number } {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const canonical = options.canonical !== false;
  let pos = 0;

  const need = (n: number) => {
    if (pos + n > bytes.length) throw new CborError(`truncated, need ${n} more bytes`, pos);
  };

  function readArgument(info: number, start: number): number | bigint {
    if (info < 24) return info;
    let value: number | bigint;
    let minimum: number | bigint;
    switch (info) {
      case 24:
        need(1);
        value = bytes[pos];
        pos += 1;
        minimum = 24;
        break;
      case 25:
        need(2);
        value = (bytes[pos] << 8) | bytes[pos + 1];
        pos += 2;
        minimum = 0x100;
        break;
      case 26:
        need(4);
        value = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getUint32(0);
        pos += 4;
        minimum = 0x10000;
        break;
      case 27: {
        need(8);
        const big = new DataView(bytes.buffer, bytes.byteOffset + pos, 8).getBigUint64(0);
        pos += 8;
        value = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
        minimum = 0x100000000;
        break;
      }
      case 31:
        throw new CborError('indefinite length is not allowed', start);
      default:
        throw new CborError(`reserved additional info ${info}`, start);
    }
    if (canonical && value < minimum) {
      throw new CborError(`argument ${value} not in shortest form`, start);
    }
    return value;
  }

  function readLength(info: number, start: number): number {
    const length = readArgument(info, start);
    if (typeof length === 'bigint' || length > bytes.length) {
      throw new CborError(`length ${length} exceeds input`, start);
    }
    return length;
  }

  function item(depth: number): CborValue {
    if (depth > 64) throw new CborError('nesting too deep', pos);
    need(1);
    const start = pos;
    const initial = bytes[pos++];
    const major = initial >> 5;
    const info = initial & 0x1f;

    switch (major) {
      case 0:
        return readArgument(info, start);
      case 1: {
        const arg = readArgument(info, start);
        return typeof arg === 'bigint' ? -1n - arg : -1 - arg;
      }
      case 2: {
        const length = readLength(info, start);
        need(length);
        const value = bytes.slice(pos, pos + length);
        pos += length;
        return value;
      }
      case 3: {
        const length = readLength(info, start);
        need(length);
        let text: string;
        try {
          text = utf8.decode(bytes.subarray(pos, pos + length));
        } catch {
          throw new CborError('text string is not valid UTF-8', start);
        }
        pos += length;
        return text;
      }
      case 4: {
        const length = readLength(info, start);
        const items: CborValue[] = [];
        for (let i = 0; i < length; i++) items.push(item(depth + 1));
        return items;
      }
      case 5: {
        const length = readLength(info, start);
        const map = new Map<CborValue, CborValue>();
        let previousKey: Uint8Array | null = null;
        const seen = new Set<string>();
        for (let i = 0; i < length; i++) {
          const keyStart = pos;
          const key = item(depth + 1);
          const keyBytes = bytes.slice(keyStart, pos);
          const keyId = Array.from(keyBytes).join(',');
          if (seen.has(keyId)) throw new CborError(`duplicate map key ${String(key)}`, keyStart);
          seen.add(keyId);
          if (canonical && previousKey && compareBytes(previousKey, keyBytes) >= 0) {
            throw new CborError(`map key ${String(key)} out of canonical order`, keyStart);
          }
          previousKey = keyBytes;
          if (key instanceof Uint8Array || key instanceof Map || Array.isArray(key)) {
            throw new CborError('map keys must be integers or text', keyStart);
          }
          map.set(key, item(depth + 1));
        }
        return map;
      }
      case 6:
        throw new CborError('tags are not expected in WebAuthn structures', start);
      case 7:
        switch (info) {
          case 20:
            return false;
          case 21:
            return true;
          case 22:
            return null;
          case 23:
            return undefined;
          case 24: {
            need(1);
            const simple = bytes[pos++];
            if (canonical && simple < 32)
              throw new CborError('simple value not in shortest form', start);
            throw new CborError(`unassigned simple value ${simple}`, start);
          }
          case 25:
          case 26:
          case 27:
            throw new CborError('floating point is not expected in WebAuthn structures', start);
          case 31:
            throw new CborError('break outside indefinite item', start);
          default:
            throw new CborError(`unassigned simple value ${info}`, start);
        }
    }
    throw new CborError(`unknown major type ${major}`, start);
  }

  const value = item(0);
  if (!options.allowTrailing && pos !== bytes.length) {
    throw new CborError(`${bytes.length - pos} trailing bytes`, pos);
  }
  return { value, end: pos };
}
