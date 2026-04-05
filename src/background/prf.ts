/**
 * WebAuthn PRF (Pseudo-Random Function) extension handling.
 * Computes HMAC-SHA256 PRF outputs and encodes them for authenticator data.
 */

import {
  arrayBufferToBase64URL,
  base64URLToArrayBuffer,
  base64urlToBase64,
  decodeBase64Flexible,
} from '../utils/base64';
import { encodeMapHeader, encodeTextString, encodeByteString } from './cbor';

export interface PrfResults {
  results: {
    first?: ArrayBuffer;
    second?: ArrayBuffer;
  };
}

export interface PrfEvalInput {
  first?: unknown;
  second?: unknown;
}

/**
 * Select the PRF eval input from the extensions payload.
 * Checks eval, then evalByCredential with flexible key matching.
 */
export function selectPrfEval(
  prfInput:
    | { eval?: PrfEvalInput; evalByCredential?: Record<string, PrfEvalInput> }
    | null
    | undefined,
  credentialId?: string
): PrfEvalInput | null {
  if (!prfInput) return null;
  if (prfInput.eval) return prfInput.eval;
  const map = prfInput.evalByCredential;
  if (!map) return null;

  const candidates = new Set<string>();
  if (credentialId) {
    candidates.add(credentialId);
    try {
      candidates.add(base64urlToBase64(credentialId));
    } catch {
      /* ignore conversion failure */
    }
  }

  for (const key of Object.keys(map)) {
    if (candidates.has(key)) return map[key];
    try {
      const decoded = base64URLToArrayBuffer(key);
      const asUrl = arrayBufferToBase64URL(decoded);
      if (asUrl && candidates.has(asUrl)) return map[key];
    } catch {
      /* ignore conversion failure */
    }
  }
  return null;
}

/**
 * Get or lazily create a PRF key for a passkey.
 * Falls back to SHA-256(privateKey) if no explicit prfKey stored.
 */
export async function getOrCreatePrfKey(passkey: {
  prfKey?: string;
  privateKey: string;
}): Promise<ArrayBuffer> {
  if (passkey.prfKey) return decodeBase64Flexible(passkey.prfKey);
  const privateKeyBytes = base64URLToArrayBuffer(passkey.privateKey);
  const derived = await crypto.subtle.digest('SHA-256', privateKeyBytes);
  passkey.prfKey = arrayBufferToBase64URL(derived);
  return derived;
}

/**
 * Normalize a PRF input value from various formats into an ArrayBuffer.
 */
export function normalizePrfInput(input: unknown): ArrayBuffer | null {
  if (!input) return null;
  if (input instanceof ArrayBuffer) return input;
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
  if (Array.isArray(input)) return new Uint8Array(input as number[]).buffer;

  if (typeof input === 'string') {
    try {
      return base64URLToArrayBuffer(input);
    } catch {
      try {
        return decodeBase64Flexible(input);
      } catch {
        return null;
      }
    }
  }

  if (typeof input === 'object' && input !== null) {
    const keys = Object.keys(input);
    if (keys.length > 0 && keys.every((k) => !isNaN(Number(k)))) {
      const maxIndex = Math.max(...keys.map(Number));
      const arr = new Uint8Array(maxIndex + 1);
      for (const key of keys) arr[Number(key)] = (input as Record<string, number>)[key];
      return arr.buffer;
    }
  }
  return null;
}

/**
 * Compute PRF HMAC-SHA256 results from eval input.
 */
export async function computePrfResults(
  prfKey: ArrayBuffer,
  evalInput: PrfEvalInput
): Promise<PrfResults | null> {
  if (!evalInput) return null;
  const results: PrfResults = { results: {} };
  const first = normalizePrfInput(evalInput.first);
  const second = normalizePrfInput(evalInput.second);

  if (first) results.results.first = await hmacSha256(prfKey, first);
  if (second) results.results.second = await hmacSha256(prfKey, second);

  if (!results.results.first && !results.results.second) return null;
  return results;
}

async function hmacSha256(keyBytes: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, data);
}

/**
 * Build clientExtensionResults including PRF output if present.
 */
export function buildClientExtensionResults(
  prfResults: PrfResults | null
): Record<string, unknown> {
  const baseResults: Record<string, unknown> = { credProps: { rk: true } };
  if (!prfResults?.results) return baseResults;

  const encoded: { results: Record<string, string> } = { results: {} };
  if (prfResults.results.first) {
    encoded.results.first = arrayBufferToBase64URL(prfResults.results.first);
  }
  if (prfResults.results.second) {
    encoded.results.second = arrayBufferToBase64URL(prfResults.results.second);
  }
  if (encoded.results.first || encoded.results.second) baseResults.prf = encoded;
  return baseResults;
}

/**
 * Encode PRF results as a CBOR extension block for authenticator data.
 */
export function encodePrfExtension(prfResults: PrfResults | null): Uint8Array | null {
  if (!prfResults?.results) return null;

  const resultEntries: number[] = [];
  let resultCount = 0;

  if (prfResults.results.first) {
    resultEntries.push(...encodeTextString('first'));
    resultEntries.push(...encodeByteString(new Uint8Array(prfResults.results.first)));
    resultCount++;
  }
  if (prfResults.results.second) {
    resultEntries.push(...encodeTextString('second'));
    resultEntries.push(...encodeByteString(new Uint8Array(prfResults.results.second)));
    resultCount++;
  }
  if (resultCount === 0) return null;

  const resultsMap = [...encodeMapHeader(resultCount), ...resultEntries];
  const prfMap = [...encodeMapHeader(1), ...encodeTextString('results'), ...resultsMap];
  const extensions = [...encodeMapHeader(1), ...encodeTextString('prf'), ...prfMap];
  return new Uint8Array(extensions);
}
