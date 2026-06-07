/**
 * TOTP / HOTP — RFC 6238 / RFC 4226
 *
 * Pure crypto helpers used by the TOTP store. No DOM, no chrome APIs.
 */

import { hmac } from '@noble/hashes/hmac';
import { sha1 } from '@noble/hashes/sha1';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpOptions {
  secret: Uint8Array;
  algorithm?: TotpAlgorithm;
  digits?: number;
  period?: number;
  timestamp?: number;
}

export interface HotpOptions extends Omit<TotpOptions, 'period' | 'timestamp'> {
  counter: number;
}

export interface OtpauthParams {
  type: 'totp' | 'hotp';
  label: string;
  issuer: string;
  account: string;
  secret: Uint8Array;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  counter: number;
}

const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;
const T0 = 0;

function hashFor(algo: TotpAlgorithm) {
  switch (algo) {
    case 'SHA256':
      return sha256;
    case 'SHA512':
      return sha512;
    case 'SHA1':
    default:
      return sha1;
  }
}

function counterBytes(counter: number): Uint8Array {
  const out = new Uint8Array(8);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  out[0] = (high >>> 24) & 0xff;
  out[1] = (high >>> 16) & 0xff;
  out[2] = (high >>> 8) & 0xff;
  out[3] = high & 0xff;
  out[4] = (low >>> 24) & 0xff;
  out[5] = (low >>> 16) & 0xff;
  out[6] = (low >>> 8) & 0xff;
  out[7] = low & 0xff;
  return out;
}

function truncate(hmacBytes: Uint8Array, digits: number): number {
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const binary =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);
  return binary % 10 ** digits;
}

function formatCode(value: number, digits: number): string {
  return value.toString().padStart(digits, '0');
}

/**
 * Generate a HOTP code (RFC 4226).
 */
export function generateHotp(opts: HotpOptions): string {
  const digits = opts.digits ?? DEFAULT_DIGITS;
  if (digits < 6 || digits > 10) {
    throw new Error(`Invalid digits: ${digits} (must be 6-10)`);
  }
  const hash = hashFor(opts.algorithm ?? 'SHA1');
  const mac = hmac(hash, opts.secret, counterBytes(opts.counter));
  return formatCode(truncate(mac, digits), digits);
}

/**
 * Generate a TOTP code (RFC 6238) for the given timestamp (ms since epoch).
 * Defaults: SHA-1, 6 digits, 30s period — matches Google Authenticator.
 */
export function generateTotp(opts: TotpOptions): string {
  const period = opts.period ?? DEFAULT_PERIOD;
  const timestamp = opts.timestamp ?? Date.now();
  const counter = Math.floor((timestamp - T0 * 1000) / (period * 1000));
  return generateHotp({ ...opts, counter });
}

/**
 * Seconds remaining in the current TOTP window.
 */
export function timeRemaining(
  timestamp: number = Date.now(),
  period: number = DEFAULT_PERIOD
): number {
  return period - (Math.floor(timestamp / 1000) % period);
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Uint8Array {
  const cleaned = input.replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  if (!cleaned) return new Uint8Array(0);
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error('Invalid base32 string');
  }

  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of cleaned) {
    const value = BASE32_ALPHABET.indexOf(ch);
    if (value < 0) {
      throw new Error(`Invalid base32 character: ${ch}`);
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

export function base32Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return output;
}

function percentDecode(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

/**
 * Parse an otpauth:// URI. Returns null for non-otpauth URLs.
 * Throws on invalid otpauth input.
 */
export function parseOtpauth(uri: string): OtpauthParams {
  const trimmed = uri.trim();
  if (!trimmed.toLowerCase().startsWith('otpauth://')) {
    throw new Error('Not an otpauth:// URI');
  }
  const url = new URL(trimmed);
  const typeRaw = url.host.toLowerCase();
  if (typeRaw !== 'totp' && typeRaw !== 'hotp') {
    throw new Error(`Unsupported OTP type: ${typeRaw}`);
  }

  const label = percentDecode(url.pathname.replace(/^\/+/, ''));
  let issuer = url.searchParams.get('issuer') || '';
  let account = '';
  if (label.includes(':')) {
    const [labelIssuer, ...rest] = label.split(':');
    if (!issuer) issuer = labelIssuer.trim();
    account = rest.join(':').trim();
  } else {
    account = label;
  }

  const secretParam = url.searchParams.get('secret');
  if (!secretParam) {
    throw new Error('Missing secret in otpauth URI');
  }
  const secret = base32Decode(secretParam);

  const algoRaw = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  if (algoRaw !== 'SHA1' && algoRaw !== 'SHA256' && algoRaw !== 'SHA512') {
    throw new Error(`Unsupported algorithm: ${algoRaw}`);
  }

  const digits = parseInt(url.searchParams.get('digits') || `${DEFAULT_DIGITS}`, 10);
  const period = parseInt(url.searchParams.get('period') || `${DEFAULT_PERIOD}`, 10);
  const counter = parseInt(url.searchParams.get('counter') || '0', 10);

  if (digits < 6 || digits > 10) {
    throw new Error(`Unsupported digits: ${digits}`);
  }
  if (period < 1) {
    throw new Error(`Unsupported period: ${period}`);
  }

  return {
    type: typeRaw,
    label,
    issuer: issuer.trim(),
    account,
    secret,
    algorithm: algoRaw,
    digits,
    period,
    counter,
  };
}

/**
 * Build an otpauth URI from parameters. Used when exporting/displaying.
 */
export function buildOtpauth(params: Omit<OtpauthParams, 'label'> & { label?: string }): string {
  const type = params.type;
  const labelRaw =
    params.label ?? (params.issuer ? `${params.issuer}:${params.account}` : params.account);
  const label = encodeURIComponent(labelRaw);
  const query = new URLSearchParams();
  query.set('secret', base32Encode(params.secret));
  if (params.issuer) query.set('issuer', params.issuer);
  if (params.algorithm !== 'SHA1') query.set('algorithm', params.algorithm);
  if (params.digits !== DEFAULT_DIGITS) query.set('digits', `${params.digits}`);
  if (type === 'totp' && params.period !== DEFAULT_PERIOD) {
    query.set('period', `${params.period}`);
  }
  if (type === 'hotp') {
    query.set('counter', `${params.counter}`);
  }
  return `otpauth://${type}/${label}?${query.toString()}`;
}
