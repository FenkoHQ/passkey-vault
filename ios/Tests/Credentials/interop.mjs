import { webcrypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { join } from 'node:path';

const { subtle } = webcrypto;
const directory = process.argv[3];
const password = 'backup-test-🔑-café';
const payload = JSON.stringify({ passkeys: [], totpEntries: [], note: 'interop' });
const bytes = (value) => new TextEncoder().encode(value);
const key = async (salt) => subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
  await subtle.importKey('raw', bytes(password), 'PBKDF2', false, ['deriveKey']),
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
);

if (process.argv[2] === 'create') {
  const salt = webcrypto.getRandomValues(new Uint8Array(32));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const data = await subtle.encrypt({ name: 'AES-GCM', iv }, await key(salt), bytes(payload));
  writeFileSync(join(directory, 'browser.json'), JSON.stringify({
    version: '1.0', encrypted: true, algorithm: 'AES-256-GCM',
    salt: Buffer.from(salt).toString('base64'), iv: Buffer.from(iv).toString('base64'),
    data: Buffer.from(data).toString('base64'),
  }));
} else {
  const envelope = JSON.parse(readFileSync(join(directory, 'native.json'), 'utf8'));
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64') },
    await key(Buffer.from(envelope.salt, 'base64')),
    Buffer.from(envelope.data, 'base64'),
  );
  assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), JSON.parse(payload));
  console.log('Browser/native encrypted backup compatibility: PASS');
}
