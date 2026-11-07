import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const source = readFileSync(new URL('../../src/crypto/bip39.ts', import.meta.url), 'utf8');
const block = source.match(/const BIP39_WORDLIST = \[([\s\S]*?)\];/)?.[1];
if (!block) throw new Error('Recovery word list is missing');
const words = [...block.matchAll(/'([^']+)'/g)].map(match => match[1]);
const digest = createHash('sha256').update(words.join(' ')).digest('hex');
if (digest !== 'fd973009e02732d71cb401308724d89c188246e5fa95155b5f84c91d51bc6bcf') {
  throw new Error('Recovery word positions changed; check compatibility before updating');
}
const destination = new URL('Sources/VaultSync/Resources/vault-words.txt', import.meta.url);
const content = `${words.join('\n')}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(destination, 'utf8') !== content) throw new Error('Native recovery words differ');
} else {
  writeFileSync(destination, content);
}
