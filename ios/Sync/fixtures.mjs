import { createHash, pbkdf2Sync, createCipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';

const require = createRequire(resolve('package.json'));
const { schnorr } = await import(require.resolve('@noble/secp256k1'));
const entropy = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const phrase = 'audit vanish execute note pledge rotate bundle stand regular burden reunion tide';
const seedHash = createHash('sha256').update(Buffer.from(entropy, 'hex')).digest('hex');
const chainID = seedHash.slice(0, 32);
const encryption = pbkdf2Sync(seedHash, `pkvault-sync-v4-${chainID}-enc`, 100_000, 32, 'sha256');
const signing = pbkdf2Sync(seedHash, `pkvault-sync-v4-${chainID}-nostr`, 100_000, 32, 'sha256');
const author = Buffer.from(schnorr.getPublicKey(signing)).toString('hex');
const plaintext = JSON.stringify({ type: 'announce', chainId: chainID, deviceName: 'Phone / 🔑', line: '\n' });
const nonce = Buffer.alloc(12, 7);
const cipher = createCipheriv('aes-256-gcm', encryption, nonce);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
const content = JSON.stringify({ n: nonce.toString('base64'), c: ciphertext.toString('base64') });
const created_at = 1_700_000_000;
const tags = [['d', `pksync-v4-${chainID}`], ['t', 'unicode / 🔑']];
const id = createHash('sha256').update(JSON.stringify([0, author, created_at, 30078, tags, content])).digest('hex');
const sig = Buffer.from(await schnorr.signAsync(Buffer.from(id, 'hex'), signing, Buffer.alloc(32))).toString('hex');
const fixture = {
  entropy, phrase, seedHash, chainID, author, plaintext,
  event: { id, pubkey: author, created_at, kind: 30078, tags, content, sig },
};
writeFileSync(new URL('Tests/VaultSyncTests/Fixtures/browser-sync.json', import.meta.url), `${JSON.stringify(fixture, null, 2)}\n`);
