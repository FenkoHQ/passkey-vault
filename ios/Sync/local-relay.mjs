import { createServer } from 'node:https';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const require = createRequire(resolve('package.json'));
const { WebSocketServer } = require('ws');
const { schnorr } = await import(require.resolve('@noble/secp256k1'));
const NOT_FOUND = 404;
const EVENT_KIND = 30078;
const MAX_FRAME = 18_432;
const MAX_EVENTS = 1000;
const server = createServer({ cert: readFileSync(process.argv[2]), key: readFileSync(process.argv[3]) }, (_, response) => {
  response.writeHead(NOT_FOUND).end();
});
const sockets = new WebSocketServer({ server, maxPayload: MAX_FRAME });
const subscriptions = new Map();
const stored = new Map();
const matches = (event, filters) => filters.some(filter => {
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since && event.created_at < filter.since) return false;
  return Object.entries(filter).filter(([key]) => key.startsWith('#')).every(([key, values]) =>
    event.tags.some(tag => tag[0] === key.slice(1) && values.includes(tag[1])));
});
const send = (socket, value) => socket.send(JSON.stringify(value));
sockets.on('connection', socket => {
  const active = new Map();
  subscriptions.set(socket, active);
  socket.on('close', () => subscriptions.delete(socket));
  socket.on('message', async bytes => {
    try {
      const [type, value, ...rest] = JSON.parse(bytes.toString());
      if (type === 'REQ') {
        active.set(value, rest);
        for (const event of stored.values()) {
          if (matches(event, rest)) send(socket, ['EVENT', value, event]);
        }
        send(socket, ['EOSE', value]);
      } else if (type === 'CLOSE') {
        active.delete(value);
      } else if (type === 'EVENT') {
        const event = value;
        const digest = createHash('sha256').update(JSON.stringify([
          0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
        ])).digest('hex');
        const valid = event.kind === EVENT_KIND && digest === event.id &&
          await schnorr.verifyAsync(Buffer.from(event.sig, 'hex'), Buffer.from(digest, 'hex'), Buffer.from(event.pubkey, 'hex'));
        send(socket, ['OK', event.id, valid, valid ? '' : 'invalid event']);
        if (!valid) return;
        stored.set(event.id, event);
        if (stored.size > MAX_EVENTS) stored.delete(stored.keys().next().value);
        for (const [peer, requests] of subscriptions) {
          for (const [id, filters] of requests) {
            if (matches(event, filters)) send(peer, ['EVENT', id, event]);
          }
        }
      }
    } catch {
      send(socket, ['NOTICE', 'invalid frame']);
    }
  });
});
server.listen(0, '127.0.0.1', () => {
  writeFileSync(process.argv[4], `wss://localhost:${server.address().port}`);
});
process.on('SIGTERM', () => {
  for (const socket of subscriptions.keys()) socket.terminate();
  server.close();
});
