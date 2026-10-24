/**
 * Child-process driver for writer-lock.test.ts (real processes, real pids, real kill -9).
 *   hold  <dir> <ms>                          acquire, print "held", sleep, release
 *   count <dir> <counter> <n>                 n locked increments of a counter file; prints each value
 *   send  <dir> <fixture> <n> <wire> [nolock] n send-tr units on <dir>/ratchet-sessions.json, as devin-comm
 *                                             does them; appends each packet's header {dh, n} to <wire>
 *   store <dir> <tag> <n>                     n HeadlessStore.upsertContact calls with distinct ids
 */
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { acquireWriterLock, withWriterLock, withWriterLockAsync } from './writer-lock';
import { readJsonStrict, writeFileAtomic } from './atomic-file';
import { HeadlessStore } from './headless-store';
import { TripleRatchet, type RatchetSnapshot } from '../crypto/message-ratchet';

const [mode, dir, a, b, c, d] = process.argv.slice(2);
const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

async function main() {
  if (mode === 'hold') {
    const release = acquireWriterLock(dir, { waitMs: 10_000 });
    process.stdout.write('held\n');
    sleep(Number(a));
    release();
    return;
  }
  if (mode === 'count') {
    const counter = a;
    for (let i = 0; i < Number(b); i++) {
      const v = withWriterLock(dir, () => {
        const next = Number(readFileSync(counter, 'utf8')) + 1;
        writeFileSync(counter, String(next));
        return next;
      }, { waitMs: 60_000, pollMs: 2 });
      process.stdout.write(`${v}\n`);
    }
    return;
  }
  if (mode === 'send') {
    const fx = JSON.parse(readFileSync(a, 'utf8'));
    const self = { x25519Sec: unb64(fx.self.xs), x25519Pub: unb64(fx.self.xp), mlkem1024Sec: unb64(fx.self.ks), mlkem1024Pub: unb64(fx.self.kp) };
    const peer = { x25519Pub: unb64(fx.peer.xp), mlkem1024Pub: unb64(fx.peer.kp) };
    const path = join(dir, 'ratchet-sessions.json');
    const unit = async () => {
      const sessions = readJsonStrict<Record<string, RatchetSnapshot>>(path, {});
      let s = sessions.peer ? TripleRatchet.importState(sessions.peer) : null;
      if (!s) s = TripleRatchet.initiate(self, peer);
      const packet = await s.send('x');
      sessions.peer = s.exportState();
      writeFileAtomic(path, JSON.stringify(sessions), { backup: false });
      return packet;
    };
    for (let i = 0; i < Number(b); i++) {
      const packet = d === 'nolock' ? await unit() : await withWriterLockAsync(dir, unit, { waitMs: 60_000, pollMs: 2 });
      appendFileSync(c, JSON.stringify({ dh: packet.header.dh, n: packet.header.n }) + '\n');
    }
    return;
  }
  if (mode === 'store') {
    const store = new HeadlessStore({ path: join(dir, 'store.json'), lockDir: dir });
    for (let i = 0; i < Number(b); i++) {
      store.upsertContact({ id: `${a}-${i}`, fingerprint: `${a}-${i}`, name: a, public_key: 'pk' });
    }
    return;
  }
  throw new Error(`unknown mode ${mode}`);
}

main().catch((e) => { process.stderr.write(String(e?.message ?? e) + '\n'); process.exit(1); });
