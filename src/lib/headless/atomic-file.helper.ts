/**
 * Child-process driver for atomic-file.test.ts (real process, real kill -9 —
 * headless-store-atomic-flush-001 anchor 4: a writer killed mid-flush must
 * leave the PREVIOUS valid book or the new one, never a torn/0B file).
 *   flushloop <dir> <file> <sizeBytes>   writeFileAtomic gen 0, print "ready",
 *                                        then back-to-back gen 1..N flushes
 *   storeloop <dir> <sizeBytes>          HeadlessStore at <dir>/store.json, 3
 *                                        seed contacts, print "ready", then
 *                                        back-to-back putNote flushes
 */
import { join } from 'node:path';
import { writeFileAtomic } from './atomic-file';
import { HeadlessStore } from './headless-store';

const [mode, dir, a, b] = process.argv.slice(2);

function main() {
  if (mode === 'flushloop') {
    const file = a;
    const size = Number(b);
    writeFileAtomic(file, JSON.stringify({ gen: 0, pad: '0'.repeat(size) }));
    process.stdout.write('ready\n');
    for (let gen = 1; gen < 10_000; gen++) {
      writeFileAtomic(file, JSON.stringify({ gen, pad: '1'.repeat(size) }));
    }
    return;
  }
  if (mode === 'storeloop') {
    const size = Number(a);
    const store = new HeadlessStore({ path: join(dir, 'store.json') });
    for (const [id, fp] of [['c1', 'fp1'], ['c2', 'fp2'], ['c3', 'fp3']] as const) {
      store.upsertContact({ id, fingerprint: fp, name: id } as never);
    }
    process.stdout.write('ready\n');
    for (let i = 0; i < 10_000; i++) {
      store.putNote({
        note_id: `n${i}`,
        thread_id: 't',
        direction: 'out',
        from_fingerprint: 'self',
        to_fingerprints: ['peer'],
        body: 'x'.repeat(size),
        sent_at: new Date().toISOString(),
      } as never);
    }
    return;
  }
  throw new Error(`unknown mode ${mode}`);
}

main();
