// src/lib/sync/receipt-frozen.test.ts: the RECEIPT exception for a held note. A held note was stored (durably staged), so the sender may be answered like any
// admitted contact, under the SAME Delivery setting rules: `frozenStaged: true`, passed by the held path's own enqueue and nowhere else. Stranger, Removed
// (no row) and a frozen contact WITHOUT the flag get nothing, exactly as before.
// Run: npx tsx --test src/lib/sync/receipt-frozen.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { receiptAllowedNow, type ReceiptAllowedIo } from './receipt-allowed';
import type { DeliveryDefaultRead } from '@/lib/trust/delivery-receipt-setting';

const OWNER = 'ab'.repeat(32), SENDER = 'cd'.repeat(32);
const GLOBALS: Array<[string, DeliveryDefaultRead]> = [
  ['global on', { state: 'ok', rec: { v: 1, value: 'on' } }],
  ['global off', { state: 'ok', rec: { v: 1, value: 'off' } }],
  ['global unknown', { state: 'ok', rec: { v: 1, value: 'unknown' } }],
  ['global absent', { state: 'absent' }],
  ['global unreadable', { state: 'unreadable' }],
];
const PER_CONTACT: unknown[] = ['on', 'off', 'x', undefined];
const io = (contact: unknown, global: DeliveryDefaultRead): ReceiptAllowedIo => ({ getContact: async () => contact as never, readGlobal: async () => global });

test('D7-1 PARITY: for EVERY Delivery setting a frozen contact with frozenStaged gets the SAME decision as an unblocked contact', async () => {
  let n = 0, trues = 0;
  for (const [gname, g] of GLOBALS) {
    for (const pc of PER_CONTACT) {
      const normal = await receiptAllowedNow(OWNER, SENDER, io({ delivery_receipts: pc }, g));
      const frozen = await receiptAllowedNow(OWNER, SENDER, io({ blocked: true, delivery_receipts: pc }, g), { frozenStaged: true });
      assert.equal(frozen, normal, `${gname}, per-contact ${String(pc)}`);
      n++; if (normal) trues++;
    }
  }
  assert.equal(n, 20);
  assert.ok(trues > 0 && trues < n, 'the matrix really contains both answers (a parity over all-false would prove nothing)');
});

test('D7-2 PARITY also holds for a contact blocked only in METADATA', async () => {
  for (const [gname, g] of GLOBALS) for (const pc of PER_CONTACT) {
    const normal = await receiptAllowedNow(OWNER, SENDER, io({ delivery_receipts: pc }, g));
    const frozen = await receiptAllowedNow(OWNER, SENDER, io({ metadata: { blocked: true }, delivery_receipts: pc }, g), { frozenStaged: true });
    assert.equal(frozen, normal, `${gname}, per-contact ${String(pc)}`);
  }
});

test('D7-3 WITHOUT the flag a frozen contact gets NO receipt, under every setting (C3 unchanged)', async () => {
  for (const [gname, g] of GLOBALS) for (const pc of PER_CONTACT) {
    assert.equal(await receiptAllowedNow(OWNER, SENDER, io({ blocked: true, delivery_receipts: pc }, g)), false, `${gname}, per-contact ${String(pc)}`);
    assert.equal(await receiptAllowedNow(OWNER, SENDER, io({ blocked: true, delivery_receipts: pc }, g), {}), false, 'an empty options object is not the flag');
  }
});

test('D7-4 a STRANGER or a REMOVED contact (no row) gets NO receipt even WITH the flag, under every setting', async () => {
  for (const [gname, g] of GLOBALS) for (const none of [null, undefined]) {
    assert.equal(await receiptAllowedNow(OWNER, SENDER, io(none, g), { frozenStaged: true }), false, `${gname}, ${String(none)}`);
  }
});

test('D7-5 the flag never makes a receipt MORE permissive than an admitted contact: an Off or an unknown default still stops it', async () => {
  const frozen = { blocked: true };
  assert.equal(await receiptAllowedNow(OWNER, SENDER, io({ ...frozen, delivery_receipts: 'off' }, GLOBALS[0][1]), { frozenStaged: true }), false, 'per-contact off');
  assert.equal(await receiptAllowedNow(OWNER, SENDER, io(frozen, GLOBALS[1][1]), { frozenStaged: true }), false, 'global off');
  assert.equal(await receiptAllowedNow(OWNER, SENDER, io({ ...frozen, delivery_receipts: 'on' }, GLOBALS[2][1]), { frozenStaged: true }), false, 'unknown default (a restore not yet answered)');
  assert.equal(await receiptAllowedNow(OWNER, SENDER, io({ ...frozen, delivery_receipts: 'on' }, GLOBALS[4][1]), { frozenStaged: true }), false, 'unreadable default');
});

test('D7-6 a reader that THROWS means no receipt, flag or not', async () => {
  const boom: ReceiptAllowedIo = { getContact: async () => { throw new Error('book unreadable'); }, readGlobal: async () => GLOBALS[0][1] };
  assert.equal(await receiptAllowedNow(OWNER, SENDER, boom, { frozenStaged: true }), false);
});

// ── the static pin: ONE call site, a literal true, never computed ──
const ROOT = process.cwd();
const walk = (dir: string): string[] =>
  readdirSync(join(ROOT, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(join(ROOT, rel)).isDirectory()) return walk(rel);
    return /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) ? [rel] : [];
  });
const SOURCES = [...walk('src'), ...walk('app')];
const text = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');

test('D7-7 `frozenStaged: true` is written at EXACTLY ONE place in the app, and it is the held path\'s enqueue', () => {
  // CODE lines only: the option's own documentation mentions the literal in a comment, which is not a call site.
  const sites = SOURCES.flatMap((f) => text(f).split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l) && /frozenStaged\s*:\s*true\b/.test(l)).map(() => f));
  assert.deepEqual(sites, ['src/lib/sync/live-book-poll.ts']);
});

test('D7-8 no `frozenStaged` is ever given a computed value: every use is the literal true or the option\'s own definition/read', () => {
  for (const f of SOURCES) {
    for (const line of text(f).split('\n')) {
      if (!/frozenStaged/.test(line)) continue;
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;                                   // a comment
      const ok = /frozenStaged\s*:\s*true\b/.test(line)                              // the one call site
        || /frozenStaged\?\s*:\s*true\b/.test(line)                                  // the option's type
        || /opts\?\.frozenStaged\s*===\s*true/.test(line);                           // the one read, in receipt-allowed.ts
      assert.ok(ok, `${f}: ${line.trim()}`);
    }
  }
});
