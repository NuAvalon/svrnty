/**
 * No IDENTITY-SIGNED delivery-receipt emitter ships (Archie #1823 option (a), A5-d / S62 v4 C8). S62 slice 3 adds exactly one emitter, the
 * designated-verifier MAC receipt in receipt-emit.ts, and this file pins that it is the only one (below).
 *
 * The S06 v1 receipt is identity-signed (ed25519 + ML-DSA-87), which makes it a transferable proof that the
 * recipient got a note. So no recipient path may build or seal one: a poll that persists a note deposits ZERO
 * receipts. The sender-side verify (buildReceiptSeam / verifyReceiptTag, S62 slice 4) stays, and "Delivered" lights up once
 * S62's designated-verifier MAC receipt lands.
 *
 * Wiring check by source, because the poll's deps (buildConsumeDeps) need an unlocked browser identity that no
 * unit test can construct. An emitter has to use buildReceiptWire (to make the receipt) or sealReceiptTo (to
 * seal it for the relay). Code must name them to reach them (a named import, a namespace access like
 * seal.sealReceiptTo, or a barrel re-export), so the check looks for either name in code with comments stripped.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = process.cwd();
const SCAN = ['src', 'app', 'scripts'];
// The modules that DEFINE the two functions (and their own tests) are the only ones allowed to name them.
const DEFINERS = new Set(['src/lib/crypto/delivery-receipt.ts', 'src/lib/messaging/seal.ts']);

/** Strip block and line comments (a line comment needs a non-':' before '//', so URLs in strings survive). */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function sourceFiles(dir: string): string[] {
  let out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out = out.concat(sourceFiles(p));
    else if (/\.(ts|tsx|mts|js|mjs)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) out.push(relative(ROOT, p));
  }
  return out;
}

describe('delivery receipts: no identity-signed emitter; only the MAC emitter ships', () => {
  it('no non-test module uses buildReceiptWire or sealReceiptTo outside their definers', () => {
    const offenders: string[] = [];
    for (const dir of SCAN) {
      for (const file of sourceFiles(join(ROOT, dir))) {
        if (DEFINERS.has(file)) continue;
        const src = readFileSync(join(ROOT, file), 'utf8');
        if (/\b(buildReceiptWire|sealReceiptTo)\b/.test(code(src))) offenders.push(file);
      }
    }
    assert.deepEqual(offenders, [], `receipt emitter wiring found in: ${offenders.join(', ')}`);
  });

  it('the live-book poll hands the note seam EXACTLY the MAC emitter (emitDeliveredReceipt), the one place a receipt is sent from', () => {
    const src = code(readFileSync(join(ROOT, 'src/lib/sync/live-book-poll.ts'), 'utf8'));
    const at = src.indexOf('note: buildNoteSeam(owner, undefined, hybrid');
    assert.ok(at > 0, 'expected the buildConsumeDeps note seam');
    const region = src.slice(at, at + 260);
    assert.match(region, /emitDeliveredReceipt\(wire/, 'the note seam must be given the MAC receipt emitter');
    assert.doesNotMatch(region, /buildReceiptWire|sealReceiptTo/, 'and never an identity-signed or classical sender');
  });

  it('only receipt-emit.ts sends a receipt: no other non-test module names sealReceiptV1To or buildReceiptWireV1 (one door, one audit point)', () => {
    const allowed = new Set(['src/lib/messaging/seal.ts', 'src/lib/messaging/receipt-wire-v1.ts', 'src/lib/messaging/receipt-emit.ts']);
    const offenders: string[] = [];
    for (const dir of SCAN) {
      for (const file of sourceFiles(join(ROOT, dir))) {
        if (allowed.has(file)) continue;
        if (/\b(sealReceiptV1To|buildReceiptWireV1)\b/.test(code(readFileSync(join(ROOT, file), 'utf8')))) offenders.push(file);
      }
    }
    assert.deepEqual(offenders, [], `receipt sending found outside receipt-emit.ts: ${offenders.join(', ')}`);
  });

  it('the sender-side verify is still wired (Delivered can light up once a sound receipt exists)', () => {
    const src = readFileSync(join(ROOT, 'src/lib/sync/live-book-poll.ts'), 'utf8');
    assert.match(src, /verifyReceiptTag/);
    assert.match(src, /receipt: buildReceiptSeam\(/);
  });
});
