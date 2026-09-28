// src/lib/trust/capability-token.test.ts
// Run: npx tsx --test src/lib/trust/capability-token.test.ts
//
// T4 capability-token: roundtrip + Flint's FLAG-2 (replay/dedup) + FLAG-1 (enum/hex/int) + cross-mailbox +
// window + tamper. The last test EMITS the S5/T6 CO-VERIFY VECTOR (deterministic X-Capability + raw fields)
// for Athena's Python verify_capability to check byte-for-byte — the byte-lock before either side wires.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  capScope,
  generateAdmitKeypair,
  issueCapability,
  makeNonce,
  presentCapability,
  verifyCapability,
  type CapOpType,
} from './capability-token';

// ── Deterministic fixtures (fixed seeds → reproducible vector) ──
const admitSk = new Uint8Array(32).fill(0x01);
const admitPub = ed25519.getPublicKey(admitSk);
const holderSk = new Uint8Array(32).fill(0x02);
const holderPub = ed25519.getPublicKey(holderSk);
const MAILBOX = 'a1b2c3d4e5f6'; // lowercase-hex
const OP: CapOpType = 'deposit';
const EPOCH = 7;
const UNIX = 1_790_000_000;
// fixed nonce = u32_be(UNIX) ‖ 0xdeadbeef  (deterministic for the vector)
const fixedNonce = (() => {
  const n = new Uint8Array(8);
  new DataView(n.buffer).setUint32(0, UNIX, false);
  n.set([0xde, 0xad, 0xbe, 0xef], 4);
  return n;
})();

function present(nonce?: Uint8Array): string {
  const issuerCert = issueCapability(admitSk, MAILBOX, OP, EPOCH, holderPub);
  return presentCapability({ holderSk, holderPub, issuerCert, mailboxId: MAILBOX, opType: OP, epoch: EPOCH, unixSec: UNIX, nonce });
}

test('roundtrip: issue → present → verify OK', () => {
  const header = present(fixedNonce);
  const r = verifyCapability({ header, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX });
  assert.equal(r.ok, true, r.reason);
  assert.equal(bytesToHex(r.holderPub!), bytesToHex(holderPub));
});

test('FLAG-2 replay: identical nonce twice → 2nd rejected by dedup', () => {
  const seen = new Set<string>();
  const header = present(fixedNonce);
  const r1 = verifyCapability({ header, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX, seenNonces: seen });
  const r2 = verifyCapability({ header, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX, seenNonces: seen });
  assert.equal(r1.ok, true);
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'replay');
});

test('FLAG-2 bursts: two DIFFERENT nonces same second → both accepted', () => {
  const seen = new Set<string>();
  const a = verifyCapability({ header: present(), mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX, seenNonces: seen });
  const b = verifyCapability({ header: present(), mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX, seenNonces: seen });
  assert.equal(a.ok, true, a.reason);
  assert.equal(b.ok, true, b.reason);
});

test('FLAG-1: op_type must be enum, mailbox_id lowercase-hex, epoch non-neg int', () => {
  assert.throws(() => capScope(MAILBOX, 'transfer' as CapOpType, EPOCH), /op_type not in enum/);
  assert.throws(() => capScope('NOTHEX', OP, EPOCH), /lowercase-hex/);
  assert.throws(() => capScope('zz', OP, EPOCH), /lowercase-hex/); // z is not hex
  assert.throws(() => capScope(MAILBOX, OP, -1), /non-negative integer/);
  assert.throws(() => capScope(MAILBOX, OP, 1.5), /non-negative integer/);
});

test('cross-mailbox replay blocked: cap for mailbox A presented at mailbox B → fails', () => {
  const header = present(fixedNonce);
  const r = verifyCapability({ header, mailboxId: 'ffffffff', admitPub, nowUnixSec: UNIX }); // wrong route target
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'issuer_cert-invalid'); // rebuilt scope differs → sig won't verify
});

test('WINDOW: nonce outside ±window → rejected', () => {
  const header = present(fixedNonce);
  const r = verifyCapability({ header, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX + 120, windowSec: 60 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'window');
});

test('tamper: flipping a byte in the presentation → verify fails', () => {
  const header = present(fixedNonce);
  const [e, o, b64] = header.split(':');
  // corrupt one base64 char (deterministically) → framing or sig break
  const bad = b64.slice(0, 8) + (b64[8] === 'A' ? 'B' : 'A') + b64.slice(9);
  const r = verifyCapability({ header: `${e}:${o}:${bad}`, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX });
  assert.equal(r.ok, false);
});

test('wrong admit pubkey → issuer_cert-invalid', () => {
  const header = present(fixedNonce);
  const other = ed25519.getPublicKey(new Uint8Array(32).fill(0x09));
  const r = verifyCapability({ header, mailboxId: MAILBOX, admitPub: other, nowUnixSec: UNIX });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'issuer_cert-invalid');
});

test('generateAdmitKeypair → issue → present → verify OK (random keys)', () => {
  const { admitSk: ask, admitPub: apub } = generateAdmitKeypair();
  const hsk = generateAdmitKeypair().admitSk; // reuse as a random 32B holder seed
  const hpub = ed25519.getPublicKey(hsk);
  const cert = issueCapability(ask, MAILBOX, OP, EPOCH, hpub);
  const header = presentCapability({ holderSk: hsk, holderPub: hpub, issuerCert: cert, mailboxId: MAILBOX, opType: OP, epoch: EPOCH, unixSec: UNIX });
  const r = verifyCapability({ header, mailboxId: MAILBOX, admitPub: apub, nowUnixSec: UNIX });
  assert.equal(r.ok, true, r.reason);
});

// ── S5/T6 CO-VERIFY VECTOR — hand to Athena's Python verify_capability (byte-exact lock) ──
test('EMIT co-verify vector for Athena verify_capability', () => {
  const issuerCert = issueCapability(admitSk, MAILBOX, OP, EPOCH, holderPub);
  const header = presentCapability({ holderSk, holderPub, issuerCert, mailboxId: MAILBOX, opType: OP, epoch: EPOCH, unixSec: UNIX, nonce: fixedNonce });
  const vector = {
    _note: 'T4 co-verify vector (Apollo). Athena verify_capability MUST accept this byte-for-byte.',
    scope: capScope(MAILBOX, OP, EPOCH),
    mailbox_id: MAILBOX,
    op_type: OP,
    epoch: EPOCH,
    admit_pub_hex: bytesToHex(admitPub),
    holder_pub_hex: bytesToHex(holderPub),
    issuer_cert_hex: bytesToHex(issuerCert),
    nonce_hex: bytesToHex(fixedNonce),
    unix_sec: UNIX,
    window_sec: 60,
    framing: 'u16-be length prefix per field: LP(issuer_cert)‖LP(holder_fresh)‖LP(holder_pub)‖LP(nonce), then base64',
    x_capability_header: header,
    expect: 'ok=true',
  };
  console.log('\n===CO_VERIFY_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===CO_VERIFY_VECTOR_END===\n');
  // self-verify the emitted vector
  const r = verifyCapability({ header, mailboxId: MAILBOX, admitPub, nowUnixSec: UNIX });
  assert.equal(r.ok, true, r.reason);
});
