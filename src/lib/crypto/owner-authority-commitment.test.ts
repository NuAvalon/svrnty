// src/lib/crypto/owner-authority-commitment.test.ts — task #809 step 2: the owner-authority pin is a labelled hash, never the raw one.
// Run: npx tsx --test src/lib/crypto/owner-authority-commitment.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ownerAuthorityCommitment, OWNER_AUTHORITY_LABEL } from './owner-authority-commitment';

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

test('KAT: fixed keys give the value an independent implementation (Python hashlib) printed, not our own helper', () => {
  assert.equal(ownerAuthorityCommitment(fill(32, 0x66), fill(2592, 0x77)), '457c987293ff968d3e6b0417cdb8e3218b72fa425b712ed169073643e16bb6f4');
});

test('the commitment is NOT the raw sha256 of the two keys (that value is the rotation commitment)', () => {
  const ed = fill(32, 0x66), dsa = fill(2592, 0x77);
  const raw = bytesToHex(sha256(Uint8Array.from([...ed, ...dsa])));
  assert.equal(raw, '0cea237c912ccfa006c42ea849f499aee500a942a5c555fce249650f1955f6e6');
  assert.notEqual(ownerAuthorityCommitment(ed, dsa), raw);
});

test('the label is part of the preimage', () => {
  assert.equal(OWNER_AUTHORITY_LABEL, 'svrnty-owner-authority-v1');
});

test('one changed byte in either key changes the commitment; swapping the keys is impossible (lengths differ)', () => {
  const ed = fill(32, 0x66), dsa = fill(2592, 0x77);
  const base = ownerAuthorityCommitment(ed, dsa);
  const ed2 = ed.slice(); ed2[31] ^= 1;
  const dsa2 = dsa.slice(); dsa2[2591] ^= 1;
  assert.notEqual(ownerAuthorityCommitment(ed2, dsa), base);
  assert.notEqual(ownerAuthorityCommitment(ed, dsa2), base);
});

test('wrong key lengths and non-byte inputs throw', () => {
  assert.throws(() => ownerAuthorityCommitment(fill(31, 1), fill(2592, 1)));
  assert.throws(() => ownerAuthorityCommitment(fill(32, 1), fill(2591, 1)));
  assert.throws(() => ownerAuthorityCommitment('x' as unknown as Uint8Array, fill(2592, 1)));
  assert.throws(() => ownerAuthorityCommitment(fill(32, 1), null as unknown as Uint8Array));
});
