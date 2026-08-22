// vCard tests — multi-TEL import (number-loss fix) + trust-state export (Queue B 0.11-0.12).
// Covers the two bugs the phones[] PR fixes: fromVCard last-wins number loss, and
// toVCard's stale edge.trust_level (legacy field absent on TrustEdge).
// Run: npx tsx --test  (extensionless — matches repo convention)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toVCard, fromVCard } from './vcard';
import type { TrustEdge } from '../trust/types';

const edge = (over: Partial<TrustEdge> = {}): TrustEdge => ({
  id: 'x', peer_fingerprint: 'FP', peer_name: 'Ada Lovelace', peer_email: 'ada@calc.org',
  peer_public_key: '', contact_info: { phones: ['+14155550001', '+442071838750'], emails: [] },
  trusted: true, trusted_since: '2026-01-02T00:00:00Z', last_interaction: '', decay_days: 730,
  trust_history: [], verification: { method: 'none', verified_at: null },
  mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
  tags: [], notes: '', connection_channels: [], added_at: '', ...over,
});

test('toVCard: one TEL per phone; trust from trusted boolean, no legacy trust_level', () => {
  const vcf = toVCard(edge());
  const tels = vcf.split(/\r\n/).filter((l) => l.startsWith('TEL'));
  assert.equal(tels.length, 2);
  assert.ok(vcf.includes('+14155550001') && vcf.includes('+442071838750'));
  assert.ok(vcf.includes('Trust: trusted'));                 // mapped from trusted:boolean
  assert.ok(!vcf.includes('trust_level') && !vcf.includes('Lundefined')); // legacy bug gone
});

test('fromVCard: parses ALL TEL lines into phones[] (no last-wins number loss)', () => {
  const vcf = [
    'BEGIN:VCARD', 'VERSION:3.0', 'FN:Grace Hopper',
    'TEL;TYPE=CELL:+13015550100', 'TEL;TYPE=HOME:+13015550200',
    'EMAIL;TYPE=INTERNET:grace@navy.mil', 'END:VCARD',
  ].join('\r\n');
  const [c] = fromVCard(vcf);
  assert.equal(c.peer_name, 'Grace Hopper');
  assert.deepEqual(c.contact_info?.phones, ['+13015550100', '+13015550200']);
  assert.equal(c.peer_email, 'grace@navy.mil');
});

test('fromVCard: real-world Apple/iCloud export — item1.-grouped fields, params, folding, X-AB skipped', () => {
  const vcf = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    'PRODID:-//Apple Inc.//macOS 14.5//EN',
    'FN;CHARSET=UTF-8:Grace Hopper',
    'N:Hopper;Grace;;;',
    'item1.TEL;type=CELL;type=VOICE;type=pref:+1 (301) 555-01', // folded across two lines ↓
    ' 00',                                                       // continuation → +1 (301) 555-0100
    'item1.X-ABLabel:_$!<Mobile>!$_',                            // Apple internal label — must be skipped
    'item2.EMAIL;type=INTERNET;type=HOME:grace@navy.mil',
    'item2.X-ABLabel:_$!<Home>!$_',
    'item3.URL;type=pref:https://example.mil/grace',
    'X-SIGNAL:+13015550100',
    'END:VCARD',
  ].join('\r\n');
  const [c] = fromVCard(vcf);
  assert.equal(c.peer_name, 'Grace Hopper');                        // FN with CHARSET param
  assert.deepEqual(c.contact_info?.phones, ['+1 (301) 555-0100']);  // grouped item1.TEL + line-UNFOLDED
  assert.equal(c.peer_email, 'grace@navy.mil');                     // grouped item2.EMAIL
  assert.deepEqual(c.contact_info?.urls, ['https://example.mil/grace']); // grouped item3.URL (value keeps its ':')
  assert.equal(c.contact_info?.handles?.signal, '+13015550100');    // X-SIGNAL handle
  assert.ok(!('ablabel' in (c.contact_info?.handles ?? {})));       // Apple X-AB* is NOT a reachable channel
});

test('round-trip: multi-phone survives toVCard -> fromVCard', () => {
  const [back] = fromVCard(toVCard(edge()));
  assert.deepEqual(back.contact_info?.phones, ['+14155550001', '+442071838750']);
});
