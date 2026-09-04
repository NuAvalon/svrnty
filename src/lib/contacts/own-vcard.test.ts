// Own-identity vCard + Apollo §2 strip-on-export negative tests (KB#87571).
// Run: npx tsx --test src/lib/contacts/own-vcard.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toOwnVCard, toHttpUrl, type OwnVCardSource } from './own-vcard';

test('toOwnVCard: name, email, phone-like signal, site, fingerprint UID', () => {
  const vcf = toOwnVCard({
    name: 'Peter Alberts',
    fingerprint: 'aabbccddeeff00112233445566778899',
    email: 'peter@example.test',
    signal: '+14155550100',
    site: 'peter.svrnty.is',
  });
  assert.ok(vcf.includes('FN:Peter Alberts'));
  assert.ok(vcf.includes('EMAIL;TYPE=INTERNET:peter@example.test'));
  assert.ok(vcf.includes('TEL;TYPE=CELL:+14155550100'));
  assert.ok(vcf.includes('X-SIGNAL:+14155550100'));
  assert.ok(vcf.includes('URL:https://peter.svrnty.is/'));
  assert.ok(vcf.includes('UID:svrnty:aabbccddeeff00112233445566778899'));
  assert.ok(vcf.includes('svrnty fingerprint: aabbccddeeff00112233445566778899'));
  assert.ok(!vcf.includes('CATEGORIES'));
  assert.ok(!vcf.includes('Trust:'));
  assert.ok(!/blocked/i.test(vcf));
});

test('toOwnVCard: non-phone signal → X-SIGNAL only (no TEL)', () => {
  const vcf = toOwnVCard({
    name: 'Ada',
    fingerprint: 'deadbeef',
    signal: '@ada.signal',
  });
  assert.ok(vcf.includes('X-SIGNAL:@ada.signal'));
  assert.ok(!vcf.split(/\r\n/).some((l) => l.startsWith('TEL')));
});

test('toHttpUrl: https host-like site; reject javascript:/data:', () => {
  assert.equal(toHttpUrl('peter.svrnty.is'), 'https://peter.svrnty.is/');
  assert.equal(toHttpUrl('https://example.test/me'), 'https://example.test/me');
  assert.equal(toHttpUrl('javascript:alert(1)'), null);
  assert.equal(toHttpUrl('data:text/html,hi'), null);
});

test('NEGATIVE: tags / blocked / keys on a spread contact never appear on own export', () => {
  const poisoned = {
    name: 'Ada',
    fingerprint: 'aa',
    email: 'ada@x.test',
    tags: ['family', 'secret-group-label'],
    blocked: true,
    peer_public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nMIIB',
    trusted: true,
  } as OwnVCardSource & {
    tags: string[];
    blocked: boolean;
    peer_public_key: string;
    trusted: boolean;
  };
  const vcf = toOwnVCard(poisoned);
  assert.ok(!vcf.includes('CATEGORIES'), 'tags must not become CATEGORIES on own export');
  assert.ok(!vcf.includes('family'));
  assert.ok(!vcf.includes('secret-group-label'));
  assert.ok(!/blocked/i.test(vcf), 'blocked flag must not appear on own export');
  assert.ok(!vcf.includes('BEGIN PGP'));
  assert.ok(!vcf.includes('trusted'));
});
