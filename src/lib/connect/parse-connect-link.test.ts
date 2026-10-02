import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseConnectLink } from './parse-connect-link';

describe('parseConnectLink', () => {
  it('accepts a known-host invite with a key fragment via INV-4', () => {
    const p = parseConnectLink('https://svrnty.is/c/AbC-_9#keymaterial');
    assert.deepEqual(p, { code: 'AbC-_9', keyFragment: 'keymaterial' });
  });

  it('accepts a scheme-less known-host paste', () => {
    const p = parseConnectLink('svrnty.is/c/abc#k');
    assert.deepEqual(p, { code: 'abc', keyFragment: 'k' });
  });

  it('accepts /c/{code} without a key fragment', () => {
    const p = parseConnectLink('https://svrnty.is/c/barecode');
    assert.deepEqual(p, { code: 'barecode', keyFragment: null });
  });

  it('accepts a bare code', () => {
    const p = parseConnectLink('GrowCode_1');
    assert.deepEqual(p, { code: 'GrowCode_1', keyFragment: null });
  });

  it('rejects off-host, bad path, javascript, and non-strings — TOTAL, no throw', () => {
    const bad = [
      'https://evil.example/c/abc#k',
      'https://svrnty.is/join/abc#k',
      'javascript:alert(1)',
      'data:text/html,hi',
      '',
      '   ',
      1,
      null,
      'not a code!!',
    ];
    for (const input of bad) {
      assert.equal(parseConnectLink(input), null);
    }
  });

  it('does not echo the raw paste on success — only code + optional fragment', () => {
    const raw = 'https://svrnty.is/c/secretcode#supersecretfrag';
    const p = parseConnectLink(raw);
    assert.equal(p?.code, 'secretcode');
    assert.equal(p?.keyFragment, 'supersecretfrag');
    assert.equal(Object.keys(p || {}).includes('raw'), false);
  });
});
