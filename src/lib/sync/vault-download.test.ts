// src/lib/sync/vault-download.test.ts
// REGRESSION GATE (Archie #166248, Peter #166207): the .svrnty vault backup "spins then stops,
// nothing downloads" was downloadVault clicking a DETACHED anchor (never appended to the DOM) —
// Firefox/Safari/mobile no-op that. This test asserts the anchor is IN THE DOM before click() so the
// bug cannot silently regress ("fixed" = a file downloads, enforced at the test level, not "looks right").
// Stubs the DOM globals (no jsdom dep — matches the node-test style here).
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test vault-download.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { downloadVault } from './vault';

function withStubbedDom(run: (ctx: {
  anchor: Record<string, unknown>;
  order: string[];
  inDomAtClick: () => boolean;
}) => void) {
  const g = globalThis as unknown as { document?: unknown; URL?: unknown };
  const origDoc = g.document;
  const origURL = g.URL;
  const order: string[] = [];
  let appended: unknown = null;
  const anchor: Record<string, unknown> = {
    click() { order.push(appended === anchor ? 'click(in-dom)' : 'click(DETACHED)'); },
    remove() { order.push('remove'); appended = null; },
  };
  g.document = {
    createElement: (tag: string) => { assert.equal(tag, 'a'); order.push('createElement'); return anchor; },
    body: { appendChild: (el: unknown) => { appended = el; order.push('appendChild'); } },
  };
  g.URL = {
    createObjectURL: () => { order.push('createObjectURL'); return 'blob:mock-vault'; },
    revokeObjectURL: () => { order.push('revokeObjectURL'); },
  };
  try {
    run({ anchor, order, inDomAtClick: () => order.includes('appendChild') && order.indexOf('appendChild') < order.indexOf('click(in-dom)') });
  } finally {
    g.document = origDoc;
    g.URL = origURL;
  }
}

test('downloadVault clicks an IN-DOM anchor (regression: a detached anchor no-ops on FF/Safari/mobile)', () => {
  withStubbedDom(({ anchor, order }) => {
    downloadVault(new Uint8Array([1, 2, 3, 4]).buffer, 'my-identity.svrnty');

    // The download attributes are set.
    assert.equal(anchor.download, 'my-identity.svrnty', 'download filename is set on the anchor');
    assert.equal(anchor.href, 'blob:mock-vault', 'href = the object URL');

    // ★ THE REGRESSION GUARD: appendChild happens BEFORE the click, so the anchor is in the DOM when
    // clicked — never the detached no-op that silently dropped the vault download (#166207).
    const iAppend = order.indexOf('appendChild');
    const iClick = order.indexOf('click(in-dom)');
    assert.ok(iAppend >= 0, 'the anchor is appended to the DOM');
    assert.ok(iClick >= 0, 'the click fired on the in-DOM anchor (NOT a detached no-op)');
    assert.ok(iAppend < iClick, 'appendChild precedes click — anchor is in the DOM before clicking');
    assert.ok(!order.includes('click(DETACHED)'), 'the anchor is NEVER clicked while detached');
  });
});

test('downloadVault does NOT synchronously revoke the object URL before the click (revoke-race guard)', () => {
  withStubbedDom(({ order }) => {
    downloadVault(new Uint8Array([9]).buffer);
    const iClick = order.indexOf('click(in-dom)');
    const iRevoke = order.indexOf('revokeObjectURL');
    // Synchronous revoke immediately after click() can cancel the download of a large blob before the
    // browser reads it. The fix defers revoke (setTimeout), so it must NOT appear in the synchronous order.
    assert.ok(iClick >= 0, 'click fired');
    assert.ok(iRevoke === -1, 'revokeObjectURL is DEFERRED (not called synchronously after click — no revoke-race)');
  });
});

test('downloadVault uses a default .svrnty filename when none is given', () => {
  withStubbedDom(({ anchor }) => {
    downloadVault(new Uint8Array([0]).buffer);
    assert.match(String(anchor.download), /^vault-\d{4}-\d{2}-\d{2}\.svrnty$/, 'default name = vault-<date>.svrnty');
  });
});
