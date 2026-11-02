import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('contact card verbs share one size', () => {
  it('Chat, Send update, and Actions use cardVerbBtnStyle', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const card = readFileSync(join(dir, 'ContactActionCard.tsx'), 'utf8');
    const menu = readFileSync(join(dir, '..', 'ui', 'CardActionMenu.tsx'), 'utf8');
    assert.match(card, /cardVerbBtnStyle\(\)/);
    assert.match(card, /cardVerbBtnStyle\(\{ muted: true \}\)/);
    assert.match(card, /gridTemplateColumns/);
    assert.match(card, /minmax\(0, 1fr\)/);
    assert.match(menu, /export function cardVerbBtnStyle/);
    assert.match(menu, /minHeight: 40/);
    assert.match(menu, /flex: '1 1 0'/);
    assert.match(menu, /return cardVerbBtnStyle\(\{ open \}\)/);
  });
});

describe('classical cards do not get Chat', () => {
  it('book and galaxy gate Chat on a living key', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const book = readFileSync(join(dir, '..', 'ContactManagement.tsx'), 'utf8');
    const galaxy = readFileSync(join(dir, '..', 'TrustMap.tsx'), 'utf8');
    assert.match(book, /const canChat = !!onOpenChat && svrn && fp\.length >= 16/);
    assert.match(book, /fingerprint=\{svrn \? \(fp \|\| undefined\) : undefined\}/);
    assert.match(galaxy, /const canNote = !!\(onOpenNote && living\)/);
    assert.match(galaxy, /fingerprint=\{living \? focusEdge\.peer_fingerprint : undefined\}/);
    assert.match(galaxy, /label="Give a piece"/);
  });
});

describe('galaxy-card verbs — disclosed living contacts only (Hypatia #198)', () => {
  it('Chat / Send update / Give a piece call existing handlers — never inferred edges', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const galaxy = readFileSync(join(dir, '..', 'TrustMap.tsx'), 'utf8');
    const card = readFileSync(join(dir, 'ContactActionCard.tsx'), 'utf8');
    // Render the three verbs.
    assert.match(card, /data-testid="galaxy-open-note"/);
    assert.match(card, /data-testid="contact-send-update"/);
    assert.match(galaxy, /label="Give a piece"/);
    // CALL existing handlers — do not reimplement.
    assert.match(galaxy, /onChat=\{\(\) => onOpenNote\?\.\(focusEdge\)\}/);
    assert.match(galaxy, /onSendUpdate=\{\(\) => onSendMethodUpdate\?\.\(focusEdge\)\}/);
    assert.match(galaxy, /setShardGiveOpen\(true\)/);
    // Give a piece is living-only (disclosed SVRNTY contact with a key).
    assert.match(galaxy, /\{living \? \([\s\S]*label="Give a piece"/);
    // Consent legend stays load-bearing — no inferred-edge render.
    assert.match(galaxy, /Every visible line consented — none inferred/);
    assert.doesNotMatch(galaxy, /friends-of-friends|auto-trust|inferred edge/i);
  });
});
