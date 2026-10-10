import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NOTES_COPY } from './notes-copy';
import { statusIsHonestFloor, statusLabel, outboundStatus } from './notes-status';

describe('notes inbox copy — claim-honesty', () => {
  it('send status is Sent · unconfirmed only', () => {
    assert.equal(NOTES_COPY.sentUnconfirmed, 'Sent · unconfirmed.');
    assert.equal(statusLabel(outboundStatus(true)), 'Sent · unconfirmed.');
    assert.equal(statusIsHonestFloor(NOTES_COPY.sentUnconfirmed), true);
    assert.equal(statusIsHonestFloor('Delivered'), false);
    assert.equal(statusIsHonestFloor('Read'), false);
    assert.equal(statusIsHonestFloor('Expired'), false);
  });

  it('never treats a failed deposit as Sent', () => {
    assert.equal(statusLabel(outboundStatus(false)), NOTES_COPY.notSent);
    assert.doesNotMatch(NOTES_COPY.notSent, /Delivered|Read|Expired|unconfirmed/);
  });

  it('does not claim post-quantum and does not leak admit-status', () => {
    const blob = JSON.stringify(NOTES_COPY).toLowerCase();
    assert.equal(blob.includes('post-quantum'), false);
    assert.equal(blob.includes('pq-hybrid'), false);
    assert.equal(blob.includes("you're not allowed"), false);
    assert.equal(blob.includes('not allowed'), false);
    assert.equal(blob.includes('not admitted'), false);
    assert.equal(blob.includes('unreachable'), false);
  });

  it('receiving copy says saved / there when you open — not appears live', () => {
    assert.match(NOTES_COPY.receiving, /saved to this device/i);
    assert.match(NOTES_COPY.receiving, /there when you open/i);
    assert.doesNotMatch(NOTES_COPY.receiving, /appears live/i);
  });

  it('uses the queue what-it-is heading', () => {
    assert.equal(NOTES_COPY.heading, 'Encrypted messages, with the people you trust');
    assert.equal(NOTES_COPY.sendAction, 'Send');
  });

  it('inbox source never renders Delivered/Read/Expired as a live status', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const inbox = readFileSync(join(dir, 'NotesInbox.tsx'), 'utf8');
    const copy = readFileSync(join(dir, 'notes-copy.ts'), 'utf8');
    const status = readFileSync(join(dir, 'notes-status.ts'), 'utf8');
    assert.match(inbox, /NOTES_COPY\.sentUnconfirmed/);
    assert.doesNotMatch(inbox, /dangerouslySetInnerHTML/);
    assert.doesNotMatch(inbox, /\/api\/relay\/msg\/status/);
    assert.match(copy, /A Delivered confirmation is coming/);
    assert.doesNotMatch(status, /Delivered confirmation/);
    const liveStatus = [NOTES_COPY.sentUnconfirmed, NOTES_COPY.notSent, statusLabel('inbound')].join('\n');
    assert.doesNotMatch(liveStatus, /\b(Delivered|Read|Expired)\b/);
  });
});
