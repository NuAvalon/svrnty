import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NOTES_COPY } from './notes-copy';
import { statusIsHonestFloor, statusLabel, outboundStatus } from './notes-status';

describe('notes inbox copy — claim-honesty', () => {
  it('honest send-state machine: 2xx→Sent·unconfirmed, 5xx/timeout→couldn’t-confirm, 4xx-refuse→Not sent', () => {
    // confirmed (2xx): reached the relay, no receipt-of-record.
    assert.equal(statusLabel(outboundStatus('confirmed')), 'Sent · unconfirmed.');
    // unconfirmed (5xx / timeout / thrown): the honest "couldn't confirm" state — NEVER "failed"
    // (a 5xx can sit over an already-durable deposit; uncertainty resolves to the non-lying state).
    assert.equal(statusLabel(outboundStatus('unconfirmed')), NOTES_COPY.sentUncertain);
    assert.notEqual(outboundStatus('unconfirmed'), 'not-sent');
    assert.doesNotMatch(NOTES_COPY.sentUncertain, /\bfailed\b|could not be sent|Delivered|Read|Expired/i);
    // refused (authoritative 400 / 413): provably did not land — the ONLY outcome that earns "Not sent".
    assert.equal(statusLabel(outboundStatus('refused')), NOTES_COPY.notSent);
    assert.doesNotMatch(NOTES_COPY.notSent, /Delivered|Read|Expired|unconfirmed/);
    // honest floor holds for every live outbound state; Delivered/Read/Expired never do.
    for (const t of [NOTES_COPY.sentUnconfirmed, NOTES_COPY.sentUncertain, NOTES_COPY.notSent]) {
      assert.equal(statusIsHonestFloor(t), true);
    }
    for (const t of ['Delivered', 'Read', 'Expired']) {
      assert.equal(statusIsHonestFloor(t), false);
    }
  });

  it('does not claim post-quantum and does not leak admit-status', () => {
    const blob = JSON.stringify(NOTES_COPY).toLowerCase();
    assert.equal(blob.includes('post-quantum'), false);
    assert.equal(blob.includes('pq-hybrid'), false);
    assert.equal(blob.includes("you're not allowed"), false);
    assert.equal(blob.includes('not allowed'), false);
    assert.equal(blob.includes('not admitted'), false);
    assert.equal(blob.includes('unreachable'), false);
    // claim-honesty (Hypatia #167343 / GPT / Peter #167278): the relay sees mailbox-id +
    // timing + size + IP = communication metadata. NEVER claim it can't tell who you talk
    // to; only confidentiality (can't read messages) is supportable.
    assert.equal(blob.includes('who you talk to'), false);
    assert.equal(blob.includes('never learns who'), false);
    assert.equal(blob.includes('communication relationship'), false);
    assert.equal(blob.includes('read your messages'), true);
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
    // The inbox renders status THROUGH the honest-state machine (statusLabel∘outboundStatus), not a raw
    // literal — so it can never emit a false "failed" on a transport hiccup, nor skip the state model.
    assert.match(inbox, /statusLabel\(outboundStatus\(/);
    assert.doesNotMatch(inbox, /dangerouslySetInnerHTML/);
    assert.doesNotMatch(inbox, /\/api\/relay\/msg\/status/);
    assert.match(copy, /A Delivered confirmation is coming/);
    assert.doesNotMatch(status, /Delivered confirmation/);
    const liveStatus = [
      NOTES_COPY.sentUnconfirmed,
      NOTES_COPY.sentUncertain,
      NOTES_COPY.notSent,
      statusLabel('inbound'),
    ].join('\n');
    assert.doesNotMatch(liveStatus, /\b(Delivered|Read|Expired)\b/);
  });
});
