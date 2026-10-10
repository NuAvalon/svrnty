import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BETA_COPY, BETA_SEND_STATUS } from './beta-messaging-copy';

const dir = dirname(fileURLToPath(import.meta.url));

function source(name: string): string {
  return readFileSync(join(dir, name), 'utf8');
}

describe('beta-messaging copy — claim-honesty', () => {
  it('uses the queue Unlock/redeem lines verbatim', () => {
    assert.equal(BETA_COPY.unlockHeading, 'Turn on beta messaging');
    assert.equal(
      BETA_COPY.unlockBody,
      'Messaging is in beta. Redeem your access key to turn it on for this address book — one key per book.',
    );
    assert.equal(BETA_COPY.redeemAction, 'Redeem key');
    assert.equal(
      BETA_COPY.unlockMicrocopy,
      "Your key unlocks messaging for you. It doesn't change what anyone else can do.",
    );
  });

  it('uses the queue what-it-is / sending / receiving lines', () => {
    assert.equal(BETA_COPY.whatItIsHeading, 'Encrypted messages, with the people you trust');
    assert.match(BETA_COPY.whatItIs, /end-to-end encrypted messages with your contacts/);
    assert.match(BETA_COPY.whatItIs, /relay only ever moves sealed blobs/);
    // claim-honesty (Hypatia #167343 / GPT / Peter #167278): the relay still sees
    // mailbox-id + timing + size + IP = communication metadata, so we must NEVER claim
    // it can't tell who you talk to — only that it can't READ messages (confidentiality,
    // supportable). Lock the honest claim; regression-guard the metadata over-claim.
    assert.match(BETA_COPY.whatItIs, /can'?t read your messages/i);
    assert.doesNotMatch(BETA_COPY.whatItIs, /who you talk to|communication relationships|never learns who/i);
    assert.match(BETA_COPY.sending, /you'll see Sent/);
    assert.match(BETA_COPY.sending, /A Delivered confirmation is coming/);
    assert.match(BETA_COPY.sendingWait, /waits for them/);
    assert.match(BETA_COPY.sendingWait, /will eventually expire/);
    assert.doesNotMatch(BETA_COPY.sendingWait, /you'll be notified it expired/);
    assert.doesNotMatch(BETA_COPY.sendingWait, /no message ever lost/);
    assert.match(BETA_COPY.receiving, /saved to this device/);
    assert.match(BETA_COPY.receiving, /there when you open your messages/);
    assert.doesNotMatch(BETA_COPY.receiving, /appears live/);
  });

  it('send-status floor is Sent — never Delivered / Read / Expired as a status', () => {
    assert.equal(BETA_SEND_STATUS.sent, 'Sent');
    const statuses = Object.values(BETA_SEND_STATUS);
    for (const s of statuses) {
      assert.equal(/^(Delivered|Read|Expired)$/i.test(s), false);
    }
    const tab = source('BetaMessagingTab.tsx');
    assert.doesNotMatch(tab, /BETA_SEND_STATUS\.(delivered|read|expired)/i);
    assert.doesNotMatch(tab, /['"`]Delivered['"`]/);
    assert.doesNotMatch(tab, /['"`]Read['"`]/);
    assert.doesNotMatch(tab, /['"`]Expired['"`]/);
  });

  it('never leaks admit-status / reachability on redeem failure', () => {
    const blob = `${JSON.stringify(BETA_COPY)}\n${source('BetaMessagingTab.tsx')}`;
    assert.doesNotMatch(blob, /you're not allowed/i);
    assert.doesNotMatch(blob, /not allowed to/i);
    assert.doesNotMatch(blob, /unreachable/i);
    assert.doesNotMatch(blob, /not admitted/i);
    assert.doesNotMatch(BETA_COPY.redeemFailed, /unauthorized|expired|issuer|mailbox/i);
  });

  it('redeem screen is gated on isBetaIssuerProvisioned', () => {
    const tab = source('BetaMessagingTab.tsx');
    const page = readFileSync(join(dir, '../../../app/page.tsx'), 'utf8');
    assert.match(tab, /isBetaIssuerProvisioned/);
    assert.match(tab, /if \(!on\) return null/);
    assert.match(page, /isBetaIssuerProvisioned/);
    assert.match(page, /BETA_COPY\.tabLabel/);
  });

  it('README.md stays messaging-free (beta copy is surface-only)', () => {
    const readme = readFileSync(join(dir, '../../../README.md'), 'utf8');
    assert.doesNotMatch(readme, /Turn on beta messaging/);
    assert.doesNotMatch(readme, /Redeem key/);
    assert.doesNotMatch(readme, /end-to-end encrypted messages/);
  });
});
