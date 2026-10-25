import { test, expect, devices, type Page, type APIRequestContext } from '@playwright/test';
import { createMessage, readKey, readSignature, verify } from 'openpgp';
import { makeE2EIdentity, seedAliceWithBob, depositNote, type E2EIdentity } from './fixtures/deposit-note';
import { COMPOSE_NOTE_TYPE } from '../src/lib/compose/compose-inbound';
import { composeSignedBytes } from '../src/lib/compose/compose-rules';
import { deriveComposeWords } from '../src/lib/compose/compose-words';

/**
 * PORTAL SIGN-VIEW, in a real browser, through the REAL app-shell poll and the REAL note seam (feedback_prove_in_playwright).
 *
 * "Bob" plays the portal's compose identity: a genuine canonical identity whose signed + sealed note reaches Alice's mailbox exactly as in
 * notes-roundtrip.spec.ts (noteOpenpgpDecryptor -> acceptInboundNote: verifyNoteSender BEFORE isAdmitted -> putNote -> emitNoteArrival). Nothing is mocked.
 *
 * TWO BUILDS, ONE FILE. The check-words switch is baked into the bundle at build time (compose-words-gate.ts), so the e2e server is started either way:
 *   COMPOSE_WORDS_E2E=1 npx playwright test e2e/compose-sign.spec.ts   -> the words appear, Approve is offered, the signature is real and verifies
 *   npx playwright test e2e/compose-sign.spec.ts                       -> production default: the card shows, there is NO Approve anywhere
 * Each run executes only the tests for its build; the other build's tests are skipped (not silently: they report as skipped).
 *
 * MATRIX: desktop Chromium AND a Pixel 7 viewport (hardened-mobile center). WebKit is a second engine and is NOT covered here.
 */

const WORDS_ON = process.env.COMPOSE_WORDS_E2E === '1';
const pixel7Mobile = Object.fromEntries(Object.entries(devices['Pixel 7']).filter(([k]) => k !== 'defaultBrowserType'));
const MATRIX: Array<{ label: string; use: Record<string, unknown> }> = [
  { label: 'desktop-chromium', use: { viewport: { width: 1280, height: 800 } } },
  { label: 'mobile-chromium (Pixel 7)', use: pixel7Mobile },
];

async function genesisReceiver(page: Page, name: string) {
  await page.goto('/');
  await page.getByRole('button', { name: /generate a new cryptographic identity/i }).click();
  await page.getByPlaceholder('Your name').fill(name);
  await page.getByPlaceholder('Encrypts your keys at rest').fill('e2e-passphrase-1234');
  await page.getByPlaceholder('Confirm passphrase').fill('e2e-passphrase-1234');
  await page.getByRole('button', { name: /^start$/i }).click();
  await page.getByRole('checkbox', { name: /written this down offline/i }).check({ timeout: 30_000 });
  await page.getByRole('button', { name: /i have it/i }).click();
  await expect(page.getByRole('tab', { name: 'Contacts', exact: true })).toBeVisible({ timeout: 20_000 });
}

let nonceCounter = 0;
const nonce = () => (Date.now() * 1000 + ++nonceCounter).toString(16).padStart(32, '0').slice(-32);

function postRequest(over: Record<string, string> = {}) {
  const now = Date.now();
  return {
    purpose: 'svrnty-loom-post-v1',
    fleet: 'autobots',
    thread: 'lane:ops',
    body: 'Line one of a message Peter wrote.\nLine two, with an emoji 🌱 and a long tail: ' + 'x'.repeat(300),
    nonce: nonce(),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 4 * 60_000).toISOString(),
    origin: 'noosphere.nuavalon.com',
    ...over,
  };
}

async function sendRequest(request: APIRequestContext, bob: E2EIdentity, aliceFp: string, aliceArmoredPub: string, req: Record<string, string>) {
  const res = await depositNote(request, {
    sender: bob,
    recipientFingerprint: aliceFp,
    recipientPublicKeyArmored: aliceArmoredPub,
    fields: { body: JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: req }) },
  });
  expect(res.status).toBe(200);
  return res;
}

const groups = (fp: string) => fp.slice(0, 16).replace(/(.{4})(?=.)/g, '$1 ');

/** Open Identity -> Settings panel, wait for the compose pin panel. */
async function openPinPanel(page: Page) {
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  const panel = page.getByTestId('compose-pin-settings');
  await panel.scrollIntoViewIfNeeded();
  await expect(panel).toBeVisible({ timeout: 20_000 });
  return panel;
}

async function pinBob(page: Page, bob: E2EIdentity, request: APIRequestContext, aliceFp: string, aliceArmoredPub: string) {
  // The first request from an unpinned sender makes NO card; it only gives Settings a key to compare.
  await sendRequest(request, bob, aliceFp, aliceArmoredPub, postRequest({ body: 'unpinned first contact' }));
  const panel = await openPinPanel(page);
  await expect(panel.getByTestId('compose-pin-line')).toHaveText('Not pinned');
  const pinAction = panel.getByTestId('compose-pin-action-pin');
  await expect(pinAction).toBeVisible({ timeout: 25_000 });
  await expect(page.getByTestId('compose-card')).toHaveCount(0);

  // "They don't match" pins nothing, and it is the focused (safe) button.
  await pinAction.click();
  const screen = page.getByTestId('compose-pin-screen');
  await expect(screen).toBeVisible();
  await expect(screen.getByTestId('compose-pin-fp')).toHaveText(groups(bob.fingerprint));
  await expect(screen.getByTestId('compose-pin-nomatch')).toBeFocused();
  await screen.getByTestId('compose-pin-nomatch').click();
  await expect(panel.getByTestId('compose-pin-result')).toHaveAttribute('data-kind', 'mismatch');
  await expect(panel.getByTestId('compose-pin-line')).toHaveText('Not pinned');

  // "They match" pins exactly this key.
  await panel.getByTestId('compose-pin-action-pin').click();
  await expect(page.getByTestId('compose-pin-fp')).toHaveText(groups(bob.fingerprint));
  await page.getByTestId('compose-pin-match').click();
  await expect(panel.getByTestId('compose-pin-result')).toHaveAttribute('data-kind', 'pinned');
  await expect(panel.getByTestId('compose-pin-line')).toHaveText(`Pinned: ${groups(bob.fingerprint)}`);
}

for (const variant of MATRIX) {
  test.describe(`portal sign-view · ${variant.label} · words ${WORDS_ON ? 'ON' : 'OFF (production default)'}`, () => {
    test.use(variant.use);

    test('pin the portal key in Settings, then a request shows the FULL body, Approve below it, and a real signature comes back', async ({ page, request }) => {
      test.skip(!WORDS_ON, 'needs the e2e build with COMPOSE_WORDS_E2E=1');
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Peter Compose');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      await pinBob(page, bob, request, aliceFp, aliceArmoredPub);

      const req = postRequest();
      await sendRequest(request, bob, aliceFp, aliceArmoredPub, req);

      const card = page.getByTestId('compose-card');
      await expect(card).toBeVisible({ timeout: 25_000 });
      // WYSIWYS: the whole body, verbatim (both lines, the emoji, the long tail), in the card.
      const body = card.getByTestId('compose-card-body');
      await expect(body).toHaveText(req.body);
      await expect(card.getByTestId('compose-card-location')).toHaveText('autobots · lane:ops');
      // The four words on the screen are the words an independent derivation gives for this exact object.
      const words = deriveComposeWords(req);
      await expect(card.getByTestId('compose-card-words')).toHaveText(`Check these words match the portal: ${words.join(' ')}`);
      // Approve sits BELOW the end of the body; the safe button has the focus.
      const approve = card.getByTestId('compose-approve');
      await approve.scrollIntoViewIfNeeded();
      const bodyBox = (await body.boundingBox())!;
      const approveBox = (await approve.boundingBox())!;
      expect(approveBox.y).toBeGreaterThanOrEqual(bodyBox.y + bodyBox.height);
      await expect(card.getByTestId('compose-decline')).toBeFocused();
      await expect(approve).toBeEnabled({ timeout: 5_000 });

      await approve.click();
      const back = page.getByTestId('compose-handback');
      await expect(back).toBeVisible({ timeout: 20_000 });
      await expect(back.getByRole('heading')).toHaveText('Signed. Not posted yet.');
      await expect(page.getByTestId('compose-card')).toHaveCount(0);
      const text = (await back.innerText()).toLowerCase();
      for (const forbidden of ['delivered', 'sent to', 'has been posted', 'posted to']) expect(text).not.toContain(forbidden);

      // The pasted text is the object the card showed plus a detached signature that VERIFIES against Alice's key over the exact signed bytes.
      const pasted = JSON.parse((await back.getByTestId('compose-handback-json').innerText()).trim()) as {
        kind: string; object: Record<string, string>; suite: string; sig_packet_b64: string;
      };
      expect(pasted.kind).toBe('post');
      expect(pasted.suite).toBe('ed25519');
      expect(pasted.object).toEqual(req);
      const sig = await readSignature({ binarySignature: Uint8Array.from(atob(pasted.sig_packet_b64), (c) => c.charCodeAt(0)) });
      const checked = await verify({
        message: await createMessage({ text: composeSignedBytes('post', 'ed25519', pasted.object) }),
        signature: sig,
        verificationKeys: await readKey({ armoredKey: aliceArmoredPub }),
      });
      await expect(checked.signatures[0].verified).resolves.toBe(true);

      await back.getByTestId('compose-handback-done').click();
      await expect(page.getByTestId('compose-handback')).toHaveCount(0);
    });

    test('Escape declines: the card goes, nothing is signed, no hand-back appears', async ({ page, request }) => {
      test.skip(!WORDS_ON, 'needs the e2e build with COMPOSE_WORDS_E2E=1');
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Peter Escape');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      await pinBob(page, bob, request, aliceFp, aliceArmoredPub);
      await sendRequest(request, bob, aliceFp, aliceArmoredPub, postRequest({ body: 'decline me' }));
      const card = page.getByTestId('compose-card');
      await expect(card).toBeVisible({ timeout: 25_000 });
      await page.keyboard.press('Escape');
      await expect(card).toHaveCount(0);
      await page.waitForTimeout(1_500);
      await expect(page.getByTestId('compose-handback')).toHaveCount(0);
    });

    test('a request with a hidden direction-flip character is REFUSED: markers shown, Close only, no way to sign', async ({ page, request }) => {
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Peter Refusal');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      await pinBob(page, bob, request, aliceFp, aliceArmoredPub);
      await sendRequest(request, bob, aliceFp, aliceArmoredPub, postRequest({ body: 'approve‮ the safe thing' }));
      const refused = page.getByTestId('compose-refused');
      await expect(refused).toBeVisible({ timeout: 25_000 });
      await expect(refused.getByTestId('compose-refused-marker')).toHaveText('[U+202E]');
      await expect(page.getByTestId('compose-approve')).toHaveCount(0);
      await expect(refused.getByRole('button')).toHaveCount(1);
      await refused.getByTestId('compose-close').click();
      await expect(refused).toHaveCount(0);
    });

    test('production default (words switch OFF): the card is readable but has NO Approve of any kind', async ({ page, request }) => {
      test.skip(WORDS_ON, 'this is the production-default build; run without COMPOSE_WORDS_E2E');
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Peter Default');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      await pinBob(page, bob, request, aliceFp, aliceArmoredPub);
      const req = postRequest();
      await sendRequest(request, bob, aliceFp, aliceArmoredPub, req);
      const card = page.getByTestId('compose-card');
      await expect(card).toBeVisible({ timeout: 25_000 });
      await expect(card.getByTestId('compose-card-body')).toHaveText(req.body);
      await expect(card.getByTestId('compose-card-no-words')).toBeVisible();
      await expect(card.getByTestId('compose-approve')).toHaveCount(0);
      await expect(card.getByRole('button')).toHaveCount(1); // only "Don't sign"
    });

    test('a verified sender that is NOT pinned never gets a card, and a stranger\'s forged request never gets one either', async ({ page, request }) => {
      test.setTimeout(120_000);
      await genesisReceiver(page, 'Peter Unpinned');
      const { aliceFp, aliceArmoredPub, bob } = await seedAliceWithBob(page);
      const mallory = await makeE2EIdentity('mallory');
      await sendRequest(request, bob, aliceFp, aliceArmoredPub, postRequest({ body: 'from an unpinned key' }));
      // Forgery: claims to be Bob, signed by Mallory -> dropped at the note seam before the host ever sees it.
      await depositNote(request, {
        sender: mallory,
        recipientFingerprint: aliceFp,
        recipientPublicKeyArmored: aliceArmoredPub,
        fields: { body: JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: postRequest({ body: 'FORGED' }) }), claimedFrom: bob.fingerprint },
      });
      await page.waitForTimeout(6_000);
      await expect(page.getByTestId('compose-card')).toHaveCount(0);
      await expect(page.getByTestId('compose-refused')).toHaveCount(0);
      await expect(page.getByText('FORGED')).toHaveCount(0);
    });
  });
}
