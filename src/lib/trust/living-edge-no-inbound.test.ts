// The Galaxy tab ember must never become a one-sided-trust oracle (Peter's hard gate, KB#93521 / registry NV-10; Flint ruling lane:svrnty #888).
//   1. livingEdgeStatus NEVER produces 'inbound' or 'mutual', for ANY combination of the fields that could plausibly drive a trust phase,
//      including a record whose device bit says they_trust_me === true (that derivation was removed with the affirm wire, #593).
//   2. app/page.tsx builds the ember's attention set from the connection phase only; it does not read the trust phase at all.
// Either failing alone is enough to reopen the oracle, so each is pinned on its own.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { livingEdgeStatus, livingStatusChip } from './living-edge-status';
import { TRUST_VISUAL_LABELS, visualForEdge } from '../../components/trust/trust-phase-visual';
import type { TrustEdge } from './types';

const LIVING_FP = 'p1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function edge(p: Record<string, unknown>): TrustEdge {
  return {
    id: LIVING_FP, peer_fingerprint: LIVING_FP, peer_name: 'x', peer_email: '', peer_public_key: 'PK', trusted: false, trusted_since: null,
    last_interaction: new Date().toISOString(), decay_days: 730, trust_history: [], verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false }, tags: [], notes: '', connection_channels: [], added_at: new Date().toISOString(),
    ...p,
  } as unknown as TrustEdge;
}

/** Every combination of the fields that could plausibly drive a trust phase, with the inputs named for failure messages. */
function allShapes(): Array<{ e: TrustEdge; why: string }> {
  const out: Array<{ e: TrustEdge; why: string }> = [];
  for (const trusted of [false, true])
    for (const theyTrustMe of [null, false, true])
      for (const reciprocal of [false, true])
        for (const lastAffirm of [undefined, new Date().toISOString()])
          for (const outbound of [undefined, true])
            for (const probe of [undefined, 'pending', 'no-ack', 'acked'])
              for (const connection of [undefined, 'pending'])
                for (const key of ['PK', ''])
                  for (const fp of [LIVING_FP, 'short']) {
                    out.push({
                      e: edge({
                        trusted,
                        trusted_since: trusted ? new Date().toISOString() : null,
                        peer_fingerprint: fp,
                        peer_public_key: key,
                        connection_status: connection,
                        mutual: { they_trust_me: theyTrustMe, reciprocal, last_sync: null, last_affirm_at: lastAffirm },
                        metadata: { trust_outbound: outbound, trust_probe: probe },
                      }),
                      why: JSON.stringify({ trusted, theyTrustMe, reciprocal, probe, connection, key: !!key, fp: fp.length }),
                    });
                  }
  return out;
}

test("livingEdgeStatus never returns 'inbound' or 'mutual' for any edge shape (incl. they_trust_me === true)", () => {
  const shapes = allShapes();
  for (const { e, why } of shapes) {
    const s = livingEdgeStatus(e);
    assert.ok(s.trust === 'none' || s.trust === 'outbound', `trust=${s.trust} for ${why}`);
    assert.notEqual(livingStatusChip(s), 'Mutual');
    assert.doesNotMatch(s.statusLine, /mutual|trusts you/i);
  }
  assert.ok(shapes.length >= 500, `covered ${shapes.length} shapes`);
});

// Flint #913: a UI arm keyed on the state the hard gate forbids revealing is a latent leak even when dead. So not only the STATUS but every
// RENDERED label for every edge shape must come from the honest vocabulary, and the dead 'trust-received' word must read like a stranger.
test("every rendered label, for every edge shape, is from the honest set; never 'Trust pending' or 'Mutual'", () => {
  // TWO surfaces with DIFFERENT vocabularies (Hypatia #921), each pinned exactly:
  //   livingStatusChip (living-edge-status.ts)           in {Known, Linked, Trusted, Classical, Pending}  (its only other output is 'Mutual')
  //   trustPhaseVisual().label (trust-phase-visual.ts)   in {Known, Trusted, Pending intro, Blocked}      (note: 'Pending intro', and blocked edges)
  // 'Mutual' / 'Mutual trust' stay in the maps (forward-compatible for PSI #588); this negative pin covers B.
  const CHIPS = new Set(['Known', 'Linked', 'Trusted', 'Classical', 'Pending']);
  const LABELS = new Set(['Known', 'Trusted', 'Pending intro', 'Blocked']);
  const seenChips = new Set<string>();
  const seenLabels = new Set<string>();
  for (const { e, why } of allShapes()) {
    const chip = livingStatusChip(livingEdgeStatus(e));
    seenChips.add(chip);
    assert.ok(CHIPS.has(chip), `chip '${chip}' for ${why}`);
    assert.doesNotMatch(chip, /Trust pending|Mutual|Awaiting|trusts you/i);
    for (const blocked of [false, true]) {
      const label = visualForEdge(e, { blocked }).label;
      seenLabels.add(label);
      assert.ok(LABELS.has(label), `label '${label}' (blocked=${blocked}) for ${why}`);
      assert.doesNotMatch(label, /Trust pending|Mutual|Awaiting|trusts you/i);
    }
  }
  // The loop is not vacuous: it reaches the trusted, known, pending-intro and blocked renderings.
  assert.ok(['Trusted', 'Known', 'Pending intro', 'Blocked'].every((l) => seenLabels.has(l)), `labels seen: ${[...seenLabels].join(', ')}`);
  // 'Known' as a CHIP is not reachable from this shape product (a keyed edge can communicate => 'Linked'); it is still in the allowed set.
  assert.ok(['Trusted', 'Linked', 'Classical', 'Pending'].every((c) => seenChips.has(c)), `chips seen: ${[...seenChips].join(', ')}`);
});

test("the dead 'trust-received' label cannot light up: it reads exactly what a stranger with no trust reads", () => {
  assert.equal(TRUST_VISUAL_LABELS['trust-received'], TRUST_VISUAL_LABELS.known);
  assert.equal(TRUST_VISUAL_LABELS['trust-received'], 'Known');
});

test('control: the same edge with only the OWNER\'s trust set does reach outbound (the loop is not vacuous)', () => {
  assert.equal(livingEdgeStatus(edge({ trusted: true })).trust, 'outbound');
  assert.equal(livingEdgeStatus(edge({ trusted: false })).trust, 'none');
});

test("app/page.tsx's Galaxy ember attention set reads the connection phase only, never the trust phase", () => {
  const src = readFileSync(join(__dirname, '..', '..', '..', 'app', 'page.tsx'), 'utf8');
  const block = /const attention = contacts([\s\S]*?)galaxyActivitySignature\(/.exec(src);
  assert.ok(block, 'the ember attention block exists');
  const code = block![1].replace(/\/\/.*$/gm, ''); // the explanatory comment names these words; only CODE counts
  assert.match(code, /status\.connection === 'pending'/);
  assert.doesNotMatch(code, /inbound/, "no 'inbound' arm");
  assert.doesNotMatch(code, /\.trust\b/, 'the trust phase is not read at all');
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Same family, found at 4e66e6d (Hypatia #959): the NEVER-MUTUAL invariant also has to hold for what the app WRITES, not only what it derives.
// livingEdgeStatus is pinned above, but the stored `mutual.reciprocal` bit is read DIRECTLY by the browse layout, the peer chords and the
// KNOW-layer PSI filter, and used to drive a "Mutual trust crystallised" toast. know-layer-sync.ts says "reciprocal has no writer since #593":
// the demo/sample seeds were the exception. Since #593 nothing in-app can produce a mutual edge (PSI #588 re-grounds it), so demo data must model
// only states the app can produce.
function sourceFiles(root: string): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        if (name !== 'node_modules' && name !== '.next') walk(p);
      } else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) {
        out.push({ path: p, text: readFileSync(p, 'utf8') });
      }
    }
  };
  walk(root);
  return out;
}
const REPO = join(__dirname, '..', '..', '..');
const SRC_AND_APP = [...sourceFiles(join(REPO, 'src')), ...sourceFiles(join(REPO, 'app'))];

test("no non-test file under src/ or app/ writes `reciprocal: true` (the stored bit has NO writer; so no demo edge can read as mutual)", () => {
  assert.ok(SRC_AND_APP.length > 200, `scanned ${SRC_AND_APP.length} files`);
  const hits = SRC_AND_APP.filter((f) => /\breciprocal\s*[:=]\s*true\b/.test(f.text)).map((f) => f.path.replace(REPO + '/', ''));
  assert.deepEqual(hits, []);
  // The control: the scanner does see a real literal (so the empty result above is not a blind spot).
  assert.match('x = { reciprocal: true }', /\breciprocal\s*[:=]\s*true\b/);
  assert.doesNotMatch('m.reciprocal === true', /\breciprocal\s*[:=]\s*true\b/);
});

test("the linked-demo seed has NO `reciprocal` pass-through: its helper cannot be handed `true` by a variable (Flint #962)", () => {
  const text = readFileSync(join(REPO, 'src/components/demo/seed-linked-demo.ts'), 'utf8');
  assert.doesNotMatch(text, /extra\.reciprocal/);
  // `\S` anchors the value: without it `\s*` backtracks to zero spaces and the lookahead sees the space instead of the word.
  const NOT_FALSE = /\breciprocal\s*:\s*(?!false\b)\S/;
  assert.doesNotMatch(text, NOT_FALSE, 'every `reciprocal:` in the seed is the literal false');
  assert.match('reciprocal: true', NOT_FALSE, 'control: sees a literal true');
  assert.match('reciprocal: extra.reciprocal,', NOT_FALSE, 'control: sees a pass-through');
  assert.match('reciprocal:extra.r', NOT_FALSE, 'control: sees a no-space pass-through');
  assert.doesNotMatch('reciprocal: false,', NOT_FALSE, 'control: ignores the honest value');
  assert.match(text, /reciprocal: false/, 'control: the seed still states the honest value');
  // The sample circle feeds `reciprocal` through `!!c.reciprocal`; with no true literal anywhere (test above) it can only ever be false.
  const sample = readFileSync(join(REPO, 'src/lib/trust/sample-circle.ts'), 'utf8');
  assert.ok((sample.match(/reciprocal: false/g) ?? []).length >= 3, 'the three formerly-mutual sample contacts are one-way now');
});

test("no 'Mutual trust crystallised' toast exists: nothing may announce a mutual bond while none can be produced", () => {
  const hits = SRC_AND_APP.filter((f) => /Mutual trust crystal|trust-map-crystallize/i.test(f.text)).map((f) => f.path.replace(REPO + '/', ''));
  assert.deepEqual(hits, []);
});

test("EVERY demo/sample contact note describes the PERSON, never a STATE (no Known/Trusted/Mutual/Pending/affirm/sync/reciprocal word; Hypatia #970/#972)", () => {
  // State lives on the chip and the galaxy. A state word in free text goes stale the moment the user changes the state (un-trust Ada and her note
  // still says Trusted), and nothing else tests free text. This is how the pre-#593 "Mutual trust ·" prefixes outlived the affirm wire.
  const STATE = /\b(known|trusted|trusts?|mutual|pending|affirm\w*|sync\w*|reciproc\w*)\b/i;
  const seeds = ['src/lib/trust/sample-circle.ts', 'src/components/demo/seed-linked-demo.ts'];
  let notes = 0;
  for (const rel of seeds) {
    const text = readFileSync(join(REPO, rel), 'utf8');
    for (const m of text.matchAll(/\bnotes:\s*(['"`])((?:\\.|(?!\1).)*)\1/g)) {
      notes++;
      assert.doesNotMatch(m[2], STATE, `${rel}: note "${m[2]}"`);
    }
  }
  assert.ok(notes >= 12, `scanned ${notes} demo notes`);
  // Controls: the scanner sees a state-prefixed note and ignores a person-only one.
  assert.match('Trusted · analytical engines', STATE);
  assert.match('Mutual · software that flew.', STATE);
  assert.match('Pending connection — accept to know', STATE);
  assert.doesNotMatch('Analytical engines and poetry.', STATE);
  assert.doesNotMatch('Living SVRNTY card — bound key. Switch identity to open their book.', STATE);
});
