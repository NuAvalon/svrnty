// scripts/claim-detectors.test.ts — the 176-case detector corpus, ported from Hypatia's pq_overclaim.test.cjs.
//
// The case arrays below are copied VERBATIM (text, expected, note) from the original — do not edit them
// here; corpus changes go upstream with the content owner (Hypatia) and are re-ported. Each family asserts
// the SAME result field the original asserted (overclaim, or present for the badge + quantum-resistant
// families). Run: npx --no-install tsx --test scripts/claim-detectors.test.ts
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pqAbsoluteOverclaim, invulnerabilityOverclaim, pqBadgeOverclaim, pqResistantIdentityOverclaim, nodeZeroOverclaim, relayMetadataPrivacyOverclaim, smartRelayOverclaim, mailboxDeliveryOverclaim, deliveredOverclaim, connectedOverclaim } from './claim-detectors';

type Case = [string, boolean, string];

const CASES: Case[] = [
  // --- POSITIVE: absolute/totalizing PQ claims with NO PSI carve-out → OVER-CLAIM ---
  ['svrnty is fully post-quantum', true, 'fully'],
  ['everything is post-quantum', true, 'everything is'],
  ['everything is PQ', true, 'everything is pq'],
  ['our post-quantum everything approach', true, 'post-quantum everything'],
  ['all traffic is post-quantum', true, 'all traffic'],
  ['every byte is post-quantum encrypted', true, 'every byte'],
  ['nothing sent over the wire is non-PQ', true, "peter's directive as copy"],
  ['nothing over the wire is classical', true, 'inverse absolute'],
  ['end-to-end post-quantum messaging', true, 'end-to-end'],
  ['100% post-quantum', true, '100%'],
  ['entirely post quantum, no exceptions', true, 'entirely, space variant'],

  // --- NEGATIVE: honest / scoped / hedged / ordinary → NOT an over-claim ---
  ['hybrid post-quantum identity, messaging, and vault', false, 'hybrid+scoped, not absolute'],
  ['post-quantum-ready signing', false, 'ready = future hedge'],
  ['hybrid-PQ identity/messaging/vault; classical mutual-visibility, PQ-PSI coming', false, 'THE honest end-state'],
  ['our post-quantum pillar protects your identity', false, 'bare pillar (existing check handles)'],
  ['fully post-quantum for identity, messaging and vault — mutual visibility stays classical (PQ-PSI coming)', false, 'absolute BUT carved-out → honest'],
  ['everything is post-quantum, though contact discovery uses classical DH for now', false, 'absolute BUT carve-out present'],
  ['classical mutual-visibility, PQ-PSI coming', false, 'carve-out alone, no absolute claim'],
  ['we use ML-KEM-1024 and ML-DSA-87', false, 'specific primitives, not absolute'],
  ['post-quantum cryptography protects everything you send', false, 'ordinary marketing, not a totalizing claim'],

  // --- SYNONYMS (Flint #127684): totalizing quantum-safe/proof/resistant → OVER-CLAIM ---
  ['svrnty is fully quantum-safe', true, 'synonym: fully quantum-safe'],
  ['everything is quantum-proof', true, 'synonym: everything quantum-proof'],
  ['all traffic is quantum-resistant', true, 'synonym: all traffic quantum-resistant'],
  ['nothing over the wire is non-quantum-safe', true, 'synonym: nothing-over-wire'],
  ['fully quantum-safe for id, messaging and vault — mutual visibility stays classical (PQ-PSI coming)', false, 'synonym totalizing BUT carved-out'],
  // BARE scoped synonyms are wireable per-feature → out of THIS check's scope (line-52's job):
  ['quantum-safe messaging', false, 'bare scoped synonym — not a totalizing claim'],
  ['quantum-resistant signing', false, 'bare scoped synonym — wireable per-feature'],
];

const INV_CASES: Case[] = [
  ['svrnty is unbreakable', true, 'unbreakable'],
  ['unhackable by design', true, 'unhackable'],
  ['your data is 100% secure', true, '100% secure'],
  ['completely secure messaging', true, 'completely secure'],
  ['your messages are quantum-proof', true, 'quantum-proof = invulnerability (Flint\'s original slip)'],
  // 2026-10-24 rule (lane:svrnty #21/#24/#29): "quantum-safe" / "PQ-secure" are absolute at ANY scope.
  ['svrnty is quantum-safe', true, 'quantum-safe = absolute (Oct-24 rule)'],
  ['quantum-safe messaging', true, 'scoped quantum-safe is STILL absolute (supersedes #127684 allow)'],
  ['quantum safe notes', true, 'spaced variant'],
  ['PQ-secure messaging', true, 'PQ-secure = absolute'],
  ['pq secure vault', true, 'spaced variant'],
  ['post-quantum (hybrid) encryption', false, 'the honest post-S15 wording is NOT an over-claim'],
  ['needs a security upgrade before you can message them', false, 'S14 skipped-send copy is claim-safe'],
  ['it is impossible to break', true, 'impossible to break'],
  ['your vault can\'t be hacked', true, "can't be hacked"],
  ['your keys can never be broken', true, 'never be broken'],
  // NEGATIVE — the honest terms + ordinary copy:
  ['quantum-resistant signing', false, 'resistant is honest, not invulnerable'],
  ['post-quantum messaging', false, 'post-quantum is honest'],
  ['secure by design', false, 'no absolute-invulnerability modifier'],
  ['we can\'t read your messages', false, "can't READ (privacy) ≠ can't be hacked"],
];

const BADGE_CASES: Case[] = [
  ['✓ post-quantum protected — a signed card carrying a verified encryption key', true, 'JoinerCeremony:459 over-claim'],
  ['post-quantum secured', true, 'secured variant'],
  ['✓ post-quantum', true, 'bare ✓ post-quantum (unhedged)'],
  ['post-quantum protected. ml-dsa-87 ready.', true, 'protected wins over a stray "ready"'],
  ['post-quantum-ready encryption. no server can read your data.', false, 'honest: post-quantum-ready'],
  ['post-quantum keys carried and ready (not yet the live path)', false, 'honest: keys carried and ready'],
  ['their post-quantum key is now stored', false, 'honest: key stored (no protected/secured/✓)'],
  ['classical today, with post-quantum keys carried and ready', false, 'honest #78 rewrite'],
  ['✓ post-quantum ready', false, '✓ post-quantum ready = hedged, must NOT flag'],
  ['upgrade to post-quantum', false, 'action label, not a badge'],
];

const QR_CASES: Case[] = [
  ['now quantum-resistant', true, 'landing.html :186 tagline — bare identity claim'],
  ['your key is you — now quantum-resistant', true, 'landing.html :186 full — key-as-identity'],
  ['your identity has been created. 4 keypairs generated. quantum-resistant.', true, 'landing.html :219 — identity-level, standalone'],
  ['your identity is quantum-resistant', true, 'bare identity-level claim'],
  ['quantum-resistant.', true, 'standalone one-word status claim'],
  // NEGATIVE — scoped to a wireable primitive (honest: the algorithm/feature IS quantum-resistant):
  ['quantum-resistant signing', false, 'scoped primitive — honest (matches existing convention line 40/62)'],
  ['quantum-resistant signatures on every message', false, 'scoped primitive (plural stem)'],
  ['quantum-resistant messaging', false, 'scoped primitive'],
  ['quantum-resistant encryption', false, 'scoped primitive'],
  ['we use quantum-resistant ml-dsa-87', false, 'scoped to the algorithm'],
  ['our signing is quantum-resistant', false, 'feature precedes — scoped'],
  ['quantum-resistant cryptography protects your messages', false, 'scoped to crypto(graphy)'],
  // NEGATIVE — hedged / term absent:
  ['quantum-resistant ready', false, 'hedged future'],
  ['classical today, quantum-resistant coming', false, 'hedged: coming'],
  ['post-quantum keys carried and ready', false, "'post-quantum' not 'quantum-resistant' — term absent"],
];

const NZ_CASES: Case[] = [
  // POSITIVE — a post-launch tier claimed live, no hedge → OVER-CLAIM
  ['watchtowers monitor every release for tampering', true, 'watchtowers live'],
  ['your peers cross-attest your identity', true, 'peer cross-attestation live'],
  ['peer attestation confirms you are who you say', true, 'peer attestation live'],
  ['install the browser extension verifier', true, 'T2 extension verifier live'],
  ['the native app verifier checks every build', true, 'T3 native verifier live'],
  ['the attestation plane proves you met in person', true, 'attestation plane (§5.2) live'],
  ['protected by a global network of watchtowers', true, 'watchtowers live (marketing)'],
  ['watchtowers and peer cross-attestation protect every install', true, 'both live, no hedge'],
  // NEGATIVE — hedged (roadmap) → honest
  ['watchtowers coming soon', false, 'watchtower hedged: coming soon'],
  ['peer cross-attestation is on the roadmap', false, 'peer-attest hedged: roadmap'],
  ['a browser extension verifier is coming post-launch', false, 'extension hedged: coming/post-launch'],
  ['the attestation plane will arrive after launch', false, 'attestation-plane hedged: will arrive'],
  ['watchtowers and peer attestation are planned for a future release', false, 'hedged: planned/future'],
  // NEGATIVE — the LIVE tier (T1 service-worker) + honest verify copy → NOT flagged (term absent)
  ['your app is verified by the service worker against node zero', false, 'T1 service-worker = live gate, exempt'],
  ['node zero verifies this release', false, 'bare node-zero/T1 verify — not a post-launch term'],
  ['you have verified this contact in person', false, 'live verify ladder — no post-launch term'],
  ['known, then verified, then trusted', false, 'know/verify/trust ladder — live, no term'],
  ['attestation of a contact you met', false, 'bare "attestation" (live ladder) — only plane/peer flagged'],
];

const RM_CASES: Case[] = [
  // POSITIVE — metadata / social-graph / who-you-talk-to / unlinkability privacy claimed live → OVER-CLAIM
  ["the relay can't see who you talk to", true, 'social graph in plain language'],
  ["we can't see who you message", true, 'who-you-message privacy'],
  ['nobody can see who you communicate with', true, 'nobody-sees-who'],
  ['your metadata is private', true, 'metadata private'],
  ['metadata-private by design', true, 'metadata-private compound'],
  ['no metadata, ever', true, 'no metadata'],
  ['your social graph is hidden from the relay', true, 'social graph hidden'],
  ['sender and recipient are unlinkable', true, 'unlinkable'],
  ['fully unlinkable messaging', true, 'unlinkable (adverb)'],
  ['the relay knows nothing about you', true, 'totalizing knows-nothing (not content-scoped)'],
  ["even we can't see who talks to whom", true, 'who-talks-to-whom'],
  ['your connections are invisible to the relay', true, 'connection graph invisible'],
  ['traffic-analysis resistant', true, 'traffic-analysis resistance (no cover traffic at launch)'],
  // NEGATIVE — HONEST CONTENT-privacy claims (E2E-blindness IS real → must NOT flag) ---
  ['your messages are private', false, 'CONTENT privacy — honest'],
  ["we can't read your messages", false, "can't READ = content, honest (not can't SEE-WHO)"],
  ['content is end-to-end encrypted', false, 'content E2E — honest'],
  ['the relay is content-blind', false, 'content-blind — honest (scoped)'],
  ['the relay is e2e-blind — it never sees your plaintext', false, 'e2e-blind + plaintext-scoped — honest'],
  ['only you and your contact can read what you send', false, 'content readability — honest (bare "contact")'],
  ["the server can't read your data", false, "can't READ data = content, honest"],
  // NEGATIVE — HONEST hedged / carve-out (Flint's launch line) → must NOT flag ---
  ['content is e2e-blind; the relay observes delivery metadata; metadata privacy is coming post-launch', false, "Flint's honest launch line"],
  ['we do not yet claim metadata privacy against the relay', false, 'negated claim — honest'],
  ['sender-recipient unlinkability is a post-launch hardening', false, 'unlinkability hedged: post-launch'],
  ['the relay sees delivery metadata today; full unlinkability comes later (pir)', false, 'disclosure + hedged: later'],
  ['social-graph privacy: coming soon', false, 'social-graph hedged: coming soon'],
  ['metadata minimized, but the relay still observes delivery patterns', false, 'honest disclosure, no privacy claim'],
  // NEGATIVE — term absent / ordinary ---
  ['your identity is yours alone', false, 'no relay-metadata object'],
  ['the relay carries opaque blobs', false, 'honest, no privacy claim'],
  // NEGATIVE — Flint's honest STORE-PROPERTY carve-out (#142210): "no stored edge / no sender field" is
  // TRUE by design (mailbox-store keeps only opaque blob + relay-id) — must NOT trip the social-graph flag ---
  ['the relay stores no social-graph edge', false, "Flint store-property: no stored edge (honest, ≠ unlinkable)"],
  ['no sender field is stored on the relay', false, 'Flint store-property: no sender field'],
  ['the relay keeps no edge-list', false, 'Flint store-property: no edge-list'],
  ['sender identity lives inside the e2e blob, not the relay', false, 'Flint design fact: sender in blob, not relay'],
  ['your social graph is not stored by the relay', false, 'not-stored = store-property, honest (≠ social graph is private)'],
];

const SR_CASES: Case[] = [
  ['smart relays route your messages now', true, 'smart-relay live'],
  ['powered by smart relays', true, 'smart-relay live (marketing)'],
  ['smart-relays are coming post-launch', false, 'hedged: post-launch'],
  ['smart relays will arrive after launch', false, 'hedged: will arrive'],
  ['we launch on the current content-blind relay', false, 'current relay — term absent'],
  ['the relay carries opaque blobs', false, 'bare relay — not smart-relay'],
];

const MB_CASES: Case[] = [
  // POSITIVE — NOT-BUILT layer only (Phase-2, zero app callers): smart-mailbox / routing / portability / pointer
  ['powered by smart mailboxes', true, 'smart mailbox (Phase-2)'],
  ['mailbox-key routing finds you anywhere', true, 'mailbox-key ROUTING (Phase-2)'],
  ['cross-relay portability — host your mailbox anywhere', true, 'cross-relay portability (Phase-2)'],
  ['swap relays anytime', true, 'multi-relay swap (Phase-2)'],
  ['your mailbox follows you across relays', true, 'portability phrasing (Phase-2)'],
  ['your mailbox pointer is published to the registry', true, 'published mailbox POINTER (Phase-2)'],
  // NEGATIVE — BASIC return-channel DELIVERY IS LIVE (Apollo #142216 self-correction) → must NOT flag
  ['your card changes reach your contacts through the relay mailbox', false, "Apollo's exact honest line — LIVE return-channel"],
  ['your updates reach your contacts', false, 'live contact-update delivery — honest'],
  ['return-channel delivery keeps your contacts in sync', false, 'live return-channel — honest'],
  ['your messages route to you', false, 'basic delivery LIVE now (was wrongly flagged pre-correction)'],
  ['your mailbox is live', false, 'delivery is live — honest'],
  ['mailbox delivery is here', false, 'delivery is live — honest'],
  // NEGATIVE — honest PRIMITIVE / contested "mailbox keys" term (Flint↔Apollo collision → manual, not auto-flagged)
  ['sealed mailbox envelopes', false, 'primitive (seal/open) — honest'],
  ['your mailbox keypair, cryptographically sealed', false, 'contested "mailbox keys" term — manual, not auto-flagged'],
  ['svrnty generates mailbox keypairs', false, 'contested "mailbox keys" term — manual (Flint↔Apollo collision)'],
  // NEGATIVE — hedged (Phase-2 / coming) → honest
  ['smart mailboxes are on the roadmap', false, 'smart-mailbox hedged: roadmap'],
  ['cross-relay portability planned post-launch', false, 'hedged: planned/post-launch'],
  ['a published mailbox pointer is coming in phase 2', false, 'pointer hedged: phase 2'],
  // NEGATIVE — unrelated
  ['your identity is yours alone', false, 'no not-built mailbox term'],
];

const DL_CASES: Case[] = [
  // POSITIVE — confirmed-receipt claimed (no delivery-ack exists) → OVER-CLAIM
  ['your update was delivered', true, 'past-tense confirmed delivery'],
  ['✓ delivered', true, 'delivered badge'],
  ['they received it', true, 'they received it (Archie example)'],
  ['they got your update', true, 'they got it'],
  ['delivery confirmed', true, 'delivery confirmed'],
  ['read receipt shows seen', true, 'read receipt'],
  ['received by your contact', true, 'received by contact'],
  ['your message has been delivered and read', true, 'has been delivered'],
  // NEGATIVE — honest "sent"/"queued"/"deposited"/live-capability + hedged-future → must NOT flag
  ['sent', false, 'sent = honest'],
  ['your update is queued', false, 'queued = honest'],
  ['your card changes reach your contacts through the relay mailbox', false, "Apollo's live capability — honest (no receipt claim)"],
  ['your update is deposited to their mailbox', false, 'deposited = honest'],
  ['will be delivered when they next poll', false, 'hedged future delivery — honest'],
  ['your updates are sent to your contacts', false, 'sent — honest'],
  ['your update is on its way', false, 'on its way = honest'],
  ['your identity is yours alone', false, 'no delivery/receipt term'],
];

const CONN_CASES: Case[] = [
  // POSITIVE — confirmed-mutual connection claimed unconditionally → OVER-CLAIM (remote join can silently half-fail)
  ['you are connected', true, 'JoinerCeremony:643 unconditional'],
  ["you're now connected", true, "you're now connected"],
  ['✓ connected', true, 'connected badge'],
  ['connection complete', true, 'connection complete'],
  ['successfully connected', true, 'successfully connected'],
  ['you are connected!', true, 'connected with punctuation'],
  // NEGATIVE — async framing / in-person scope / added-not-connected → honest
  ["you've added them, they'll see your request when they next open their wallet", false, "Archie's honest async line"],
  ['request sent — pending their confirmation', false, 'pending — honest'],
  ['you are connected in person', false, 'in-person scoped — presence confirms mutual'],
  ["you'll be connected once they accept", false, 'future + once-they-accept hedge'],
  ['connect with your contacts', false, 'verb "connect" — not a status claim'],
  ['stay connected', false, 'aspiration, not a "you are connected" status'],
  ['your identity is yours alone', false, 'no connection term'],
];

const FAMILIES: Array<[string, Case[], (t: string) => boolean]> = [
  ["absolute/totalizing PQ — pqAbsoluteOverclaim().overclaim", CASES, (t) => pqAbsoluteOverclaim(t).overclaim],
  ["invulnerability word-honesty — invulnerabilityOverclaim().overclaim", INV_CASES, (t) => invulnerabilityOverclaim(t).overclaim],
  ["post-login PQ badge — pqBadgeOverclaim().present", BADGE_CASES, (t) => pqBadgeOverclaim(t).present],
  ["identity-level quantum-resistant — pqResistantIdentityOverclaim().present", QR_CASES, (t) => pqResistantIdentityOverclaim(t).present],
  ["Node Zero post-launch tier — nodeZeroOverclaim().overclaim", NZ_CASES, (t) => nodeZeroOverclaim(t).overclaim],
  ["relay metadata / social-graph privacy — relayMetadataPrivacyOverclaim().overclaim", RM_CASES, (t) => relayMetadataPrivacyOverclaim(t).overclaim],
  ["smart-relay live — smartRelayOverclaim().overclaim", SR_CASES, (t) => smartRelayOverclaim(t).overclaim],
  ["mailbox not-built layer — mailboxDeliveryOverclaim().overclaim", MB_CASES, (t) => mailboxDeliveryOverclaim(t).overclaim],
  ["delivered (confirmed-receipt) — deliveredOverclaim().overclaim", DL_CASES, (t) => deliveredOverclaim(t).overclaim],
  ["connected (unconditional remote join) — connectedOverclaim().overclaim", CONN_CASES, (t) => connectedOverclaim(t).overclaim],
];

// Guard against a silently dropped case: the corpus is 176 cases (pq_overclaim.test.cjs, 2026-10-24).
const TOTAL = FAMILIES.reduce((n, [, cases]) => n + cases.length, 0);
if (TOTAL !== 176) throw new Error(`claim-detectors corpus has ${TOTAL} cases, expected 176 — a case was dropped or added without updating this guard`);

for (const [label, cases, flag] of FAMILIES) {
  describe(label, () => {
    for (const [text, expected, note] of cases) {
      it(`${expected ? 'FLAG' : 'pass'}: ${note} — "${text.slice(0, 60)}"`, () => {
        assert.equal(flag(text), expected);
      });
    }
  });
}

// --- G-1 punctuation gap (launch copy-fix spec 9585bac1 item 6; fixtures = Hypatia's g1_punctuation_test.py 71d110d4, verbatim) ---
// The registry pattern must catch "post-quantum" claims whose words are separated by punctuation, not only spaces/hyphens.
describe('G-1 registry pattern: punctuation between the words', () => {
  const g1 = JSON.parse(readFileSync(join(__dirname, 'claim-registry.json'), 'utf8')).claims.find((c: { id: string }) => c.id === 'G-1');
  const NEW = new RegExp(g1.patterns.find((p: string) => p.startsWith('post-quantum(?:') && p.includes('protected|encrypted')), 'i');
  const OLD = /post-quantum(?:[-\s]+\w+){0,4}[-\s]+(protected|encrypted|encryption(?![-\s]+keys?\b))/i;
  const HIT = [
    '✓ Post-quantum (hybrid) encryption — a signed card carrying a verified encryption key.',
    'Post-quantum, end-to-end encrypted messages.',
    'post-quantum/hybrid encrypted',
    'Post-quantum (ML-KEM-1024) protected notes',
    'post-quantum: encrypted by default',
    'Post-quantum encrypted messages',
  ];
  const MISS = [
    'This card carries a verified post-quantum encryption key.',
    'Each identity advertises a post-quantum encryption key, and the hybrid X25519 + ML-KEM-1024 primitives are built and tested',
    'a post-quantum (ML-KEM) encryption key',
  ];
  it('NEG first: the old pattern misses the punctuation forms', () => {
    assert.equal(HIT.slice(0, 5).filter((s) => !OLD.test(s)).length, 5);
  });
  it('the registry pattern catches every punctuation form', () => {
    for (const s of HIT) assert.equal(NEW.test(s), true, s);
  });
  it('and still passes an encryption KEY (a key is not protection)', () => {
    for (const s of MISS) assert.equal(NEW.test(s), false, s);
  });
  it('a post-quantum-ready hedge is caught by the pattern (the hedge rule, not the pattern, excuses it)', () => {
    assert.equal(NEW.test('Post-quantum-ready encryption. No server can read your messages.'), true);
  });
});
