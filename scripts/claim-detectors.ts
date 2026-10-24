// scripts/claim-detectors.ts — TypeScript port of Hypatia's pq_overclaim.cjs (claim-honesty detectors).
//
// PORTED FAITHFULLY, NOT RE-DERIVED: every regex, term list, hedge and return shape below is byte-identical
// to autobots shared/outbox/hypatia/pq_overclaim.cjs (2026-10-24). The ONLY edits are TypeScript
// parameter annotations on the exported functions and `module.exports` → `export`. Regex/logic changes
// belong upstream with the content owner (Hypatia) first, then re-port. Corpus: claim-detectors.test.ts
// (176 cases, must stay all-green). Consumed by scripts/claim-sweep.ts via scripts/claim-registry.json
// (`detector` field). The file header below is the original's.
//
// PQ ABSOLUTE-CLAIM DETECTOR — for the svrnty launch-honesty gate (launch_claim_sweep.cjs).
//
// WHY THIS EXISTS (Flint #127640, Peter #127616, Apollo-confirmed):
//   PQ-at-launch = HYBRID for identity / messaging / vault ONLY.
//   PSI (mutual-contact-discovery) STAYS CLASSICAL DH at launch — PQ-PSI is research-grade,
//   post-launch, no drop-in. So the honest claim is:
//     "hybrid-PQ identity/messaging/vault; classical mutual-visibility, PQ-PSI coming."
//   Therefore ANY totalizing claim — "fully/everything post-quantum", "nothing over the wire is
//   non-PQ" — is an OVER-CLAIM with NO wired-true state at launch. Unlike a bare "post-quantum"
//   pillar (which flips honest once Flint's hybrid wire lands), an absolute claim can ONLY be
//   honest by being ABSENT or by carrying the explicit PSI-classical CARVE-OUT.
//
// This is why the gate must hardcode wired=false for this check (NOT WIRED.pqSigning && ...):
// wiring the hybrid does not make "fully PQ" true. Do not "helpfully" tie it to a WIRED flag.
//
// Pure + side-effect-free so it can be unit-tested WITHOUT the live browser (see
// pq_overclaim.test.cjs). Input is normalized here (lowercase + whitespace-collapse) to exactly
// match launch_claim_sweep.cjs's clean()+toLowerCase() so test strings and live copy see the
// same regex behavior. The gate is a FLOOR, not a ceiling — human copy-review still matters.

// PQ term: "post-quantum" + the common marketing synonyms (Flint co-verify #127684 — "fully
// quantum-safe" / "quantum-proof" would otherwise slip the totalizing set; forward-guard, since
// current copy uses "post-quantum"). SCOPE: synonyms are caught only inside TOTALIZING
// constructions below (same PSI-carve-out logic as the rest of this check). BARE scoped synonyms
// ("quantum-safe messaging") are wireable per-feature → they belong to the gate's bare-"post-quantum"
// check (launch_claim_sweep line ~52), not here — mixing wireable + un-wireable semantics in one
// check would muddy it. (Follow-up flagged to Flint: teach the bare check the same synonyms.)
const PQ = '(?:post.?quantum|quantum.?(?:safe|proof|resistant)|pq)';

// Totalizing PQ phrasings = the over-claim surface.
const ABSOLUTE_PQ = [
  new RegExp(`\\b(?:fully|entirely|completely|totally|end.to.end|100%?)\\s+${PQ}\\b`),
  new RegExp(`\\b(?:everything|all\\s+of\\s+it|it\\s+all)\\s+(?:is\\s+)?${PQ}\\b`),
  new RegExp(`\\b${PQ}\\s+everything\\b`),
  new RegExp(`\\ball\\s+(?:traffic|data|messages?|bytes?|communications?)\\b[^.]{0,30}\\b${PQ}\\b`),
  new RegExp(`\\bevery\\s+byte\\b[^.]{0,30}\\b${PQ}\\b`),
  new RegExp(`\\bnothing\\s+(?:sent\\s+|going\\s+)?(?:over|across)\\s+(?:the\\s+)?wire\\s+is\\s+(?:non.?pq|non.?post.?quantum|not\\s+post.?quantum|non.?quantum.?(?:safe|proof|resistant)|classical)\\b`),
];

// The explicit PSI-classical carve-out that RESCUES an absolute claim into honesty.
// Must name that mutual-visibility / contact-discovery / PSI is classical (or PQ-PSI is coming).
const PSI_CARVEOUT = [
  /\bclassical\b[^.]{0,40}\b(mutual|contact|visibility|discovery|psi|dh)\b/,
  /\b(mutual.?visibility|mutual.?contact|contact.?discovery|psi)\b[^.]{0,40}\bclassical\b/,
  /\bpq.?psi\b[^.]{0,30}\b(coming|soon|post.?launch|not\s+yet|later)\b/,
];

function normalize(text: string | null | undefined): string {
  return (text || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

// Returns { present, carveout, overclaim }. overclaim === present && !carveout.
function pqAbsoluteOverclaim(text: string) {
  const t = normalize(text);
  const present = ABSOLUTE_PQ.some(re => re.test(t));
  const carveout = PSI_CARVEOUT.some(re => re.test(t));
  return { present, carveout, overclaim: present && !carveout };
}

// ABSOLUTE-INVULNERABILITY word-honesty (Flint #127688): claims of total invulnerability that
// over-claim at ANY scope/wiring — no crypto is "proof"/"unbreakable" (NIST convention: post-quantum
// / quantum-RESISTANT, never "proof"; a hybrid is hard-to-break, never invulnerable). DISTINCT logic
// from the PSI-carve-out above: NO hedge or carve-out rescues an invulnerability claim — the only
// honest fix is to not make it. "quantum-proof" lives HERE (proof = invulnerability), not in the
// totalizing PQ set.
// "quantum-safe" / "PQ-secure" WERE allowed here as loose synonyms (Flint #127684, Sep) — SUPERSEDED
// 2026-10-24 (loom lane:svrnty #21/#24/#29: Flint "never quantum-safe/PQ-secure in user copy",
// Hypatia "NEVER, not just until Nov-5: absolute claims; ML-KEM is assumption-based", Archie agreed,
// Flint CONFIRMED "never" in lane:svrnty #33).
// They are now invulnerability claims at ANY scope, same as "proof". The honest wording, once S15 has
// flipped and Flint has co-verified it live: "post-quantum (hybrid) encryption" / "quantum-resistant".
const INVULNERABILITY = [
  /\bquantum.?proof\b/,
  /\bquantum.?safe\b/,
  /\bpq.?secure\b/,
  /\bunbreakable\b/,
  /\bunhackable\b/,
  /\bimpossible\s+to\s+(?:break|hack|crack)\b/,
  /\b(?:100%?|completely|totally|perfectly|absolutely)\s+secure\b/,
  /\b(?:can'?t|cannot)\s+be\s+(?:hacked|broken|cracked)\b/,
  /\bnever\s+be\s+(?:hacked|broken|cracked)\b/,
];

// Returns { present, overclaim }. No carve-out — an invulnerability claim is over at any scope.
function invulnerabilityOverclaim(text: string) {
  const t = normalize(text);
  const present = INVULNERABILITY.some(re => re.test(t));
  return { present, overclaim: present };
}

// POST-LOGIN PQ BADGE over-claim (JoinerCeremony-class, #521): a "✓ post-quantum protected" /
// "post-quantum secured" badge claims LIVE PQ protection (vs the honest "post-quantum ready/carried").
// UNLIKE the absolute check, this HAS a wired-true state — the gate ANDs `present` with
// WIRED.pqSigning && WIRED.pqEncryption, so a "protected" badge flips honest once the hybrid wire lands.
// Hedge allows up to 3 words between "post-quantum" and "ready/carried" ("post-quantum keys carried and
// ready" = the honest #78 rewrite). "protected"/"secured" is an over-claim regardless of a stray hedge;
// the ✓/verified clause is exempted only when the copy is genuinely hedged. TEST before trusting (dialect trap).
const PQ_BADGE_HEDGE = /post[- ]?quantum(?:[- ]?\w+){0,3}[- ]?(?:ready|carried)/;
const PQ_BADGE_PROTECTED = /post[- ]?quantum[- ]?(?:protected|secured)/;
const PQ_BADGE_VERIFIED = /(?:✓|verified)\s*[·:]?\s*post[- ]?quantum/;

// Returns { present, hedged }. present === over-claim badge on the surface (gate ANDs with wired-state).
function pqBadgeOverclaim(text: string) {
  const t = normalize(text);
  const hedged = PQ_BADGE_HEDGE.test(t);
  const present = PQ_BADGE_PROTECTED.test(t) || (PQ_BADGE_VERIFIED.test(t) && !hedged);
  return { present, hedged };
}

// IDENTITY-LEVEL "QUANTUM-RESISTANT" OVER-CLAIM (Hypatia 🌀6467, 2026-09-12 — the landing.html / sweep-G3 gap).
// The three checks above ALL miss a bare "your identity is quantum-resistant" claim:
//   - pqAbsoluteOverclaim catches "quantum-resistant" only inside TOTALIZING constructions (line 28/31).
//   - invulnerabilityOverclaim DELIBERATELY treats "quantum-resistant" as the HONEST fix for "quantum-proof" (line 66).
//   - pqBadgeOverclaim keys on "post-quantum", not "quantum-resistant".
// So landing.html's "now quantum-resistant" (:186) / "Quantum-resistant." (:219) slipped every check — a LIVE
// claim that the IDENTITY is quantum-resistant while its DID commits ONLY the classical Ed25519 key (PQ keys
// carried-not-BOUND → the DID SHA256(Ed25519) is forgeable under a broken Ed25519).
// THE NUANCE (concept 'Claim-Honesty as Architecture Integrity' v11, KB#89349): "quantum-resistant" is HONEST
// describing a wireable PRIMITIVE (ML-DSA signing IS quantum-resistant) but an OVER-CLAIM describing the
// IDENTITY / KEY as a whole when the canonical DID is classical-bound. So flag a BARE, identity-level
// "quantum-resistant" — EXEMPT when scoped to a wireable primitive (signing/messaging/encryption/…​) or hedged
// ("ready"/"carried"). This is FLAG-FOR-REVIEW: the sweep surfaces the claim; runbook G3 verifies whether the
// DID is the canonical HYBRID (PQ committed). Honest ⟺ PQ keys BOUND into the DID, not merely carried.
const QR_TERM = /\bquantum[- ]?resistant\b/;
// scope stems (match "signing/signature/signatures", "messaging/messages", "encryption/encrypted",
// "crypto/cryptography/cryptographic") — a wireable primitive genuinely IS quantum-resistant when wired.
const QR_SCOPED = /\bquantum[- ]?resistant[- ]?(?:sign|signature|messag|encrypt|vault|cipher|crypto|algorithm|hash|dh|kem|dsa|ml[- ]?dsa|ml[- ]?kem|key[- ]?exchange)/;
const QR_SCOPED_PRE = /\b(?:sign|signatur|messag|encrypt|vault|cipher|crypto|algorithm|hash|dh|kem|dsa|ml[- ]?dsa|ml[- ]?kem)\w*\b[^.]{0,15}\bquantum[- ]?resistant\b/;
const QR_HEDGE = /\bquantum[- ]?resistant[- ]?(?:ready|coming|soon|later)\b|\b(?:ready|coming|carried|soon)\b[^.]{0,12}\bquantum[- ]?resistant\b/;

// Returns { present, scoped, hedged }. present === a bare identity-level "quantum-resistant" over-claim
// (FLAG-FOR-REVIEW; verify DID-is-canonical-hybrid per sweep G3 — honest only if PQ is BOUND into the DID).
function pqResistantIdentityOverclaim(text: string) {
  const t = normalize(text);
  const term = QR_TERM.test(t);
  const scoped = QR_SCOPED.test(t) || QR_SCOPED_PRE.test(t);
  const hedged = QR_HEDGE.test(t);
  return { present: term && !scoped && !hedged, scoped, hedged };
}

// NODE ZERO POST-LAUNCH-TIER OVER-CLAIM (Hypatia 🌀6772, 2026-09-22 — the equinox-launch Node-Zero gap).
// GROUND TRUTH (Peter #141727 / KB#90121): Node Zero recognition = the PRE-MINT LAUNCH GATE. The
// T1 SERVICE-WORKER verifier is the launch-gate tier (may be live at reveal). T2 browser-extension /
// T3 native verifier / WATCHTOWERS / PEER cross-attestation, and the embodiment ATTESTATION PLANE (§5.2,
// "coming"), are POST-LAUNCH by design and must NOT read as live. So a present-tense LIVE claim about a
// post-launch tier, WITHOUT a nearby coming/roadmap hedge, is an over-claim. T1 / "service worker" /
// bare "node zero verifies" is EXEMPT (the live gate) — it is deliberately NOT in the term set, so an
// honest T1 claim never trips this. Bare "attestation" is EXEMPT too (the live Know→Verify ladder uses
// it) — only "attestation PLANE" (the coming embodiment plane) and PEER/CROSS-attestation are flagged.
// FLAG-FOR-REVIEW (like the QR check): the sweep surfaces the claim; the reveal-copy read (guardedSession)
// + Flint's §15 launch-ranking are the arbiters. Pure + tested (pq_overclaim.test.cjs). Gate = FLOOR.
// BOUNDARY CONFIRMED by Flint (§15 class-owner, #142078): T1-live / all-else-post-launch is correct as coded.
// WATCHTOWER CONTINGENCY (Flint): watchtowers are "strongly-recommended AT/NEAR launch" in §2 but confirmed
// NOT built at reveal (w/ Apollo/Athena) — so "watchtowers live/watching" IS an over-claim, correctly flagged.
// IF a minimal watchtower stands up BEFORE the reveal, it flips to live → move 'watchtowers?' OUT of NZ_TERMS
// (one-line). DEFAULT post-launch; do NOT assume it's live. (Re-confirm with Flint at reveal-time.)
const NZ_TERMS = [
  'watchtowers?',
  'peer[- ]?(?:cross[- ]?)?attest\\w*',
  'cross[- ]?attest\\w*',
  '(?:browser[- ]?)?extension[- ]?verif\\w*',
  'native[- ]?(?:app[- ]?)?verif\\w*',
  'attestation[- ]?plane',
];
const NZ_TERM_RE = new RegExp('\\b(?:' + NZ_TERMS.join('|') + ')');
// Hedge words that rescue a post-launch-tier mention into honesty (roadmap framing).
const NZ_HEDGE_WORD = '(?:coming(?:\\s+soon)?|soon|planned|road\\s?map|post[- ]?launch|not\\s+yet|later|in\\s+development|on\\s+the\\s+way|future|to\\s+come|will\\s+(?:soon\\s+)?(?:be|come|arrive|ship|support|let|allow|enable))';
// Scoped hedge: a hedge within ~40 non-sentence-ending chars of a post-launch term (either order), so a
// stray "coming" elsewhere on the surface (e.g. "Distress — coming") can't exempt a live watchtower claim.
const NZ_HEDGED_RE = new RegExp(
  NZ_HEDGE_WORD + '[^.]{0,40}\\b(?:' + NZ_TERMS.join('|') + ')' +
  '|\\b(?:' + NZ_TERMS.join('|') + ')[^.]{0,40}' + NZ_HEDGE_WORD
);

// Returns { present, hedged, overclaim }. overclaim === present && !hedged. FLAG-FOR-REVIEW — confirm
// against the reveal build + Flint's §15 launch-ranking (T1 service-worker = the only launch tier).
function nodeZeroOverclaim(text: string) {
  const t = normalize(text);
  const present = NZ_TERM_RE.test(t);
  const hedged = NZ_HEDGED_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

// RELAY METADATA / SOCIAL-GRAPH PRIVACY OVER-CLAIM (Hypatia 🌀6781, 2026-09-22 — Flint's relay
// threat-model #142188 / Archie #142195, shared/outbox/flint/attestation/relay_behavior_audit_threat_model.md §3).
// GROUND TRUTH: the relay is CONTENT-blind (E2E) — TRUE — but it OBSERVES DELIVERY METADATA (who
// deposits-to / polls which mailbox, when, what size → the social graph). Sender↔recipient
// unlinkability is NOT achieved at launch (post-launch padding→batching→PIR/mixnet ladder). So the
// reveal/UX must NOT claim metadata / social-graph / unlinkability privacy AGAINST THE RELAY.
// Over-claiming here = broken sovereignty promise = CONSTITUTIONAL harm (invariant-over-convenience).
// Flint's honest launch line (the carve-out that RESCUES): "content is E2E-blind to the relay; the
// relay observes delivery metadata; we do not yet claim metadata/social-graph privacy against the
// relay — post-launch hardening."
//
// THE PRECISION TRAP (my seat, surface≠substrate): a CONTENT-privacy claim is HONEST ("your messages
// are private", "we can't read your messages", "content-blind", "E2E") — E2E-blindness IS real. Only
// a METADATA / WHO-YOU-TALK-TO / SOCIAL-GRAPH / UNLINKABILITY claim over-claims. The detector keys on
// the metadata/social-graph OBJECT so content claims never match; the totalizing "relay knows nothing"
// / "blind relay" family is CONTENT-EXEMPTED (honest iff scoped to content/message/plaintext).
// FLAG-FOR-REVIEW + hedge-aware. TEST the content-honest + carve-out cases as must-NOT-flag (regex-dialect trap). Gate = FLOOR.
const RM_HEDGE_WORD = '(?:coming(?:\\s+soon)?|soon|planned|road\\s?map|post[- ]?launch|not\\s+yet|later|in\\s+development|on\\s+the\\s+way|future|to\\s+come|will\\s+(?:soon\\s+)?(?:be|come|arrive|ship|support))';
// "who you talk to" — the social-graph object in plain language.
const RM_WHO = 'who\\s+(?:you\\b[^.]{0,20}(?:talk|messag|chat|contact|connect|communicat|speak|writ|dm)|(?:talks?|is\\s+talking|spoke|speaks?)\\s+to\\s+whom)';
// social-graph / connection-graph object (bare "contact" is NOT here — only contact-graph/network).
const RM_SOCIAL = '(?:social[- ]?graph|contact[- ]?(?:graph|network)|(?:your\\s+)?connections?\\b|who\\s+you\\s+know)';
// privacy/concealment predicate ("read" is deliberately EXCLUDED — reading = content, honest).
const RM_PRIV = "(?:private|privacy|hidden|hides?|hiding|invisible|secret|anonymous|conceal\\w*|protected|can'?t\\s+(?:see|tell|know|link|trace|correlate)|cannot\\s+(?:see|tell|know|link|trace|correlate)|no\\s+one\\s+(?:can\\s+)?(?:see|know|tell)|nobody\\s+(?:can\\s+)?(?:see|know|tell))";
const RM_PRESENT_RES = [
  new RegExp('\\bmetadata\\b[^.]{0,25}\\b' + RM_PRIV + '|\\b' + RM_PRIV + '[^.]{0,25}\\bmetadata\\b'),
  /\b(?:no|zero|without|hides?|hiding|conceal\w*)\s+(?:all\s+|any\s+|your\s+)?metadata\b/,
  /\bmetadata[- ](?:private|privacy|blind|free|hidden|anonymous)\b/,
  new RegExp('\\b' + RM_SOCIAL + '[^.]{0,25}\\b' + RM_PRIV + '|\\b' + RM_PRIV + '[^.]{0,25}\\b' + RM_SOCIAL),
  new RegExp('\\b' + RM_WHO + '[^.]{0,25}\\b' + RM_PRIV + '|\\b' + RM_PRIV + '[^.]{0,25}\\b' + RM_WHO),
  /\bunlinkab\w*/,
  /\btraffic[- ]?analysis[- ]?(?:resistant|proof|private|safe|free)\b/,
];
// Totalizing "relay/server/we knows|sees nothing" + "blind relay" — CONTENT-EXEMPT (honest iff scoped to content).
const RM_TOTALIZING_RE = /\b(?:relay|server|we|it|no\s+one|nobody)\s+(?:can\s+)?(?:knows?|sees?|learns?|observes?)\s+nothing\b|\b(?:blind\s+relay|relay\s+is\s+blind|server\s+is\s+blind)\b/;
const RM_CONTENT_EXEMPT_RE = new RegExp(
  '(?:content|e2e|end[- ]to[- ]end|message)[- ]?blind' +
  '|(?:knows?|sees?|learns?|reads?)\\s+nothing[^.]{0,25}(?:of\\s+|about\\s+|in\\s+)?(?:your\\s+)?(?:content|messages?|plaintext|payload|what\\s+you\\s+(?:say|send|write))' +
  '|(?:content|messages?|plaintext|payload)[^.]{0,25}(?:knows?|sees?|learns?|reads?)\\s+nothing'
);
const RM_HEDGE_RE = new RegExp([
  RM_HEDGE_WORD + '[^.]{0,45}(?:metadata|social[- ]?graph|unlinkab\\w*|' + RM_WHO + ')',
  '(?:metadata|social[- ]?graph|unlinkab\\w*|' + RM_WHO + ')[^.]{0,45}' + RM_HEDGE_WORD,
  '(?:relay|server|it|we)\\s+(?:can\\s+|still\\s+)?(?:observe|observes|see|sees|learn|learns|know|knows|has|record|records)\\b[^.]{0,30}\\bmetadata\\b',
  '\\bmetadata\\b[^.]{0,30}(?:is\\s+|are\\s+|stays?\\s+|remains?\\s+)?(?:observed|visible|seen|exposed|not\\s+private|leak|minimized)',
  "(?:do(?:es)?\\s+not|don'?t|doesn'?t|won'?t|no|never|not)\\s+(?:yet\\s+)?(?:claim|promise|guarantee|offer|provide|assert|achieve)\\w*[^.]{0,45}(?:metadata|social[- ]?graph|unlinkab\\w*|privacy)",
].join('|'));

// Returns { present, hedged, overclaim }. overclaim === present && !hedged. FLAG-FOR-REVIEW —
// confirm against the reveal copy + Flint's threat-model (relay observes delivery metadata at launch).
function relayMetadataPrivacyOverclaim(text: string) {
  const t = normalize(text);
  const familyPresent = RM_PRESENT_RES.some(re => re.test(t));
  const totalizing = RM_TOTALIZING_RE.test(t) && !RM_CONTENT_EXEMPT_RE.test(t);
  const present = familyPresent || totalizing;
  const hedged = RM_HEDGE_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

// SMART-RELAY LIVE OVER-CLAIM (Hypatia 🌀6781 — Archie #142181: "launch on the CURRENT content-blind
// relay; smart-relays are POST-LAUNCH"). A present-tense "smart relay(s)" live claim over-claims at
// launch. Honest iff absent or hedged (coming/post-launch). The CURRENT relay is a plain content-blind
// mailbox relay — do NOT flag bare "relay"/"mailbox" (those are live); only "smart relay". "mailbox
// keys" left to manual review (ambiguous which side of the gate — flag in the coverage note).
const SR_TERM_RE = /\bsmart[- ]?relays?\b/;
const SR_HEDGE_RE = new RegExp('\\bsmart[- ]?relays?\\b[^.]{0,40}' + RM_HEDGE_WORD + '|' + RM_HEDGE_WORD + '[^.]{0,40}\\bsmart[- ]?relays?\\b');
function smartRelayOverclaim(text: string) {
  const t = normalize(text);
  const present = SR_TERM_RE.test(t);
  const hedged = SR_HEDGE_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

// MAILBOX NOT-BUILT-FEATURE OVER-CLAIM (Hypatia 🌀6781, 2026-09-22 — Apollo #142216 CORRECTED his own
// #142208 by grounding the send-flow deeper; Flint Q2 #142210).
// CORRECTED GROUND TRUTH (Apollo ☀7001, origin/main): BASIC return-channel DELIVERY IS LIVE — the
// mailbox uses mailbox_id = deriveMailboxId(recipient_fp) (deterministic, NO keypair) + IDENTITY-key
// owner-auth + E2E envelope, and it's WIRED: sendContactUpdate @ SoverentityFrontend.tsx:1763 deposits
// a contact-update to the recipient's deriveMailboxId(fp) mailbox; startLiveBookPolling/startKnowLayerSync
// @ ContactManagement.tsx:290/310 poll + consume (decrypt→verify→apply→persist→ack-delete). So
// "your card changes / updates reach your contacts through the relay mailbox" = TRUE/LIVE → NOT flagged.
// NOT LIVE (Phase-2, zero app callers): the dedicated per-mailbox KEYPAIR (generateMailboxKeypair) +
// published mailbox POINTER (publishMailboxPointer) + smart-relay mailbox-key ROUTING + multi-relay PORTABILITY.
//
// SO THE FLAG LINE (Apollo's corrected, sharper cut): flag ONLY the not-built layer — "smart mailbox" /
// mailbox-key ROUTING / cross|multi-relay PORTABILITY ("your mailbox follows you across relays") /
// published mailbox POINTER. Do NOT flag basic delivery ("updates reach your contacts") — it's LIVE now.
// ⚠ TERMINOLOGY COLLISION (surfaced to Archie/Athena, the terminology owners): "mailbox keys" is
// CONTESTED — Flint Q2 reads it as the LIVE recipient-keyed return-channel (current); Apollo #142216
// reads it as the NOT-LIVE dedicated keypair layer ("the word 'keys' is the tell"). They AGREE on the
// mechanisms + live-status; only the phrase's referent is overloaded. So bare "mailbox keys/keypair" is
// NOT auto-flagged (honest xor over-claim by referent) → MANUAL review + a disambiguation call owed.
// General-messaging-scope (vs the live contact-update scope) also = manual review (no crisp regex line).
// FLAG-FOR-REVIEW + hedge-aware (Phase-2/coming rescues). Unit-tested (regex-dialect trap). Gate = FLOOR.
const MB_HEDGE_WORD = '(?:coming(?:\\s+soon)?|soon|post[- ]?launch|phase[- ]?2|phase\\s+two|planned|road\\s?map|not\\s+yet|later|in\\s+development|on\\s+the\\s+way|future|to\\s+come|will\\s+(?:soon\\s+)?(?:be|come|arrive|ship))';
const MB_PRESENT_RES = [
  /\bsmart[- ]?mailbox\w*/,                                                                          // smart mailbox — Phase-2 (both cuts agree)
  /\bmailbox[- ]?key[- ]?routing\b|\bkeyed\s+routing\b|\bmailbox\s+routing\b/,                        // mailbox-key ROUTING — Phase-2 (routing, NOT bare "mailbox keys")
  /\bcross[- ]?relay\b|\bmulti[- ]?relay\b|\bswap\s+relays?\b|\brelay[- ]?portab\w*|\bmailbox[- ]?portab\w*/, // cross/multi-relay portability — Phase-2
  /\bhost\s+(?:your\s+)?mailbox\s+(?:anywhere|elsewhere)\b|\bmove\s+your\s+mailbox\b|\bmailbox\s+(?:follows?|travels?|moves?|goes?)\s+(?:with\s+)?(?:you|across|between|to)\b/, // "mailbox follows you across relays" — portability
  /\bmailbox[- ]?pointer\b|\bpublish(?:e[sd])?\b[^.]{0,20}\bpointer\b/,                               // published mailbox POINTER (publishMailboxPointer) — Phase-2 (Apollo)
];
// Hedge anchors = the not-built feature words. Period-guard [^.] blocks a stray cross-sentence hedge.
const MB_TERM_ALT = '(?:smart[- ]?mailbox\\w*|mailbox|routing|cross[- ]?relay|multi[- ]?relay|portab\\w*|pointer|relays?)';
const MB_HEDGE_RE = new RegExp(MB_HEDGE_WORD + '[^.]{0,40}' + MB_TERM_ALT + '|' + MB_TERM_ALT + '[^.]{0,40}' + MB_HEDGE_WORD);

function mailboxDeliveryOverclaim(text: string) {
  const t = normalize(text);
  const present = MB_PRESENT_RES.some(re => re.test(t));
  const hedged = MB_HEDGE_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

// "DELIVERED" (CONFIRMED-RECEIPT) OVER-CLAIM (Hypatia 🌀6781, 2026-09-22 — Archie #142232, Flint
// two-seat #142225). sendContactUpdate treats relay-200 (deposit-ok) as "sent" — there is NO e2e
// delivery-ack, so the app CANNOT confirm the recipient received/consumed the update (delivery happens
// only when the recipient polls, unconfirmed to the sender). So any copy claiming a contact-update is
// "delivered" / "they received it" / "read" = OVER-CLAIM; only "sent" / "queued" / "deposited" is honest.
// COMPOSES with mailboxDeliveryOverclaim's corrected boundary: the delivery PATH is live (Apollo #142216,
// "reach your contacts" = honest capability), but per-send RECEIPT is not confirmable — so "reach/sent"
// PASSES, "delivered/received-by-them/read-receipt" FLAGS. Honest future ("will be delivered when they
// poll") is hedged. Unit-tested (regex-dialect trap). FLAG-FOR-REVIEW. Gate = FLOOR.
const DL_PRESENT_RE = /\bdelivered\b|\bdelivery\s+(?:confirmed|confirmation|receipt)\b|\bconfirmed\s+delivery\b|\bread\s+receipts?\b|\bthey\s+(?:received|got|read|saw|'ve\s+(?:seen|read|got(?:ten)?))\b|\brecipient\s+(?:received|got|read|has\s+(?:seen|read))\b|\b(?:received|seen|read)\s+by\s+(?:your\s+)?(?:contact|recipient|them)\b/;
// Honest future/conditional "delivered" (capability, not a confirmed-receipt claim) → rescues.
const DL_HEDGE_RE = /\b(?:will\s+be|to\s+be|be|can\s+be|gets?|once|when|after|if)\s+deliver\w*|\bdeliver\w*\s+(?:when|once|after|if)\b|\bwill\s+deliver\b/;
function deliveredOverclaim(text: string) {
  const t = normalize(text);
  const present = DL_PRESENT_RE.test(t);
  const hedged = DL_HEDGE_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

// "CONNECTED" UNCONDITIONAL-ON-REMOTE-JOIN OVER-CLAIM (Hypatia 🌀6781, 2026-09-22 — Archie #142279,
// Flint ruling #142276). JoinerCeremony:643 shows "You are connected" UNCONDITIONALLY, but a dropped
// REMOTE join = a silent asymmetric half-join (you added them; they haven't confirmed). So "you are
// connected" / "connection complete" claimed unconditionally on a REMOTE/async join = OVER-CLAIM — the
// joiner-path analog of deliveredOverclaim (confirmed-MUTUAL-state claimed when only a one-sided async
// action happened). HONEST: async framing ("you've added them, they'll see your request when they next
// open their wallet") OR in-person scope ("connected in person" — presence confirms mutual). Present =
// a confirmed-mutual-connection status claim; hedged = async/pending/added-not-connected/in-person.
// (Athena lands the JoinerCeremony copy fix; sweep = automated backstop.) Unit-tested. FLAG-FOR-REVIEW. Gate = FLOOR.
// NOTE: the ✓/✔ alternative has NO leading \b — ✓ is a non-word char, so `\b✓` never matches (the
// leading boundary only guards the word-char alternatives). "successfully" keeps its \b. (Test caught this.)
const CONN_PRESENT_RE = /\b(?:you'?re|you\s+are)\s+(?:now\s+)?(?:connected|linked|paired)\b|\bnow\s+connected\b|(?:✓|✔)\s*connected\b|\bsuccessfully\s+connected\b|\bconnection\s+(?:complete|established|confirmed|successful)\b/;
const CONN_HEDGE_RE = /\bthey'?ll\s+see\b|\bwhen\s+they\s+(?:next\s+)?(?:open|log|come|add|accept)|\bpending\b|\byou'?ve\s+added\b|\brequest\s+(?:sent|pending)\b|\bawait\w*|\bonce\s+they\s+(?:accept|confirm|open|add)|\bin\s+person\b|\bwhen\s+you\s+(?:meet|both)\b|\bnot\s+yet\b|\bthey'?ll\s+need\b/;
function connectedOverclaim(text: string) {
  const t = normalize(text);
  const present = CONN_PRESENT_RE.test(t);
  const hedged = CONN_HEDGE_RE.test(t);
  return { present, hedged, overclaim: present && !hedged };
}

export { pqAbsoluteOverclaim, invulnerabilityOverclaim, pqBadgeOverclaim, pqResistantIdentityOverclaim, nodeZeroOverclaim, relayMetadataPrivacyOverclaim, smartRelayOverclaim, mailboxDeliveryOverclaim, deliveredOverclaim, connectedOverclaim, normalize, ABSOLUTE_PQ, PSI_CARVEOUT, INVULNERABILITY, PQ_BADGE_HEDGE, PQ_BADGE_PROTECTED, PQ_BADGE_VERIFIED, QR_TERM, QR_SCOPED, QR_SCOPED_PRE, QR_HEDGE, NZ_TERMS, NZ_TERM_RE, NZ_HEDGED_RE, RM_PRESENT_RES, RM_TOTALIZING_RE, RM_CONTENT_EXEMPT_RE, RM_HEDGE_RE, SR_TERM_RE, SR_HEDGE_RE, MB_PRESENT_RES, MB_HEDGE_RE, DL_PRESENT_RE, DL_HEDGE_RE, CONN_PRESENT_RE, CONN_HEDGE_RE };
