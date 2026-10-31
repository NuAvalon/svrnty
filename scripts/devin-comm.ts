// scripts/devin-comm.ts — agent-to-agent comm runner (calls existing lib only; NO crypto here).
// Usage (from repo root):
//   npx tsx scripts/devin-comm.ts mint
//   npx tsx scripts/devin-comm.ts admit <peer-card.json>
//   npx tsx scripts/devin-comm.ts send <fingerprint> "<body>"
//   npx tsx scripts/devin-comm.ts poll
//   npx tsx scripts/devin-comm.ts poll-json          — decrypt inbound → durable journal (flint §B cron)
//   npx tsx scripts/devin-comm.ts loop [intervalMs]
//   npx tsx scripts/devin-comm.ts grow [uses]          — mint a Grow shortlink (remote, multi-use)
//   npx tsx scripts/devin-comm.ts join <url> --expect-fp <fp64> --name <petname>  — resolve a Grow link, send joiner-response, THEN admit the giver (refuses on any mismatch)
//   npx tsx scripts/devin-comm.ts gate                 — list Gate arrivals (verified joiners awaiting admit)
//   npx tsx scripts/devin-comm.ts admit-gate <fp>      — admit a Gate arrival as Known → notes flow
//   npx tsx scripts/devin-comm.ts admit <card.json>    — admit a new peer
// Secrets live in ~/.svrnty-agent/ — outside the repo, never committed.
// Agent-local protocol state (issued Grow codes + Gate arrivals) lives alongside it as JSON.

import { readFileSync, writeFileSync, appendFileSync, chmodSync, existsSync, mkdirSync } from 'node:fs';
import { routeInbound, loomNotice, openTaskChannel, openTasksNotice, deadNotesNotice, countedOpen, safeToken, shortNoteId, displayLine, gateArrivalLine, gateListLine } from './devin-comm-inbound';
import { readJsonStrict, writeFileAtomic, RATCHET_HINT } from '../src/lib/headless/atomic-file';
import { mintHeadlessAgent, serializeMintArtifact, type SerializedMintArtifact } from '../src/lib/identity/headless-mint';
import { HeadlessStore, type HeadlessContact } from '../src/lib/headless/headless-store';
import { custodyToHeadlessOwner } from '../src/lib/headless/custody-owner';
import { withWriterLock, withWriterLockAsync } from '../src/lib/headless/writer-lock';
import { sendNoteFromHeadless, buildHeadlessConsumeDeps, type HeadlessOwner } from '../src/lib/headless/headless-client';
import { DEAD_LETTER_FILE } from '../src/lib/headless/headless-dead-letter';
import { resolvePeerKemForSend, formatNotSent, trackedFetch, sendThrowLine } from '../src/lib/headless/peer-kem';
import { consumeInboundContactUpdates, type ConsumeSummary, type JoinerResponseSeam } from '../src/lib/sync/consume-mailbox';
import { verifyJoinerResponse } from '../src/lib/trust/joiner-response';
import { deriveOwnerHybridSecrets } from '../src/lib/crypto/living-book-receive';
import type { LivingBookHybridSecrets } from '../src/lib/crypto/living-book-sleeve';
import { acceptJoinerAtGate, buildAdmitRecord } from '../src/lib/trust/grow-gate';
import {
  isCodeOutstanding,
  codeUnderCap,
  alreadyAccepted,
  pruneIssuedCodes,
  type IssuedCodeMap,
  type GateArrival,
} from '../src/lib/identity/client-store';
import { clampGrowCap } from '../src/lib/trust/trust-recipe';
import { createRelay, resolveRelay } from '../src/lib/sync/relay';
import { sendJoinerResponse } from '../src/lib/sync/send-joiner-response';
import { TripleRatchet, type RatchetIdentity, type RatchetPeer, type RatchetPacket, type RatchetSnapshot } from '../src/lib/crypto/message-ratchet';
import { strip0x40 } from '../src/lib/identity/raw-sign';
import { fingerprintMatchesKey } from '../src/lib/identity/fingerprint';
import { runJoin, parseJoinFlags } from '../src/lib/headless/join-grow-link';
import { backupStoreBeforeJoin } from '../src/lib/headless/join-backup';
import { base64ToUint8, uint8ToBase64 } from '../src/lib/crypto/pq';
import * as openpgp from 'openpgp';

// Security (Flint KB#3285 / #256 finding #1): agent-local state holds LIVE tr session keys
// (ratchet-sessions.json), plus issued-codes / gate / store. Set a restrictive umask at startup so
// EVERY file this process writes defaults to 0600 and every dir it makes to 0700 — not 0644
// (local-readable session keys = a channel-confidentiality hole; only mint.json was 0600 before).
// The sandbox dir is also mkdir+chmod'd 0700 in main(). mint.json keeps its explicit chmod too.
process.umask(0o077);

const DIR = process.env.SVRNTY_AGENT_DIR ?? '/home/alpha/devin-sandbox/.svrnty-agent'; // sandboxed agent home — never $HOME/.ssh territory; per-agent override for gateway-custodied identities
const MINT = `${DIR}/mint.json`;
const STORE = `${DIR}/store.json`;
const CODES = `${DIR}/issued-codes.json`;
const GATE = `${DIR}/gate.json`;
const RATCHETS = `${DIR}/ratchet-sessions.json`;
const RELAY = process.env.SVRNTY_RELAY ?? 'https://dev.svrnty.is/api/relay';

// ~7d acceptance window — must mirror R1_ACCEPTANCE_WINDOW_MS in src/lib/identity/client-store.ts
// (that constant is module-private; the browser persists the map to IndexedDB, we persist JSON).
const ACCEPTANCE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// The browser lib fetches RELATIVE paths ('/api/relay', '/api/relay/<code>'); a headless run has no
// origin, so rewrite relative fetches onto the relay's origin. Transport plumbing only — the AES
// envelope, signing, and wire format all stay inside the vetted functions.
const RELAY_ORIGIN = new URL(RELAY).origin;
const realFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = ((input: any, init?: any) =>
  realFetch(typeof input === 'string' && input.startsWith('/') ? `${RELAY_ORIGIN}${input}` : input, init)
) as typeof fetch;

function loadMint(): SerializedMintArtifact {
  return JSON.parse(readFileSync(MINT, 'utf8'));
}

// The ONE owner builder: the custody helper maps every OwnerIdentity field, incl. custody ① kemSecretKey. Without it
// the consumer has no hybrid open-material and can read only classical notes (10-30 incident: Mneme's hybrid-sealed
// notes were refused at every seam). Pinned by src/lib/headless/devin-comm-owner-wiring.test.ts.
function ownerFrom(a: SerializedMintArtifact): HeadlessOwner {
  return custodyToHeadlessOwner(a);
}

// ── agent-local JSON state (issued Grow codes + Gate arrivals) ─────────────────────────────────

// Missing = empty; present but unparseable = abort. Returning `empty` on a torn read let the next save
// persist {} over real state (ratchet sessions, gate arrivals, issued codes). Flint 2026-10-24.
const loadJson = readJsonStrict;

function loadCodes(): IssuedCodeMap {
  return pruneIssuedCodes(loadJson<IssuedCodeMap>(CODES, {}), Date.now());
}

function saveCodes(map: IssuedCodeMap): void {
  writeFileAtomic(CODES, JSON.stringify(map, null, 2));
}

type GateMap = Record<string, Record<string, GateArrival>>;

function loadGate(): GateMap {
  return loadJson<GateMap>(GATE, {});
}

function saveGate(map: GateMap): void {
  writeFileAtomic(GATE, JSON.stringify(map, null, 2));
}

/**
 * The R1 return-channel seam for a headless giver: same verify + accept-oracle semantics as the
 * browser buildJoinerSeam (live-book-poll.ts), backed by issued-codes.json + gate.json instead of
 * IndexedDB. Joiners land at the Gate — never auto-admitted; `admit-gate` is the owner tap.
 */
function buildLocalJoinerSeam(owner: HeadlessOwner, store: HeadlessStore): JoinerResponseSeam {
  const ownFp = owner.fingerprint;
  const codes = loadCodes(); // snapshot per poll — same as browser loadIssuedCodeMap
  // #711 (b): the joiner-response is sealed PQ-hybrid to our KEM key (a CLI join and the web app both pass giverPqKemPublicKey). Without
  // the hybrid open-material, verifyJoinerResponse could only try the classical leg, so the response never opened and the Gate stayed empty
  // (Peter's web join to Athena's grow link, 2026-10-31). Same dual-read as the browser seam (live-book-poll.ts): hybrid first, classical
  // fallback. Lazy + memoized: derived at most once per poll, and only when a joiner blob actually arrives. undefined for a classical owner.
  let hybridMemo: Promise<LivingBookHybridSecrets | undefined> | null = null;
  const hybrid = () =>
    (hybridMemo ??= deriveOwnerHybridSecrets(owner.privateKeyArmored, owner.passphrase, owner.kemPublicKey, owner.kemSecretKey));
  const acceptNonce = (nonce: string, joinerFp: string): boolean =>
    isCodeOutstanding(codes, ownFp, nonce, Date.now()) &&
    codeUnderCap(codes, ownFp, nonce) &&
    !alreadyAccepted(codes, ownFp, nonce, joinerFp);
  return {
    verify: (blob) =>
      verifyJoinerResponse(
        blob,
        { fingerprint: ownFp, privateKeyArmored: owner.privateKeyArmored, passphrase: owner.passphrase, hybrid },
        acceptNonce,
        { requirePq: false },
      ),
    accept: (pj) =>
      acceptJoinerAtGate(ownFp, pj, codes, {
        getContactByFingerprint: async (_o: string, fp: string) => store.getContactByFingerprint(fp) as any,
        getGateArrival: async (o: string, fp: string) => (loadGate()[o]?.[fp] ?? null) as any,
        enqueueGateArrival: async (o: string, arrival: GateArrival) =>
          withWriterLock(DIR, () => {
            const g = loadGate();
            if (!g[o]) g[o] = {};
            g[o][arrival.fingerprint] = arrival;
            saveGate(g);
          }),
        // `codes` is this poll's snapshot, already marked in place by markAcceptedInMap. Saving it whole would
        // drop a code minted (grow) since the poll began, so merge its accepted lists into a fresh read.
        recordAcceptedJoiner: async () =>
          withWriterLock(DIR, () => {
            const fresh = loadCodes();
            for (const [o, byCode] of Object.entries(codes)) {
              for (const [c, entry] of Object.entries(byCode)) {
                const cur = fresh[o]?.[c];
                if (cur) cur.accepted = [...new Set([...cur.accepted, ...entry.accepted])];
              }
            }
            saveCodes(fresh);
          }),
      }),
  };
}

// #712: consume stops between envelopes after this long, commits + acks what it consumed, and leaves the rest for the next pass, so a
// deep backlog drains across passes instead of dying at the watchdog (the ward's POLL_TIMEOUT_S, 60-600 s; Weft cells run 55 s).
// Default 40 s fits under the tightest of those with room for start-up. SVRNTY_CONSUME_BUDGET_MS overrides: digits only, 1 s-600 s.
const CONSUME_BUDGET_MS = (() => {
  const v = process.env.SVRNTY_CONSUME_BUDGET_MS ?? '';
  return /^[0-9]{1,6}$/.test(v) ? Math.min(600_000, Math.max(1_000, Number(v))) : 40_000;
})();

async function pollOnce(owner: HeadlessOwner, store: HeadlessStore): Promise<ConsumeSummary & { receipts_sent: number }> {
  // #713: record every loss (metadata only) in the agent dir before its envelope is acked (Flint #189046).
  const deps = await buildHeadlessConsumeDeps(owner, store, {
    relayBase: RELAY,
    budgetMs: CONSUME_BUDGET_MS,
    deadLetterPath: `${DIR}/${DEAD_LETTER_FILE}`,
  });
  deps.joiner = buildLocalJoinerSeam(owner, store);
  const consumed = await consumeInboundContactUpdates(deps);
  // Layer 1: "Delivered" receipts go out AFTER the pass (no chunk open, no writer lock held by this process; Flint C1), and only for notes
  // the store now holds from admitted senders (C2/C3). Counts only.
  const r = await deps.sendReceipts();
  return { ...consumed, receipts_sent: r.sent };
}

// ── triple-ratchet (tr-v1) headless consume/send — mirrors messaging/direct-session.ts ─────────
// Calls the fleet TripleRatchet only; session snapshots persist in ratchet-sessions.json.

const TR_BODY = 'svrnty-tr-v1';
type TrSessions = Record<string, RatchetSnapshot>;
const loadTr = (): TrSessions => loadJson<TrSessions>(RATCHETS, {}, RATCHET_HINT);
// backup:false: a restorable stale ratchet = chain-key reuse on the next send (Flint 2026-10-24).
const saveTr = (m: TrSessions) => writeFileAtomic(RATCHETS, JSON.stringify(m, null, 2), { backup: false });

function ratchetSelf(a: SerializedMintArtifact): RatchetIdentity {
  const p = a.private;
  return {
    x25519Sec: base64ToUint8(p.x25519_sec), x25519Pub: base64ToUint8(p.x25519_pub),
    mlkem1024Sec: base64ToUint8(p.mlkem1024_sec), mlkem1024Pub: base64ToUint8(p.mlkem1024_pub),
  };
}

async function ratchetPeerOf(contact: HeadlessContact): Promise<RatchetPeer | null> {
  if (!contact.pq_kem_public_key || !contact.public_key) return null;
  try {
    const key = await openpgp.readKey({ armoredKey: contact.public_key });
    const enc = await key.getEncryptionKey();
    const q = enc.keyPacket.publicParams.Q ?? enc.keyPacket.publicParams.A;
    return { x25519Pub: strip0x40(q), mlkem1024Pub: base64ToUint8(contact.pq_kem_public_key) };
  } catch { return null; }
}

function trPacket(body: string): RatchetPacket | null {
  try {
    const o = JSON.parse(body);
    return o?.type === TR_BODY && o.packet ? o.packet : null;
  } catch { return null; }
}

async function trOpen(a: SerializedMintArtifact, contact: HeadlessContact, body: string, onLocked?: () => void): Promise<string | null> {
  const packet = trPacket(body);
  const peer = await ratchetPeerOf(contact);
  if (!packet || !peer) return null;
  const self = ratchetSelf(a);
  // load → advance → save is one locked unit: a send-tr interleaving here would have its chain advance
  // overwritten by this stale copy, and the next send would re-use that chain index (key reuse).
  return withWriterLockAsync(DIR, async () => {
    onLocked?.();                                        // poll-json's attempt charge: only once the lock is HELD (Flint #2366)
    const sessions = loadTr();
    const snap = sessions[contact.fingerprint];
    if (snap) {
      const s = TripleRatchet.importState(snap);
      if (!s) return null;
      const pt = await s.receive(packet);
      if (pt === null) return null;
      sessions[contact.fingerprint] = s.exportState();
      saveTr(sessions);
      return pt;
    }
    const first = await TripleRatchet.acceptFirst(self, peer, packet);
    if (!first) return null;
    sessions[contact.fingerprint] = first.session.exportState();
    saveTr(sessions);
    return first.plaintext;
  });
}

function printNewArrivals(ownerFp: string, seen: Set<string>): void {
  const g = loadGate()[ownerFp] ?? {};
  for (const a of Object.values(g)) {
    if (seen.has(a.fingerprint)) continue;
    seen.add(a.fingerprint);
    console.log(gateArrivalLine(a));
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  // Ensure the sandbox dir exists + is owner-only (0700) before any state is written
  // (chmod covers the case where it pre-existed with looser perms). #256 finding #1.
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  chmodSync(DIR, 0o700);
  const store = new HeadlessStore({ path: STORE, lockDir: DIR });

  if (cmd === 'mint') {
    if (existsSync(MINT)) throw new Error('mint.json already exists — refusing to re-mint');
    const a = await mintHeadlessAgent({ throwaway: false, recoveryMode: 'm-of-n' });
    const s = serializeMintArtifact(a);
    writeFileSync(MINT, JSON.stringify(s), { flag: 'wx', mode: 0o600 });   // create-only: never overwrite an identity
    chmodSync(MINT, 0o600);
    const id = s.public.card.identity;
    console.log(JSON.stringify({
      durable_id: s.public.durable_id,
      fingerprint: id.fingerprint,
      public_key: id.public_key,
      pq_sig_public_key: id.pq_sig_public_key,
      pq_kem_public_key: id.pq_kem_public_key,
    }));
    return;
  }

  if (cmd === 'admit') {
    const card = JSON.parse(readFileSync(rest[0], 'utf8'));
    // Never exit 0 when nothing usable was written (Archie #1310): a card with no fingerprint or no public key is refused, not stored.
    if (typeof (card.fingerprint ?? card.durable_id) !== 'string' || !(card.fingerprint ?? card.durable_id) || typeof card.public_key !== 'string' || !card.public_key) {
      throw new Error('admit refused: the card needs a fingerprint (or durable_id) and a public_key. Nothing was written.');
    }
    const contact: HeadlessContact = {
      id: card.durable_id ?? card.fingerprint,
      fingerprint: card.fingerprint ?? card.durable_id,
      name: card.name ?? 'devin-cloud',
      public_key: card.public_key,
      pq_sig_public_key: card.pq_sig_public_key,
      pq_kem_public_key: card.pq_kem_public_key,
    };
    store.upsertContact(contact);
    // Defensive and UNTESTABLE by construction: the store's writer lock throws first on a failed write, so no test can reach "written but absent".
    // Kept on purpose (Archie #1366); this is not a proven guarantee.
    const back = store.getContactByFingerprint(contact.fingerprint);
    if (!back || back.public_key !== contact.public_key) throw new Error(`admit failed: ${contact.fingerprint.slice(0, 16)} is not in the store after the write. Nothing is trusted.`);
    console.log(`admitted ${contact.fingerprint}`);
    return;
  }

  if (!existsSync(MINT)) throw new Error('run mint first');
  const artifact = loadMint();
  const owner = ownerFrom(artifact);

  if (cmd === 'grow') {
    // Mint a Grow shortlink: signed card → AES-sealed relay blob → /c/<code>#<key> URL.
    const uses = clampGrowCap(rest[0] ? Number(rest[0]) : 7);
    const result = await createRelay(JSON.stringify(artifact.public.card));
    const url = new URL(result.url);
    const relayUrl = new URL(RELAY);
    url.host = relayUrl.host; // point the link at OUR relay's domain, not the packaged default
    withWriterLock(DIR, () => {
      const codes = loadCodes();
      if (!codes[owner.fingerprint]) codes[owner.fingerprint] = {};
      const prior = codes[owner.fingerprint][result.code];
      codes[owner.fingerprint][result.code] = {
        acceptUntil: Date.now() + ACCEPTANCE_WINDOW_MS,
        accepted: prior?.accepted ?? [],
        cap: uses,
        channel: 'remote',
      };
      saveCodes(codes);
    });
    console.log(JSON.stringify({ url: url.toString(), code: result.code, cap: uses, expiresAt: result.expiresAt }));
    return;
  }

  if (cmd === 'join') {
    // Resolve a Grow link, deposit our signed joiner-response, and ONLY THEN admit the giver (src/lib/headless/join-grow-link.ts: Flint spec J1-J6).
    //   devin-comm join <url> --expect-fp <fp64> --name <petname>
    // --expect-fp is the fingerprint the person read out of band; the link alone proves nothing about who minted it. The petname is ours, never the card's.
    const myId = artifact.public.card.identity;
    const out = await runJoin(parseJoinFlags(rest), {
      backup: () => { backupStoreBeforeJoin(STORE); }, // J5: dated 0600 copy; skips ONLY when lstat says ENOENT, refuses a symlink or any other error (join-backup.ts)
      resolve: (code, fragment) => resolveRelay(code, fragment),
      derives: (fp, publicKey, pq) => fingerprintMatchesKey(fp, publicKey, pq),
      deposit: (target) =>
        sendJoinerResponse(
          {
            fingerprint: owner.fingerprint,
            epoch: 0, // headless agents are pre-rotation; matches the contact.update wire epoch
            publicKeyArmored: myId.public_key,
            displayName: myId.display_name || 'devin-local',
            privateKeyArmored: owner.privateKeyArmored,
            passphrase: owner.passphrase,
            kemPublicKeyB64: myId.pq_kem_public_key,
            sigPublicKeyB64: myId.pq_sig_public_key,
          },
          target,
          { relayBase: RELAY },
        ),
      admit: (contact) => store.upsertContact(contact),
    });
    if (!out.ok && out.refusal === 'admit-failed-after-deposit' && out.pending) {
      // The deposit already succeeded, so the giver may have added us. Save their card (public material only) for a manual admit; do NOT re-run join.
      const pend = `${STORE}.pending-admit-${out.pending.fingerprint.slice(0, 8)}.json`;
      let saved = false;
      try {
        writeFileSync(pend, JSON.stringify({ fingerprint: out.pending.fingerprint, durable_id: out.pending.id, name: out.pending.name, public_key: out.pending.public_key, pq_sig_public_key: out.pending.pq_sig_public_key, pq_kem_public_key: out.pending.pq_kem_public_key }), { mode: 0o600 });
        chmodSync(pend, 0o600);
        saved = true;
      } catch { /* reported below */ }
      console.error(`joiner-response DEPOSITED, but admitting ${out.pending.name} failed${out.detail ? `: ${out.detail}` : ''}. They can add you; their replies will be dropped until you admit them. Do NOT re-run join (a second deposit counts against the link).`);
      console.error(saved ? `Run: npx tsx scripts/devin-comm.ts admit ${pend}` : `Could not save their card either. Their fingerprint is ${out.pending.fingerprint}: get their card file from them and run: npx tsx scripts/devin-comm.ts admit <card.json>`);
      process.exitCode = 1;
      return;
    }
    if (!out.ok) {
      console.error(`join refused: ${out.refusal}${out.detail ? ` (${out.detail})` : ''}. Nothing was admitted.`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify({ admitted: out.admitted, fp8: out.fp8, name: out.name, joinerResponse: out.joinerResponse }));
    return;
  }

  if (cmd === 'gate') {
    const g = loadGate()[owner.fingerprint] ?? {};
    const arrivals = Object.values(g);
    if (!arrivals.length) {
      console.log('no one waiting at the Gate');
      return;
    }
    for (const a of arrivals) {
      console.log(gateListLine(a));
    }
    return;
  }

  if (cmd === 'admit-gate') {
    const fp = rest[0];
    const arrival = withWriterLock(DIR, () => {
      const g = loadGate();
      const arrival = g[owner.fingerprint]?.[fp];
      if (!arrival) throw new Error(`no gate arrival ${fp}`);
      const rec = buildAdmitRecord(arrival, {});
      store.upsertContact({                       // re-entrant: same lock, one unit with the gate removal
        id: arrival.fingerprint,
        fingerprint: arrival.fingerprint,
        name: rec.name,
        public_key: rec.public_key,
        epoch: rec.epoch,
        trust_level: rec.trust_level,
        pq_sig_public_key: rec.pq_sig_public_key,
        pq_kem_public_key: rec.pq_kem_public_key,
      });
      delete g[owner.fingerprint][fp];
      if (!Object.keys(g[owner.fingerprint]).length) delete g[owner.fingerprint];
      saveGate(g);
      return arrival;
    });
    console.log(`admitted ${arrival.fingerprint} as Known — notes now flow: send ${arrival.fingerprint} "<body>"`);
    return;
  }

  if (cmd === 'send-tr') {
    // Seal a note with the triple ratchet (tr-v1 body inside the classical OpenPGP note wire).
    const [fp, body] = rest;
    const peer = store.getContactByFingerprint(fp);
    if (!peer) throw new Error(`peer ${fp} not admitted`);
    // The outer hybrid seal needs the peer's ML-KEM key, taken from the ADMITTED record and re-checked
    // against its fingerprint (#456). Resolve it BEFORE the ratchet chain is advanced + persisted: a refusal
    // must leave ratchet-sessions.json untouched, not burn an index for a message that was never sent.
    const kem = await resolvePeerKemForSend(peer);
    if (!kem.ok) { console.error(formatNotSent(fp, kem.reason)); process.exitCode = 1; return; }
    const rp = await ratchetPeerOf(peer);
    if (!rp) throw new Error(`peer ${fp} lacks ratchet keys (x25519/mlkem)`);
    const self = ratchetSelf(artifact);
    // Advance + persist the chain under the lock BEFORE the relay POST: a failed POST then burns an index,
    // it never re-uses one (key reuse is the failure mode, Flint 2026-10-24).
    const packet = await withWriterLockAsync(DIR, async () => {
      const sessions = loadTr();
      let s = sessions[fp] ? TripleRatchet.importState(sessions[fp]) : null;
      if (!s) s = TripleRatchet.initiate(self, rp);
      const packet = await s.send(body);
      sessions[fp] = s.exportState();
      saveTr(sessions);
      return packet;
    });
    const wire = JSON.stringify({ type: TR_BODY, packet });
    let r: Awaited<ReturnType<typeof sendNoteFromHeadless>>;
    const tf = trackedFetch(globalThis.fetch);
    try {
      r = await sendNoteFromHeadless({ owner, peerFingerprint: fp, peerPublicKeyArmored: peer.public_key, peerPqKemPublicKey: kem.kem, body: wire, store, relayBase: RELAY, fetchImpl: tf.fetchImpl });
    } catch (e) {   // a THROW (not deposited:false): worded by how far it got, never a false NOT SENT; the chain already advanced
      console.error(sendThrowLine(fp, e, tf.stage(), true)); process.exitCode = 1; return;
    }
    console.log(JSON.stringify(r));
    if (!r.deposited) { console.error(formatNotSent(fp, 'the relay did not accept the deposit (kept locally as not sent; this ratchet index is spent)')); process.exitCode = 1; }
    return;
  }

  if (cmd === 'send') {
    const [fp, body] = rest;
    const peer = store.getContactByFingerprint(fp);
    if (!peer) throw new Error(`peer ${fp} not admitted`);
    const kem = await resolvePeerKemForSend(peer);   // admitted record only, fingerprint-bound (#456)
    if (!kem.ok) { console.error(formatNotSent(fp, kem.reason)); process.exitCode = 1; return; }
    let r: Awaited<ReturnType<typeof sendNoteFromHeadless>>;
    const tf = trackedFetch(globalThis.fetch);
    try {
      r = await sendNoteFromHeadless({ owner, peerFingerprint: fp, peerPublicKeyArmored: peer.public_key, peerPqKemPublicKey: kem.kem, body, store, relayBase: RELAY, fetchImpl: tf.fetchImpl });
    } catch (e) {   // a THROW (not deposited:false): worded by how far it got, never a false NOT SENT
      console.error(sendThrowLine(fp, e, tf.stage())); process.exitCode = 1; return;
    }
    console.log(JSON.stringify(r));
    // Not deposited = not sent. Say so on stderr and exit non-zero (the wrappers key on both); and do not
    // ping the webhook below for a reply that never left.
    if (!r.deposited) { console.error(formatNotSent(fp, 'the relay did not accept the deposit (kept locally as not sent)')); process.exitCode = 1; return; }
    // Peter's rule: replies to devin-cloud must also ping his automation webhook (wakes his session).
    if (fp === 'b0d61d883e39edb9a85ceb3ff3472e0cfd6cc6a4a0007c25eaa9275c9c5bea81') {
      try {
        const env = await import('node:fs').then(m => m.readFileSync('/home/alpha/devin-sandbox/.env', 'utf8'));
        const url = env.match(/devin-cloud-webhook-url:(\S+)/)?.[1];
        const secret = env.match(/devin-cloud-secret:(\S+)/)?.[1];
        if (url && secret) {
          const wr = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${secret}` }, body: JSON.stringify({ event: 'svrnty-reply', from: owner.fingerprint, note_id: r.note_id }) });
          console.log(`webhook: ${wr.status}`);
        }
      } catch (e) { console.log('webhook: skipped', (e as Error).message); }
    }
    return;
  }

  if (cmd === 'poll') {
    const s = await pollOnce(owner, store);
    console.log('summary:', JSON.stringify(s));
    printNewArrivals(owner.fingerprint, new Set());
    for (const n of store.listNotes().filter((n) => n.direction === 'inbound')) {
      const c = store.getContactByFingerprint(n.from_fingerprint);
      const pt = c && trPacket(n.body) ? await trOpen(artifact, c, n.body) : null;
      const shown = pt ?? n.body;
      console.log(`[note ${shortNoteId(n.note_id)} from ${n.from_fingerprint.slice(0, 12)}… @${n.sent_at}] ${displayLine(shown)}`);
    }
    return;
  }

  if (cmd === 'poll-json') {
    // Flint §B key-side (KB#3285): decrypt inbound notes and durably JOURNAL each SUCCESSFUL
    // decrypt. Triple-ratchet decrypt is ONE-SHOT / forward-secret — the ratchet advances + persists
    // the instant trOpen succeeds, so a plaintext captured now can NEVER be re-derived. Journal-at-
    // decrypt (0600 via the process umask, inside the agent sandbox) is the durable capture; the
    // downstream flint cron (devin_quarantine.py) sanitizes + deposits into external_quarantine.
    // SECURITY: emit ONLY authenticated-and-decrypted notes. NEVER the ciphertext fallback that the
    // human `poll` command uses (pt ?? n.body) — a non-tr body or a failed decrypt is dropped, so no
    // raw wire or unauthenticated content ever reaches the quarantine table.
    const journalPath = `${DIR}/decrypt-journal.jsonl`;
    const consumed = await pollOnce(owner, store);
    // "journaled 0" must not hide WHY (Athena #593, Archie #595): a poll the relay REFUSED looks identical to an
    // empty mailbox in the journal summary. consume reports the refusal as `rejected` (the HTTP status);
    // say it on stderr here and carry it in the stdout JSON below. Exit code is unchanged (0) on purpose.
    if (consumed.rejected !== undefined) {
      console.error(`POLL REFUSED by the relay: HTTP ${consumed.rejected} (a refused poll is not an empty mailbox)`);
    }
    // poll-json-watermark-001: the journal IS the durable consumed-set —
    // a journaled note_id already had its one-shot decrypt spent, so
    // trOpen can only return null while re-paying readKey + importState +
    // ML-KEM receive EVERY pass (~3min @94% CPU on node18, watchmail
    // serializes behind it). Skip journaled ids; failed/absent notes still
    // get their attempt (out-of-order packets can become decryptable as
    // the ratchet advances).
    // Skip-set keyed (peer_fp, note_id) — NOT note_id alone: putNote keys
    // on sender-chosen note_id and overwrites on collision, so a bare id
    // could shadow a different sender's note forever (flint seam review).
    const journaledIds = new Set<string>();
    try {
      for (const line of readFileSync(journalPath, 'utf8').split('\n')) {
        const t = line.trim();
        if (!t) continue;
        try {
          const m = JSON.parse(t);
          if (m.note_id) journaledIds.add(`${m.peer_fp ?? ''}:${m.note_id}`);
        } catch { /* tolerate a torn line */ }
      }
    } catch { /* no journal yet — first pass */ }
    // Dead-packet tombstone: a tr packet whose decrypt keeps failing
    // (ratchet already advanced past it) re-pays the full importState +
    // receive every pass FOREVER — sage measured ~45s per dead packet on
    // node18 (4 dead notes = ~3min pass even with journaled skips). Try up
    // to 5 passes (covers out-of-order delivery that becomes decryptable
    // as the ratchet advances), then tombstone it out of the loop.
    const attemptsPath = `${DIR}/decrypt-attempts.json`;
    let attempts: Record<string, number> = {};
    try { attempts = JSON.parse(readFileSync(attemptsPath, 'utf8')); } catch { /* first pass */ }
    const MAX_ATTEMPTS = 5;
    let journaled = 0;
    let skipped = 0;
    let skippedLoom = 0;     // loom fan-out: visible count, not silence
    let loomNotices = 0;     // loom envelopes addressed to us → body-less journal notice (Archie #177969)
    const openTasks = new Map<string, { note_id: string; channel: string; sent_at: string }[]>();
    let decryptFailed = 0;   // tr packet that failed trOpen this pass (e.g. no session: Flint Bug 2)
    let dead = 0;            // tr packet tombstoned after MAX_ATTEMPTS failures (Mneme FINAL)
    const deadByPeer = new Map<string, { note_id: string; sent_at: string }[]>();   // → one notice per peer
    for (const note of store.listNotes().filter((n) => n.direction === 'inbound')) {
      if (journaledIds.has(`${note.from_fingerprint}:${note.note_id}`)) { skipped++; continue; }
      const c = store.getContactByFingerprint(note.from_fingerprint);
      // in-book AND not-blocked (admitContact) for BOTH paths: a blocked sender vanishes, so its
      // stored notes must not resurface (survivor-safety v1.1; Flint #260). Loom fan-out → skip.
      const route = routeInbound(c, note.body);
      if (route === 'skip_loom') {
        // Addressed to us (mention / task_request assigned to us) → a body-less notice in the
        // journal, so the depositor badges it (Archie #177969). Open task_requests are collected
        // per peer and become ONE notice after the loop (Flint #263). Other fan-out: counted (#260).
        const notice = loomNotice(note.body, owner.fingerprint);
        if (!notice) {
          const ch = openTaskChannel(note.body);
          if (ch !== null) {
            const list = openTasks.get(note.from_fingerprint) ?? [];
            list.push({ note_id: note.note_id, channel: ch, sent_at: note.sent_at });
            openTasks.set(note.from_fingerprint, list);
          }
          skippedLoom++;
          continue;
        }
        appendFileSync(journalPath, JSON.stringify({
          note_id: note.note_id,
          peer_fp: note.from_fingerprint,
          sent_at: safeToken(note.sent_at),
          plaintext: notice,
          transport: 'loom-notice',
        }) + '\n');
        journaled++;
        loomNotices++;
        continue;
      }
      if (!c || route === 'skip_unadmitted') continue;
      if (route === 'plain') {
        // PLAIN note (Mneme's replies, 2026-10-24: sat unseen 2h). Already sender-authenticated +
        // admitted before putNote, same as the BM store.json path in devin_quarantine.py
        // (f3e115f2), which docker cells can't use: their store stays in-container. Journal it so
        // the depositor sees every inbound note regardless of transport. Never ciphertext: a TR
        // body is classified 'tr' and still goes through trOpen below. Journaled with peer_fp, so
        // the (peer_fp, note_id) skip-set above skips it on the next pass.
        appendFileSync(journalPath, JSON.stringify({
          note_id: note.note_id,
          peer_fp: note.from_fingerprint,
          sent_at: note.sent_at,
          plaintext: note.body,
          transport: 'plain',
        }) + '\n');
        journaled++;
        continue;
      }
      const key = `${note.from_fingerprint}:${note.note_id}`;
      if ((attempts[key] ?? 0) >= MAX_ATTEMPTS) {                       // tombstoned (Mneme FINAL)
        dead++;
        if (attempts[key] === MAX_ATTEMPTS) {                           // not yet announced (MAX+1 = announced)
          const list = deadByPeer.get(note.from_fingerprint) ?? [];
          list.push({ note_id: note.note_id, sent_at: note.sent_at });
          deadByPeer.set(note.from_fingerprint, list);
        }
        continue;
      }
      // counted + persisted once trOpen HOLDS the lock (Flint #2361/#2366): a kill inside receive counts, lock contention doesn't
      const pt = await countedOpen(attempts, key, (a) => writeFileAtomic(attemptsPath, JSON.stringify(a)), (charge) => trOpen(artifact, c, note.body, charge));
      if (pt === null) {
        decryptFailed++;
        continue;                                        // failed/consumed — counted, never stored
      }
      appendFileSync(journalPath, JSON.stringify({
        note_id: note.note_id,
        peer_fp: note.from_fingerprint,
        sent_at: note.sent_at,
        plaintext: pt,
      }) + '\n');
      journaled++;
    }
    for (const [peerFp, items] of openTasks) {
      const agg = openTasksNotice(peerFp, items);
      if (journaledIds.has(`${peerFp}:${agg.note_id}`)) continue;   // same set already announced
      appendFileSync(journalPath, JSON.stringify({
        note_id: agg.note_id,
        peer_fp: peerFp,
        sent_at: safeToken(items.map((i) => i.sent_at).sort().at(-1)),
        plaintext: agg.text,
        transport: 'loom-notice',
      }) + '\n');
      journaled++;
      loomNotices++;
    }
    for (const [peerFp, items] of deadByPeer) {
      const agg = deadNotesNotice(peerFp, items, MAX_ATTEMPTS);
      for (const i of items) attempts[`${peerFp}:${i.note_id}`] = MAX_ATTEMPTS + 1;   // announced: never re-counted
      if (journaledIds.has(`${peerFp}:${agg.note_id}`)) continue;   // same set already announced
      appendFileSync(journalPath, JSON.stringify({
        note_id: agg.note_id,
        peer_fp: peerFp,
        sent_at: safeToken(items.map((i) => i.sent_at).sort().at(-1)),
        plaintext: agg.text,
        transport: 'dead-notice',
      }) + '\n');
      journaled++;
    }
    writeFileAtomic(attemptsPath, JSON.stringify(attempts));
    // polled / rejected / dropped come straight from consume's summary (see ConsumeSummary). `dropped` is an
    // AGGREGATE for THIS poll with no sender in it, and it has two kinds: a terminal drop (undecryptable,
    // bad signature, not-in-book) is counted once and acked away, but a RETRYABLE envelope stays in the mailbox
    // and is counted again on every poll until it resolves. So a steady dropped>0 can be one stuck envelope.
    console.log(JSON.stringify({ journaled, skipped, skipped_loom: skippedLoom, loom_notices: loomNotices, decrypt_failed: decryptFailed, dead, journal: journalPath, polled: consumed.polled, rejected: consumed.rejected ?? null, dropped: consumed.dropped,
      // #720 counters (counts only; the ward allowlist in devin_quarantine names exactly these keys). `lost` = per-reason consumed losses
      // (headless has no dead-letter sink, so deadLettered/unrecorded/released stay 0 here); opened_* = which leg of the dual-read opened.
      held: consumed.held, deadLettered: consumed.deadLettered, unrecorded: consumed.unrecorded, released: consumed.released, lost: consumed.lost,
      opened_hybrid: consumed.opened_hybrid, opened_classical: consumed.opened_classical,
      // #712: redelivered envelopes acked without a second open (C1), and envelopes left for the next pass by the time budget
      deduped: consumed.deduped ?? 0, deferred: consumed.deferred ?? 0,
      // layer 1: receipts verified → our outbound notes now Delivered / receipts this poll sent back to senders (counts only)
      delivered: consumed.delivered, receipts_sent: consumed.receipts_sent }));
    return;
  }

  if (cmd === 'loop') {
    const seen = new Set(store.listNotes().map((n) => n.note_id));
    const gateSeen = new Set(Object.keys(loadGate()[owner.fingerprint] ?? {}));
    const intervalMs = rest[0] ? Number(rest[0]) : 10_000;
    let inFlight = false;
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        await pollOnce(owner, store);
        printNewArrivals(owner.fingerprint, gateSeen);
        for (const n of store.listNotes()) {
          if (n.direction === 'inbound' && !seen.has(n.note_id)) {
            seen.add(n.note_id);
            const c = store.getContactByFingerprint(n.from_fingerprint);
            const pt = c && trPacket(n.body) ? await trOpen(artifact, c, n.body) : null;
            console.log(`[note ${shortNoteId(n.note_id)} from ${n.from_fingerprint.slice(0, 12)}… @${n.sent_at}] ${displayLine(pt ?? n.body)}`);
          }
        }
      } catch (err) {
        console.error('[poll] tick failed (will retry):', err);
      } finally {
        inFlight = false;
      }
    };
    setInterval(() => void tick(), intervalMs);
    console.log(`polling ${RELAY} as ${owner.fingerprint.slice(0, 16)}… (Ctrl-C to stop)`);
    void tick();
    return;
  }

  throw new Error(`unknown command ${cmd}`);
}

main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
