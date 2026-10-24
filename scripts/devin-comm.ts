// scripts/devin-comm.ts — agent-to-agent comm runner (calls existing lib only; NO crypto here).
// Usage (from repo root):
//   npx tsx scripts/devin-comm.ts mint
//   npx tsx scripts/devin-comm.ts admit <peer-card.json>
//   npx tsx scripts/devin-comm.ts send <fingerprint> "<body>"
//   npx tsx scripts/devin-comm.ts poll
//   npx tsx scripts/devin-comm.ts poll-json          — decrypt inbound → durable journal (flint §B cron)
//   npx tsx scripts/devin-comm.ts loop [intervalMs]
//   npx tsx scripts/devin-comm.ts grow [uses]          — mint a Grow shortlink (remote, multi-use)
//   npx tsx scripts/devin-comm.ts join <url>           — resolve a Grow link, admit giver, send joiner-response
//   npx tsx scripts/devin-comm.ts gate                 — list Gate arrivals (verified joiners awaiting admit)
//   npx tsx scripts/devin-comm.ts admit-gate <fp>      — admit a Gate arrival as Known → notes flow
//   npx tsx scripts/devin-comm.ts admit <card.json>    — admit a new peer
// Secrets live in ~/.svrnty-agent/ — outside the repo, never committed.
// Agent-local protocol state (issued Grow codes + Gate arrivals) lives alongside it as JSON.

import { readFileSync, writeFileSync, appendFileSync, chmodSync, existsSync, mkdirSync } from 'node:fs';
import { routeInbound, loomNotice } from './devin-comm-inbound';
import { mintHeadlessAgent, serializeMintArtifact, type SerializedMintArtifact } from '../src/lib/identity/headless-mint';
import { HeadlessStore, type HeadlessContact } from '../src/lib/headless/headless-store';
import { sendNoteFromHeadless, buildHeadlessConsumeDeps, type HeadlessOwner } from '../src/lib/headless/headless-client';
import { consumeInboundContactUpdates, type ConsumeSummary, type JoinerResponseSeam } from '../src/lib/sync/consume-mailbox';
import { verifyJoinerResponse } from '../src/lib/trust/joiner-response';
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

function ownerFrom(a: SerializedMintArtifact): HeadlessOwner {
  const id = a.public.card.identity;
  return {
    fingerprint: a.public.durable_id,
    publicKeyArmored: id.public_key,
    privateKeyArmored: a.private.classical_private_key,
    passphrase: a.private.classical_kpass,
    kemPublicKey: id.pq_kem_public_key,
    sigPublicKey: id.pq_sig_public_key,
  };
}

// ── agent-local JSON state (issued Grow codes + Gate arrivals) ─────────────────────────────────

function loadJson<T>(path: string, empty: T): T {
  if (!existsSync(path)) return empty;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T;
  } catch {
    return empty;
  }
}

function loadCodes(): IssuedCodeMap {
  return pruneIssuedCodes(loadJson<IssuedCodeMap>(CODES, {}), Date.now());
}

function saveCodes(map: IssuedCodeMap): void {
  writeFileSync(CODES, JSON.stringify(map, null, 2));
}

type GateMap = Record<string, Record<string, GateArrival>>;

function loadGate(): GateMap {
  return loadJson<GateMap>(GATE, {});
}

function saveGate(map: GateMap): void {
  writeFileSync(GATE, JSON.stringify(map, null, 2));
}

/**
 * The R1 return-channel seam for a headless giver: same verify + accept-oracle semantics as the
 * browser buildJoinerSeam (live-book-poll.ts), backed by issued-codes.json + gate.json instead of
 * IndexedDB. Joiners land at the Gate — never auto-admitted; `admit-gate` is the owner tap.
 */
function buildLocalJoinerSeam(owner: HeadlessOwner, store: HeadlessStore): JoinerResponseSeam {
  const ownFp = owner.fingerprint;
  const codes = loadCodes(); // snapshot per poll — same as browser loadIssuedCodeMap
  const acceptNonce = (nonce: string, joinerFp: string): boolean =>
    isCodeOutstanding(codes, ownFp, nonce, Date.now()) &&
    codeUnderCap(codes, ownFp, nonce) &&
    !alreadyAccepted(codes, ownFp, nonce, joinerFp);
  return {
    verify: (blob) =>
      verifyJoinerResponse(
        blob,
        { fingerprint: ownFp, privateKeyArmored: owner.privateKeyArmored, passphrase: owner.passphrase },
        acceptNonce,
        { requirePq: false },
      ),
    accept: (pj) =>
      acceptJoinerAtGate(ownFp, pj, codes, {
        getContactByFingerprint: async (_o: string, fp: string) => store.getContactByFingerprint(fp) as any,
        getGateArrival: async (o: string, fp: string) => (loadGate()[o]?.[fp] ?? null) as any,
        enqueueGateArrival: async (o: string, arrival: GateArrival) => {
          const g = loadGate();
          if (!g[o]) g[o] = {};
          g[o][arrival.fingerprint] = arrival;
          saveGate(g);
        },
        recordAcceptedJoiner: async () => saveCodes(codes), // map already mutated in place by markAcceptedInMap
      }),
  };
}

async function pollOnce(owner: HeadlessOwner, store: HeadlessStore): Promise<ConsumeSummary> {
  const deps = buildHeadlessConsumeDeps(owner, store, { relayBase: RELAY });
  deps.joiner = buildLocalJoinerSeam(owner, store);
  return consumeInboundContactUpdates(deps);
}

// ── triple-ratchet (tr-v1) headless consume/send — mirrors messaging/direct-session.ts ─────────
// Calls the fleet TripleRatchet only; session snapshots persist in ratchet-sessions.json.

const TR_BODY = 'svrnty-tr-v1';
type TrSessions = Record<string, RatchetSnapshot>;
const loadTr = (): TrSessions => loadJson<TrSessions>(RATCHETS, {});
const saveTr = (m: TrSessions) => writeFileSync(RATCHETS, JSON.stringify(m, null, 2));

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

async function trOpen(a: SerializedMintArtifact, contact: HeadlessContact, body: string): Promise<string | null> {
  const packet = trPacket(body);
  const peer = await ratchetPeerOf(contact);
  if (!packet || !peer) return null;
  const self = ratchetSelf(a);
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
}

function printNewArrivals(ownerFp: string, seen: Set<string>): void {
  const g = loadGate()[ownerFp] ?? {};
  for (const a of Object.values(g)) {
    if (seen.has(a.fingerprint)) continue;
    seen.add(a.fingerprint);
    console.log(`[gate] ${a.displayName || a.fingerprint.slice(0, 12)} (${a.fingerprint}) waiting — admit-gate ${a.fingerprint} to let them in`);
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  // Ensure the sandbox dir exists + is owner-only (0700) before any state is written
  // (chmod covers the case where it pre-existed with looser perms). #256 finding #1.
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  chmodSync(DIR, 0o700);
  const store = new HeadlessStore({ path: STORE });

  if (cmd === 'mint') {
    if (existsSync(MINT)) throw new Error('mint.json already exists — refusing to re-mint');
    const a = await mintHeadlessAgent({ throwaway: false, recoveryMode: 'm-of-n' });
    const s = serializeMintArtifact(a);
    writeFileSync(MINT, JSON.stringify(s));
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
    const contact: HeadlessContact = {
      id: card.durable_id ?? card.fingerprint,
      fingerprint: card.fingerprint ?? card.durable_id,
      name: card.name ?? 'devin-cloud',
      public_key: card.public_key,
      pq_sig_public_key: card.pq_sig_public_key,
      pq_kem_public_key: card.pq_kem_public_key,
    };
    store.upsertContact(contact);
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
    console.log(JSON.stringify({ url: url.toString(), code: result.code, cap: uses, expiresAt: result.expiresAt }));
    return;
  }

  if (cmd === 'join') {
    // Resolve a Grow link → admit the giver → deposit our signed joiner-response to their mailbox.
    const u = new URL(rest[0]);
    const code = u.pathname.split('/c/')[1];
    const keyFragment = u.hash.slice(1);
    if (!code || !keyFragment) throw new Error('expected a /c/<code>#<key> Grow link');
    const card = JSON.parse(await resolveRelay(code, keyFragment));
    const id = card.identity ?? card;
    const giverFp = id.fingerprint ?? card.durable_id;
    if (!giverFp || !id.public_key) throw new Error('resolved card missing fingerprint/public_key');
    store.upsertContact({
      id: giverFp,
      fingerprint: giverFp,
      name: id.display_name || 'grow-giver',
      public_key: id.public_key,
      pq_sig_public_key: id.pq_sig_public_key,
      pq_kem_public_key: id.pq_kem_public_key,
      trust_level: 'known',
    });
    const myId = artifact.public.card.identity;
    const r = await sendJoinerResponse(
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
      { fingerprint: giverFp, publicKeyArmored: id.public_key, inviteNonce: code },
      { relayBase: RELAY },
    );
    console.log(JSON.stringify({ admitted: giverFp, joinerResponse: r }));
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
      console.log(`${a.fingerprint}  "${a.displayName}"  via ${a.inviteNonce} (${a.mintChannel})  arrived ${a.arrivedAt}`);
    }
    return;
  }

  if (cmd === 'admit-gate') {
    const fp = rest[0];
    const g = loadGate();
    const arrival = g[owner.fingerprint]?.[fp];
    if (!arrival) throw new Error(`no gate arrival ${fp}`);
    const rec = buildAdmitRecord(arrival, {});
    store.upsertContact({
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
    console.log(`admitted ${arrival.fingerprint} as Known — notes now flow: send ${arrival.fingerprint} "<body>"`);
    return;
  }

  if (cmd === 'send-tr') {
    // Seal a note with the triple ratchet (tr-v1 body inside the classical OpenPGP note wire).
    const [fp, body] = rest;
    const peer = store.getContactByFingerprint(fp);
    if (!peer) throw new Error(`peer ${fp} not admitted`);
    const rp = await ratchetPeerOf(peer);
    if (!rp) throw new Error(`peer ${fp} lacks ratchet keys (x25519/mlkem)`);
    const sessions = loadTr();
    const self = ratchetSelf(artifact);
    let s = sessions[fp] ? TripleRatchet.importState(sessions[fp]) : null;
    if (!s) s = TripleRatchet.initiate(self, rp);
    const packet = await s.send(body);
    sessions[fp] = s.exportState();
    saveTr(sessions);
    const wire = JSON.stringify({ type: TR_BODY, packet });
    const r = await sendNoteFromHeadless({ owner, peerFingerprint: fp, peerPublicKeyArmored: peer.public_key, body: wire, store, relayBase: RELAY });
    console.log(JSON.stringify(r));
    return;
  }

  if (cmd === 'send') {
    const [fp, body] = rest;
    const peer = store.getContactByFingerprint(fp);
    if (!peer) throw new Error(`peer ${fp} not admitted`);
    const r = await sendNoteFromHeadless({ owner, peerFingerprint: fp, peerPublicKeyArmored: peer.public_key, body, store, relayBase: RELAY });
    console.log(JSON.stringify(r));
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
      console.log(`[note ${n.note_id} from ${n.from_fingerprint.slice(0, 12)}… @${n.sent_at}] ${shown}`);
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
    await pollOnce(owner, store);
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
    let decryptFailed = 0;   // tr packet that failed trOpen this pass (e.g. no session: Flint Bug 2)
    let dead = 0;            // tr packet tombstoned after MAX_ATTEMPTS failures (Mneme FINAL)
    for (const note of store.listNotes().filter((n) => n.direction === 'inbound')) {
      if (journaledIds.has(`${note.from_fingerprint}:${note.note_id}`)) { skipped++; continue; }
      const c = store.getContactByFingerprint(note.from_fingerprint);
      // in-book AND not-blocked (admitContact) for BOTH paths: a blocked sender vanishes, so its
      // stored notes must not resurface (survivor-safety v1.1; Flint #260). Loom fan-out → skip.
      const route = routeInbound(c, note.body);
      if (route === 'skip_loom') {
        // Addressed to us (mention / our or open task_request) → a body-less notice in the journal,
        // so the depositor badges it (Archie #177969). Other fan-out: counted, never silent (#260).
        const notice = loomNotice(note.body, owner.fingerprint);
        if (!notice) { skippedLoom++; continue; }
        appendFileSync(journalPath, JSON.stringify({
          note_id: note.note_id,
          peer_fp: note.from_fingerprint,
          sent_at: note.sent_at,
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
      if ((attempts[key] ?? 0) >= MAX_ATTEMPTS) { dead++; continue; }   // tombstoned (Mneme FINAL)
      const pt = await trOpen(artifact, c, note.body);
      if (pt === null) {
        attempts[key] = (attempts[key] ?? 0) + 1;
        decryptFailed++;
        continue;                                        // failed/consumed — counted, never stored
      }
      delete attempts[key];
      appendFileSync(journalPath, JSON.stringify({
        note_id: note.note_id,
        peer_fp: note.from_fingerprint,
        sent_at: note.sent_at,
        plaintext: pt,
      }) + '\n');
      journaled++;
    }
    writeFileSync(attemptsPath, JSON.stringify(attempts), { mode: 0o600 });
    console.log(JSON.stringify({ journaled, skipped, skipped_loom: skippedLoom, loom_notices: loomNotices, decrypt_failed: decryptFailed, dead, journal: journalPath }));
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
            console.log(`[note ${n.note_id} from ${n.from_fingerprint.slice(0, 12)}… @${n.sent_at}] ${pt ?? n.body}`);
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
