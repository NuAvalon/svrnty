// src/components/JoinerCeremony.tsx
'use client';
//
// The joiner's side of the 9/10 connection ceremony. Mirror of the initiator
// component (src/components/Ceremony.tsx): the SAME proven state machine
// (src/lib/ceremony/machine.ts) drives both devices — role affects rendering, not the
// transition graph ("one impl, not two").
//
// Perspective: this instance runs on the JOINER's device (the receiver — arrives via the
// /c/[code] relay link, receives the card, persists the edge, watches their own lattice
// light up). The three middle steps (card, edge, lattice) are the joiner's REAL local
// actions here (the mirror of the initiator, where those three are "on their device"). The
// handshake already happened the moment they opened this link; the tear (step 5) happens on
// the GIVER's device, so it carries the "on their device" framing.
//
// Honest-scoping: the relay is a single-use dead-drop (src/lib/sync/relay.ts) — one code
// carries one payload. A CARD link walks the full stepper. A SHARD link ("the tear" landing
// on this device) is one meaningful act — accepting a recovery piece — so it gets a focused
// accept panel rather than being forced through a card-shaped 5-step rail. Nothing here
// touches prod; all state is local (IndexedDB) or the client-side relay.

import { useCallback, useEffect, useRef, useState } from 'react';
import { resolveRelay } from '@/lib/sync/relay';
import {
  getActiveFingerprint,
  loadIdentity,
  loadKey,
  addContact,
  updateContact,
  getContactByFingerprint,
  getAllContacts,
  storeHeldShard,
  SHARD_CUSTODY_TYPE,
  isSessionUnlocked,
  initSessionKey,
  lockSession,
} from '@/lib/identity/client-store';
import { sendJoinerResponse } from '@/lib/sync/send-joiner-response';
import { classifyImportedCard } from '@/lib/identity/identity-card-sign';
import { TrustMap } from '@/components/TrustMap';
import { useCeremony } from '@/lib/ceremony/useCeremony';
import { stepLabel, CEREMONY_STEP_ORDER, type CeremonyStepId } from '@/lib/ceremony/machine';
import type { TrustEdge } from '@/lib/trust/types';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import { isPQEncapLive } from '@/lib/claim-gates';

// Emerald/gold palette — matches the initiator (Ceremony.tsx) so the two devices read as
// one ceremony.
const C = {
  bg: '#0a0a0f',
  panel: 'rgba(10, 14, 12, 0.92)',
  emerald: '#34d399',
  emeraldDim: 'rgba(52, 211, 153, 0.15)',
  gold: '#c8a84e',
  ink: '#e8e4d9',
  faint: 'rgba(255,255,255,0.35)',
  err: '#ef4444',
};

// Which device each step happens on, from the JOINER's perspective — the mirror of the
// initiator's STEP_LOCUS. The middle three are the joiner's own actions; the tear is the
// giver's.
const STEP_LOCUS: Record<CeremonyStepId, 'you' | 'them' | 'done'> = {
  handshake: 'you',
  card: 'you',
  edge: 'you',
  lattice: 'you',
  tear: 'them',
  complete: 'done',
};

// ContactRecord -> TrustEdge projection now lives in the shared helper (single source of truth;
// carries pq — see contact-edge.ts). The main page (app/page.tsx) projects through the same one.

interface PeerCard {
  name: string;
  fingerprint: string;
  publicKey: string;
  email: string;
  // Authenticated pq (branch 4b) or null; alarm drives the import banner (branch-3 loud / 4c soft-info).
  pq: { pq_kem_public_key: string; pq_sig_public_key: string } | null;
  alarm: 'quiet' | 'loud' | 'soft-info';
}

// R1 return-channel deposit. After the joiner adds the giver, deposit a signed
// joiner-response to the GIVER's mailbox so the giver learns of us and the edge becomes MUTUAL — closing
// the one-directional Grow asymmetry (giver polls → verifyJoinerResponse → adds us as KNOWN → the 0.4
// contact.update wire now flows both ways). Best-effort + FAIL-SOFT: signing requires our unlocked
// private key; if the identity is locked or the deposit fails, the local edge still stands and the
// ceremony never blocks — any failure is a local-only diagnostic, NEVER surfaced to a peer/relay (I-1).
// The giver's mailbox holds the response for ~7d, so a deposit that lands on a later unlocked open still
// connects. IDENTITY-ONLY: carries our {fp, epoch, key, name}, never contact methods.
async function depositJoinerResponse(ownerFp: string, peer: PeerCard, code: string): Promise<void> {
  try {
    if (!peer.fingerprint || !peer.publicKey || !code) return; // nothing to bind the response to
    const key = await loadKey(ownerFp);
    if (!key) {
      // Locked session — cannot sign. The edge is already stored; the return channel simply doesn't fire
      // this time (a later unlocked open can re-deposit within the giver's ~7d mailbox window).
      console.warn('[joiner-response] identity locked — return-channel deposit deferred (edge stands locally)');
      return;
    }
    const id = await loadIdentity(ownerFp);
    const ownPub: string = id?.identity?.public_key || '';
    if (!ownPub) return; // no own key to present — cannot build a verifiable response
    const displayName: string = id?.identity?.display_name || id?.identity?.name || '';
    const res = await sendJoinerResponse(
      {
        fingerprint: ownerFp,
        epoch: 0, // no key-rotation yet — the joiner ships contact.updates at epoch 0 (matches giver floor)
        publicKeyArmored: ownPub,
        displayName,
        privateKeyArmored: key.privateKey,
        passphrase: key.passphrase,
        // §5 canonical-fp binding: thread our PQ pubkeys so the giver recomputes our 64-hex canonical id.
        // Only when BOTH are present (a canonical identity); a classical identity omits them.
        ...(id?.post_quantum?.kem_public_key && id?.post_quantum?.sig_public_key
          ? { kemPublicKeyB64: id.post_quantum.kem_public_key, sigPublicKeyB64: id.post_quantum.sig_public_key }
          : {}),
      },
      { fingerprint: peer.fingerprint, publicKeyArmored: peer.publicKey, inviteNonce: code },
    );
    if (!res.ok) {
      console.warn('[joiner-response] deposit not delivered (edge stands locally):', res.status);
    }
  } catch (err) {
    console.warn('[joiner-response] deposit failed (edge stands locally):', err);
  }
}

export function JoinerCeremony({ code, keyFragment }: { code: string; keyFragment: string }) {
  const ceremony = useCeremony('joiner');
  const { state } = ceremony;
  // Stable action identities (useCallback deps [] in useCeremony) — safe as effect deps.
  const { handshakeEstablished, fail } = ceremony;

  const [kind, setKind] = useState<'card' | 'shard' | null>(null);
  const [peer, setPeer] = useState<PeerCard | null>(null);
  const [ownerFp, setOwnerFp] = useState<string | null>(null);
  const [ownerName, setOwnerName] = useState<string>('You');
  const [contacts, setContacts] = useState<TrustEdge[]>([]);
  const [alreadyKnown, setAlreadyKnown] = useState(false);

  // Unlock gate (R1): the joiner arrives at /c/ with a LOCKED session (the memory-only session key does
  // not survive the navigation). Signing the return-channel joiner-response needs the private key, so we
  // prompt for the passphrase at the "make the edge live" step to complete a MUTUAL connection.
  const [needsUnlock, setNeedsUnlock] = useState(false);
  const [unlockPass, setUnlockPass] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockBusy, setUnlockBusy] = useState(false);

  // Shard ("the tear") landing on this device.
  const [shardFrom, setShardFrom] = useState<string>('Someone');
  const [shardState, setShardState] = useState<'idle' | 'accepting' | 'accepted' | 'exists'>('idle');
  const [shardMsg, setShardMsg] = useState<string>('');

  const startedRef = useRef(false);

  // --- Mount: get our identity, resolve + decrypt the relay, classify the payload. ---
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let cancelled = false;

    (async () => {
      try {
        const fp = await getActiveFingerprint();
        if (cancelled) return;
        if (!fp) {
          fail('No active identity found. Set up your identity on the main page first, then revisit this link.');
          return;
        }
        setOwnerFp(fp);
        loadIdentity(fp)
          .then((id) => {
            if (!cancelled && id) {
              setOwnerName(id?.identity?.display_name || id?.identity?.name || id?.name || 'You');
            }
          })
          .catch(() => {});

        const decrypted = await resolveRelay(code, keyFragment);
        if (cancelled) return;

        const parsed = JSON.parse(decrypted);
        if (parsed?.type === SHARD_CUSTODY_TYPE) {
          setKind('shard');
          setShardFrom(parsed?.from?.name || 'Someone');
          // Stash for the accept action.
          setPeer(null);
          (window as any).__svrnty_shard = parsed;
        } else {
          const p = parsed.identity || parsed;
          // C2 / Invariant-1 + signature: classify the card BEFORE showing the reassuring fingerprint
          // box or persisting anything. Branch 1 (fp↔key fail / malformed) refuses the card — otherwise
          // the out-of-band "is this your fingerprint?" ritual would falsely pass while the stored key
          // is an attacker's. Branches 2/3/4 import the classical contact; the pq sub-disposition
          // decides whether the authenticated pq_kem/pq_sig is stored (spec §4).
          const d = await classifyImportedCard(parsed);
          if (cancelled) return;
          if (!d.importClassical) {
            fail(
              'This card could not be verified — its fingerprint does not match its key, so it was not imported. Ask them to send you a fresh link.',
            );
            return;
          }
          setKind('card');
          setPeer({
            name: p.display_name || p.name || p.peer_name || 'Unknown',
            fingerprint: p.fingerprint || p.peer_fingerprint || '',
            publicKey: p.public_key || p.publicKey || '',
            email: p.email || '',
            pq: d.pq,
            alarm: d.alarm === 'reject' ? 'quiet' : d.alarm,
          });
        }
        handshakeEstablished(code); // machine: handshake -> card
      } catch (err: any) {
        if (cancelled) return;
        fail(err?.message || 'This link has expired or already been used.');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [code, keyFragment, handshakeEstablished, fail]);

  // --- Card ceremony actions ---
  const receiveCard = useCallback(() => {
    if (!peer) return;
    ceremony.cardConveyed(peer.fingerprint, peer.name); // card -> edge
  }, [peer, ceremony]);

  const persistEdge = useCallback(async () => {
    if (!peer || !ownerFp) return;
    // A MUTUAL connection requires signing a joiner-response with our private key (so the giver learns of
    // us and the edge is two-way). The session key is memory-only and does NOT survive the /c/ navigation,
    // so a joiner arriving via a link is locked. Prompt for the passphrase here — unlocking both persists
    // the edge AND signs the return deposit. Without this, the deposit is skipped and the connect stays
    // one-directional (the R1 bug). If already unlocked (e.g. same-tab from the main app), proceed directly.
    if (!isSessionUnlocked()) {
      setNeedsUnlock(true);
      return;
    }
    try {
      // Idempotent: if we already know them, don't double-add — advance with the existing edge.
      const existing = peer.fingerprint
        ? await getContactByFingerprint(ownerFp, peer.fingerprint)
        : null;
      let edgeId: string;
      const pqFields = peer.pq
        ? { pq_kem_public_key: peer.pq.pq_kem_public_key, pq_sig_public_key: peer.pq.pq_sig_public_key }
        : {};
      if (existing) {
        // Upgrade-on-re-exchange (§7#5): back-fill authenticated pq onto a known edge that has
        // none — no duplicate; never silently replace a different stored pq (rotation is a separate,
        // deliberate, lineage-tracked path, not a re-import side effect).
        if (peer.pq && !existing.pq_kem_public_key) {
          await updateContact(existing.id, pqFields);
        }
        setAlreadyKnown(true);
        edgeId = existing.id;
      } else {
        const contact = await addContact(ownerFp, {
          name: peer.name,
          fingerprint: peer.fingerprint,
          public_key: peer.publicKey,
          // KNOWN, not 'pending': the joiner added the giver from a CRYPTO-VERIFIED Grow card
          // (classifyImportedCard verified the signature) — that earns KNOWN immediately
          // (KNOWN = add-from-link/qr, no mutuality; mutuality is only for TRUSTED). 'pending'
          // under-claimed the tier (render-neutral — the faint node keys on connection_status, not
          // trust_level — but the stored value should honestly match the crypto). Causality-cleared: no
          // logic-reader keys on trust_level==='pending'.
          trust_level: 'known',
          email: peer.email,
          ...pqFields, // authenticated pq (branch 4b) only; dropped on 2/3/4a/4c
        } as any);
        edgeId = contact.id;
      }
      // R1: the edge is live locally — now fire the return-channel deposit to the giver (best-effort,
      // non-blocking) so the connection becomes MUTUAL. The ceremony advances immediately regardless of
      // whether the deposit lands (fail-soft); a locked identity or relay hiccup never blocks the UI.
      void depositJoinerResponse(ownerFp, peer, code);
      // Load the constellation for the lattice step (includes the new facet).
      try {
        const raw = await getAllContacts(ownerFp);
        setContacts(raw.map(contactRecordToEdge));
      } catch { /* non-fatal — lattice will just show the owner */ }
      ceremony.edgePersisted(edgeId); // edge -> lattice
    } catch (err: any) {
      ceremony.fail(err?.message || 'Could not write the edge.');
    }
  }, [peer, ownerFp, code, ceremony]);

  // Unlock the identity to sign the mutual connection, then persist the edge + deposit. initSessionKey
  // derives the key WITHOUT validating, so a wrong passphrase yields a key that can't decrypt — verify by
  // a loadKey (which throws on a bad passphrase) and lock again on failure so isSessionUnlocked stays honest.
  const submitUnlock = useCallback(async () => {
    if (!ownerFp || !unlockPass || unlockBusy) return;
    setUnlockBusy(true);
    setUnlockError(null);
    try {
      await initSessionKey(unlockPass);
      await loadKey(ownerFp); // throws on a wrong passphrase (can't decrypt the stored key)
      setNeedsUnlock(false);
      setUnlockPass('');
      await persistEdge(); // now unlocked → adds the edge + signs & deposits the joiner-response + advances
    } catch {
      lockSession(); // clear the bad session key so the gate stays honest
      setUnlockError('That passphrase didn’t unlock your identity. Please try again.');
    } finally {
      setUnlockBusy(false);
    }
  }, [ownerFp, unlockPass, unlockBusy, persistEdge]);

  // --- Shard ("the tear") accept ---
  const acceptShard = useCallback(async () => {
    if (!ownerFp) return;
    const raw = (window as any).__svrnty_shard;
    if (!raw || !raw.shard) {
      setShardMsg('The piece could not be read.');
      return;
    }
    setShardState('accepting');
    try {
      await storeHeldShard(ownerFp, {
        owner_fingerprint: raw.from?.fingerprint || raw.shard.identity_fingerprint || '',
        owner_name: raw.from?.name || 'Unknown',
        shard: raw.shard,
        threshold: raw.threshold || raw.shard.threshold || 0,
        total: raw.total || 0,
      } as any);
      setShardMsg(
        `You are now holding a piece of ${raw.from?.name || 'their'} recovery. Keep it safe — any few keepers together can help them restore.`,
      );
      setShardState('accepted');
      try { delete (window as any).__svrnty_shard; } catch { /* ignore */ }
    } catch (err: any) {
      setShardMsg(err?.message || 'Could not accept the piece.');
      setShardState('idle');
    }
  }, [ownerFp]);

  // ============================ SHARD LINK — focused accept ============================
  if (kind === 'shard') {
    return (
      <Shell>
        <Badge tone="gold" label="A piece entrusted to you" />
        {shardState !== 'accepted' ? (
          <>
            <h2 style={headingStyle}>{shardFrom} tore off a piece</h2>
            <p style={subStyle}>
              They entrusted a shard of their recovery to you — a piece of their survivability,
              held by someone they trust. It was decrypted on your device; the server never saw it.
            </p>
            <button
              style={primaryBtnStyle}
              disabled={shardState === 'accepting'}
              onClick={acceptShard}
            >
              {shardState === 'accepting' ? 'Accepting…' : 'Accept the piece'}
            </button>
            {shardMsg && shardState === 'idle' && (
              <p style={{ color: C.err, marginTop: 14, fontSize: 13 }}>{shardMsg}</p>
            )}
          </>
        ) : (
          <>
            <div style={{ fontSize: 34, marginBottom: 8 }}>🜂</div>
            <h2 style={headingStyle}>You are a keeper</h2>
            <p style={subStyle}>{shardMsg}</p>
            <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
          </>
        )}
        {state.error && <ErrorLine text={state.error} />}
      </Shell>
    );
  }

  // ================================ CARD LINK — full stepper ================================
  const idx = CEREMONY_STEP_ORDER.indexOf(state.step);

  return (
    <Shell wide>
      {/* Progress rail */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 28 }}>
        {CEREMONY_STEP_ORDER.filter((s) => s !== 'complete').map((s, i) => {
          const done = i < idx;
          const active = CEREMONY_STEP_ORDER[i] === state.step;
          return (
            <div key={s} style={{ flex: 1, textAlign: 'center' }}>
              <div
                style={{
                  height: 3,
                  borderRadius: 2,
                  background: done || active ? C.emerald : C.emeraldDim,
                  opacity: done ? 0.6 : active ? 1 : 0.4,
                }}
              />
              <div
                style={{
                  marginTop: 6,
                  fontSize: 10,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  color: active ? C.emerald : C.faint,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {stepLabel(s)}
              </div>
            </div>
          );
        })}
      </div>

      <div
        style={{
          background: C.panel,
          border: `1px solid ${C.emeraldDim}`,
          borderRadius: 16,
          padding: 32,
          textAlign: 'center',
        }}
      >
        {STEP_LOCUS[state.step] === 'them' && <LocusTag />}

        {/* handshake — arriving / retrieving */}
        {state.step === 'handshake' && !state.error && (
          <div>
            <Spinner />
            <h2 style={headingStyle}>Opening the secure channel…</h2>
            <p style={subStyle}>Retrieving and decrypting their card. Code: {code}</p>
          </div>
        )}

        {/* card — their card has reached your device */}
        {state.step === 'card' && peer && (
          <div>
            <h2 style={headingStyle}>{peer.name} shared their card</h2>
            <p style={subStyle}>
              An identity card reached your device through the relay, encrypted — no server could read it.
            </p>
            <div style={cardBoxStyle}>
              <div style={{ fontSize: 10, color: C.faint, letterSpacing: 1, marginBottom: 4 }}>FINGERPRINT</div>
              <code style={{ color: C.emerald, fontSize: 12, wordBreak: 'break-all' }}>
                {peer.fingerprint || '—'}
              </code>
            </div>
            {/* PQ disposition (spec §4 cry-wolf: loud only on an invalid signature) */}
            {peer.alarm === 'loud' && (
              <p style={{ color: C.err, fontSize: 12, marginTop: 8 }}>
                ⚠ Could not verify this card&apos;s key material — possible tampering. It imports as a
                classical contact only; ask them to re-share over a fresh link.
              </p>
            )}
            {peer.alarm === 'soft-info' && (
              <p style={{ color: C.faint, fontSize: 12, marginTop: 8 }}>
                Their post-quantum key uses an unsupported format — importing classical only.
              </p>
            )}
            {peer.alarm === 'quiet' && peer.pq && (
              isPQEncapLive() ? (
                <p style={{ color: C.emerald, fontSize: 12, marginTop: 8 }}>
                  ✓ Post-quantum protected — a signed card carrying a verified encryption key.
                </p>
              ) : (
                <p style={{ color: C.faint, fontSize: 12, marginTop: 8 }}>
                  Post-quantum ready — this card carries a verified post-quantum encryption key;
                  protection activates when the encryption seam is live.
                </p>
              )
            )}
            <button style={primaryBtnStyle} onClick={receiveCard}>Receive their card →</button>
          </div>
        )}

        {/* edge — persist the connection locally */}
        {state.step === 'edge' && peer && (
          <div>
            <h2 style={headingStyle}>Make the edge live</h2>
            <p style={subStyle}>
              Add {peer.name} to your network — a connection saved to your device, between the two of you.
              (A known contact for now; trust is something you choose to grant later.)
            </p>
            {!needsUnlock ? (
              <button style={primaryBtnStyle} onClick={persistEdge}>Add to my network →</button>
            ) : (
              <div style={{ marginTop: 18 }}>
                {/* Anti-phishing: a secret is demanded BY and FOR the user's OWN
                    vault (owner act) — never framed as the price of connecting with the giver. Owner
                    action, {peer.name} as the object. Shown only AFTER the intentional "Add" click. */}
                <p style={{ ...subStyle, marginBottom: 12 }}>
                  Unlock your svrnty to finish adding {peer.name}. This is your own vault — your key
                  never leaves this device.
                </p>
                <input
                  type="password"
                  value={unlockPass}
                  onChange={(e) => setUnlockPass(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') void submitUnlock(); }}
                  placeholder="Your passphrase"
                  autoFocus
                  style={unlockInputStyle}
                />
                <button
                  style={{ ...primaryBtnStyle, opacity: !unlockPass || unlockBusy ? 0.5 : 1 }}
                  disabled={!unlockPass || unlockBusy}
                  onClick={() => void submitUnlock()}
                >
                  {unlockBusy ? 'Unlocking…' : 'Unlock →'}
                </button>
                {unlockError && (
                  <p style={{ color: C.err, fontSize: 12, marginTop: 8 }}>{unlockError}</p>
                )}
              </div>
            )}
          </div>
        )}

        {/* lattice — your constellation gains a facet */}
        {state.step === 'lattice' && (
          <div>
            <h2 style={headingStyle}>A facet lights up</h2>
            <p style={subStyle}>
              {peer?.name ? `${peer.name} now appears in your constellation.` : 'A new facet appears in your constellation.'}
              {alreadyKnown ? ' You were already connected.' : ''}
            </p>
            <div style={{ margin: '16px auto', maxWidth: 360 }}>
              <TrustMap ownerFingerprint={ownerFp || ''} ownerName={ownerName} contacts={contacts} />
            </div>
            <button style={primaryBtnStyle} onClick={() => ceremony.latticeRendered()}>
              The facet is lit →
            </button>
          </div>
        )}

        {/* tear — the giver's local act (on their device) */}
        {state.step === 'tear' && (
          <div>
            <h2 style={headingStyle}>They may tear off a piece</h2>
            <p style={subStyle}>
              On {peer?.name || 'their'} device, they can tear off a shard of their recovery and
              entrust it to you. If they do, it arrives as its own link — open it to become a keeper.
            </p>
            <button style={primaryBtnStyle} onClick={() => ceremony.shardGiven()}>Finish →</button>
          </div>
        )}

        {/* complete */}
        {state.step === 'complete' && (
          <div>
            <div style={{ fontSize: 40, marginBottom: 8 }}>🜂</div>
            <h2 style={headingStyle}>You are connected</h2>
            <p style={subStyle}>A card received, an edge live, a facet lit in your constellation.</p>
            <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
          </div>
        )}

        {state.error && (
          <ErrorLine text={state.error} />
        )}
      </div>
    </Shell>
  );
}

// ------------------------------- small presentational helpers -------------------------------

function Shell({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: C.bg,
        color: C.ink,
      }}
    >
      <div style={{ width: '100%', maxWidth: wide ? 640 : 440 }}>
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 6, color: C.gold }}>SVRNTY</div>
          <div style={{ fontSize: 11, color: C.faint, letterSpacing: 1 }}>Secure Identity Exchange</div>
        </div>
        {!wide ? (
          <div
            style={{
              background: C.panel,
              border: `1px solid ${C.emeraldDim}`,
              borderRadius: 16,
              padding: 32,
              textAlign: 'center',
            }}
          >
            {children}
          </div>
        ) : (
          children
        )}
      </div>
    </div>
  );
}

function Badge({ tone, label }: { tone: 'gold' | 'emerald'; label: string }) {
  const col = tone === 'gold' ? C.gold : C.emerald;
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 14 }}>
      <div style={{ width: 8, height: 8, borderRadius: 999, background: col }} />
      <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: 1, color: col }}>{label}</span>
    </div>
  );
}

function LocusTag() {
  return (
    <div
      style={{
        display: 'inline-block',
        fontSize: 10,
        letterSpacing: 2,
        textTransform: 'uppercase',
        color: C.gold,
        border: '1px solid rgba(200,168,78,0.3)',
        borderRadius: 999,
        padding: '3px 10px',
        marginBottom: 16,
        fontFamily: "'JetBrains Mono', monospace",
      }}
    >
      On their device
    </div>
  );
}

function Spinner() {
  return (
    <div
      className="animate-spin"
      style={{
        display: 'inline-block',
        width: 24,
        height: 24,
        borderRadius: '50%',
        border: '2px solid rgba(52,211,153,0.2)',
        borderTopColor: C.emerald,
        marginBottom: 16,
      }}
    />
  );
}

function ErrorLine({ text }: { text: string }) {
  return (
    <p style={{ color: C.err, marginTop: 18, fontSize: 13 }}>
      {text}{' '}
      <a href="/" style={{ color: C.emerald, textDecoration: 'underline' }}>Go to SVRNTY</a>
    </p>
  );
}

const headingStyle: React.CSSProperties = {
  fontFamily: "'Cormorant Garamond', serif",
  fontSize: 26,
  fontWeight: 300,
  color: C.ink,
  letterSpacing: 1,
  margin: '0 0 8px',
};
const subStyle: React.CSSProperties = {
  fontFamily: "'Space Grotesk', sans-serif",
  fontSize: 14,
  color: C.faint,
  lineHeight: 1.6,
  maxWidth: 420,
  margin: '0 auto',
};
const cardBoxStyle: React.CSSProperties = {
  background: 'rgba(6, 10, 8, 0.8)',
  border: `1px solid ${C.emeraldDim}`,
  borderRadius: 8,
  padding: '12px 16px',
  margin: '16px auto 4px',
  maxWidth: 360,
};
const unlockInputStyle: React.CSSProperties = {
  display: 'block',
  width: '100%',
  maxWidth: 320,
  margin: '0 auto 4px',
  background: 'rgba(6, 10, 8, 0.8)',
  border: `1px solid ${C.emeraldDim}`,
  borderRadius: 8,
  padding: '11px 14px',
  color: C.ink,
  fontSize: 14,
  fontFamily: "'Space Grotesk', sans-serif",
  textAlign: 'center',
  outline: 'none',
};
const primaryBtnStyle: React.CSSProperties = {
  background: 'rgba(52, 211, 153, 0.12)',
  border: '1px solid rgba(52, 211, 153, 0.3)',
  borderRadius: 8,
  padding: '12px 22px',
  color: C.emerald,
  fontSize: 12,
  fontWeight: 500,
  letterSpacing: 2,
  textTransform: 'uppercase',
  fontFamily: "'Space Grotesk', sans-serif",
  cursor: 'pointer',
  marginTop: 20,
};
const linkBtnStyle: React.CSSProperties = {
  display: 'inline-block',
  background: 'rgba(180, 160, 100, 0.08)',
  border: '1px solid rgba(180, 160, 100, 0.15)',
  borderRadius: 8,
  padding: '12px 22px',
  color: C.faint,
  fontSize: 12,
  letterSpacing: 1,
  textTransform: 'uppercase',
  fontFamily: "'Space Grotesk', sans-serif",
  textDecoration: 'none',
  marginTop: 20,
};
