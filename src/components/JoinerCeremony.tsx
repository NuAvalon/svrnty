// src/components/JoinerCeremony.tsx
'use client';
//
// The joiner's side of a Grow connection — COLLAPSED (2026-10-10, Peter #170061).
//
// Peter's directive: "the Grow link needs to tell you to open your .svrnty vault; when
// scanned from in your vault, it adds the person to the galaxy or the gate. Simple."
// Flint's security refinement (#170073): a scanned Grow link is an INBOUND request —
// it must land in the GATE (pending), never auto-elevate into the Galaxy. Promotion to a
// Known star stays a deliberate owner tap in GrowGatePanel. The signed-card verify
// (classifyImportedCard, fingerprint↔key binding) is PRESERVED — a Grow link must not be
// spoofable into adding someone else.
//
// So the old 5-step ceremony rail (handshake → card → edge → lattice → tear) collapses to:
//   1. No identity  → "Open your SVRNTY vault first" (Peter's literal ask).
//   2. Locked        → unlock inline (owner act — your OWN vault, key never leaves the device).
//   3. Card verified → ONE tap "Add to my Gate" → enqueueGateArrival + the R1 return-channel.
//   4. Done          → "They're at your Gate. Admit them to your Galaxy when you're ready."
//
// PRESERVED exactly (admission logic unchanged — UX orchestration only):
//   • classifyImportedCard refuse-branch (fp↔key mismatch / malformed → never imported).
//   • enqueueGateArrival (scan → GATE, pending; promotion is the explicit GrowGatePanel admit).
//   • depositJoinerResponse — the R1 return-channel so the edge becomes MUTUAL (best-effort,
//     fail-soft; a locked identity or relay hiccup never blocks and never surfaces to a peer).
//   • SHARD ("the tear") landing on this device keeps its focused accept panel.
//
// Nothing here touches prod; all state is local (IndexedDB) or the client-side relay. The
// shared ceremony state machine (src/lib/ceremony/machine.ts) is unchanged and still drives the
// INITIATOR (Ceremony.tsx) — this component no longer needs the stepper.

import { useCallback, useEffect, useRef, useState } from 'react';
import { resolveRelay } from '@/lib/sync/relay';
import {
  getActiveFingerprint,
  loadIdentity,
  loadKey,
  updateContact,
  getContactByFingerprint,
  storeHeldShard,
  SHARD_CUSTODY_TYPE,
  isSessionUnlocked,
  initSessionKey,
  lockSession,
  enqueueGateArrival,
} from '@/lib/identity/client-store';
import { sendJoinerResponse } from '@/lib/sync/send-joiner-response';
import { emitContactChange } from '@/lib/contacts/contact-events';
import { classifyImportedCard } from '@/lib/identity/identity-card-sign';
import type { DeviceMailboxPublic } from '@/lib/identity/device-mailbox';
import { isPQEncapLive } from '@/lib/claim-gates';
import { clampArrivalName } from '@/lib/trust/grow-gate';

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

interface PeerCard {
  name: string;
  fingerprint: string;
  publicKey: string;
  email: string;
  // Authenticated pq (branch 4b) or null; alarm drives the import banner (branch-3 loud / 4c soft-info).
  pq: { pq_kem_public_key: string; pq_sig_public_key: string } | null;
  // piece-2: authenticated device-mailbox (onion seal-target), non-null ONLY under a valid signature
  // (classifyImportedCard branch 4). Threaded into the direct persist paths exactly like pq.
  deviceMailbox: DeviceMailboxPublic | null;
  alarm: 'quiet' | 'loud' | 'soft-info';
}

type Phase = 'loading' | 'card' | 'done';

// R1 return-channel deposit. After the joiner adds the giver, deposit a signed
// joiner-response to the GIVER's mailbox so the giver learns of us and the edge becomes MUTUAL — closing
// the one-directional Grow asymmetry (giver polls → verifyJoinerResponse → gates us → the 0.4
// contact.update wire now flows both ways). Best-effort + FAIL-SOFT: signing requires our unlocked
// private key; if the identity is locked or the deposit fails, the local gate entry still stands and the
// flow never blocks — any failure is a local-only diagnostic, NEVER surfaced to a peer/relay (I-1).
// The giver's mailbox holds the response for ~7d, so a deposit that lands on a later unlocked open still
// connects. IDENTITY-ONLY: carries our {fp, epoch, key, name}, never contact methods.
async function depositJoinerResponse(ownerFp: string, peer: PeerCard, code: string): Promise<void> {
  try {
    if (!peer.fingerprint || !peer.publicKey || !code) return; // nothing to bind the response to
    const key = await loadKey(ownerFp);
    if (!key) {
      // Locked session — cannot sign. The gate entry is already stored; the return channel simply doesn't
      // fire this time (a later unlocked open can re-deposit within the giver's ~7d mailbox window).
      console.warn('[joiner-response] identity locked — return-channel deposit deferred (gate entry stands locally)');
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
      console.warn('[joiner-response] deposit not delivered (gate entry stands locally):', res.status);
    }
  } catch (err) {
    console.warn('[joiner-response] deposit failed (gate entry stands locally):', err);
  }
}

export function JoinerCeremony({ code, keyFragment }: { code: string; keyFragment: string }) {
  const [phase, setPhase] = useState<Phase>('loading');
  const [kind, setKind] = useState<'card' | 'shard' | null>(null);
  const [peer, setPeer] = useState<PeerCard | null>(null);
  const [ownerFp, setOwnerFp] = useState<string | null>(null);
  const [noIdentity, setNoIdentity] = useState(false);
  const [alreadyKnown, setAlreadyKnown] = useState(false);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Unlock gate: the joiner arrives at /c/ with a LOCKED session (the memory-only session key does not
  // survive the navigation). Adding to the gate + signing the mutual return-channel needs the private key,
  // so we prompt for the passphrase on the "Add" tap. In the in-app scan path the vault is already unlocked,
  // so this never shows — one tap.
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
          // Peter's "the Grow link needs to tell you to open your .svrnty vault." No active identity =
          // nothing to add them to. A dedicated screen, not a scary error.
          setNoIdentity(true);
          return;
        }
        setOwnerFp(fp);

        const decrypted = await resolveRelay(code, keyFragment);
        if (cancelled) return;

        const parsed = JSON.parse(decrypted);
        if (parsed?.type === SHARD_CUSTODY_TYPE) {
          setKind('shard');
          setShardFrom(parsed?.from?.name || 'Someone');
          setPeer(null);
          (window as any).__svrnty_shard = parsed;
          return;
        }

        const p = parsed.identity || parsed;
        // C2 / Invariant-1 + signature: classify the card BEFORE showing the reassuring fingerprint box or
        // persisting anything. Branch 1 (fp↔key fail / malformed) refuses the card — otherwise the
        // out-of-band "is this your fingerprint?" ritual would falsely pass while the stored key is an
        // attacker's. Branches 2/3/4 import the classical contact; the pq sub-disposition decides whether
        // the authenticated pq_kem/pq_sig is stored (spec §4). THIS IS THE ANTI-SPOOF GATE — unchanged.
        const d = await classifyImportedCard(parsed);
        if (cancelled) return;
        if (!d.importClassical) {
          setError(
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
          deviceMailbox: d.deviceMailbox,
          alarm: d.alarm === 'reject' ? 'quiet' : d.alarm,
        });
        setPhase('card');
      } catch (err: any) {
        if (cancelled) return;
        setError(err?.message || 'This link has expired or already been used.');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [code, keyFragment]);

  // --- The single action: add the giver to MY Gate (pending) + fire the mutual return-channel. ---
  // Scan → GATE, never auto-Galaxy (Flint #170073). Promotion to a Known star is the explicit
  // GrowGatePanel admit tap — scanning is not trusting.
  const addToGate = useCallback(async () => {
    if (!peer || !ownerFp || adding) return;
    // Adding to the gate + signing the mutual return-channel needs the private key, and the session key is
    // memory-only (does NOT survive the /c/ navigation). Prompt for the passphrase here — unlocking both
    // enables the gate write AND signs the return deposit. If already unlocked (in-app scan), proceed.
    if (!isSessionUnlocked()) {
      setNeedsUnlock(true);
      return;
    }
    setAdding(true);
    setError(null);
    try {
      // Idempotent: if we already know them (or they already wait at our gate under the same fp),
      // enqueueGateArrival upserts — don't double-report. Back-fill authenticated pq / device-mailbox onto a
      // known edge that lacks them (§7#5 upgrade-on-re-exchange), never silently replacing a different key.
      const existing = peer.fingerprint
        ? await getContactByFingerprint(ownerFp, peer.fingerprint)
        : null;
      if (existing) {
        if ((peer.pq && !existing.pq_kem_public_key) || (peer.deviceMailbox && !existing.device_mailbox)) {
          await updateContact(existing.id, {
            ...(peer.pq
              ? { pq_kem_public_key: peer.pq.pq_kem_public_key, pq_sig_public_key: peer.pq.pq_sig_public_key }
              : {}),
            ...(peer.deviceMailbox ? { device_mailbox: peer.deviceMailbox } : {}),
          });
        }
        setAlreadyKnown(true);
      } else {
        // NOTE (piece-2 coverage boundary, unchanged): the device-mailbox is NOT threaded through the
        // holding-room gate pipeline (GateArrival → admit) yet — a gated joiner lands WITHOUT a mailbox
        // until a re-exchange back-fills it (safe: emit under-reveals, fail-closed). Threading the gate
        // pipeline is a tracked fast-follow (co-owned with Apollo's emit UI work).
        await enqueueGateArrival(ownerFp, {
          fingerprint: peer.fingerprint,
          displayName: clampArrivalName(peer.name),
          publicKeyArmored: peer.publicKey,
          epoch: 0,
          inviteNonce: code,
          mintChannel: 'remote', // scan provenance is never "verified" — the owner's later tap is (grow-gate).
          arrivedAt: new Date().toISOString(),
          direction: 'scanned_giver',
          ...(peer.pq
            ? { pqKemPublicKey: peer.pq.pq_kem_public_key, pqSigPublicKey: peer.pq.pq_sig_public_key }
            : {}),
        });
        emitContactChange({ ids: [], reason: 'ui-edit' });
      }
      // R1: fire the return-channel deposit to the giver (best-effort, non-blocking) so the connection
      // becomes MUTUAL. Done advances regardless of whether the deposit lands (fail-soft).
      void depositJoinerResponse(ownerFp, peer, code);
      setPhase('done');
    } catch (err: any) {
      setError(err?.message || 'Could not add them to your Gate.');
    } finally {
      setAdding(false);
    }
  }, [peer, ownerFp, code, adding]);

  // Unlock the identity to sign the mutual connection, then add to the gate + deposit. initSessionKey
  // derives the key WITHOUT validating, so a wrong passphrase yields a key that can't decrypt — verify by a
  // loadKey (which throws on a bad passphrase) and lock again on failure so isSessionUnlocked stays honest.
  const submitUnlock = useCallback(async () => {
    if (!ownerFp || !unlockPass || unlockBusy) return;
    setUnlockBusy(true);
    setUnlockError(null);
    try {
      await initSessionKey(unlockPass);
      await loadKey(ownerFp); // throws on a wrong passphrase (can't decrypt the stored key)
      setNeedsUnlock(false);
      setUnlockPass('');
      await addToGate(); // now unlocked → adds to the gate + signs & deposits the joiner-response + advances
    } catch {
      lockSession(); // clear the bad session key so the gate stays honest
      setUnlockError('That passphrase didn’t unlock your identity. Please try again.');
    } finally {
      setUnlockBusy(false);
    }
  }, [ownerFp, unlockPass, unlockBusy, addToGate]);

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

  // ============================ NO IDENTITY — open your vault first ============================
  if (noIdentity) {
    return (
      <Shell>
        <Badge tone="gold" label="A card is waiting for you" />
        <h2 style={headingStyle}>Open your SVRNTY vault</h2>
        <p style={subStyle}>
          Someone shared their card with you. To add them, open your own SVRNTY vault first — set up or
          unlock your identity, then open this link again.
        </p>
        <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
      </Shell>
    );
  }

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
        {error && <ErrorLine text={error} />}
      </Shell>
    );
  }

  // ================================ CARD LINK — one screen ================================
  return (
    <Shell>
      {/* loading — arriving / retrieving. "Opening the secure channel" + Code render are relied on by the
          grow-2tab / scan-to-join specs and prove the key never leaves the fragment. */}
      {phase === 'loading' && !error && (
        <div>
          <Spinner />
          <h2 style={headingStyle}>Opening the secure channel…</h2>
          <p style={subStyle}>Retrieving and decrypting their card. Code: {code}</p>
        </div>
      )}

      {/* card — their verified card reached your device; one tap to add them to your Gate. */}
      {phase === 'card' && peer && (
        <div>
          <h2 style={headingStyle}>{peer.name} wants to connect</h2>
          <p style={subStyle}>
            They shared their signed card with you — decrypted on your device, no server could read it.
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

          {!needsUnlock ? (
            <>
              <p style={{ ...subStyle, marginTop: 16, fontSize: 13 }}>
                Add them to your Gate. Scanning isn’t trusting — you choose when to welcome them into your
                Galaxy.
              </p>
              <button
                style={{ ...primaryBtnStyle, opacity: adding ? 0.6 : 1 }}
                disabled={adding}
                data-testid="join-add-to-gate"
                onClick={() => void addToGate()}
              >
                {adding ? 'Adding…' : 'Add to my Gate →'}
              </button>
            </>
          ) : (
            <div style={{ marginTop: 18 }}>
              {/* Anti-phishing: the secret is demanded BY and FOR the user's OWN vault (owner act) — never
                  framed as the price of connecting with the giver. {peer.name} is the object, not the asker. */}
              <p style={{ ...subStyle, marginBottom: 12 }}>
                Unlock your SVRNTY to add {peer.name}. This is your own vault — your key never leaves this
                device.
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

      {/* done — they're at the Gate (or already known); Galaxy promotion stays a deliberate tap. */}
      {phase === 'done' && (
        <div>
          <div style={{ fontSize: 40, marginBottom: 8 }}>🜂</div>
          {alreadyKnown ? (
            <>
              <h2 style={headingStyle}>You’re already connected</h2>
              <p style={subStyle}>{peer?.name || 'They'} are already in your network.</p>
            </>
          ) : (
            <>
              <h2 style={headingStyle}>{peer?.name || 'They'} are at your Gate</h2>
              <p style={subStyle}>
                Welcome them into your Galaxy whenever you’re ready — open Galaxy and tap the Gate to admit
                them as Known. Verify stays your own later tap.
              </p>
            </>
          )}
          <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
        </div>
      )}

      {error && <ErrorLine text={error} />}
    </Shell>
  );
}

// ------------------------------- small presentational helpers -------------------------------

function Shell({ children }: { children: React.ReactNode }) {
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
      <div style={{ width: '100%', maxWidth: 440 }}>
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 6, color: C.gold }}>SVRNTY</div>
          <div style={{ fontSize: 11, color: C.faint, letterSpacing: 1 }}>Secure Identity Exchange</div>
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
          {children}
        </div>
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
