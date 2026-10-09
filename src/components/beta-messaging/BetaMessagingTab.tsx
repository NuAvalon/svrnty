'use client';

/**
 * Beta-messaging glass (CURSOR_QUEUE copy item).
 * Unlock/redeem renders ONLY when the beta gate is ON (issuer provisioned).
 * Calls fleet signMailboxClaimRequest + POST /api/relay/claim. Does not
 * reimplement token verify or the claim registry.
 */

import { useEffect, useState, type CSSProperties, type FormEvent } from 'react';
import { loadKey } from '@/lib/identity/client-store';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { BETA_COPY } from './beta-messaging-copy';
import { isBetaIssuerProvisioned } from './is-beta-gate-on';
import { readLocalBetaClaimed, writeLocalBetaClaimed } from './beta-claimed-local';
import { boundAccessKey } from './beta-messaging-text';
import {
  publicKeyFromIdentity,
  pqPubStringsFromIdentity,
  redeemBetaAccessKey,
} from './beta-redeem';

type Props = {
  identity: {
    identity?: { fingerprint?: string; name?: string; public_key?: string };
    post_quantum?: { kem_public_key?: string; sig_public_key?: string };
  } | null;
  /** Test override. Default = isBetaIssuerProvisioned(). */
  gateOn?: boolean;
};

const fieldStyle: CSSProperties = {
  width: '100%',
  fontFamily: E.fontMono,
  fontSize: 13,
  color: E.text,
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 10,
  padding: '10px 12px',
};

const primaryBtn: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 13,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: E.bg,
  background: E.accent,
  border: 'none',
  borderRadius: 999,
  padding: '10px 18px',
  cursor: 'pointer',
};

export function BetaMessagingTab({ identity, gateOn }: Props) {
  const on = gateOn ?? isBetaIssuerProvisioned();
  const fp = identity?.identity?.fingerprint || '';
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [claimed, setClaimed] = useState(() => (fp ? readLocalBetaClaimed(fp) : false));

  useEffect(() => {
    setClaimed(fp ? readLocalBetaClaimed(fp) : false);
  }, [fp]);

  if (!on) return null;

  const onRedeem = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const accessKey = boundAccessKey(token);
    if (!accessKey) {
      setError(BETA_COPY.redeemEmpty);
      return;
    }
    if (!fp) {
      setError(BETA_COPY.identityLocked);
      return;
    }
    const publicKeyArmored = publicKeyFromIdentity(identity);
    if (!publicKeyArmored) {
      setError(BETA_COPY.identityKeysMissing);
      return;
    }
    setBusy(true);
    try {
      const key = await loadKey(fp);
      if (!key?.privateKey) {
        setError(BETA_COPY.identityLocked);
        return;
      }
      const pq = pqPubStringsFromIdentity(identity);
      const result = await redeemBetaAccessKey({
        token: accessKey,
        fingerprint: fp,
        publicKeyArmored,
        privateKeyArmored: key.privateKey,
        passphrase: key.passphrase,
        kemPublicKey: pq.kemPublicKey,
        sigPublicKey: pq.sigPublicKey,
      });
      if (!result.ok) {
        setError(BETA_COPY.redeemFailed);
        return;
      }
      writeLocalBetaClaimed(fp);
      setClaimed(true);
      setToken('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      data-testid="beta-messaging-tab"
      style={{
        ...solarGlass,
        maxWidth: 640,
        margin: '0 auto',
        padding: 24,
        fontFamily: E.fontSans,
        color: E.text,
      }}
    >
      {claimed ? (
        <BetaExplainer />
      ) : (
        <form onSubmit={(e) => void onRedeem(e)} data-testid="beta-redeem-form">
          <h2
            style={{
              fontFamily: E.fontSans,
              fontSize: 22,
              letterSpacing: '0.02em',
              fontWeight: 600,
              color: E.accent,
              margin: '0 0 8px',
            }}
          >
            {BETA_COPY.unlockHeading}
          </h2>
          <p style={{ margin: '0 0 16px', fontSize: 14, color: E.muted, lineHeight: 1.5 }}>
            {BETA_COPY.unlockBody}
          </p>
          <label
            htmlFor="beta-access-key"
            style={{ display: 'block', fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.dim, marginBottom: 6 }}
          >
            {BETA_COPY.accessKeyLabel}
          </label>
          <input
            id="beta-access-key"
            data-testid="beta-access-key"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder={BETA_COPY.accessKeyPlaceholder}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            style={{ ...fieldStyle, marginBottom: 12 }}
          />
          <button
            type="submit"
            data-testid="beta-redeem-btn"
            disabled={busy}
            style={{ ...primaryBtn, opacity: busy ? 0.6 : 1, cursor: busy ? 'not-allowed' : 'pointer' }}
          >
            {busy ? BETA_COPY.redeemingAction : BETA_COPY.redeemAction}
          </button>
          <p style={{ margin: '12px 0 0', fontSize: 13, color: E.dim, lineHeight: 1.45 }}>
            {BETA_COPY.unlockMicrocopy}
          </p>
          {error && (
            <p data-testid="beta-redeem-error" style={{ margin: '12px 0 0', fontSize: 13, color: E.danger }}>
              {error}
            </p>
          )}
        </form>
      )}
    </section>
  );
}

function BetaExplainer() {
  return (
    <div data-testid="beta-messaging-explainer">
      <h2
        style={{
          fontFamily: E.fontSans,
          fontSize: 18,
          letterSpacing: '0.04em',
          color: E.accent,
          margin: '0 0 8px',
          textTransform: 'none',
        }}
      >
        {BETA_COPY.whatItIsHeading}
      </h2>
      <p style={{ margin: '0 0 16px', fontSize: 14, color: E.muted, lineHeight: 1.55 }}>
        {BETA_COPY.whatItIs}
      </p>
      <p style={{ margin: '0 0 10px', fontSize: 14, color: E.text, lineHeight: 1.55 }}>
        {BETA_COPY.sending}
      </p>
      <p style={{ margin: '0 0 16px', fontSize: 14, color: E.muted, lineHeight: 1.55 }}>
        {BETA_COPY.sendingWait}
      </p>
      <p style={{ margin: 0, fontSize: 14, color: E.text, lineHeight: 1.55 }}>
        {BETA_COPY.receiving}
      </p>
    </div>
  );
}
