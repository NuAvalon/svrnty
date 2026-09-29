'use client';

/**
 * Encrypt / Decrypt — no-wire contact messaging glass.
 * Calls fleet encryptToContact / decryptFromContact. Does not send, does not touch the relay.
 */

import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { getAllContacts } from '@/lib/identity/client-store';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { decryptMessageFromContact, encryptMessageToContact } from './encrypt-decrypt-actions';
import { findSenderCard, toEncryptableContacts, type EncryptableContact } from './encrypt-decrypt-contacts';
import { ENCDEC_BOUNDS, ENCDEC_COPY } from './encrypt-decrypt-copy';
import { boundDisplayText, formatFingerprintGroups, formatFingerprintShort } from './encrypt-decrypt-text';
import { loadOwnerMessageKeys } from './load-owner-message-keys';

type Mode = 'encrypt' | 'decrypt';

type Props = {
  identity: { identity?: { fingerprint?: string; name?: string } } | null;
};

const fieldStyle: CSSProperties = {
  width: '100%',
  fontFamily: E.fontSans,
  fontSize: 14,
  color: E.text,
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 10,
  padding: '10px 12px',
};

const areaStyle: CSSProperties = {
  ...fieldStyle,
  fontFamily: E.fontMono,
  fontSize: 12,
  minHeight: 140,
  resize: 'vertical',
  lineHeight: 1.5,
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

const ghostBtn: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 13,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: E.accent,
  background: 'transparent',
  border: `1px solid ${E.borderLit}`,
  borderRadius: 999,
  padding: '10px 18px',
  cursor: 'pointer',
};

export function EncryptDecryptTab({ identity }: Props) {
  const fp = identity?.identity?.fingerprint || '';
  const [mode, setMode] = useState<Mode>('encrypt');
  const [rows, setRows] = useState<EncryptableContact[]>([]);
  const [selectedFp, setSelectedFp] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [opened, setOpened] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [verifiedLine, setVerifiedLine] = useState<string | null>(null);
  const [unverified, setUnverified] = useState(false);

  const loadBook = useCallback(async () => {
    if (!fp) return;
    try {
      const records = await getAllContacts(fp);
      setRows(toEncryptableContacts(records));
    } catch {
      setRows([]);
    }
  }, [fp]);

  useEffect(() => {
    void loadBook();
  }, [loadBook]);

  useEffect(() => {
    return subscribeContactChanges(() => {
      void loadBook();
    });
  }, [loadBook]);

  const selected = useMemo(
    () => rows.find((c) => c.fingerprint === selectedFp) ?? null,
    [rows, selectedFp],
  );

  const resetOutput = () => {
    setStatus(null);
    setError(null);
    setCopied(false);
    setVerifiedLine(null);
    setUnverified(false);
  };

  const onEncrypt = async () => {
    resetOutput();
    const message = plaintext.slice(0, ENCDEC_BOUNDS.plaintext);
    if (!message.trim()) {
      setError(ENCDEC_COPY.emptyPlaintext);
      return;
    }
    if (!selected) {
      setError(rows.length === 0 ? ENCDEC_COPY.noEncryptableContacts : ENCDEC_COPY.noContactSelected);
      return;
    }
    setBusy(true);
    try {
      const keys = await loadOwnerMessageKeys(fp, identity);
      if (!keys) {
        setError(ENCDEC_COPY.identityKeysMissing);
        return;
      }
      const out = await encryptMessageToContact(message, selected.keys, keys.sender);
      if (!out.ok) {
        setError(out.error);
        return;
      }
      setCiphertext(out.armored);
      setStatus(ENCDEC_COPY.notSent(selected.name));
    } catch {
      setError(ENCDEC_COPY.encryptFailed);
    } finally {
      setBusy(false);
    }
  };

  const onDecrypt = async () => {
    resetOutput();
    setOpened('');
    const armored = ciphertext.slice(0, ENCDEC_BOUNDS.ciphertext);
    if (!armored.trim()) {
      setError(ENCDEC_COPY.emptyCiphertext);
      return;
    }
    setBusy(true);
    try {
      const keys = await loadOwnerMessageKeys(fp, identity);
      if (!keys) {
        setError(ENCDEC_COPY.identityKeysMissing);
        return;
      }
      const first = await decryptMessageFromContact(armored, keys.me);
      if (!first.ok) {
        setError(first.error);
        return;
      }
      const match = findSenderCard(rows, first.result.senderFingerprint);
      let openedMsg = first.result;
      let senderVerified = first.result.senderVerified;
      if (match) {
        const again = await decryptMessageFromContact(armored, keys.me, match.keys);
        if (again.ok) {
          openedMsg = again.result;
          senderVerified = again.result.senderVerified;
        }
      }
      setOpened(boundDisplayText(openedMsg.message, ENCDEC_BOUNDS.plaintext));
      if (senderVerified && match) {
        setVerifiedLine(
          ENCDEC_COPY.verifiedFrom(match.name, formatFingerprintGroups(match.fingerprint)),
        );
        setUnverified(false);
      } else {
        setVerifiedLine(null);
        setUnverified(true);
      }
    } catch {
      setError(ENCDEC_COPY.decryptFailed);
    } finally {
      setBusy(false);
    }
  };

  const onCopy = async () => {
    if (!ciphertext.trim()) return;
    try {
      await navigator.clipboard.writeText(ciphertext);
      setCopied(true);
    } catch {
      setCopied(false);
      setError(ENCDEC_COPY.copyHint);
    }
  };

  return (
    <section
      data-testid="encrypt-decrypt-tab"
      style={{
        ...solarGlass,
        maxWidth: 640,
        margin: '0 auto',
        padding: 24,
        fontFamily: E.fontSans,
        color: E.text,
      }}
    >
      <h2
        style={{
          fontFamily: E.fontSans,
          fontSize: 18,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: E.accent,
          margin: '0 0 8px',
        }}
      >
        {ENCDEC_COPY.tabLabel}
      </h2>
      <p style={{ margin: '0 0 20px', fontSize: 14, color: E.muted, lineHeight: 1.5 }}>
        {ENCDEC_COPY.intro}
      </p>

      <div
        role="group"
        aria-label="Encrypt or decrypt"
        style={{
          display: 'flex',
          gap: 8,
          marginBottom: 20,
          padding: 4,
          borderRadius: 12,
          border: `1px solid ${E.border}`,
          background: 'rgba(30,20,10,.55)',
        }}
      >
        {(['encrypt', 'decrypt'] as const).map((m) => {
          const active = mode === m;
          return (
            <button
              key={m}
              type="button"
              aria-pressed={active}
              data-testid={m === 'encrypt' ? 'encdec-mode-encrypt' : 'encdec-mode-decrypt'}
              onClick={() => {
                setMode(m);
                resetOutput();
                if (m === 'encrypt') {
                  setOpened('');
                  setUnverified(false);
                  setVerifiedLine(null);
                }
              }}
              style={{
                flex: 1,
                border: 'none',
                borderRadius: 8,
                padding: '10px 12px',
                cursor: 'pointer',
                fontFamily: E.fontSans,
                fontSize: 13,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: active ? E.text : E.muted,
                background: active ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
              }}
            >
              {m === 'encrypt' ? ENCDEC_COPY.modeEncrypt : ENCDEC_COPY.modeDecrypt}
            </button>
          );
        })}
      </div>

      {mode === 'encrypt' ? (
        <label style={{ display: 'block', marginBottom: 16, fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.muted }}>
          {ENCDEC_COPY.pickerLabelEncrypt}
          <select
            data-testid="encdec-contact-picker"
            value={selectedFp}
            onChange={(e) => {
              setSelectedFp(e.target.value);
              resetOutput();
            }}
            disabled={rows.length === 0}
            style={{ ...fieldStyle, marginTop: 8, color: E.text }}
          >
            <option value="">{rows.length === 0 ? ENCDEC_COPY.noEncryptableContacts : ENCDEC_COPY.pickerPlaceholder}</option>
            {rows.map((c) => (
              <option key={c.fingerprint} value={c.fingerprint}>
                {c.name} · {formatFingerprintShort(c.fingerprint)}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      {mode === 'encrypt' && rows.length === 0 ? (
        <p data-testid="encdec-empty-book" style={{ color: E.danger, fontSize: 13, margin: '0 0 16px' }}>
          {ENCDEC_COPY.noEncryptableContacts}
        </p>
      ) : null}

      {mode === 'encrypt' ? (
        <label style={{ display: 'block', marginBottom: 16, fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.muted }}>
          {ENCDEC_COPY.plaintextLabel}
          <textarea
            data-testid="encdec-plaintext"
            value={plaintext}
            maxLength={ENCDEC_BOUNDS.plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            style={{ ...areaStyle, marginTop: 8, fontFamily: E.fontSans }}
          />
        </label>
      ) : (
        <label style={{ display: 'block', marginBottom: 16, fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.muted }}>
          {ENCDEC_COPY.ciphertextLabel}
          <textarea
            data-testid="encdec-ciphertext-in"
            value={ciphertext}
            maxLength={ENCDEC_BOUNDS.ciphertext}
            onChange={(e) => {
              setCiphertext(e.target.value);
              resetOutput();
              setOpened('');
            }}
            placeholder="-----BEGIN SVRNTY ENCRYPTED MESSAGE-----"
            style={{ ...areaStyle, marginTop: 8 }}
          />
        </label>
      )}

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 16 }}>
        {mode === 'encrypt' ? (
          <button
            type="button"
            data-testid="encdec-encrypt-btn"
            onClick={() => void onEncrypt()}
            disabled={busy}
            style={{ ...primaryBtn, opacity: busy ? 0.6 : 1 }}
          >
            {ENCDEC_COPY.encryptAction}
          </button>
        ) : (
          <button
            type="button"
            data-testid="encdec-decrypt-btn"
            onClick={() => void onDecrypt()}
            disabled={busy}
            style={{ ...primaryBtn, opacity: busy ? 0.6 : 1 }}
          >
            {ENCDEC_COPY.decryptAction}
          </button>
        )}
      </div>

      {error ? (
        <p data-testid="encdec-error" role="alert" style={{ color: E.danger, fontSize: 13, margin: '0 0 12px' }}>
          {error}
        </p>
      ) : null}

      {status ? (
        <p data-testid="encdec-not-sent" style={{ color: E.ok, fontSize: 13, margin: '0 0 12px' }}>
          {status}
        </p>
      ) : null}

      {mode === 'encrypt' && ciphertext ? (
        <div style={{ marginTop: 8 }}>
          <label style={{ display: 'block', fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.muted }}>
            {ENCDEC_COPY.ciphertextLabel}
            <textarea
              data-testid="encdec-ciphertext-out"
              readOnly
              value={ciphertext}
              style={{ ...areaStyle, marginTop: 8 }}
            />
          </label>
          <button
            type="button"
            data-testid="encdec-copy-ciphertext"
            onClick={() => void onCopy()}
            style={{ ...ghostBtn, marginTop: 10 }}
          >
            {copied ? ENCDEC_COPY.copied : ENCDEC_COPY.copyCiphertext}
          </button>
        </div>
      ) : null}

      {mode === 'decrypt' && opened ? (
        <div style={{ marginTop: 8 }}>
          {verifiedLine ? (
            <p data-testid="encdec-verified" style={{ color: E.ok, fontSize: 13, margin: '0 0 12px' }}>
              {verifiedLine}
            </p>
          ) : null}
          {unverified ? (
            <p data-testid="encdec-unverified" style={{ color: E.danger, fontSize: 13, margin: '0 0 12px' }}>
              {ENCDEC_COPY.senderNotVerified}
            </p>
          ) : null}
          <label style={{ display: 'block', fontSize: 12, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.muted }}>
            {ENCDEC_COPY.plaintextLabel}
            <textarea
              data-testid="encdec-plaintext-out"
              readOnly
              value={opened}
              style={{ ...areaStyle, marginTop: 8, fontFamily: E.fontSans }}
            />
          </label>
        </div>
      ) : null}
    </section>
  );
}
