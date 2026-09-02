'use client';

/**
 * CUR-1 — revise a contact method + pick shared-with recipients + Send update.
 * Solar Ember UI only. Wire broadcast is Flint's seam (see contact-method-send.ts).
 */

import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import type { MethodKind } from './SovereignIdentityCard';
import {
  methodKindLabel,
  sendContactMethodUpdate,
  type ContactMethodSendFn,
  type ContactMethodSendResult,
} from './contact-method-send';
import { appendMethodRevision } from './method-history';
import { solarEmber as E } from '../recovery/solar-ember';

export type AudienceContact = {
  fingerprint: string;
  name: string;
  /** Prefer contacts with a pubkey (encrypt targets when Flint wires send). */
  public_key?: string;
  trusted?: boolean;
  /** Owner-local group labels (never on the wire). */
  tags?: string[];
};

export type ContactMethodReviseDialogProps = {
  open: boolean;
  kind: MethodKind;
  initialValue?: string;
  contacts: AudienceContact[];
  /** Owner fingerprint — used to append CUR-2 local method-history drafts. */
  ownerFingerprint?: string;
  /** Pre-select these fingerprints (e.g. focused Trust Map peer). */
  preselectedFingerprints?: string[];
  onClose: () => void;
  /** Persist draft locally (email → identity; signal/site → local_methods bag). */
  onLocalSave: (kind: MethodKind, value: string) => void | Promise<void>;
  /** Fired after a local history row is appended (CUR-2 panel refresh). */
  onHistoryChange?: () => void;
  sendFn?: ContactMethodSendFn;
};

export function ContactMethodReviseDialog({
  open,
  kind,
  initialValue = '',
  contacts,
  ownerFingerprint,
  preselectedFingerprints,
  onClose,
  onLocalSave,
  onHistoryChange,
  sendFn = sendContactMethodUpdate,
}: ContactMethodReviseDialogProps) {
  const [value, setValue] = useState(initialValue);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<ContactMethodSendResult | null>(null);
  const [localNote, setLocalNote] = useState<string | null>(null);

  const sorted = useMemo(() => {
    return [...contacts]
      .map((c) => ({
        ...c,
        fingerprint: (c.fingerprint || '').trim(),
        name: c.name || 'Unnamed',
      }))
      .filter((c) => c.fingerprint.length > 0)
      .sort((a, b) => {
        const ta = a.trusted ? 0 : 1;
        const tb = b.trusted ? 0 : 1;
        if (ta !== tb) return ta - tb;
        return a.name.localeCompare(b.name);
      });
  }, [contacts]);

  useEffect(() => {
    if (!open) return;
    setValue(initialValue);
    setStatus(null);
    setLocalNote(null);
    const preset = new Set<string>();
    const seed = (preselectedFingerprints ?? []).filter((fp) => typeof fp === 'string' && fp.trim());
    if (seed.length > 0) {
      for (const fp of seed) preset.add(fp.trim());
    } else {
      // Default: trusted peers with a public key (honest encrypt targets later).
      for (const c of contacts) {
        const fp = (c.fingerprint || '').trim();
        if (fp && c.trusted && c.public_key) preset.add(fp);
      }
    }
    setSelected(preset);
  }, [open, initialValue, preselectedFingerprints, contacts]);

  const toggle = (fp: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(fp)) next.delete(fp);
      else next.add(fp);
      return next;
    });
  };

  const selectTrusted = () => {
    const next = new Set<string>();
    for (const c of contacts) {
      if (c.trusted) next.add(c.fingerprint);
    }
    setSelected(next);
  };

  const clearAll = () => setSelected(new Set());

  const knownGroups = useMemo(() => {
    const set = new Set<string>();
    for (const c of contacts) {
      for (const t of c.tags || []) {
        const v = t.trim();
        if (v) set.add(v);
      }
    }
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [contacts]);

  const selectGroup = (tag: string) => {
    const next = new Set<string>();
    for (const c of contacts) {
      if ((c.tags || []).includes(tag)) next.add(c.fingerprint);
    }
    setSelected(next);
  };

  const recordHistory = (recipients: string[]) => {
    if (!ownerFingerprint) return;
    const next = value.trim();
    const prev = (initialValue || '').trim();
    if (!next || next === prev) return;
    appendMethodRevision(ownerFingerprint, {
      kind: kind as 'email' | 'signal' | 'site',
      value: next,
      previousValue: prev || undefined,
      recipientFingerprints: recipients,
      note: recipients.length ? 'Queued notify (send stub)' : 'Saved locally',
    });
    onHistoryChange?.();
  };

  const handleSaveLocal = async () => {
    setBusy(true);
    setLocalNote(null);
    try {
      await onLocalSave(kind, value.trim());
      recordHistory([]);
      // Persist succeeded — close so the card is the confirmation (a quiet
      // inline note with the dialog still open reads as "didn't save").
      setBusy(false);
      onClose();
    } catch (e) {
      setLocalNote(e instanceof Error ? e.message : 'Could not save locally.');
      setBusy(false);
    }
  };

  const handleSend = async () => {
    setBusy(true);
    setStatus(null);
    try {
      // Always persist draft first so the card reflects the revise.
      await onLocalSave(kind, value.trim());
      const recipients = [...selected];
      recordHistory(recipients);
      const result = await sendFn({
        kind,
        value: value.trim(),
        recipientFingerprints: recipients,
      });
      if (result.ok) {
        setBusy(false);
        onClose();
        return;
      }
      setStatus(result);
      setBusy(false);
    } catch (e) {
      setStatus({
        ok: false,
        reason: 'error',
        message: e instanceof Error ? e.message : 'Send failed.',
      });
      setBusy(false);
    }
  };

  const label = methodKindLabel(kind);
  const wireNote =
    kind === 'email'
      ? 'Maps to wire field emails when Flint wires send.'
      : kind === 'signal'
        ? 'Signal is local-only for now — not in contact.update allowlist yet (fleet grow).'
        : 'Site/URL is local-only for now — not in contact.update allowlist yet (fleet grow).';

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        // Controlled: only close when Radix requests it — never unmount on open.
        if (!next) onClose();
      }}
    >
      <DialogContent
        className="max-w-md border-[var(--se-border)] bg-[var(--se-surface-solid)] text-[var(--se-text)] sm:rounded-2xl"
        style={{ fontFamily: E.fontSans }}
      >
        <DialogHeader>
          <DialogTitle style={{ color: E.text, fontFamily: E.fontSans }}>
            Revise {label}
          </DialogTitle>
          <DialogDescription style={{ color: E.muted, fontSize: 13, lineHeight: 1.5 }}>
            Update your living contact method, then choose who to notify. This is your send list for
            this update — not a claim about who already holds your card.
          </DialogDescription>
        </DialogHeader>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span
              style={{
                fontSize: 10,
                letterSpacing: '0.14em',
                textTransform: 'uppercase',
                color: E.dim,
              }}
            >
              {label}
            </span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={
                kind === 'email'
                  ? 'you@example.com'
                  : kind === 'signal'
                    ? '+1… or Signal username'
                    : 'https://…'
              }
              spellCheck={false}
              style={{
                background: E.inputBg,
                border: `1px solid ${E.border}`,
                borderRadius: 10,
                padding: '10px 12px',
                color: E.text,
                fontFamily: kind === 'site' || kind === 'signal' ? E.fontMono : E.fontSans,
                fontSize: 14,
                outline: 'none',
              }}
            />
            <span style={{ fontSize: 11, color: E.dim, lineHeight: 1.4 }}>{wireNote}</span>
          </label>

          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 8,
                marginBottom: 8,
              }}
            >
              <span
                style={{
                  fontSize: 10,
                  letterSpacing: '0.14em',
                  textTransform: 'uppercase',
                  color: E.dim,
                }}
              >
                Shared with · notify
              </span>
              <span style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={selectTrusted}
                  style={ghostBtn}
                >
                  Trusted
                </button>
                <button type="button" onClick={clearAll} style={ghostBtn}>
                  Clear
                </button>
              </span>
            </div>

            {knownGroups.length > 0 ? (
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 6,
                  marginBottom: 8,
                  alignItems: 'center',
                }}
              >
                <span style={{ fontSize: 10, color: E.dim, fontFamily: E.fontSans }}>Groups:</span>
                {knownGroups.map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    onClick={() => selectGroup(tag)}
                    title={`Notify everyone tagged “${tag}” (local group)`}
                    style={{
                      ...ghostBtn,
                      padding: '3px 8px',
                      fontSize: 11,
                      color: E.muted,
                    }}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            ) : null}

            <div
              style={{
                maxHeight: 200,
                overflowY: 'auto',
                borderRadius: 12,
                border: `1px solid ${E.border}`,
                background: E.inputBg,
              }}
            >
              {sorted.length === 0 ? (
                <p style={{ margin: 0, padding: 14, fontSize: 12, color: E.muted }}>
                  No contacts yet. Share your card first — then you can notify people who hold it.
                </p>
              ) : (
                sorted.map((c) => {
                  const checked = selected.has(c.fingerprint);
                  return (
                    <label
                      key={c.fingerprint}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '10px 12px',
                        borderBottom: `1px solid ${E.border}`,
                        cursor: 'pointer',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggle(c.fingerprint)}
                        style={{ accentColor: 'var(--se-accent)' }}
                      />
                      <span style={{ flex: 1, minWidth: 0 }}>
                        <span
                          style={{
                            display: 'block',
                            fontSize: 13,
                            color: E.text,
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {c.name || 'Unnamed'}
                          {c.trusted ? (
                            <span style={{ color: E.accent, marginLeft: 6, fontSize: 10 }}>
                              trusted
                            </span>
                          ) : null}
                        </span>
                        <span
                          style={{
                            display: 'block',
                            fontSize: 10,
                            color: E.dim,
                            fontFamily: E.fontMono,
                          }}
                        >
                          {c.fingerprint.slice(0, 12)}…
                          {!c.public_key ? ' · no pubkey yet' : ''}
                        </span>
                      </span>
                    </label>
                  );
                })
              )}
            </div>
            <p style={{ margin: '8px 0 0', fontSize: 11, color: E.dim }}>
              {selected.size} selected
            </p>
          </div>

          {(status || localNote) && (
            <p
              style={{
                margin: 0,
                fontSize: 12,
                lineHeight: 1.5,
                color: status && !status.ok ? E.danger : E.muted,
              }}
            >
              {status ? status.message : localNote}
            </p>
          )}
        </div>

        <DialogFooter className="gap-2 sm:gap-2">
          <button type="button" onClick={onClose} disabled={busy} style={ghostBtnWide}>
            Close
          </button>
          <button
            type="button"
            onClick={() => void handleSend()}
            disabled={busy || selected.size === 0 || !value.trim()}
            title={
              selected.size === 0
                ? 'Pick someone to notify, or Save locally'
                : 'Wire send is stubbed — Flint owns encrypt+deposit'
            }
            style={{
              ...ghostBtnWide,
              opacity: busy || selected.size === 0 || !value.trim() ? 0.45 : 1,
            }}
          >
            {busy ? '…' : 'Send update'}
          </button>
          <button
            type="button"
            onClick={() => void handleSaveLocal()}
            disabled={busy || !value.trim()}
            style={{
              ...primaryBtn,
              opacity: busy || !value.trim() ? 0.6 : 1,
            }}
          >
            {busy ? '…' : 'Save locally'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const ghostBtn: CSSProperties = {
  background: 'transparent',
  border: `1px solid ${E.border}`,
  color: E.muted,
  borderRadius: 8,
  padding: '4px 8px',
  fontSize: 11,
  cursor: 'pointer',
  fontFamily: E.fontSans,
};

const ghostBtnWide: CSSProperties = {
  ...ghostBtn,
  padding: '8px 12px',
  fontSize: 12,
};

const primaryBtn: CSSProperties = {
  background: 'color-mix(in srgb, var(--se-accent) 18%, transparent)',
  border: `1px solid ${E.borderLit}`,
  color: E.accent,
  borderRadius: 8,
  padding: '8px 14px',
  fontSize: 12,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontWeight: 600,
};
