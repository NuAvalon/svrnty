'use client';

/**
 * CUR-8 — L6 tag-management UI (create / rename / remove / assign).
 * Solar Ember glass only. Tags are private owner labels on this device —
 * never shared with contacts or the relay (Apollo strip-on-wire).
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
import { solarEmber as E, solarGlass } from '../recovery/solar-ember';
import {
  assignTag,
  collectTagCatalog,
  normalizeTagLabel,
  readContactTags,
  removeTag,
  renameTag,
  tagPersistPatch,
  TAG_MAX_LEN,
  type TagReadable,
} from './local-tags';

export type TagContact = TagReadable & {
  id: string;
  name: string;
  fingerprint?: string;
};

export type TagPersistFn = (
  contactId: string,
  patch: { tags: string[]; metadata: Record<string, unknown> }
) => void | Promise<void>;

export type TagManagementDialogProps = {
  open: boolean;
  contacts: TagContact[];
  onClose: () => void;
  /** Persist tag list for one contact (local IndexedDB only). */
  onPersist: TagPersistFn;
  /** Called after a batch of persists so the book can refresh. */
  onDone?: () => void | Promise<void>;
};

export function TagManagementDialog({
  open,
  contacts,
  onClose,
  onPersist,
  onDone,
}: TagManagementDialogProps) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [createValue, setCreateValue] = useState('');
  /** Tags created in-session but not yet on any contact (local UI only). */
  const [pendingLabels, setPendingLabels] = useState<string[]>([]);
  const [renameValue, setRenameValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const catalog = useMemo(() => collectTagCatalog(contacts), [contacts]);

  // Drop pending drafts once they appear in the live catalog.
  useEffect(() => {
    if (pendingLabels.length === 0) return;
    setPendingLabels((prev) =>
      prev.filter((p) => !catalog.some((t) => t.label.toLowerCase() === p.toLowerCase()))
    );
  }, [catalog, pendingLabels.length]);

  const listEntries = useMemo(() => {
    const extras = pendingLabels
      .filter((p) => !catalog.some((t) => t.label.toLowerCase() === p.toLowerCase()))
      .map((label) => ({ label, memberIds: [] as string[] }));
    return [...catalog, ...extras].sort((a, b) => a.label.localeCompare(b.label));
  }, [catalog, pendingLabels]);

  const selected = useMemo(() => {
    if (!selectedKey) return null;
    return listEntries.find((t) => t.label.toLowerCase() === selectedKey) || null;
  }, [listEntries, selectedKey]);

  useEffect(() => {
    if (!open) return;
    setCreateValue('');
    setPendingLabels([]);
    setRenameValue('');
    setNote(null);
    setErr(null);
    if (catalog.length > 0) {
      setSelectedKey((prev) => {
        if (prev && catalog.some((t) => t.label.toLowerCase() === prev)) return prev;
        return catalog[0].label.toLowerCase();
      });
    } else {
      setSelectedKey(null);
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps -- reset only on open

  useEffect(() => {
    if (selected) setRenameValue(selected.label);
  }, [selected?.label]);

  const memberSet = useMemo(
    () => new Set(selected?.memberIds ?? []),
    [selected]
  );

  const sortedContacts = useMemo(
    () =>
      [...contacts].sort((a, b) =>
        (a.name || 'Unnamed').localeCompare(b.name || 'Unnamed')
      ),
    [contacts]
  );

  const runBatch = async (
    work: () => Promise<string>,
  ) => {
    setBusy(true);
    setErr(null);
    setNote(null);
    try {
      const msg = await work();
      setNote(msg);
      await onDone?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not save tags.');
    } finally {
      setBusy(false);
    }
  };

  const handleCreate = () => {
    const label = normalizeTagLabel(createValue);
    if (!label) {
      setErr(`Enter a tag name (1–${TAG_MAX_LEN} characters).`);
      return;
    }
    setErr(null);
    setSelectedKey(label.toLowerCase());
    setCreateValue('');
    if (catalog.some((t) => t.label.toLowerCase() === label.toLowerCase())) {
      setNote(`“${label}” already exists — assign people below.`);
      return;
    }
    setPendingLabels((prev) =>
      prev.some((p) => p.toLowerCase() === label.toLowerCase()) ? prev : [...prev, label]
    );
    setNote(`“${label}” ready — pick people to assign. It stays on this device only.`);
  };

  const handleRename = () => {
    if (!selected) return;
    const next = normalizeTagLabel(renameValue);
    if (!next) {
      setErr(`Enter a new name (1–${TAG_MAX_LEN} characters).`);
      return;
    }
    if (next.toLowerCase() === selected.label.toLowerCase() && next === selected.label) {
      setNote('Name unchanged.');
      return;
    }
    const from = selected.label;
    const wasPendingOnly = selected.memberIds.length === 0;
    void runBatch(async () => {
      if (wasPendingOnly) {
        setPendingLabels((prev) => {
          const without = prev.filter((p) => p.toLowerCase() !== from.toLowerCase());
          if (catalog.some((t) => t.label.toLowerCase() === next.toLowerCase())) return without;
          return [...without, next];
        });
        setSelectedKey(next.toLowerCase());
        return `Renamed to “${next}”.`;
      }
      for (const c of contacts) {
        const prev = readContactTags(c);
        if (!prev.some((t) => t.toLowerCase() === from.toLowerCase())) continue;
        const tags = renameTag(prev, from, next);
        await onPersist(c.id, tagPersistPatch(c.metadata as Record<string, unknown>, tags));
      }
      setSelectedKey(next.toLowerCase());
      return `Renamed to “${next}”.`;
    });
  };

  const handleDelete = () => {
    if (!selected) return;
    const from = selected.label;
    const wasPendingOnly = selected.memberIds.length === 0;
    void runBatch(async () => {
      if (wasPendingOnly) {
        setPendingLabels((prev) => prev.filter((p) => p.toLowerCase() !== from.toLowerCase()));
        setSelectedKey(null);
        return `Discarded “${from}”.`;
      }
      for (const c of contacts) {
        const prev = readContactTags(c);
        if (!prev.some((t) => t.toLowerCase() === from.toLowerCase())) continue;
        const tags = removeTag(prev, from);
        await onPersist(c.id, tagPersistPatch(c.metadata as Record<string, unknown>, tags));
      }
      setSelectedKey(null);
      return `Removed “${from}” from your book.`;
    });
  };

  const toggleMember = (contact: TagContact) => {
    const label = selected?.label;
    if (!label) {
      setErr('Create or select a tag first.');
      return;
    }
    void runBatch(async () => {
      const prev = readContactTags(contact);
      const on = prev.some((t) => t.toLowerCase() === label.toLowerCase());
      const tags = on ? removeTag(prev, label) : assignTag(prev, label);
      await onPersist(contact.id, tagPersistPatch(contact.metadata as Record<string, unknown>, tags));
      setSelectedKey(label.toLowerCase());
      return on
        ? `Removed ${contact.name || 'contact'} from “${label}”.`
        : `Added ${contact.name || 'contact'} to “${label}”.`;
    });
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent
        className="sm:max-w-xl border-0 p-0 gap-0 overflow-hidden"
        style={{ ...solarGlass, color: E.text, fontFamily: E.fontSans } as CSSProperties}
      >
        <DialogHeader className="px-5 pt-5 pb-3 space-y-2">
          <DialogTitle
            style={{
              fontFamily: E.fontSerif,
              fontWeight: 400,
              fontSize: 22,
              letterSpacing: '0.02em',
              color: E.text,
            }}
          >
            Private tags
          </DialogTitle>
          <DialogDescription style={{ color: E.muted, fontSize: 13, lineHeight: 1.5 }}>
            Labels you author on this device to organize your circle. They stay
            private — never shared with contacts or the relay.
          </DialogDescription>
        </DialogHeader>

        <div className="px-5 pb-2 flex gap-2 flex-wrap">
          <input
            type="text"
            placeholder="New tag name"
            value={createValue}
            maxLength={TAG_MAX_LEN}
            onChange={(e) => setCreateValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleCreate();
              }
            }}
            style={fieldStyle()}
            aria-label="New tag name"
          />
          <ActionBtn label={busy ? '…' : 'Create'} primary onClick={handleCreate} disabled={busy} />
        </div>

        <div className="px-5 pb-4 grid gap-3 grid-cols-1 sm:grid-cols-[minmax(120px,38%)_1fr]">
          <div
            style={{
              border: `1px solid ${E.border}`,
              borderRadius: 12,
              background: 'color-mix(in srgb, var(--se-accent) 4%, transparent)',
              maxHeight: 320,
              overflow: 'auto',
              padding: 6,
            }}
          >
            {listEntries.length === 0 ? (
              <p style={{ margin: 8, fontSize: 12, color: E.dim }}>
                No tags yet. Create one to start clustering your circle.
              </p>
            ) : (
              listEntries.map((t) => {
                const key = t.label.toLowerCase();
                const active = selectedKey === key;
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => {
                      setSelectedKey(key);
                      setErr(null);
                      setNote(null);
                    }}
                    style={{
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 10px',
                      marginBottom: 2,
                      borderRadius: 8,
                      border: active ? `1px solid ${E.borderLit}` : '1px solid transparent',
                      background: active
                        ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
                        : 'transparent',
                      color: E.text,
                      fontFamily: E.fontSans,
                      fontSize: 13,
                      cursor: 'pointer',
                    }}
                  >
                    <span style={{ color: active ? E.accent : E.text }}>{t.label}</span>
                    <span style={{ display: 'block', fontSize: 11, color: E.dim, marginTop: 2 }}>
                      {t.memberIds.length === 0
                        ? 'no one yet'
                        : t.memberIds.length === 1
                          ? '1 person'
                          : `${t.memberIds.length} people`}
                    </span>
                  </button>
                );
              })
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minHeight: 280 }}>
            {selected ? (
              <>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                  <input
                    type="text"
                    value={renameValue}
                    maxLength={TAG_MAX_LEN}
                    onChange={(e) => setRenameValue(e.target.value)}
                    style={{ ...fieldStyle(), flex: 1, minWidth: 100 }}
                    aria-label="Rename tag"
                  />
                  <ActionBtn label="Rename" onClick={handleRename} disabled={busy} />
                  <ActionBtn label="Remove tag" danger onClick={handleDelete} disabled={busy} />
                </div>
                {selected.memberIds.length === 0 && (
                  <p style={{ margin: 0, fontSize: 11, color: E.dim }}>
                    Assign someone below to save “{selected.label}” on this device.
                  </p>
                )}
                <p style={{ margin: 0, fontSize: 12, color: E.muted }}>
                  Toggle people in this tag
                </p>
                <div
                  style={{
                    flex: 1,
                    overflow: 'auto',
                    border: `1px solid ${E.border}`,
                    borderRadius: 12,
                    padding: 6,
                    maxHeight: 220,
                  }}
                >
                  {sortedContacts.length === 0 ? (
                    <p style={{ margin: 8, fontSize: 12, color: E.dim }}>
                      Your book is empty — add contacts first.
                    </p>
                  ) : (
                    sortedContacts.map((c) => {
                      const on =
                        readContactTags(c).some(
                          (t) => t.toLowerCase() === selected.label.toLowerCase()
                        ) || memberSet.has(c.id);
                      return (
                        <button
                          key={c.id}
                          type="button"
                          disabled={busy}
                          onClick={() => toggleMember(c)}
                          style={{
                            display: 'flex',
                            width: '100%',
                            alignItems: 'center',
                            gap: 10,
                            textAlign: 'left',
                            padding: '8px 10px',
                            marginBottom: 2,
                            borderRadius: 8,
                            border: on ? `1px solid ${E.borderLit}` : '1px solid transparent',
                            background: on
                              ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                              : 'transparent',
                            color: E.text,
                            fontFamily: E.fontSans,
                            fontSize: 13,
                            cursor: busy ? 'wait' : 'pointer',
                          }}
                        >
                          <span
                            aria-hidden
                            style={{
                              width: 14,
                              height: 14,
                              borderRadius: 4,
                              border: `1px solid ${on ? E.accent : E.border}`,
                              background: on
                                ? 'color-mix(in srgb, var(--se-accent) 35%, transparent)'
                                : 'transparent',
                              flexShrink: 0,
                            }}
                          />
                          <span style={{ flex: 1, minWidth: 0 }}>
                            <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {c.name || 'Unnamed'}
                            </span>
                            {c.fingerprint && (
                              <span
                                style={{
                                  display: 'block',
                                  fontSize: 10,
                                  color: E.dim,
                                  fontFamily: E.fontMono,
                                  letterSpacing: '0.04em',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                }}
                              >
                                {c.fingerprint.slice(0, 16)}…
                              </span>
                            )}
                          </span>
                        </button>
                      );
                    })
                  )}
                </div>
              </>
            ) : (
              <p style={{ margin: 'auto', fontSize: 13, color: E.dim, textAlign: 'center' }}>
                Select a tag or create one.
              </p>
            )}
          </div>
        </div>

        {(note || err) && (
          <p
            style={{
              margin: '0 20px 8px',
              fontSize: 12,
              color: err ? E.danger : E.ok,
            }}
            role="status"
          >
            {err || note}
          </p>
        )}

        <DialogFooter className="px-5 pb-5 pt-1">
          <ActionBtn label="Done" primary onClick={onClose} />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function fieldStyle(): CSSProperties {
  return {
    background: E.inputBg,
    border: `1px solid ${E.border}`,
    borderRadius: 8,
    padding: '8px 10px',
    color: E.text,
    fontFamily: E.fontSans,
    fontSize: 13,
    flex: 1,
    minWidth: 140,
    boxSizing: 'border-box',
  };
}

function ActionBtn({
  label,
  onClick,
  primary,
  danger,
  disabled,
}: {
  label: string;
  onClick: () => void;
  primary?: boolean;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: '8px 12px',
        borderRadius: 8,
        border: `1px solid ${danger ? 'color-mix(in srgb, var(--se-danger) 45%, transparent)' : primary ? E.borderLit : E.border}`,
        background: primary
          ? 'color-mix(in srgb, var(--se-accent) 18%, transparent)'
          : danger
            ? 'color-mix(in srgb, var(--se-danger) 10%, transparent)'
            : 'transparent',
        color: danger ? E.danger : primary ? E.accent : E.text,
        fontFamily: E.fontSans,
        fontSize: 12,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </button>
  );
}
