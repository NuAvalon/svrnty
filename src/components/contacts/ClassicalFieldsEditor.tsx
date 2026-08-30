'use client';

import { useMemo, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type BookFieldKind =
  | 'phone'
  | 'email'
  | 'url'
  | 'adr'
  | 'org'
  | 'title'
  | 'nickname'
  | 'bday'
  | 'handle'
  | 'custom';

export type BookField = {
  id: string;
  kind: BookFieldKind;
  value: string;
  label?: string;
};

const KINDS: Array<{ kind: BookFieldKind; label: string }> = [
  { kind: 'phone', label: 'Phone' },
  { kind: 'email', label: 'Email' },
  { kind: 'url', label: 'Link' },
  { kind: 'adr', label: 'Address' },
  { kind: 'org', label: 'Organization' },
  { kind: 'title', label: 'Title' },
  { kind: 'nickname', label: 'Nickname' },
  { kind: 'bday', label: 'Birthday' },
  { kind: 'handle', label: 'Handle' },
  { kind: 'custom', label: 'Custom' },
];

let seq = 0;
function nid() {
  seq += 1;
  return `f-${seq}`;
}

export function fieldsFromContactInfo(ci?: {
  phones?: string[];
  emails?: string[];
  urls?: string[];
  handles?: Record<string, string>;
  org?: string;
  title?: string;
  nickname?: string;
  bday?: string;
  adr?: string;
  extras?: Array<{ label: string; value: string }>;
}): BookField[] {
  const out: BookField[] = [];
  for (const v of ci?.phones || []) out.push({ id: nid(), kind: 'phone', value: v });
  for (const v of ci?.emails || []) out.push({ id: nid(), kind: 'email', value: v });
  for (const v of ci?.urls || []) out.push({ id: nid(), kind: 'url', value: v });
  if (ci?.adr) out.push({ id: nid(), kind: 'adr', value: ci.adr });
  if (ci?.org) out.push({ id: nid(), kind: 'org', value: ci.org });
  if (ci?.title) out.push({ id: nid(), kind: 'title', value: ci.title });
  if (ci?.nickname) out.push({ id: nid(), kind: 'nickname', value: ci.nickname });
  if (ci?.bday) out.push({ id: nid(), kind: 'bday', value: ci.bday });
  for (const [k, v] of Object.entries(ci?.handles || {})) {
    out.push({ id: nid(), kind: 'handle', value: `${k}: ${v}` });
  }
  for (const extra of ci?.extras || []) {
    out.push({ id: nid(), kind: 'custom', value: extra.value, label: extra.label });
  }
  return out;
}

export function fieldsToContactInfo(fields: BookField[]): NonNullable<import('@/lib/trust/types').TrustEdge['contact_info']> {
  const phones: string[] = [];
  const emails: string[] = [];
  const urls: string[] = [];
  const handles: Record<string, string> = {};
  const extras: Array<{ label: string; value: string }> = [];
  let org: string | undefined;
  let title: string | undefined;
  let nickname: string | undefined;
  let bday: string | undefined;
  let adr: string | undefined;
  for (const f of fields) {
    const v = f.value.trim();
    if (!v && f.kind !== 'custom') continue;
    if (f.kind === 'phone') phones.push(v);
    else if (f.kind === 'email') emails.push(v);
    else if (f.kind === 'url') urls.push(v);
    else if (f.kind === 'adr') adr = v;
    else if (f.kind === 'org') org = v;
    else if (f.kind === 'title') title = v;
    else if (f.kind === 'nickname') nickname = v;
    else if (f.kind === 'bday') bday = v;
    else if (f.kind === 'handle') {
      const idx = v.indexOf(':');
      if (idx > 0) handles[v.slice(0, idx).trim()] = v.slice(idx + 1).trim();
    } else if (f.kind === 'custom' && (f.label || v)) {
      extras.push({ label: (f.label || 'custom').trim(), value: v });
    }
  }
  return { phones, emails, urls, handles, org, title, nickname, bday, adr, extras };
}

export function ClassicalFieldsEditor({
  fields,
  onChange,
}: {
  fields: BookField[];
  onChange: (next: BookField[]) => void;
}) {
  const [addKind, setAddKind] = useState<BookFieldKind>('phone');
  const labels = useMemo(() => Object.fromEntries(KINDS.map((k) => [k.kind, k.label])), []);

  return (
    <div data-testid="classical-fields-editor" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {fields.map((f) => (
        <div key={f.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ width: 88, fontSize: 11, color: E.dim, fontFamily: E.fontSans, flexShrink: 0 }}>
            {f.kind === 'custom' ? (
              <input
                value={f.label || ''}
                placeholder="Label"
                onChange={(e) =>
                  onChange(fields.map((x) => (x.id === f.id ? { ...x, label: e.target.value } : x)))
                }
                style={inp(true)}
              />
            ) : (
              labels[f.kind]
            )}
          </span>
          <input
            value={f.value}
            onChange={(e) => onChange(fields.map((x) => (x.id === f.id ? { ...x, value: e.target.value } : x)))}
            placeholder={f.kind === 'handle' ? 'signal: @name' : labels[f.kind]}
            style={{ ...inp(false), flex: 1 }}
          />
          <button
            type="button"
            onClick={() => onChange(fields.filter((x) => x.id !== f.id))}
            style={{
              border: 'none',
              background: 'transparent',
              color: E.dim,
              cursor: 'pointer',
              fontSize: 11,
              fontFamily: E.fontSans,
            }}
          >
            Remove
          </button>
        </div>
      ))}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <select
          value={addKind}
          onChange={(e) => setAddKind(e.target.value as BookFieldKind)}
          style={{ ...inp(false), width: 140 }}
          aria-label="Field type to add"
        >
          {KINDS.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          data-testid="classical-add-field"
          onClick={() =>
            onChange([...fields, { id: nid(), kind: addKind, value: '', label: addKind === 'custom' ? '' : undefined }])
          }
          style={{
            fontSize: 12,
            fontFamily: E.fontSans,
            padding: '7px 12px',
            borderRadius: 8,
            border: `1px solid ${E.borderLit}`,
            background: 'transparent',
            color: E.accent,
            cursor: 'pointer',
          }}
        >
          Add field
        </button>
      </div>
      <p style={{ margin: 0, fontSize: 11, color: E.dim, fontFamily: E.fontSans }}>
        These export in the vCard. Classical only — not published on the living wire.
      </p>
    </div>
  );
}

function inp(compact: boolean): CSSProperties {
  return {
    background: E.inputBg,
    border: `1px solid ${E.border}`,
    borderRadius: 8,
    padding: compact ? '4px 6px' : '8px 10px',
    color: E.text,
    fontFamily: E.fontSans,
    fontSize: compact ? 11 : 13,
    width: compact ? '100%' : undefined,
    boxSizing: 'border-box',
  };
}
