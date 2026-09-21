// src/lib/contacts/contact-worm.test.ts
//
// §9 WORM MUST-FIRE TEST (claim d, Flint pin #141768/#141780). The trust-graph-worm scenario: a card
// with LIVE payloads in EVERY field must render inert AND *propagate* inert end-to-end — a re-emitted /
// re-exported card cannot carry the payload onward along a trust edge.
//
// Proves the ENFORCE-BY-CONSTRUCTION layer-3 defense (safe-text.ts, wired into apply-contact-update):
// the invisible/control/bidi class (Trojan-Source, homoglyph-spoof, invisible worm markers) is stripped
// AT INGESTION, before the store — the class render-escaping structurally cannot catch. Visible markup
// (<script>, <img onerror>) is PRESERVED as data (doctrine: each sink context-escapes it — React for
// display, escapeVCard for export) — never blanket-stripped/rejected (that would corrupt legit "<3").
//
// All test chars are explicit code points (no literal invisibles in source — a security test must be
// auditable). Runner: node --import tsx --test src/lib/contacts/contact-worm.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyVerifiedContactUpdate, type StoredContact, type VerifiedContactUpdate } from './apply-contact-update.js';
import { toVCard, fromVCard } from './vcard.js';
import { sanitizeContactInfo, sanitizeContactRecordText, sanitizeSingleLine, sanitizeText, DISPLAY_NAME_MAX, NOTE_MAX } from './safe-text.js';

// The invisible/control/bidi class that MUST NOT survive ingestion into the store (or propagation out).
// TAB (U+0009) + LF (U+000A) are legit in multi-line notes and are intentionally EXCLUDED from this set.
const INVISIBLE_BIDI = new RegExp(
  '[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u00AD\\u061C\\u200B-\\u200F\\u2028\\u2029\\u202A-\\u202E\\u2060\\u2066-\\u2069\\uFEFF]',
);

function assertNoInvisible(s: unknown, where: string) {
  assert.equal(typeof s, 'string', `${where} should be a string`);
  assert.ok(!INVISIBLE_BIDI.test(s as string), `${where} must carry NO invisible/control/bidi char`);
}

// Explicit code points for the worm carriers.
const RLO = String.fromCharCode(0x202e); // right-to-left override (Trojan-Source)
const ZW = String.fromCharCode(0x200b); // zero-width space
const BOM = String.fromCharCode(0xfeff); // zero-width no-break space / BOM
const NUL = String.fromCharCode(0x0000); // C0 control
const ALM = String.fromCharCode(0x061c); // Arabic letter mark (bidi)
const SCRIPT = '<script>alert(1)</script>'; // visible markup — must SURVIVE as data

const payloadUpdate: VerifiedContactUpdate = {
  fingerprint: 'FP_WORM',
  epoch: 0,
  version: 1,
  changed_fields: ['display_name', 'note', 'emails', 'phones', 'handles', 'urls'],
  delta: {
    display_name: `Alice${RLO}gnp.exe${ZW}${SCRIPT}`,
    note: `line1${NUL}${ZW}line2 ${SCRIPT}\r\nNOTE:INJECTED;X-EVIL:1`, // CRLF + fake vCard header injection
    emails: [`ev${RLO}il@x.com`, `a@b.co${ZW}`],
    phones: [`+1${ZW}555${RLO}123`],
    handles: { signal: `user${ZW}name${RLO}`, telegram: `tg${NUL}user${ALM}` },
    urls: [`https://ex${ZW}ample.com${RLO}`, `javascript:alert(1)${BOM}`],
  },
};

const base: StoredContact = {
  id: 'c1', fingerprint: 'FP_WORM', name: 'old', email: '', public_key: '', trust_level: 'trusted',
  added_at: '2026-01-01T00:00:00Z', version: 0,
};

test('WORM-1 ingestion strips invisible/bidi from EVERY field, before store', () => {
  const { next } = applyVerifiedContactUpdate(base, payloadUpdate, '2026-09-21T00:00:00Z');
  assertNoInvisible(next.name, 'display_name→name');
  assertNoInvisible(next.notes, 'note→notes');
  for (const e of next.emails as string[]) assertNoInvisible(e, 'email');
  for (const p of next.phones as string[]) assertNoInvisible(p, 'phone');
  const ci = next.contact_info as { handles: Record<string, string>; urls: string[] };
  for (const [k, v] of Object.entries(ci.handles)) assertNoInvisible(v, `handle ${k}`);
  for (const u of ci.urls) assertNoInvisible(u, 'url');
  assertNoInvisible(next.email, 'primary email');
  assertNoInvisible(next.phone, 'primary phone');
});

test('WORM-2 visible markup PRESERVED as data (escape at sink, not strip at ingestion); carriers stripped', () => {
  const { next } = applyVerifiedContactUpdate(base, payloadUpdate, '2026-09-21T00:00:00Z');
  const name = next.name as string;
  const notes = next.notes as string;
  // <script> survives verbatim — DATA, not stripped (React escapes at render; stripping would corrupt "<3").
  assert.ok(name.includes(SCRIPT), 'markup survives ingestion as literal text');
  // ...but its invisible worm carriers are gone.
  assert.ok(!name.includes(RLO) && !name.includes(ZW), 'invisible carriers stripped from name');
  // multi-line note keeps its legit LF; the injected CR is normalized away (no vCard header-injection vector).
  assert.ok(notes.includes('\n'), 'legit newline preserved in multi-line note');
  assert.ok(!notes.includes(String.fromCharCode(0x0d)), 'CR normalized away');
  assert.ok(!notes.includes(NUL), 'C0 control stripped from note');
});

test('WORM-3 PROPAGATION — re-export via vCard stays inert end-to-end', () => {
  const { next } = applyVerifiedContactUpdate(base, payloadUpdate, '2026-09-21T00:00:00Z');
  const edge = {
    peer_name: next.name,
    peer_email: next.email,
    notes: next.notes,
    contact_info: next.contact_info,
  } as unknown as Parameters<typeof toVCard>[0];
  const vcf = toVCard(edge);

  // (a) no invisible/bidi survived into the exported card (stripped at ingestion → cannot propagate).
  assertNoInvisible(vcf, 'exported vCard');
  // (b) no injected vCard header line from the payload's CRLF — escapeVCard + CR-normalize neutralize it.
  const lines = vcf.split(/\r\n|\n/);
  assert.ok(!lines.some((l) => /^X-EVIL:/.test(l)), 'no injected X-EVIL header line');
  assert.ok(!lines.some((l) => /^NOTE:INJECTED/.test(l)), 'no injected NOTE:INJECTED header line');
  // (c) the FN line is a single inert logical line — the name payload cannot break field framing.
  const fn = lines.find((l) => l.startsWith('FN:'));
  assert.ok(fn && !/[\r\n]/.test(fn), 'FN is one inert line');
});

test('WORM-4 vCard-IMPORT path: malicious .vcf → fromVCard → sanitize (edgeToRecordFields mirror) → inert store + re-export', () => {
  // A hostile .vcf a peer hands you. This exercises the SAME calls edgeToRecordFields makes at ingestion
  // (the vCard-import store convergence) — the path that bypassed applyVerifiedContactUpdate (Flint #141804).
  const vcf = [
    'BEGIN:VCARD', 'VERSION:3.0',
    `FN:Alice${RLO}gnp.exe${ZW}${SCRIPT}`,
    `NOTE:evil${ZW}note${RLO}\\nX-EVIL:1`, // escaped-\n in the wire → fromVCard restores a real newline
    `TEL;TYPE=CELL:+1${ZW}555${RLO}123`,
    `EMAIL;TYPE=INTERNET:ev${RLO}il@x.com`,
    `URL:https://ex${ZW}ample.com${RLO}`,
    `X-SIGNAL:user${ZW}name${RLO}`,
    'END:VCARD',
  ].join('\r\n');
  const parsed = fromVCard(vcf);
  assert.ok(parsed.length === 1, 'one card parsed');
  const edge = parsed[0];
  // Mirror edgeToRecordFields' ingestion sanitization exactly:
  const name = sanitizeSingleLine(edge.peer_name || '', DISPLAY_NAME_MAX);
  const notes = sanitizeText(edge.notes || '', { max: NOTE_MAX, allowNewlines: true });
  const ci = sanitizeContactInfo(edge.contact_info);

  assertNoInvisible(name, 'imported name');
  assert.ok(name.includes(SCRIPT), 'markup survives import as data');
  assertNoInvisible(notes, 'imported notes');
  for (const p of (ci?.phones as string[]) ?? []) assertNoInvisible(p, 'imported phone');
  for (const em of (ci?.emails as string[]) ?? []) assertNoInvisible(em, 'imported email');
  for (const u of (ci?.urls as string[]) ?? []) assertNoInvisible(u, 'imported url');
  for (const [k, v] of Object.entries((ci?.handles as Record<string, string>) ?? {})) assertNoInvisible(v, `imported handle ${k}`);

  // Re-export the sanitized-imported card → still inert end-to-end (propagation).
  const out = toVCard({ peer_name: name, notes, contact_info: ci } as unknown as Parameters<typeof toVCard>[0]);
  assertNoInvisible(out, 're-exported imported vCard');
  assert.ok(!out.split(/\r\n|\n/).some((l) => /^X-EVIL:/.test(l)), 'no injected header from imported note');
});

test('WORM-5 CHOKEPOINT: a record BYPASSING FIELD_MAP/edgeToRecordFields → text inert + crypto/lookup fields BYTE-EXACT', () => {
  // Simulates the admit paths (JoinerCeremony:309 / grow-gate:174) — a raw ContactRecord handed straight
  // to addContact/updateContact, never through FIELD_MAP or edgeToRecordFields. sanitizeContactRecordText
  // is what those store fns now call; it must hold ALONE (Flint chokepoint pin #141811, item 4).
  const FP = 'a'.repeat(64); // byte-exact identity/lookup key — getContactByFingerprint depends on it
  const PUB = `ARMORED-PUBLIC-KEY-${RLO}-bytes`; // crypto field — even if it (implausibly) held a control char, we must NOT alter it
  const raw = {
    fingerprint: FP,
    public_key: PUB,
    added_at: '2026-01-01T00:00:00Z',
    trust_level: 'verified',
    version: 3,
    epoch: 0,
    name: `Mallory${RLO}gnp.exe${ZW}${SCRIPT}`,
    email: `m${RLO}@x.com`,
    phone: `+1${ZW}555${RLO}123`,
    phones: [`+1${ZW}555${RLO}123`],
    emails: [`m${ZW}@x.com`],
    notes: `n${NUL}${ZW}ote${RLO}\r\nX-EVIL:1`,
    contact_info: { handles: { signal: `s${RLO}${ZW}ig` }, urls: [`javascript:1${BOM}`], org: `Org${RLO}Inc` },
  };
  const out = sanitizeContactRecordText(raw);

  // text fields inert
  assertNoInvisible(out.name, 'name'); assertNoInvisible(out.email, 'email'); assertNoInvisible(out.phone, 'phone');
  assertNoInvisible(out.notes, 'notes');
  for (const p of out.phones) assertNoInvisible(p, 'phone[]');
  for (const em of out.emails) assertNoInvisible(em, 'email[]');
  const ci = out.contact_info as { handles: Record<string, string>; urls: string[]; org: string };
  assertNoInvisible(ci.handles.signal, 'handle'); assertNoInvisible(ci.urls[0], 'url'); assertNoInvisible(ci.org, 'org');
  assert.ok(out.name.includes(SCRIPT), 'markup preserved as data');

  // ★ item 2: crypto / lookup / structural fields BYTE-EXACT — NEVER sanitized (would corrupt identity + break matching).
  assert.equal(out.fingerprint, FP, 'fingerprint byte-exact (the lookup key)');
  assert.equal(out.public_key, PUB, 'public_key byte-exact (crypto — even a control char left untouched)');
  assert.equal(out.added_at, '2026-01-01T00:00:00Z', 'added_at byte-exact');
  assert.equal(out.trust_level, 'verified', 'trust_level byte-exact');
  assert.equal(out.version, 3, 'version preserved');
  assert.equal(out.epoch, 0, 'epoch preserved');
});
