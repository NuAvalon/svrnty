#!/usr/bin/env node
// qa-quarantine.mjs — validates qa/quarantine.json and splits the unified test set.
//
// Usage:
//   node scripts/qa-quarantine.mjs list gate       # newline-separated GATE files (blocking run)
//   node scripts/qa-quarantine.mjs list quarantined # newline-separated QUARANTINED files (info tier)
//   node scripts/qa-quarantine.mjs check           # lint the list only (also runs inside `list`)
//
// An entry is INVALID if: file missing, fields missing, expires < today, or file doesn't exist
// on disk. Any invalid entry fails the gate — quarantine is enumerated-with-expiry, not a dump.
import { readFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';

const LIST = 'qa/quarantine.json';
const [, , cmd, which = 'gate'] = process.argv;

function die(msg) {
  console.error(`qa-quarantine: ${msg}`);
  process.exit(1);
}

const doc = JSON.parse(readFileSync(LIST, 'utf8'));
const entries = doc.quarantined;
if (!Array.isArray(entries)) die(`${LIST}: 'quarantined' must be an array`);

const today = new Date().toISOString().slice(0, 10);
const errors = [];
for (const [i, e] of entries.entries()) {
  const tag = `entry[${i}] ${e.file || '(no file)'}`;
  if (!e.file) errors.push(`${tag}: missing 'file'`);
  if (!e.owner) errors.push(`${tag}: missing 'owner'`);
  if (!e.reason) errors.push(`${tag}: missing 'reason'`);
  if (!e.expires) errors.push(`${tag}: missing 'expires'`);
  else if (e.expires < today) errors.push(`${tag}: EXPIRED ${e.expires} — drain or renew with justification`);
  if (e.file && !existsSync(e.file)) errors.push(`${tag}: file does not exist`);
}
const dupes = entries.map((e) => e.file).filter((f, i, a) => a.indexOf(f) !== i);
for (const d of new Set(dupes)) errors.push(`duplicate entry for ${d}`);

if (cmd === 'check') {
  if (errors.length) {
    errors.forEach((e) => console.error(`qa-quarantine: ${e}`));
    process.exit(1);
  }
  console.log(`qa-quarantine: ${entries.length} entries valid (${today})`);
  process.exit(0);
}

if (errors.length) {
  errors.forEach((e) => console.error(`qa-quarantine: ${e}`));
  process.exit(1);
}

// Discover test files exactly like the workflow does (find src -name '*.test.ts').
const all = execSync("find src -name '*.test.ts' | sort", { encoding: 'utf8' }).trim().split('\n');
const q = new Set(entries.map((e) => e.file));
const unknown = [...q].filter((f) => !all.includes(f));
if (unknown.length) die(`quarantined file(s) not matched by 'find src -name *.test.ts': ${unknown.join(', ')}`);

if (cmd !== 'list') die(`unknown command '${cmd}' (use 'list gate|quarantined' or 'check')`);
const out = which === 'quarantined' ? [...q] : all.filter((f) => !q.has(f));
if (which === 'gate' && out.length === 0) die('gate set is empty — everything is quarantined?');
console.log(out.join('\n'));
