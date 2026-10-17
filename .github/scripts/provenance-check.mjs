#!/usr/bin/env node
/**
 * provenance-check (v0) — validates the PROVENANCE CHAIN block on a PR.
 *
 * Division (per spec shared/outbox/flint/provenance_chain_spec.md):
 *   Flint = authz rule + honest scope · Archie = path→tier schema · Athena = this hook infra.
 *
 * v0 is WARN-not-block (friction-minimal, Peter): it emits GitHub `::warning::` annotations
 * and ALWAYS exits 0. Escalate specific tiers to blocking (exit 1) only once proven.
 *
 * HONEST SCOPE (Flint, load-bearing): this enforces RECORDED provenance (present + well-formed
 * + entitled-by-NAME). It is NOT tamper-evident — any author can write "Authorized-by". That
 * requires per-authorizer signing (pending key-custody). Never label this "tamper-evident authz".
 *
 * Inputs (env, with local-test fallbacks):
 *   PR_BODY        — the PR description (GitHub: github.event.pull_request.body)
 *   CHANGED_FILES  — newline-separated changed paths (GitHub: from the diff)
 * Local test: `node provenance-check.mjs <body-file> <changed-files-file>`
 */
import fs from 'node:fs';

// --- Archie's path→tier schema (REFINED to svrnty's actual layout, #172575) ---
// CONSEQUENTIAL (full trailer, would-block): the crypto/trust/relay/identity libs, the
// message-transport chokepoints, claim-gate flips, satellite backend, canonical blueprint +
// charter (consequential even as .md), build config, CI workflows, and container build files.
// CONSEQUENTIAL patterns take PRECEDENCE over TRIVIAL (so a blueprint*.md stays consequential).
const CONSEQUENTIAL = [
  /^src\/lib\/crypto\//i,                                 // crypto: ratchet, pq, kdf, envelope
  /^src\/lib\/trust\//i,                                  // trust-graph, trust-affirm, PSI / at-rest-blinder
  /^src\/lib\/relay\//i,                                  // relay / mailbox-store (OPT-2)
  /^src\/lib\/identity\//i,                               // keys, cards, recovery, introduction
  /(^|\/)(transport|consume-mailbox|notes-send)\.ts$/i,   // message-transport chokepoints (excludes *.test.ts)
  /(^|\/)claim-gates\.ts$/i,                              // any claim-gate flip
  /satellite/i,                                           // satellite relay backend (infra/svrnty/satellite*)
  /blueprint/i, /charter/i,                               // canonical blueprint + charter docs
  /\.config\./i,                                          // *.config.* (next / playwright / postcss / eslint)
  /^\.github\/workflows\//i,                              // CI workflows
  /(^|\/)Dockerfile(\.\w+)?$/i,                           // Dockerfile(.variant)
  /(^|\/)(docker-)?compose([.\-][\w.-]*)?\.ya?ml$/i,      // docker-compose.yml / compose.*.yml
  /\bauthn\b|\bauthz\b|\bauth[-_]/i,                      // authn/authz anywhere (tightened — no "author" FP, Flint)
];
// TRIVIAL = docs / tests / lint / format / styles. (blueprint/charter .md caught above by precedence.)
const TRIVIAL = [/\.md$/i, /\.test\./i, /\.spec\./i, /\.css$/i, /\.(eslintrc|prettier)/i, /^docs\//i];

function classify(files) {
  if (files.some(f => CONSEQUENTIAL.some(re => re.test(f)))) return 'consequential';
  if (files.length && files.every(f => TRIVIAL.some(re => re.test(f)))) return 'trivial';
  return 'standard';
}

// A value is a non-answer if it's empty, a "todo/tbd/..." token, or an UNFILLED <...>
// template placeholder. NOTE: "n/a" is deliberately NOT a placeholder — it's a valid
// answer for Impact/Blueprint ("no blast-radius" / "not blueprint-touching").
const PLACEHOLDER = /^(todo|tbd|\.\.\.|\s*)$/i;
function field(body, name) {
  // match "- **Name:** value" (value may wrap until the next "- **" or heading)
  const re = new RegExp(`\\*\\*${name}:\\*\\*\\s*([^\\n]*)`, 'i');
  const m = body.match(re);
  return m ? m[1].trim() : null;
}
const present = v => {
  if (v == null) return false;
  const t = v.trim();
  if (!t || t.startsWith('<')) return false; // empty, or an unfilled <...> template placeholder
  return !PLACEHOLDER.test(t);
};

function warn(msg) { console.log(`::warning title=provenance-check::${msg}`); }

function main() {
  const body = process.env.PR_BODY ?? (process.argv[2] ? fs.readFileSync(process.argv[2], 'utf8') : '');
  const files = (process.env.CHANGED_FILES ?? (process.argv[3] ? fs.readFileSync(process.argv[3], 'utf8') : ''))
    .split('\n').map(s => s.trim()).filter(Boolean);

  const tier = classify(files);
  const f = {
    Change: field(body, 'Change'), Impact: field(body, 'Impact'), Origin: field(body, 'Origin'),
    'Authorized-by': field(body, 'Authorized-by'), Blueprint: field(body, 'Blueprint'),
  };

  const issues = [];
  if (tier === 'trivial') {
    if (!present(f.Change)) issues.push('Change missing (trivial: a one-line Change is still expected).');
  } else {
    // standard + consequential need Change + Origin; consequential needs the full block + real Authorized-by.
    for (const k of ['Change', 'Origin']) if (!present(f[k])) issues.push(`${k} missing.`);
    if (tier === 'consequential') {
      for (const k of ['Impact', 'Authorized-by', 'Blueprint']) if (!present(f[k])) issues.push(`${k} missing (required for a consequential change).`);
      // authz-by-name (v0 heuristic; Flint's rule): consequential must NOT self-authorize.
      const authRaw = f['Authorized-by'] || '';
      const auth = authRaw.toLowerCase();
      if (present(f['Authorized-by']) && /^self\b/.test(auth))
        issues.push('Authorized-by: "self" is not valid for a consequential change — needs the owner + Reviewed-by ACKs, or Peter\'s go for prod/claim-flip.');
      // well-formedness (Flint tune #2 + Archie: a Peter authorization must be VERIFIABLE, not a bare
      // "Peter"): require a go-ref — a #<id>, an ISO date, or a link. Still RECORDED-scope (WARN), not proof.
      if (present(f['Authorized-by']) && /\bpeter\b/i.test(auth)) {
        const hasGoRef = /#\d{3,}/.test(authRaw) || /\b\d{4}-\d{2}-\d{2}\b/.test(authRaw) || /\bhttps?:\/\//i.test(authRaw);
        if (!hasGoRef)
          issues.push('Authorized-by cites Peter but gives no go-ref — add the message-id (#NNN), an ISO date, or a link. A bare "Peter" is not a verifiable authorization for a consequential change.');
      }
    }
  }

  console.log(`provenance-check (v0, RECORDED provenance — not tamper-evident) · tier=${tier} · files=${files.length}`);
  if (issues.length) {
    issues.forEach(warn);
    warn(`Provenance block incomplete for a ${tier} change. See .github/PULL_REQUEST_TEMPLATE.md. (WARN only — not blocking.)`);
  } else {
    console.log('✓ provenance block present + well-formed for this tier.');
  }
  process.exit(0); // v0: never block.
}
main();
