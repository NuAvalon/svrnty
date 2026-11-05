<!--
PROVENANCE CHAIN (v0 — "recorded provenance", see note at bottom)
Fill the block below. The CI check (provenance-check) WARNS (does not block) if it's
missing or incomplete. CONSEQUENTIAL changes — src/lib/{crypto,trust,relay,identity}/**,
the message-transport files (transport / consume-mailbox / notes-send), claim-gates.ts,
satellite backend, canonical blueprint + charter, *.config.*, CI workflows, Dockerfile /
compose — need the full block + a real Authorized-by (Peter's go for prod/claim-flip MUST
cite a #id / date / link). STANDARD changes (other src/ UI) need Change + Origin. TRIVIAL
changes (docs / *.md / tests / *.css / lint / format) can use "self".
-->

## Provenance
- **Change:** <one line — what changed>
- **Impact:** <blast-radius — subsystems/files affected; the CI check auto-annotates from the diff>
- **Origin:** <where the idea came from — e.g. "Peter #172501", "conch thread:svrnty-launch", "KB#3274", an agent>
- **Authorized-by:** <who authorized — a REAL authorization that happened:
    • prod-push / claim-gate flip → Peter's actual go (message-id + timestamp)
    • Tier-1 shared (orchestration / governance) → owning agent + the Reviewed-by ACKs
    • domain-owned → the owning agent (self-authz OK)>
- **Blueprint:** <touched + charter-ref | n/a — "touched" on a claim-gate/architecture change fires the fold-check>

## Summary
<what & why>

<!--
NOTE — HONEST SCOPE: "Authorized-by" here is RECORDED provenance (present + well-formed +
entitled-by-NAME), NOT cryptographically tamper-evident — any author could write the line.
It becomes tamper-evident only when the authorizer signs it with a per-authorizer key
(pending per-agent key custody). Do not read this line as proof of authorization, only as a record of it.
-->
