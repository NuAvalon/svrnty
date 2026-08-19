// src/lib/relay/owner-auth.ts
// Owner-ownership proof for the return-channel mailbox fetch/ack ops (joint §4, Q1 seam #116216).
//
// Q1 = SIGNED POLL REQUEST (not a bearer token): the owner signs a request over
// (mailbox_id ‖ nonce ‖ ts) with their identity key; the server verifies the signature AND that
// sha(pubkey) → mailbox_id binds the key to the mailbox. No token-issuance endpoint, smallest surface.
//
// ⚠ This is the load-bearing I-4/owner-only boundary. It MUST be verified BEFORE any store access so
// the non-owner path is mailbox-state-INDEPENDENT (no existence oracle; owner-fail ≡ no-mailbox ≡
// empty — §5 §C, Flint D2). STEP 4 wires the real Ed25519 verification + confirms the exact wire
// encoding with Flint (he pins his A-half helper to a real owner-signature sample).
//
// Until then this returns false for every request → all poll/ack fall to the uniform non-owner path,
// so the anti-oracle half of Flint's gate (B/C/E) activates and goes green first, exactly as planned.

export async function verifyOwnerAuth(_request: Request, _mailboxId: string): Promise<boolean> {
  // TODO(step-4): parse the signed-poll-request headers, verify Ed25519 sig over
  // (mailbox_id ‖ nonce ‖ ts) against the presented pubkey, and check sha(pubkey) === mailbox_id.
  return false;
}
