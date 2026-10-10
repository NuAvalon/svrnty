// infra/fed-qa/registry-stub.mjs — mailbox-registry TEST-DOUBLE.
// Mirrors the REAL wire contract in src/lib/crypto/mailbox-registry-client.ts
// (satellite.py MailboxRegisterRequest):
//   POST /mailbox/register  {mailbox_fp, x25519_pk, mlkem1024_pk,
//                            owner_identity_fp, epoch, owner_sig} → 201 {ok:true}
//   GET  /mailbox/{fp}      → {mailbox_fp, x25519_pk, mlkem1024_pk, epoch} or 404
// Verification performed HERE (real contract):
//   - mailbox_fp ≡ SHA256(x25519_pub[32] || mlkem1024_pub[1568]) — raw bytes,
//     not hex strings (mailbox-envelope.ts:60). Mismatch → 400 fp_pubkey_mismatch.
//   - owner_sig = Ed25519 over "svrnty-mailbox-reg-v1:{owner_identity_fp}:{mailbox_fp}:{epoch}"
//     (raw-sign.ts:136). The real satellite resolves owner_identity_fp → pubkey
//     from its identity registry; a stub has none, so the harness seeds one via
//     the TEST-ONLY channel `PUT /_test/identity/{fp}` (body {ed25519_pk: 64hex}).
//     That route is stub scaffolding, NOT wire shape — never point a client at it.
//     Unseeded owner → 403 owner_unknown; bad sig → 403 bad_owner_sig.
// Expiry: MAILBOX_TTL_MS env (default 0 = never) stands in for the satellite's
// 30-day GC; expired boxes are deleted on access and re-registerable (S8/G3).
import http from 'node:http';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

const X25519_HEX = 64; // 32B
const KEM_PUB_HEX = 3136; // 1568B
const FP_HEX = 64;
const TTL_MS = Number(process.env.MAILBOX_TTL_MS || 0);

const boxes = new Map(); // mailbox_fp -> {x25519_pk, mlkem1024_pk, epoch, registered_at}
const owners = new Map(); // owner_identity_fp -> ed25519 pubkey (raw 32B)

function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(b);
}

const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/i.test(s);

function edKey(rawHex) {
  // Wrap a raw 32B Ed25519 pubkey as SPKI DER (prefix per RFC 8410).
  return createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(rawHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });
}

function gc(fp) {
  const rec = boxes.get(fp);
  if (rec && TTL_MS > 0 && Date.now() - rec.registered_at > TTL_MS) boxes.delete(fp);
}

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://x');

    // TEST-ONLY owner seed — not part of the wire contract (see header).
    const seed = u.pathname.match(/^\/_test\/identity\/([0-9a-f]{16,64})$/i);
    if (req.method === 'PUT' && seed) {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const f = JSON.parse(body || '{}');
        if (!isHex(f.ed25519_pk, 64)) return send(res, 400, { error: 'bad_request' });
        owners.set(seed[1].toLowerCase(), f.ed25519_pk);
        send(res, 200, { ok: true });
      });
      return;
    }

    if (req.method === 'POST' && u.pathname === '/mailbox/register') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const f = JSON.parse(body || '{}');
        const shapeOk =
          isHex(f.mailbox_fp, FP_HEX) &&
          isHex(f.x25519_pk, X25519_HEX) &&
          isHex(f.mlkem1024_pk, KEM_PUB_HEX) &&
          typeof f.owner_identity_fp === 'string' && f.owner_identity_fp.length >= 16 &&
          Number.isSafeInteger(f.epoch) && f.epoch >= 0 &&
          typeof f.owner_sig === 'string' && f.owner_sig.length > 0;
        if (!shapeOk) return send(res, 400, { error: 'bad_request' });
        // Content-binding MUST (mailbox-registry-client.ts:104).
        const derived = createHash('sha256')
          .update(Buffer.concat([Buffer.from(f.x25519_pk, 'hex'), Buffer.from(f.mlkem1024_pk, 'hex')]))
          .digest('hex');
        if (derived !== f.mailbox_fp.toLowerCase())
          return send(res, 400, { error: 'fp_pubkey_mismatch' });
        // Owner-proof: Ed25519 over the canonical preimage with the seeded key.
        const ownerKey = owners.get(f.owner_identity_fp.toLowerCase());
        if (!ownerKey) return send(res, 403, { error: 'owner_unknown' });
        const preimage = `svrnty-mailbox-reg-v1:${f.owner_identity_fp}:${f.mailbox_fp}:${f.epoch}`;
        let sigOk = false;
        try {
          sigOk = cryptoVerify(null, Buffer.from(preimage), edKey(ownerKey), Buffer.from(f.owner_sig, 'base64'));
        } catch { /* malformed sig → false */ }
        if (!sigOk) return send(res, 403, { error: 'bad_owner_sig' });
        // Idempotent (fp is a content-address); per-mailbox epoch floor — a lower
        // epoch is refused, equal/higher refreshes.
        gc(f.mailbox_fp);
        const prev = boxes.get(f.mailbox_fp);
        if (prev && f.epoch < prev.epoch) return send(res, 409, { error: 'epoch_regressed' });
        boxes.set(f.mailbox_fp, {
          x25519_pk: f.x25519_pk,
          mlkem1024_pk: f.mlkem1024_pk,
          epoch: f.epoch,
          registered_at: Date.now(),
        });
        send(res, 201, { ok: true, epoch: f.epoch });
      });
      return;
    }
    const m = u.pathname.match(/^\/mailbox\/([A-Za-z0-9_-]+)$/);
    if (req.method === 'GET' && m) {
      const fp = m[1];
      gc(fp);
      const rec = boxes.get(fp);
      if (!rec) return send(res, 404, { error: 'not_found' });
      // NEVER owner_identity_fp / owner_sig — mirrors the satellite's field discipline.
      const { x25519_pk, mlkem1024_pk, epoch } = rec;
      return send(res, 200, { mailbox_fp: fp, x25519_pk, mlkem1024_pk, epoch });
    }
    send(res, 404, { error: 'not_found' });
  })
  .listen(8100, () => console.log(`registry-stub on :8100 (ttl=${TTL_MS || 'never'})`));
