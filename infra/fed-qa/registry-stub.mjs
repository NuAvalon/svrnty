// infra/fed-qa/registry-stub.mjs — mailbox-registry TEST-DOUBLE.
// Mirrors the REAL wire contract in src/lib/crypto/mailbox-registry-client.ts
// (satellite.py MailboxRegisterRequest):
//   POST /mailbox/register  {mailbox_fp, x25519_pk, mlkem1024_pk,
//                            owner_identity_fp, epoch, owner_sig} → 201 {ok:true}
//   GET  /mailbox/{fp}      → {mailbox_fp, x25519_pk, mlkem1024_pk, epoch} or 404
// Stub gaps (documented, same class as before): it does NOT recompute
// mailbox_fp = SHA256(pubkeys) or verify owner_sig — it validates field
// presence + hex lengths only. It exists so the fed-qa harness can exercise
// CLIENT behaviour until the real satellite (infra/svrnty) is published; it
// proves the wire shape, NOT satellite correctness — an always-green stub in
// place of the real service would be false evidence. When the real image
// lands, swap this service for it (same route shape).
import http from 'node:http';

const X25519_HEX = 64; // 32B
const KEM_PUB_HEX = 3136; // 1568B
const FP_HEX = 64;

const boxes = new Map(); // mailbox_fp -> {x25519_pk, mlkem1024_pk, epoch}

function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(b);
}

const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/i.test(s);

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
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
        // Idempotent (fp is a content-address); per-mailbox epoch floor — a lower
        // epoch is refused, equal/higher refreshes. owner_sig verification is the
        // REAL satellite's job (see header).
        const prev = boxes.get(f.mailbox_fp);
        if (prev && f.epoch < prev.epoch) return send(res, 409, { error: 'epoch_regressed' });
        boxes.set(f.mailbox_fp, { x25519_pk: f.x25519_pk, mlkem1024_pk: f.mlkem1024_pk, epoch: f.epoch });
        send(res, 201, { ok: true, epoch: f.epoch });
      });
      return;
    }
    const m = u.pathname.match(/^\/mailbox\/([A-Za-z0-9_-]+)$/);
    if (req.method === 'GET' && m) {
      const fp = m[1];
      const rec = boxes.get(fp);
      if (!rec) return send(res, 404, { error: 'not_found' });
      // NEVER owner_identity_fp / owner_sig — mirrors the satellite's field discipline.
      return send(res, 200, { mailbox_fp: fp, ...rec });
    }
    send(res, 404, { error: 'not_found' });
  })
  .listen(8100, () => console.log('registry-stub on :8100'));
