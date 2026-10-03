// infra/fed-qa/registry-stub.mjs — mailbox-registry TEST-DOUBLE.
// Implements ONLY the documented wire contract in src/lib/crypto/mailbox-registry-client.ts:
//   POST /mailbox/register  {mailbox_fp, x25519_pub, mlkem_ek, owner_proof} → 200/201 {ok:true}
//   GET  /mailbox/{fp}      → {mailbox_fp, x25519_pub, mlkem_ek, epoch} or 404
// It exists so the fed-qa harness can exercise CLIENT behaviour until the real
// satellite (infra/svrnty) is published. It proves the wire shape, NOT satellite
// correctness — an always-green stub in place of the real service would be false
// evidence. When the real image lands, swap this service for it (same route shape).
import http from 'node:http';

const boxes = new Map(); // mailbox_fp -> {x25519_pub, mlkem_ek, epoch}

function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(b);
}

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST' && u.pathname === '/mailbox/register') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const { mailbox_fp, x25519_pub, mlkem_ek } = JSON.parse(body || '{}');
        if (!mailbox_fp || !x25519_pub || !mlkem_ek) return send(res, 400, { error: 'bad_request' });
        // Owner-proof verification is the REAL satellite's job — the stub accepts any
        // well-formed body (test-double limitation, see header).
        const prev = boxes.get(mailbox_fp);
        boxes.set(mailbox_fp, { x25519_pub, mlkem_ek, epoch: (prev?.epoch ?? 0) + (prev ? 1 : 0) });
        send(res, 201, { ok: true });
      });
      return;
    }
    const m = u.pathname.match(/^\/mailbox\/([A-Za-z0-9_-]+)$/);
    if (req.method === 'GET' && m) {
      const fp = m[1];
      const rec = boxes.get(fp);
      if (!rec) return send(res, 404, { error: 'not_found' });
      // NEVER owner_identity_fp — mirrors the satellite's field discipline.
      return send(res, 200, { mailbox_fp: fp, ...rec });
    }
    send(res, 404, { error: 'not_found' });
  })
  .listen(8100, () => console.log('registry-stub on :8100'));
