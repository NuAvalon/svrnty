import { readFileSync } from 'node:fs';
import * as openpgp from 'openpgp';
import { TripleRatchet } from '../src/lib/crypto/message-ratchet';
import { strip0x40 } from '../src/lib/identity/raw-sign';
import { base64ToUint8 } from '../src/lib/crypto/pq';
async function main() {
  const mint = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/mint.json','utf8'));
  const store = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/store.json','utf8'));
  const p = mint.private;
  const self = { x25519Sec: base64ToUint8(p.x25519_sec), x25519Pub: base64ToUint8(p.x25519_pub), mlkem1024Sec: base64ToUint8(p.mlkem1024_sec), mlkem1024Pub: base64ToUint8(p.mlkem1024_pub) };
  const contact = store.contacts.find((c:any)=>c.fingerprint.startsWith('962fb7b4'));
  const key = await openpgp.readKey({ armoredKey: contact.public_key });
  const enc = await key.getEncryptionKey();
  const q = enc.keyPacket.publicParams.Q ?? enc.keyPacket.publicParams.A;
  const peer = { x25519Pub: strip0x40(q), mlkem1024Pub: base64ToUint8(contact.pq_kem_public_key) };
  const note = store.notes.find((n:any)=>n.note_id==='note_gEaavtMh9sR51qIP');
  const wire = JSON.parse(note.body);
  console.log('self keys lens:', self.x25519Sec.length, self.mlkem1024Sec.length);
  console.log('peer keys lens:', peer.x25519Pub.length, peer.mlkem1024Pub.length);
  const first = await TripleRatchet.acceptFirst(self, peer, wire.packet);
  console.log('acceptFirst →', first ? `plaintext: ${first.plaintext}` : 'null');
}
main().catch(e=>console.error('ERR', e));
