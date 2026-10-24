import { readFileSync } from 'node:fs';
import * as openpgp from 'openpgp';
import { TripleRatchet, type RatchetIdentity, type RatchetPeer, type RatchetPacket } from '../src/lib/crypto/message-ratchet';
import { strip0x40 } from '../src/lib/identity/raw-sign';
import { base64ToUint8 } from '../src/lib/crypto/pq';

async function peerX25519(armored: string): Promise<Uint8Array> {
  const key = await openpgp.readKey({ armoredKey: armored });
  const enc = await key.getEncryptionKey();
  const pp = enc.keyPacket.publicParams as { Q?: Uint8Array; A?: Uint8Array };
  const q = (pp.Q ?? pp.A) as Uint8Array;   // type-only: same value as before
  return strip0x40(q);
}

async function main() {
  const mint = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/mint.json','utf8'));
  const store = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/store.json','utf8'));
  const priv = mint.private;
  const self: RatchetIdentity = {
    x25519Sec: base64ToUint8(priv.x25519_sec),
    x25519Pub: base64ToUint8(priv.x25519_pub),
    mlkem1024Sec: base64ToUint8(priv.mlkem1024_sec),
    mlkem1024Pub: base64ToUint8(priv.mlkem1024_pub),
  };
  const contact = store.contacts.find((c:any)=>c.fingerprint.startsWith('962fb7b4'));
  const peer: RatchetPeer = {
    x25519Pub: await peerX25519(contact.public_key),
    mlkem1024Pub: base64ToUint8(contact.pq_kem_public_key),
  };
  const note = store.notes.find((n:any)=>n.note_id==='note_gEaavtMh9sR51qIP');
  const wire = JSON.parse(note.body);
  const first = await TripleRatchet.acceptFirst(self, peer, wire.packet as RatchetPacket);
  if (!first) { console.log('acceptFirst → null (no session established)'); return; }
  console.log('PLAINTEXT:', first.plaintext);
  console.log('session snapshot keys:', Object.keys(first.session.exportState()));
}
main().catch(e=>console.error('ERR', e.message));
