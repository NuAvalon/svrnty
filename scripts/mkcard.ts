import { readFileSync } from 'node:fs';
async function main() {
  const mint = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/mint.json','utf8'));
  const pkg = JSON.stringify(mint.public.card); // already a signed identity-exchange card
  const b64u = (b: ArrayBuffer|Uint8Array) => Buffer.from(b as ArrayBuffer).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, new TextEncoder().encode(pkg));
  const packed = new Uint8Array(12+ct.byteLength); packed.set(iv,0); packed.set(new Uint8Array(ct),12);
  const res = await fetch('https://dev.svrnty.is/api/relay', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({encrypted:b64u(packed)})});
  const j = await res.json();
  const raw = await crypto.subtle.exportKey('raw',key);
  console.log('LINK: https://dev.svrnty.is/c/'+j.code+'#'+b64u(raw));
}
main().catch(e => { console.error(e); process.exit(1); });
