// scripts/loom-sign.ts — loom envelope signing/verify for THIS box's svrnty identity.
// Thin CLI wrapper over fleet rawSign + fingerprintMatchesKey + signPubFromOpenPgpPublic.
// Calls existing svrnty library functions only; key material never leaves the node process.
// Subcommands (consumed by loom/cli.py via LOOM_SIGN_TS):
//   sign                              stdin msg → hex ed25519 sig on stdout (seed read in place, never printed)
//   pub <armored_pub>                 → hex raw 32B ed25519 sign pubkey (extracted from an OpenPGP public key)
//   verify <pub_hex> <sig_hex>        stdin msg → exit 0 valid / 1 invalid
//   fp-check <asc> <kem> <sigk> <fp>  → exit 0 if canonical fp of (sign‖enc‖kem‖sig) matches claimed fp
//   fp-derive <asc> <kem> <sigk>      → canonical fp of the quad on stdout (fail-path diagnostics only)
// Env: SVRNTY_MINT (mint.json path) or SVRNTY_AGENT_DIR (dir containing mint.json);
//      default ~/devin-sandbox/.svrnty-agent/mint.json.

import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
// node<19 lacks globalThis.crypto.getRandomValues — mailbox-envelope needs it.
if (!(globalThis as { crypto?: { getRandomValues?: unknown } }).crypto?.getRandomValues) {
  (globalThis as { crypto?: unknown }).crypto = webcrypto;
}
import * as openpgp from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { rawSign } from '../src/lib/identity/raw-sign';
import { fingerprintMatchesKey, signPubFromOpenPgpPublic, canonicalPubsFromArmoredPublicKey } from '../src/lib/identity/fingerprint';
import { base64ToUint8 } from '../src/lib/crypto/pq';
import { encryptToContact, decryptFromContact, type ContactKeys, type SenderKeys, type MyKeys } from '../src/lib/crypto/contact-message';

const MINT = process.env.SVRNTY_MINT
  ?? (process.env.SVRNTY_AGENT_DIR ? `${process.env.SVRNTY_AGENT_DIR}/mint.json` : undefined)
  ?? `${process.env.HOME}/devin-sandbox/.svrnty-agent/mint.json`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);

  if (cmd === 'sign') {
    const msg = new Uint8Array(readFileSync(0));   // binary-safe stdin
    const mint = JSON.parse(readFileSync(MINT, 'utf8'));   // touched, never printed
    const seed = base64ToUint8(mint.private.ed25519_seed);
    console.log(bytesToHex(rawSign(msg, seed)));
    return;
  }

  if (cmd === 'fp-check') {
    // cli.py passes temp-file paths for all three card fields (asc, kem, sigk)
    const [ascPath, kemPath, sigkPath, claimedFp] = rest;
    const asc = readFileSync(ascPath, 'utf8');
    const kem = readFileSync(kemPath, 'utf8').trim();
    const sigk = readFileSync(sigkPath, 'utf8').trim();
    const ok = await fingerprintMatchesKey(claimedFp, asc, {
      kem_public_key: kem,
      sig_public_key: sigk,
    });
    process.exit(ok ? 0 : 1);
  }

  if (cmd === 'fp-derive') {
    // sig-gate-reason-drift-vs-race-001: print the card's DERIVED canonical
    // fp — the SAME quad+sha256 basis fp-check verifies against — so the
    // consume gate can label a mismatch '<claimed>-vs-card:<derived>' and
    // a stale card (admission race) never again shares a label with a
    // genuine key rotation. Called only on the fp-check fail path.
    const [ascPath, kemPath, sigkPath] = rest;
    const asc = readFileSync(ascPath, 'utf8');
    const kem = readFileSync(kemPath, 'utf8').trim();
    const sigk = readFileSync(sigkPath, 'utf8').trim();
    const pubs = await canonicalPubsFromArmoredPublicKey(asc, kem, sigk);
    console.log(pubs.fingerprint);
    return;
  }

  if (cmd === 'pub') {
    const [ascPath] = rest;
    const asc = readFileSync(ascPath, 'utf8');
    const key = await openpgp.readKey({ armoredKey: asc });
    console.log(bytesToHex(signPubFromOpenPgpPublic(key)));
    return;
  }

  if (cmd === 'verify') {
    const [pubHex, sigHex] = rest;
    const msg = new Uint8Array(readFileSync(0));   // binary-safe stdin
    const ok = ed25519.verify(hexToBytes(sigHex), msg, hexToBytes(pubHex));
    process.exit(ok ? 0 : 1);
  }

  if (cmd === 'contact-encrypt') {
    // Encrypt stdin text to a contact card JSON file using svrnty's PQ-hybrid
    // Sign-then-Seal (X25519 + ML-KEM-1024 + Ed25519 + ML-DSA-87) -> produces
    // '-----BEGIN SVRNTY ENCRYPTED MESSAGE-----' for the svrnty PWA Decrypt tab!
    const [contactCardJsonPath] = rest;
    const msg = readFileSync(0, 'utf8');
    const contact = JSON.parse(readFileSync(contactCardJsonPath, 'utf8')) as ContactKeys;
    const mint = JSON.parse(readFileSync(MINT, 'utf8'));
    const sender: SenderKeys = {
      signSeed: base64ToUint8(mint.private.ed25519_seed),
      sigSecret: base64ToUint8(mint.private.mldsa87_secret),
      senderFingerprint: mint.public.durable_id,
    };
    const armored = await encryptToContact(msg, contact, sender);
    console.log(armored);
    return;
  }

  if (cmd === 'contact-decrypt') {
    // Decrypt stdin '-----BEGIN SVRNTY ENCRYPTED MESSAGE-----' sealed to this
    // cell's identity keys and verify the sender against optional contactCardJsonPath.
    const [senderCardJsonPath] = rest;
    const armored = readFileSync(0, 'utf8');
    const mint = JSON.parse(readFileSync(MINT, 'utf8'));
    const me: MyKeys = {
      x25519Sec: base64ToUint8(mint.private.x25519_sec),
      mlkem1024Sec: base64ToUint8(mint.private.mlkem1024_sec),
      x25519Pub: base64ToUint8(mint.private.x25519_pub),
      mlkem1024Pub: base64ToUint8(mint.private.mlkem1024_pub),
      myFingerprint: mint.public.durable_id,
    };
    const senderCard = senderCardJsonPath
      ? (JSON.parse(readFileSync(senderCardJsonPath, 'utf8')) as ContactKeys)
      : undefined;
    const res = await decryptFromContact(armored, me, senderCard);
    if (!res) {
      console.error('decrypt failed');
      process.exit(1);
    }
    console.log(JSON.stringify(res));
    return;
  }

  throw new Error(`unknown command: ${cmd}`);
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
