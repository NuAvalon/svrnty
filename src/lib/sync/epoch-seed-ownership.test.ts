// extractRawSign hands back the unlocked key's OWN seed buffer. The unlock cycle shares that key with the rest of the poll (it signs the poll and ack
// requests), so zeroing the extracted buffer would break the cycle's signing. The epoch seam therefore takes a COPY and zeroes the copy only.
// This pins the facts that decision rests on, so a later "tidy-up" that zeroes the original fails here and not in production.
// Run: npx tsx --test src/lib/sync/epoch-seed-ownership.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey, sign, createMessage, readSignature, verify, readKey } from 'openpgp';
import { extractRawSign } from '@/lib/identity/raw-sign';

async function signAndVerify(key: Awaited<ReturnType<typeof decryptKey>>, publicKey: string): Promise<boolean> {
  try {
    const sig = await sign({ message: await createMessage({ text: 'poll' }), signingKeys: key, detached: true, format: 'armored' });
    const v = await verify({ message: await createMessage({ text: 'poll' }), signature: await readSignature({ armoredSignature: sig as string }), verificationKeys: await readKey({ armoredKey: publicKey }) });
    await v.signatures[0].verified;
    return true;
  } catch {
    return false;
  }
}

test('extractRawSign returns the unlocked key\'s OWN buffer; zeroing it breaks the key\'s signing; zeroing a COPY does not', async () => {
  const passphrase = 'pw';
  // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime, and is what the app passes
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'a', email: 'a@t.test' }], passphrase, format: 'armored' });
  const key = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  assert.equal(await signAndVerify(key, publicKey), true, 'control: the unlocked key signs');

  const { seed } = extractRawSign(key);
  const copy = seed.slice();
  assert.equal(seed === (key as unknown as { keyPacket: { privateParams: { seed: Uint8Array } } }).keyPacket.privateParams.seed, true, 'the returned seed IS the key\'s own buffer');

  copy.fill(0);
  assert.equal(await signAndVerify(key, publicKey), true, 'zeroing a copy leaves the key usable');

  seed.fill(0);
  assert.equal(await signAndVerify(key, publicKey), false, 'zeroing the original makes the cycle\'s key unusable');
});
