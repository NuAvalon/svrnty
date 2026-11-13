// Bundled and served same-origin by e2e/csp-script-lock.spec.ts, so it runs under the page's real policy.
import { readPrivateKey, decryptKey } from 'openpgp';

(window as unknown as { __probe: (armored: string, passphrase: string) => Promise<unknown> }).__probe = async (armored, passphrase) =>
  decryptKey({ privateKey: await readPrivateKey({ armoredKey: armored }), passphrase });
