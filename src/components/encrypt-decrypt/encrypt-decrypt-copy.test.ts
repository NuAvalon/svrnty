import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ENCDEC_COPY } from './encrypt-decrypt-copy';

describe('encrypt-decrypt copy — claim-honesty', () => {
  it('never uses Send as a verb (this tab does not send)', () => {
    const blob = JSON.stringify(ENCDEC_COPY);
    assert.doesNotMatch(blob, /\bSend\b/);
    assert.equal(ENCDEC_COPY.copyCiphertext, 'Copy ciphertext');
    assert.match(ENCDEC_COPY.intro, /does not send/);
    assert.match(ENCDEC_COPY.notSent('Ada'), /not sent/);
  });

  it('does not claim post-quantum or end-to-end', () => {
    const blob = JSON.stringify(ENCDEC_COPY).toLowerCase();
    assert.equal(blob.includes('post-quantum'), false);
    assert.equal(blob.includes('end-to-end'), false);
    assert.equal(blob.includes('pq-hybrid'), false);
  });

  it('uses the fleet-specified verified / not-verified lines', () => {
    assert.equal(
      ENCDEC_COPY.verifiedFrom('Ada', 'abcd'),
      'Verified from Ada · abcd',
    );
    assert.equal(ENCDEC_COPY.senderNotVerified, 'sender NOT cryptographically verified');
  });

  it('keeps decrypt failures as fixed non-leaky strings', () => {
    assert.match(ENCDEC_COPY.decryptFailed, /could not be opened/);
    assert.doesNotMatch(ENCDEC_COPY.decryptFailed, /secret|seed|key material/i);
  });

  it('tab source has Copy ciphertext and no Send / PQ claims', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const tab = readFileSync(join(dir, 'EncryptDecryptTab.tsx'), 'utf8');
    const copy = readFileSync(join(dir, 'encrypt-decrypt-copy.ts'), 'utf8');
    const blob = `${tab}\n${copy}`;
    assert.equal(ENCDEC_COPY.copyCiphertext, 'Copy ciphertext');
    assert.match(tab, /ENCDEC_COPY\.copyCiphertext/);
    assert.doesNotMatch(blob, /['"`]Send['"`]/);
    assert.doesNotMatch(tab, /dangerouslySetInnerHTML/);
    const visible = JSON.stringify(ENCDEC_COPY).toLowerCase();
    assert.equal(visible.includes('post-quantum'), false);
    assert.equal(visible.includes('end-to-end'), false);
  });
});
