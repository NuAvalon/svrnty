import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TRUST_RECIPE_COPY } from '../../lib/trust/trust-recipe';
import { VERIFY_SHEET_COPY, boundVerifyName } from './verify-copy';

describe('verify sheet copy — claim-honesty', () => {
  it('mismatch interpolates only a bounded name, never scan text', () => {
    assert.equal(
      VERIFY_SHEET_COPY.mismatch('Ada'),
      "this isn't the key you have for Ada — do not verify",
    );
    const poisoned = `Ada\u0000${'x'.repeat(200)}\u202e`;
    const msg = VERIFY_SHEET_COPY.mismatch(poisoned);
    assert.equal(msg.includes('\u0000'), false);
    assert.equal(msg.includes('\u202e'), false);
    assert.ok(msg.length < 120);
    assert.match(msg, /do not verify/);
  });

  it('bounds hostile display names', () => {
    assert.equal(boundVerifyName(''), '');
    assert.equal(boundVerifyName('  Ada  '), 'Ada');
    assert.ok(boundVerifyName('é'.repeat(80)).length <= 64);
  });

  it('uses recipe verify strings verbatim and does not claim a public badge', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const sheet = readFileSync(join(dir, 'VerifySheet.tsx'), 'utf8');
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifyWhy/);
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifyPrivate/);
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifyInPerson/);
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifyOtherChannel/);
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifyConfirm/);
    assert.match(sheet, /TRUST_RECIPE_COPY\.verifiedHere/);
    assert.equal(TRUST_RECIPE_COPY.verifyWhy, "Anyone can use my name. They can't forge this key.");
    assert.doesNotMatch(sheet, /dangerouslySetInnerHTML/);
    const blob = JSON.stringify({
      title: VERIFY_SHEET_COPY.title,
      scanTheirQr: VERIFY_SHEET_COPY.scanTheirQr,
      confirmOther: VERIFY_SHEET_COPY.confirmOther,
    }).toLowerCase();
    assert.equal(blob.includes('post-quantum'), false);
    assert.equal(blob.includes('end-to-end'), false);
    assert.equal(blob.includes('social recovery'), false);
  });
});
