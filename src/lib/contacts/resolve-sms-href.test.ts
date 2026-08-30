import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { resolveSmsHref, resolveWhatsAppPhoneHref } from './resolve-sms-href';

describe('resolveSmsHref', () => {
  it('mirrors tel safety into sms:', () => {
    assert.equal(resolveSmsHref('+1 (415) 555-0123'), 'sms:+14155550123');
    assert.equal(resolveSmsHref('123'), null);
  });
});

describe('resolveWhatsAppPhoneHref', () => {
  it('builds wa.me from safe phones', () => {
    assert.equal(resolveWhatsAppPhoneHref('+14155550123'), 'https://wa.me/14155550123');
    assert.equal(resolveWhatsAppPhoneHref('nope'), null);
  });
});
