// src/lib/contacts/safe-contact-link.test.ts
// CUR-3 · I-10a scheme-allowlist floor for tap-to-open contact methods.
// Run: npx tsx --test src/lib/contacts/safe-contact-link.test.ts

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveEmailHref,
  resolvePhoneHref,
  resolveUrlHref,
  resolveHandleHref,
  sanitizeContactMethodText,
  safeEmailLink,
  safePhoneLink,
  safeUrlLink,
} from './safe-contact-link';

describe('sanitizeContactMethodText', () => {
  test('strips control chars and bounds length', () => {
    assert.equal(sanitizeContactMethodText('hi\u0000there'), 'hithere');
    assert.equal(sanitizeContactMethodText('a'.repeat(300)).length, 200);
  });
  test('rejects non-strings as empty', () => {
    assert.equal(sanitizeContactMethodText(null), '');
    assert.equal(sanitizeContactMethodText(42 as unknown as string), '');
  });
});

describe('resolveEmailHref', () => {
  test('mailto for plain email', () => {
    assert.equal(resolveEmailHref('ada@analytical.engine'), 'mailto:ada@analytical.engine');
  });
  test('rejects scheme smuggle', () => {
    assert.equal(resolveEmailHref('javascript:alert(1)'), null);
    assert.equal(resolveEmailHref('foo@bar'), null);
  });
});

describe('resolvePhoneHref', () => {
  test('tel for E.164-ish numbers', () => {
    assert.equal(resolvePhoneHref('+1 (415) 555-0123'), 'tel:+14155550123');
    assert.equal(resolvePhoneHref('415-555-0123'), 'tel:4155550123');
  });
  test('rejects too-short / garbage', () => {
    assert.equal(resolvePhoneHref('123'), null);
    assert.equal(resolvePhoneHref('not-a-phone'), null);
  });
});

describe('resolveUrlHref — I-10a allowlist', () => {
  test('https personal urls pass', () => {
    assert.equal(resolveUrlHref('https://analytical.engine/~ada'), 'https://analytical.engine/~ada');
  });
  test('bare host gets https', () => {
    assert.equal(resolveUrlHref('signal.me/#p/+15551234567'), 'https://signal.me/#p/+15551234567');
  });
  test('app deep-link hosts pass', () => {
    assert.ok(resolveUrlHref('https://wa.me/15551234567')?.startsWith('https://wa.me/'));
    assert.ok(resolveUrlHref('https://t.me/a_turing')?.startsWith('https://t.me/'));
  });
  test('NEVER javascript: or data:', () => {
    assert.equal(resolveUrlHref('javascript:alert(1)'), null);
    assert.equal(resolveUrlHref('data:text/html,hi'), null);
    assert.equal(resolveUrlHref('JAVASCRIPT:alert(1)'), null);
  });
  test('rejects unknown schemes', () => {
    assert.equal(resolveUrlHref('ftp://evil.example/x'), null);
    assert.equal(resolveUrlHref('vbscript:msg'), null);
  });
  test('rejects proto-relative //', () => {
    assert.equal(resolveUrlHref('//evil.example/x'), null);
  });
  test('mailto:/tel: via URL path still gated', () => {
    assert.equal(resolveUrlHref('mailto:ada@analytical.engine'), 'mailto:ada@analytical.engine');
    assert.equal(resolveUrlHref('tel:+14155550123'), 'tel:+14155550123');
    assert.equal(resolveUrlHref('mailto:javascript:alert(1)'), null);
  });
});

describe('resolveHandleHref', () => {
  test('signal phone → signal.me #p', () => {
    assert.equal(resolveHandleHref('signal', '+15551234567'), 'https://signal.me/#p/+15551234567');
  });
  test('signal username → signal.me #eu', () => {
    assert.equal(resolveHandleHref('signal', '@ada.lovelace'), 'https://signal.me/#eu/ada.lovelace');
  });
  test('telegram → t.me', () => {
    assert.equal(resolveHandleHref('telegram', '@a_turing'), 'https://t.me/a_turing');
  });
  test('whatsapp → wa.me', () => {
    assert.equal(resolveHandleHref('whatsapp', '+1 555 123 4567'), 'https://wa.me/15551234567');
  });
  test('unknown platform stays inert', () => {
    assert.equal(resolveHandleHref('icq', '12345'), null);
    assert.equal(resolveHandleHref('custom', 'javascript:alert(1)'), null);
  });
  test('email_alt → mailto', () => {
    assert.equal(resolveHandleHref('email_alt', 'shannon@theory.info'), 'mailto:shannon@theory.info');
  });
});

describe('safe*Link wrappers', () => {
  test('poisoned url label is sanitized; href null', () => {
    const s = safeUrlLink('javascript:alert(1)');
    assert.equal(s.href, null);
    assert.equal(s.label, 'javascript:alert(1)'); // text ok; not a link
  });
  test('good email', () => {
    const s = safeEmailLink('a@b.co');
    assert.equal(s.href, 'mailto:a@b.co');
  });
  test('good phone', () => {
    const s = safePhoneLink('+14155550123');
    assert.equal(s.href, 'tel:+14155550123');
  });
});
