#!/usr/bin/env node
// STUB (tests first): the poll/withdraw authenticator. Refuses everything until the implementation commit.
export const L = 0n;
export const SMALL_ORDER_HEX = Object.freeze([]);
export function decodePoint(_b) { return null; }
export function isSmallOrder(_P) { return false; }
export function parseAuthRequest(_raw) { throw new Error('not implemented'); }
export async function verifyAuth(_req, _opts) { return { ok: false, reason: 'internal' }; }
