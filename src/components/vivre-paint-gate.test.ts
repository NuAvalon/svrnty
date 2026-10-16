import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('inbound distress paint is Flint-gated OFF', () => {
  it('isInboundDistressPaintLive is false until the emit-path wires a real received signal', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const gate = readFileSync(join(dir, 'vivre-paint-gate.ts'), 'utf8');
    assert.match(gate, /export function isInboundDistressPaintLive/);
    assert.match(gate, /return false/);
    assert.match(gate, /export function paintInboundDistress/);
    assert.doesNotMatch(gate, /return true/);
  });

  it('VivreBurn / StarEmber / VivreCaution no-op the paint — galaxy is not gutted', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(dir, 'VivreBurn.tsx'), 'utf8');
    assert.match(src, /isInboundDistressPaintLive/);
    assert.match(src, /if \(!isInboundDistressPaintLive\(\)\) return null/);
    assert.match(src, /export function VivreBurn/);
    assert.match(src, /export function StarEmber/);
    assert.match(src, /export function VivreCaution/);
  });
});
