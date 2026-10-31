/**
 * devin-comm builds its owner with the custody helper, so the ML-KEM secret (custody ①) reaches the consumer.
 *
 * 10-30 incident: scripts/devin-comm.ts kept its own ownerFrom() that never set kemSecretKey. With no hybrid
 * open-material, every poller could open only classical notes; a peer whose client seals hybrid (Mneme, since
 * ~10-25) was refused at every seam. On the old release those refusals were silently ack-deleted. The library
 * already had custodyToHeadlessOwner (custody-owner.test.ts pins that it maps kemSecretKey and that the owner
 * derives hybrid secrets); this pins that the CLI actually uses it. Source check, because devin-comm.ts runs
 * main() on import.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const code = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
const SRC = code(readFileSync(join(process.cwd(), 'scripts/devin-comm.ts'), 'utf8'));

test('devin-comm builds its owner via custodyToHeadlessOwner (threads kemSecretKey)', () => {
  assert.match(SRC, /import\s*\{[^}]*\bcustodyToHeadlessOwner\b[^}]*\}\s*from\s*'[^']*custody-owner'/);
  const body = SRC.match(/function ownerFrom\([^)]*\)[^{]*\{([\s\S]*?)\n\}/);
  assert.ok(body, 'ownerFrom still exists as the one owner builder');
  assert.match(body![1], /custodyToHeadlessOwner\(/, 'ownerFrom delegates to the custody helper');
});

test('devin-comm builds no owner object by hand (no second copy that can drop a field)', () => {
  assert.doesNotMatch(SRC, /privateKeyArmored:\s*a\.private/, 'a hand-built owner literal is back');
});
