// Run: npx tsx --test src/components/relay/relay-holds-wiring.test.ts
// SOURCE-SHAPE pins (not behaviour: the behaviour is run in a real browser by e2e/relay-holds.spec.ts): what the panel's component may and may not contain, and where it is mounted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const DIR = 'src/components/relay';
const strip = (s: string): string => s.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
const COMPONENT = strip(readFileSync(`${DIR}/RelayHoldsSection.tsx`, 'utf8'));
const FRONT = readFileSync('src/components/SoverentityFrontend.tsx', 'utf8');

test('RHW1 THE PANEL SENDS NOTHING ITSELF: the component and the view-model import no network, relay, signing or storage module and call no fetch; only the port, the copy and the gate', () => {
  assert.doesNotMatch(COMPONENT, /\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|\/api\/|localStorage|sessionStorage|indexedDB/);
  const imports = [...COMPONENT.matchAll(/from '([^']+)'/g)].map((m) => m[1]);
  for (const i of imports) assert.ok(['react', '@/components/recovery/solar-ember', '@/components/ui/CardActionMenu', '@/lib/claim-gates'].includes(i) || i.startsWith('./relay-holds-'), `unexpected import ${i}`);
  for (const f of readdirSync(DIR).filter((n) => /^relay-holds-(model|view-model|copy|refresh)\.ts$/.test(n))) {
    const src = strip(readFileSync(`${DIR}/${f}`, 'utf8'));
    assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|localStorage|sessionStorage|indexedDB|allowed-revoke|reconcile-allowed-hook|client-store/, f);
    // the sync module is allowed in ONLY for the pure predicate and its types: nothing that signs or sends
    for (const m of src.matchAll(/import \{([^}]*)\} from '@\/lib\/sync\/allowed-sync';/g)) {
      const names = m[1].split(',').map((x) => x.trim().replace(/^type\s+/, '')).filter(Boolean);
      for (const n of names) assert.ok(['allowedRowShouldExist', 'AllowedListResult', 'PeerConsent'].includes(n), `${f}: ${n} may not be imported from the sync module`);
    }
  }
});

test('RHW2 NO FINGERPRINT ON SCREEN: a fingerprint is never a JSX child, an attribute value or a test id; rows are keyed and named by position', () => {
  assert.doesNotMatch(COMPONENT, />\s*\{[^}]*\bfp\b[^}]*\}\s*</, 'no fp as a child');
  assert.doesNotMatch(COMPONENT, /data-testid=\{[^}]*\bfp\b/, 'no fp in a test id');
  assert.doesNotMatch(COMPONENT, /\btitle=\{[^}]*\bfp\b|\bhref=|\bid=\{[^}]*\bfp\b/, 'no fp in an attribute');
});

test('RHW3 the entry is shown only while the PSI gate is live: nothing is rendered, and no read is made, while it is dark (no reads exist then, and "could not check" would mislead)', () => {
  assert.match(COMPONENT, /gate: \(\) => boolean|gate\?: \(\) => boolean/);
  assert.match(COMPONENT, /if \(!gate\(\)\) return null;/);
  assert.match(COMPONENT, /isPSIDiscoveryLive/);
});

test('RHW4 opening makes no request: the component reads through loadPanel only, and the one place that asks the relay again is the refresh button, behind canRefresh', () => {
  assert.match(COMPONENT, /loadPanel\(port\)/);
  assert.match(COMPONENT, /canRefresh\(/);
  assert.equal((COMPONENT.match(/port\.refresh\(\)/g) ?? []).length, 2, 'exactly two callers of the check: the refresh button and a CONFIRMED repair');
  assert.match(COMPONENT, /repairRow\(/);
});

test('RHW5 the warning is rendered for EVERY Repair row, before its button, and the button label is the copy owner\'s', () => {
  const w = COMPONENT.indexOf('{RELAY_REPAIR_WARNING}');
  const b = COMPONENT.indexOf('{RELAY_REPAIR_BUTTON}');
  assert.ok(w > 0 && b > 0 && w < b, 'the warning comes before the button in the row');
  assert.match(COMPONENT, /RELAY_REFRESH_BUTTON/);
});

test('RHW6 MOUNT: the section sits right after "Held messages" in Lenses & vault, behind the same fingerprint condition, through the owner-keyed mounts', () => {
  assert.match(FRONT, /import \{ RelayHoldsMount \} from '@\/components\/relay\/RelayHoldsMount';/);
  assert.match(FRONT, /import \{ HeldMessagesMount \} from '@\/components\/held\/HeldMessagesMount';/);
  const held = FRONT.indexOf('<HeldMessagesMount ');
  const relay = FRONT.indexOf('<RelayHoldsMount ');
  assert.ok(held > 0 && relay > held, 'after the held-messages entry');
  assert.match(FRONT.slice(relay - 60, relay + 160), /identity\?\.identity\?\.fingerprint \? <RelayHoldsMount ownerFingerprint=\{identity\.identity\.fingerprint\} \/> : null/);
  assert.equal((FRONT.match(/<RelayHoldsMount /g) ?? []).length, 1, 'mounted once');
});

test('RHW7 the mount the app uses is KEYED by owner and makes its port once per owner, so an open panel cannot carry one owner\'s state to the next (the behaviour is run in a real browser by e2e/owner-switch.spec.ts); the frontend holds no bare section', () => {
  const mount = strip(readFileSync(`${DIR}/RelayHoldsMount.tsx`, 'utf8'));
  assert.match(mount, /<RelayHoldsSection key=\{ownerFingerprint\} /);
  assert.match(mount, /useMemo\(\(\) => makePort\(ownerFingerprint\), \[makePort, ownerFingerprint\]\)/);
  assert.doesNotMatch(strip(FRONT), /<RelayHoldsSection\b/);
});
