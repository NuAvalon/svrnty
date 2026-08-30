import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DEFAULT_REACH_PREFS,
  effectiveBondReach,
  narrowerReach,
  parseReachPrefs,
  reachOrdinal,
  reachStatusLine,
  withEdgeReach,
  type ReachPrefs,
} from './reach-prefs';
import { prefsToOwnerReachPolicy } from './apollo-reach-seam';

describe('reach-prefs parse', () => {
  it('defaults on null / garbage', () => {
    assert.deepEqual(parseReachPrefs(null), {
      ...DEFAULT_REACH_PREFS,
      edgeReach: {},
    });
    assert.deepEqual(parseReachPrefs('{'), {
      ...DEFAULT_REACH_PREFS,
      edgeReach: {},
    });
  });

  it('accepts valid awaken + default + edges', () => {
    const raw = JSON.stringify({
      awakenCircle: true,
      defaultReach: 'l1',
      edgeReach: { aabbccdd: 'private', 'AA:BB:CC': 'l2' },
    });
    const p = parseReachPrefs(raw);
    assert.equal(p.awakenCircle, true);
    assert.equal(p.defaultReach, 'l1');
    assert.equal(p.edgeReach.aabbccdd, 'private');
    // AA:BB:CC → aabbcc; l2 vs default l1 narrows to l1
    assert.equal(p.edgeReach.aabbcc, 'l1');
  });

  it('narrows wider edge overrides to default on parse', () => {
    const p = parseReachPrefs(
      JSON.stringify({
        awakenCircle: true,
        defaultReach: 'l1',
        edgeReach: { deadbeef: 'l2' },
      })
    );
    assert.equal(p.edgeReach.deadbeef, 'l1');
  });
});

describe('narrow-only composition', () => {
  it('reachOrdinal private < l1 < l2', () => {
    assert.ok(reachOrdinal('private') < reachOrdinal('l1'));
    assert.ok(reachOrdinal('l1') < reachOrdinal('l2'));
  });

  it('narrowerReach picks the tighter level', () => {
    assert.equal(narrowerReach('private', 'l2'), 'private');
    assert.equal(narrowerReach('l2', 'l1'), 'l1');
    assert.equal(narrowerReach('l1', 'l1'), 'l1');
  });

  it('effectiveBondReach is private when circle asleep', () => {
    const prefs: ReachPrefs = {
      awakenCircle: false,
      defaultReach: 'l2',
      edgeReach: { abcdef: 'l1' },
    };
    assert.equal(effectiveBondReach(prefs, 'abcdef'), 'private');
  });

  it('effectiveBondReach uses override when awake', () => {
    const prefs: ReachPrefs = {
      awakenCircle: true,
      defaultReach: 'l2',
      edgeReach: { abcdef0123456789: 'private' },
    };
    assert.equal(effectiveBondReach(prefs, 'ABCDEF0123456789'), 'private');
    assert.equal(effectiveBondReach(prefs, 'ffffffffffff'), 'l2');
  });

  it('withEdgeReach refuse-widen via narrowerReach', () => {
    let prefs: ReachPrefs = {
      awakenCircle: true,
      defaultReach: 'l1',
      edgeReach: {},
    };
    prefs = withEdgeReach(prefs, 'aa', 'l2');
    assert.equal(prefs.edgeReach.aa, 'l1');
    prefs = withEdgeReach(prefs, 'aa', 'private');
    assert.equal(prefs.edgeReach.aa, 'private');
    prefs = withEdgeReach(prefs, 'aa', 'inherit');
    assert.equal(prefs.edgeReach.aa, undefined);
  });
});

describe('claim-honest status', () => {
  it('asleep copy mentions private + never inferred', () => {
    const line = reachStatusLine(DEFAULT_REACH_PREFS);
    assert.match(line, /asleep/i);
    assert.match(line, /private/i);
    assert.match(line, /never infers/i);
  });

  it('awake copy flags fleet gate + intent', () => {
    const line = reachStatusLine({
      awakenCircle: true,
      defaultReach: 'l1',
      edgeReach: { aa: 'private' },
    });
    assert.match(line, /awake/i);
    assert.match(line, /Trusted \(L1\)|L1/i);
    assert.match(line, /fleet-owned|consent intent/i);
  });
});

describe('apollo seam mapping', () => {
  it('prefsToOwnerReachPolicy mirrors fields (no gate invent)', () => {
    const prefs: ReachPrefs = {
      awakenCircle: true,
      defaultReach: 'l2',
      edgeReach: { ab: 'l1' },
    };
    assert.deepEqual(prefsToOwnerReachPolicy(prefs), {
      awakenCircle: true,
      defaultReach: 'l2',
      edgeReach: { ab: 'l1' },
    });
  });
});
