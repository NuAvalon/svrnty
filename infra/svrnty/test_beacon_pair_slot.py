"""A pair's slot belongs to the pair.

A slot is derived from the shared secret of two parties AND the two public points, so a deposit made by anyone else lands in a slot of
its own. These tests run real proofs through the real verifier (node + the pinned snarkjs) and the real matcher, with checked-in
THROWAWAY fixtures (beacon-verifier/fixtures/pair-slot/README.md), and pin what a third party cannot do:

  * a valid proof from a party outside the pair is accepted into ITS OWN slot, forms no bond with the pair, and its answer is the
    same bytes whether or not the pair has deposited;
  * the same proof moved to the pair's slot (or given the pair's nullifier or poll key) is refused, and no deposit is stored for it;
  * a counterpart key handed over so that the outside party holds the pair's shared secret (checked when the fixtures were generated) still does not
    reach the pair's slot.

The fixtures: A and B are the pair. C is a third party proving against B with its own secret. H is a third party that was handed the
counterpart key that makes its shared secret equal the pair's (checked when the fixtures were generated; this file shows only that its slot differs).
"""
import json
import os
import sqlite3
from contextlib import closing

import pytest

import beacon_centurion as bc

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "beacon-verifier", "fixtures", "pair-slot")
NODE = os.environ.get("BEACON_NODE", "node")
E, SLOT, NULL, POLL = 0, 1, 2, 3   # positions in the public signals


def _load(who):
    with open(os.path.join(FIX, f"proof_{who}.json")) as p, open(os.path.join(FIX, f"public_{who}.json")) as s:
        return json.load(p), json.load(s)


def _body(who, public=None):
    proof, signals = _load(who)
    return json.dumps({"proof": proof, "publicSignals": signals if public is None else public}).encode()


EPOCH = int(_load("A")[1][E])


def _centurion(tmp_path, name="p.db"):
    return bc.Centurion(str(tmp_path / name), vkey_path=os.path.join(FIX, "vkey.json"), node=NODE,
                        clock=lambda: EPOCH * bc.EPOCH_SECONDS + 5, per_epoch_cap=10, ip_per_minute=100, timeout_s=60)


def _rows(c, sql):
    with closing(sqlite3.connect(c.db_path)) as db:
        return db.execute(sql).fetchall()


def _slots_held(c):
    return sorted(r[0] for r in _rows(c, "SELECT slot FROM beacon_deposits"))


def test_the_two_parties_of_one_pair_form_one_bond(tmp_path):
    """Control: the fixtures are valid and the matcher does join a pair, so the tests below cannot pass only because the matcher matches nothing."""
    c = _centurion(tmp_path)
    a, b = _load("A")[1], _load("B")[1]
    assert a[SLOT] == b[SLOT] and a[NULL] != b[NULL]
    assert c.deposit(_body("A"), "a") == bc.ACCEPTED
    assert c.deposit(_body("B"), "b") == bc.ACCEPTED
    assert [(r[0], r[1]) for r in _rows(c, "SELECT slot, count(*) FROM beacon_matches GROUP BY slot")] == [(a[SLOT], 1)]


def test_a_party_outside_the_pair_lands_in_its_own_slot_and_forms_no_bond(tmp_path):
    a, outside = _load("A")[1], _load("C")[1]
    assert a[SLOT] != outside[SLOT]
    c = _centurion(tmp_path)
    assert c.deposit(_body("A"), "a") == bc.ACCEPTED
    assert c.deposit(_body("C"), "c") == bc.ACCEPTED
    assert _slots_held(c) == sorted([a[SLOT], outside[SLOT]])     # one row in each slot: the pair's slot holds only the pair's own row
    assert _rows(c, "SELECT * FROM beacon_matches") == []
    assert _rows(c, "SELECT * FROM beacon_security_alarms") == []


def test_the_outside_partys_answer_is_the_same_bytes_with_or_without_the_pair_present(tmp_path):
    with_pair = _centurion(tmp_path, "with.db")
    assert with_pair.deposit(_body("A"), "a") == bc.ACCEPTED
    without = _centurion(tmp_path, "without.db")
    assert with_pair.deposit(_body("C"), "c") == without.deposit(_body("C"), "c")


@pytest.mark.parametrize("position,name", [(SLOT, "the pair's slot"), (NULL, "another nullifier"), (POLL, "another poll key")])
def test_a_valid_outside_proof_moved_to_the_pairs_values_is_refused_and_stores_nothing(tmp_path, position, name):
    a, b, outside = _load("A")[1], _load("B")[1], _load("C")[1]
    moved = list(outside)
    moved[position] = {SLOT: a[SLOT], NULL: b[NULL], POLL: b[POLL]}[position]
    assert moved != outside
    c = _centurion(tmp_path)
    assert c.deposit(_body("A"), "a") == bc.ACCEPTED
    answer = json.loads(c.deposit(_body("C", moved), "c"))
    assert answer["status"] == "refused", name
    assert _slots_held(c) == [a[SLOT]]
    assert _rows(c, "SELECT * FROM beacon_matches") == []
    assert _rows(c, "SELECT * FROM beacon_security_alarms") == []
    assert c.deposit(_body("C"), "c") == bc.ACCEPTED                # control: the unmoved proof is valid, so the refusal was the move


def test_a_counterpart_key_handed_over_does_not_put_an_outside_party_in_the_pairs_slot(tmp_path):
    """H holds the pair's shared secret (the counterpart key was chosen so; checked when the fixtures were generated), but the slot also covers the two public points."""
    a, handed = _load("A")[1], _load("H")[1]
    assert a[SLOT] != handed[SLOT]
    c = _centurion(tmp_path)
    assert c.deposit(_body("A"), "a") == bc.ACCEPTED
    assert c.deposit(_body("H"), "h") == bc.ACCEPTED
    assert _slots_held(c) == sorted([a[SLOT], handed[SLOT]])
    assert _rows(c, "SELECT * FROM beacon_matches") == []
    assert _rows(c, "SELECT * FROM beacon_security_alarms") == []
