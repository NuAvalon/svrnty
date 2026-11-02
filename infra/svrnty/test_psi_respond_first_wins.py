"""PSI /respond: the first answer for a session is the one that is kept.

The session lookup in psi_respond only selects a session that is still pending, but the write that stores the answer
used to be keyed on the session id alone and never looked at how many rows it changed. Two answers that both passed the
lookup before either wrote would both be stored, the later one replacing the earlier. Nothing interleaves them today
(one worker, no await between the two statements); these tests pin the behaviour so a later change cannot reopen it.

The competing answer is made to land between the lookup and the write by wrapping the connection the handler uses: when
the handler is about to run its UPDATE, a second connection first stores another answer and commits.

Run (from infra/svrnty, with the packages pinned in the Dockerfile plus pytest and httpx installed):
    python -m pytest test_psi_respond_first_wins.py -q
"""
import sqlite3

# Imported first: it points SATELLITE_DATA at a scratch directory before satellite is imported (w is its fixture).
from test_psi_session_parity import w, same  # noqa: F401, I001
import satellite


def stored(sid: str):
    db = sqlite3.connect(str(satellite.DB_PATH))
    try:
        return db.execute("SELECT status, responder_blinded FROM psi_sessions WHERE session_id = ?", (sid,)).fetchone()
    finally:
        db.close()


def notices_to(fp: str) -> int:
    db = sqlite3.connect(str(satellite.DB_PATH))
    try:
        return db.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender_fingerprint = 'satellite:psi'",
                          (fp,)).fetchone()[0]
    finally:
        db.close()


class Interleave:
    """A connection wrapper that lets one other answer land just before this connection's UPDATE of the session."""

    def __init__(self, real, sid):
        self._real, self._sid, self.fired = real, sid, False

    def execute(self, sql, params=()):
        if not self.fired and sql.lstrip().startswith("UPDATE psi_sessions"):
            self.fired = True
            other = sqlite3.connect(str(satellite.DB_PATH))
            other.execute("UPDATE psi_sessions SET responder_blinded = ?, reblinded_initiator = ?, status = 'responded' "
                          "WHERE session_id = ?", ('["WINNER"]', '["WINNER"]', self._sid))
            other.commit()
            other.close()
        return self._real.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_a_second_answer_in_a_later_request_is_refused_and_the_first_is_kept(w):
    g = w.genuine()
    assert w.respond(w.a, g).status_code == 200
    first = stored(g)
    again = w.respond(w.a, g)
    assert again.status_code == 404
    assert stored(g) == first
    assert notices_to(w.b.fp) == 1


def test_an_answer_that_loses_to_one_landing_between_its_lookup_and_its_write_is_refused(w, monkeypatch):
    g = w.genuine()
    real_get_db = satellite.get_db
    monkeypatch.setattr(satellite, "get_db", lambda: Interleave(real_get_db(), g))
    r = w.respond(w.a, g)
    # The answer that landed first is the stored one; the late one is refused like an answer to a closed session.
    assert stored(g) == ("responded", '["WINNER"]')
    assert r.status_code == 404
    assert notices_to(w.b.fp) == 0


def test_the_refused_late_answer_looks_like_an_answer_to_a_session_that_does_not_exist(w, monkeypatch):
    u, g = w.unmade(), w.genuine()
    real_get_db = satellite.get_db
    monkeypatch.setattr(satellite, "get_db", lambda: Interleave(real_get_db(), g))
    late = w.respond(w.a, g)
    monkeypatch.setattr(satellite, "get_db", real_get_db)
    assert same(late, g) == same(w.respond(w.a, u), u)
