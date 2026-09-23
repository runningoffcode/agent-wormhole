"""Watchtower ingest hardening.

Three things, each of which was measured broken:

  * ``solana_rpc.py`` did not import at all. A helper had been inserted
    between a ``@dataclass`` decorator and the class it decorated, so the
    decorator wrapped the function and raised ``AttributeError`` at import
    time. No test imported the module, which is how it stayed that way.
  * The EVM client did ``float(retry_after)``, which raises ``ValueError`` on
    an RFC-9110 HTTP-date, and the only ``except`` in its retry loop catches
    ``requests.RequestException`` -- so a 429 carrying a date crashed the
    monitor outright.
  * ``CursorStore.load()`` promised that a corrupt file yields a fresh cursor
    and caught ``ValueError`` to keep that promise. Valid JSON that is not an
    object -- ``null``, a list, a string, a number, a bool -- raised
    ``AttributeError`` from ``.items()`` instead, which nothing caught.
"""
import dataclasses
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watchtower.ingest import evm_rpc, solana_rpc  # noqa: E402  (import IS the test)
from watchtower.ingest.base import Cursor, CursorStore, retry_after_seconds  # noqa: E402


class TheModulesImport(unittest.TestCase):
    def test_rpc_stats_is_a_dataclass_with_isolated_state(self):
        # If the decorator ever detaches from the class again, ``by_method``
        # becomes a shared class attribute and two clients count each other's
        # calls -- or, as it actually was, the module fails to import at all.
        self.assertTrue(dataclasses.is_dataclass(solana_rpc.RpcStats))
        self.assertTrue(dataclasses.is_dataclass(evm_rpc.RpcStats))
        a, b = solana_rpc.RpcStats(), solana_rpc.RpcStats()
        a.note("getSlot")
        self.assertEqual(a.by_method, {"getSlot": 1})
        self.assertEqual(b.by_method, {})


class RetryAfterBothForms(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(retry_after_seconds("5", 1.0), 5.0)

    def test_http_date_in_the_future(self):
        when = datetime.now(timezone.utc) + timedelta(seconds=30)
        got = retry_after_seconds(format_datetime(when, usegmt=True), 1.0)
        self.assertTrue(20.0 <= got <= 31.0, got)

    def test_http_date_in_the_past_falls_back(self):
        self.assertEqual(
            retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 7.0), 7.0
        )

    def test_garbage_negative_and_missing_fall_back(self):
        self.assertEqual(retry_after_seconds("soon", 3.0), 3.0)
        self.assertEqual(retry_after_seconds("-4", 3.0), 3.0)
        self.assertEqual(retry_after_seconds(None, 3.0), 3.0)
        self.assertEqual(retry_after_seconds("", 3.0), 3.0)


class _Resp:
    def __init__(self, status, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body or {}
        self.text = str(body)

    def json(self):
        return self._body


class _Session:
    """Scripted responses, in order. Counts calls so a test can prove the
    request after the 429 was actually made."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        return self._responses.pop(0)


class EvmClientSurvivesAnHttpDate(unittest.TestCase):
    def setUp(self):
        self._sleep = evm_rpc.time.sleep
        self.slept = []
        evm_rpc.time.sleep = lambda s: self.slept.append(s)

    def tearDown(self):
        evm_rpc.time.sleep = self._sleep

    def _client(self, responses):
        c = evm_rpc.EvmRPC(url="http://rpc.test", rps=0, max_retries=3)
        c._session = _Session(responses)
        return c

    def test_http_date_retry_after_does_not_raise(self):
        when = datetime.now(timezone.utc) + timedelta(seconds=2)
        c = self._client([
            _Resp(429, {"retry-after": format_datetime(when, usegmt=True)}),
            _Resp(200, body={"jsonrpc": "2.0", "id": 1, "result": "0x1"}),
        ])
        method = next(iter(c.READ_ONLY_METHODS))
        self.assertEqual(c.call(method, []), "0x1")
        self.assertEqual(c._session.calls, 2)
        self.assertTrue(self.slept and 0.0 < self.slept[0] <= 60.0, self.slept)

    def test_integer_retry_after_still_works(self):
        # CONTROL: the form that always worked must keep working.
        c = self._client([
            _Resp(429, {"retry-after": "3"}),
            _Resp(200, body={"jsonrpc": "2.0", "id": 1, "result": "0x2"}),
        ])
        method = next(iter(c.READ_ONLY_METHODS))
        self.assertEqual(c.call(method, []), "0x2")
        self.assertEqual(self.slept[0], 3.0)


class CorruptCursorYieldsFresh(unittest.TestCase):
    def test_every_non_object_json_shape(self):
        d = tempfile.mkdtemp()
        for bad in ("null", "[]", '"x"', "1", "true", "[1, 2]"):
            with self.subTest(bad=bad):
                p = os.path.join(d, "cursor.json")
                Path(p).write_text(bad, encoding="utf-8")
                cur = CursorStore(p).load("base")
                self.assertIsInstance(cur, Cursor)
                self.assertEqual(cur.source, "base")

    def test_control_a_real_cursor_round_trips(self):
        # Without this, a load() that ALWAYS returned a fresh cursor would pass
        # the test above while losing everyone's place on every restart.
        d = tempfile.mkdtemp()
        store = CursorStore(os.path.join(d, "cursor.json"))
        store.save(Cursor(source="base"))
        self.assertEqual(store.load("base").source, "base")


if __name__ == "__main__":
    unittest.main()
