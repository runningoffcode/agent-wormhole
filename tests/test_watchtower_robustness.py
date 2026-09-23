"""AW-63. Two of the watchtower defects: it crashed where it documents
degradation, and published the canary it exists to keep secret.

A `Retry-After: <HTTP-date>` — RFC-9110 legal and routine from CDNs in front of
RPC endpoints — reached `float()` and raised ValueError out of the RPC client.
`except RpcError` does not catch that, so the monitor DIED instead of backing
off.

And `scan_text_for_canaries` redacted only the FIRST occurrence of the ONE
address it matched, so a memo naming a canary twice — or naming two canaries —
published the address in the evidence. The canary is the thing the module
exists to keep secret: once published, the trap is spent and the attacker knows
which address is watched.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from watchtower.canary import Canary, CanaryRegistry, scan_text_for_canaries

# Imported, not extracted. This used to read solana_rpc.py as TEXT and exec
# the parser out of it by string-slicing, so the test would not need
# `requests` installed. The side effect: the parser was "tested" while the
# module it lived in did not import at all, and nothing noticed. The parser
# now lives in base.py, which imports nothing beyond the standard library, so
# the original reason is gone and the import is the honest form.
from watchtower.ingest.base import retry_after_seconds

A = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
B = "9yLMug3DX98e08UYKTEqcE6kClifUrB94UASvKptbBtV"


class RetryAfter(unittest.TestCase):
    def test_delta_seconds_is_honoured(self):
        self.assertEqual(retry_after_seconds("30", 7.0), 30.0)

    def test_an_http_date_does_not_raise(self):
        # The shape that killed the monitor.
        when = (datetime.now(timezone.utc) + timedelta(seconds=45)).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        self.assertGreater(retry_after_seconds(when, 7.0), 30.0)

    def test_anything_unreadable_falls_back_to_our_own_backoff(self):
        # A header we cannot read is a reason to use our own schedule, not a
        # reason to stop monitoring.
        past = (datetime.now(timezone.utc) - timedelta(seconds=45)).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        for value in ("soon", "", None, "-5", past, 30, []):
            self.assertEqual(retry_after_seconds(value, 7.0), 7.0, repr(value))


class CanaryRedaction(unittest.TestCase):
    def setUp(self):
        self.registry = CanaryRegistry(
            [Canary(address=A, label="a"), Canary(address=B, label="b")]
        )

    def _evidence(self, text: str) -> str:
        hits = scan_text_for_canaries(text, "sig", self.registry)
        return " ".join(str(h.evidence) for h in hits)

    def test_a_single_mention_is_redacted(self):
        self.assertNotIn(A, self._evidence(f"send to {A} now"))

    def test_a_SECOND_mention_is_redacted_too(self):
        # The defect: only the first occurrence was replaced.
        evidence = self._evidence(f"send to {A} and also {A} again")
        self.assertNotIn(A, evidence)
        self.assertIn("<canary>", evidence)

    def test_a_DIFFERENT_canary_in_the_same_text_is_redacted(self):
        # Only the matched address was replaced, so a second canary in the
        # same memo was published verbatim.
        evidence = self._evidence(f"pay {A} then {B}")
        self.assertNotIn(A, evidence)
        self.assertNotIn(B, evidence)

    def test_the_hit_still_identifies_which_canary_fired(self):
        # Redaction must not cost the signal: the operator has to know which
        # trap was tripped. That lives on the hit, not in published evidence.
        hits = scan_text_for_canaries(f"send to {A}", "sig", self.registry)
        self.assertEqual(hits[0].canary.address, A)


if __name__ == "__main__":
    unittest.main()
