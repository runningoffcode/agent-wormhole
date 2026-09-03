"""Address provenance — the ledger the payment guard reads at signing time.

The properties that matter:
  1. The attack shape is captured: an address arriving in prose is recorded as
     `read`, and ONLY quote/operator origins clear it.
  2. The legitimate-merchant exemption works: a payTo inside an x402-shaped
     body earns `quote`, so reading a 402 response does not taint the merchant
     you are about to legitimately pay — but an address in the same body's
     description does NOT inherit that trust.
  3. Extraction is strict enough to be usable: 64-byte signatures and
     non-base58 look-alikes are not recorded as Solana addresses.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from wormhole.addresses import (
    classify,
    extract_addresses,
    quote_payees,
    record,
    record_from_text,
)

EVM = "0x2222222222222222222222222222222222222222"
SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # 32-byte base58
SIG64 = "5" * 87  # signature-length base58: decodes to way over 32 bytes


class TestExtraction(unittest.TestCase):
    def test_finds_both_shapes(self):
        text = f"send funds to {EVM} or {SOL} today"
        found = extract_addresses(text)
        self.assertIn(EVM, found)
        self.assertIn(SOL, found)

    def test_evm_is_lowercased_because_case_is_only_checksum(self):
        found = extract_addresses("pay 0xABCDEFabcdef0123456789ABCDEFabcdef012345 now")
        self.assertIn("0xabcdefabcdef0123456789abcdefabcdef012345", found)

    def test_signature_length_base58_is_not_an_address(self):
        self.assertEqual(extract_addresses(f"tx {SIG64} confirmed"), set())

    def test_non_base58_lookalike_is_ignored(self):
        # contains 0/O/I/l — not in the alphabet, so the regex cannot match a
        # full 32+ run and the decode gate never even fires.
        self.assertEqual(extract_addresses("O0Il" * 12), set())


class TestQuoteExemption(unittest.TestCase):
    def test_payto_in_402_body_is_a_quote_origin(self):
        body = json.dumps({
            "x402Version": 1,
            "accepts": [{"scheme": "exact", "network": "base",
                         "payTo": EVM, "amount": "1000000",
                         "description": f"support wallet {SOL}"}],
        })
        self.assertEqual(quote_payees(body), {EVM})

    def test_description_address_does_not_inherit_quote_trust(self):
        body = json.dumps({
            "accepts": [{"payTo": EVM, "description": f"also pay {SOL}"}],
        })
        with TemporaryDirectory() as d:
            p = Path(d) / "ledger.jsonl"
            record_from_text(body, via="test", path=p)
            kinds = classify(path=p)
            self.assertIn(EVM, kinds["trusted"])
            self.assertIn(SOL, kinds["tainted"])

    def test_non_x402_json_gets_no_exemption(self):
        body = json.dumps({"note": "refund", "payTo_like": EVM})
        self.assertEqual(quote_payees(body), set())


class TestLedger(unittest.TestCase):
    def test_read_only_is_tainted_until_upgraded(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "ledger.jsonl"
            record({EVM}, "read", "tool:WebFetch", path=p)
            self.assertIn(EVM, classify(path=p)["tainted"])
            # The upgrade is the point: the same address later arriving on a
            # trusted channel clears it.
            record({EVM}, "operator", "cli", path=p)
            kinds = classify(path=p)
            self.assertIn(EVM, kinds["trusted"])
            self.assertNotIn(EVM, kinds["tainted"])

    def test_duplicate_pairs_write_once(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "ledger.jsonl"
            self.assertEqual(record({EVM}, "read", "a", path=p), 1)
            self.assertEqual(record({EVM}, "read", "b", path=p), 0)
            self.assertEqual(len(p.read_text().splitlines()), 1)

    def test_unknown_source_is_an_error_not_a_silent_write(self):
        with TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                record({EVM}, "model", "x", path=Path(d) / "l.jsonl")

    def test_missing_ledger_classifies_empty(self):
        kinds = classify(path=Path("/nonexistent/never/ledger.jsonl"))
        self.assertEqual(kinds, {"trusted": set(), "tainted": set()})


if __name__ == "__main__":
    unittest.main()
