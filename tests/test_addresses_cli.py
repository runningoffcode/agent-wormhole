"""Exercise the documented trust command through the real argument parser."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from wormhole.cli import main


class TestAddressesCli(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ledger = Path(temp.name) / "addresses.jsonl"
        self.address = "0x1111111111111111111111111111111111111111"

    def run_command(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(["addresses", *args, "--ledger", str(self.ledger)])

    def assert_recorded(self):
        entries = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual([(e["address"], e["source"]) for e in entries],
                         [(self.address, "operator")])

    def test_documented_trust_subcommand(self):
        self.assertEqual(self.run_command("trust", self.address), 0)
        self.assert_recorded()

    def test_bare_address_remains_supported(self):
        self.assertEqual(self.run_command(self.address), 0)
        self.assert_recorded()

    def test_no_address_lists_without_creating_ledger(self):
        self.assertEqual(self.run_command(), 0)
        self.assertFalse(self.ledger.exists())

    def test_invalid_extra_arguments_do_not_write(self):
        with self.assertRaises(SystemExit) as result:
            self.run_command("unknown", self.address)
        self.assertEqual(result.exception.code, 2)
        self.assertFalse(self.ledger.exists())

    def test_missing_trust_address_does_not_write(self):
        with self.assertRaises(SystemExit) as result:
            self.run_command("trust")
        self.assertEqual(result.exception.code, 2)
        self.assertFalse(self.ledger.exists())
