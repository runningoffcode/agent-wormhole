"""Blast-radius scoring tests.

The property under test is that `loop_closed` means what it says. Reporting a
closed infection loop on a contained host is the kind of false alarm that
teaches people to ignore the tool -- and it is the exact bug this suite exists
to prevent recurring.
"""

import unittest

from wormhole import scoring
from wormhole.rules.injection import Finding


def _f(rule_id, severity="medium"):
    return Finding(rule_id=rule_id, severity=severity, title="t", detail="d")


class TestLoopClosed(unittest.TestCase):

    def test_contained_host_is_not_a_closed_loop(self):
        """No findings means every link scores at its floor. Floors are
        residual capability, not a usable infection step."""
        br = scoring.compute([])
        self.assertFalse(br.loop_closed,
                         f"floors {br.execute}/{br.persist}/{br.propagate} "
                         "must not read as a closed loop")
        self.assertLessEqual(br.score, 4)

    def test_fully_capable_host_closes_the_loop(self):
        br = scoring.compute([
            _f("POSTURE-001", "critical"),  # unrestricted shell
            _f("POSTURE-004"),              # writable config
            _f("POSTURE-002"),              # network egress
        ])
        self.assertTrue(br.loop_closed)
        self.assertEqual(br.broken_links, [])
        self.assertGreaterEqual(br.score, 6)

    def test_score_scales_with_exposure(self):
        """More writable configs and more outbound channels should score
        strictly higher than the minimum closed loop."""
        minimal = scoring.compute([
            _f("POSTURE-001", "critical"), _f("POSTURE-004"), _f("POSTURE-002"),
        ])
        maximal = scoring.compute([
            _f("POSTURE-001", "critical"),
            _f("POSTURE-004"), _f("POSTURE-004"), _f("POSTURE-004"),
            _f("POSTURE-002"), _f("POSTURE-005"), _f("POSTURE-006"),
        ])
        self.assertGreater(maximal.score, minimal.score)
        self.assertEqual(maximal.band, "severe")

    def test_missing_persistence_breaks_the_loop(self):
        """Sandbox isolation is the control that prevents config writes. With
        no writable config there is nowhere to persist, so the loop opens --
        this is the paper's 0% ASR result expressed in the score."""
        br = scoring.compute([_f("POSTURE-001", "critical"), _f("POSTURE-002")])
        self.assertFalse(br.loop_closed)
        self.assertIn("persist", br.broken_links)

    def test_broken_links_are_reported(self):
        br = scoring.compute([])
        self.assertTrue(br.broken_links)
        for link in br.broken_links:
            self.assertIn(link, ("execute", "persist", "propagate"))


class TestSeverityWeighting(unittest.TestCase):

    def test_escalates_in_severe_host(self):
        """Escalation requires a closed loop *and* a severe score, so an
        ordinary closed loop does not inflate every finding by one level."""
        br = scoring.compute([
            _f("POSTURE-001", "critical"),
            _f("POSTURE-004"), _f("POSTURE-004"), _f("POSTURE-004"),
            _f("POSTURE-002"), _f("POSTURE-005"), _f("POSTURE-006"),
        ])
        self.assertTrue(br.loop_closed)
        self.assertGreaterEqual(br.score, 8)
        self.assertEqual(scoring.weight_severity("high", br), "critical")

    def test_never_de_escalates(self):
        """A sandbox can be reconfigured; a critical finding stays critical."""
        br = scoring.compute([])
        self.assertEqual(scoring.weight_severity("critical", br), "critical")
        self.assertEqual(scoring.weight_severity("high", br), "high")


if __name__ == "__main__":
    unittest.main()
