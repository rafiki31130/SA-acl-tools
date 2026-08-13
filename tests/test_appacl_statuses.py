"""`APP_ACL_STATUSES` is the exact projection of what the application-level code produces.

Same device as `tests/test_statuses.py`, applied to the other partition of the package,
and **with that module's extractor** rather than a copy of it: the whole point of the
device is that a hand-maintained duplicate drifts, so duplicating the instrument to check
a second enumeration would be the very mistake it exists to catch.

The two directions, and they are attacked from both ends:

- a status produced by the application-level code and absent from `APP_ACL_STATUSES`
  fails here;
- a status declared in `APP_ACL_STATUSES` with no real case fails in
  `tests/test_appacl_pipeline.py`, which requires observing each of them.

The limits of the instrument are the ones its own module states at length: it is static,
it follows no value at run time, and it covers exactly the files of `APP_SOURCES`.
"""

import os
import unittest

from acltools.appacl_model import APP_ACL_STATUSES
from acltools.model import ACL_STATUSES

from .test_statuses import (
    APP_SOURCES,
    SOURCES,
    _apply_exemptions,
    scan_paths,
)


def statuses_produced_by_the_application_level_code():
    return scan_paths(APP_SOURCES)[0]


class ThePartitionIsCompleteTest(unittest.TestCase):
    """Every scanned file lands in exactly one of the two sets - neither, or both, is a
    hole. A module in neither is a place where a status can be born unseen, which is the
    blind spot the whole device exists to close."""

    def test_the_two_sets_do_not_overlap(self):
        self.assertEqual(set(SOURCES) & set(APP_SOURCES), set())

    def test_together_they_cover_the_package_and_the_two_adapters(self):
        from . import BIN_DIR

        package = os.path.join(BIN_DIR, "acltools")
        expected = {
            os.path.join(package, name)
            for name in os.listdir(package)
            if name.endswith(".py")
        }
        expected.add(os.path.join(BIN_DIR, "editacl.py"))
        expected.add(os.path.join(BIN_DIR, "editappacl.py"))
        self.assertEqual(set(SOURCES) | set(APP_SOURCES), expected)

    def test_the_application_level_set_is_not_empty(self):
        self.assertGreaterEqual(len(APP_SOURCES), 8)


class TheEnumerationIsDerivedFromTheCodeTest(unittest.TestCase):

    def test_the_code_produces_no_undeclared_status(self):
        unknown = statuses_produced_by_the_application_level_code() - set(
            APP_ACL_STATUSES
        )
        self.assertEqual(
            set(),
            unknown,
            "status(es) produced by the application-level core and absent from "
            "APP_ACL_STATUSES: %s. A status is not added without being declared, nor "
            "without its case in tests/test_appacl_pipeline.py." % sorted(unknown),
        )

    def test_no_declared_status_is_dead(self):
        dead = set(APP_ACL_STATUSES) - statuses_produced_by_the_application_level_code()
        self.assertEqual(
            set(),
            dead,
            "status(es) declared in APP_ACL_STATUSES that the code no longer produces: "
            "%s" % sorted(dead),
        )

    def test_the_extraction_is_not_empty(self):
        """Guard rail against the "zero produced by a dead instrument": an extraction
        that found nothing would make the two tests above true by vacuity."""
        self.assertGreaterEqual(
            len(statuses_produced_by_the_application_level_code()), 12
        )

    def test_the_enumeration_has_no_duplicate(self):
        self.assertEqual(len(APP_ACL_STATUSES), len(set(APP_ACL_STATUSES)))

    def test_no_status_construct_escapes_the_extractor(self):
        """What the extractor cannot read, it refuses. A noisy blind spot is infinitely
        better than a silent one."""
        _statuses, opaque_sites = scan_paths(APP_SOURCES)
        remaining, _used = _apply_exemptions(opaque_sites)
        self.assertEqual(
            [],
            remaining,
            "construct(s) touching a status that the extractor cannot interpret with "
            "certainty:\n%s" % "\n".join("  %r" % site for site in remaining),
        )


class TheTwoEnumerationsAreDistinctTest(unittest.TestCase):
    """The two commands do not share a status enumeration, and that is deliberate.

    One counts objects and knows nothing of `created`, `noop_inherited` or
    `skipped_impact_ceiling`; the other counts stanzas and knows nothing of
    `skipped_private`, `skipped_derived` or `skipped_immutable`. A single list would put
    every consumer of either in front of statuses the command it watches can never
    produce.
    """

    def test_each_carries_a_status_the_other_does_not(self):
        self.assertEqual(
            set(APP_ACL_STATUSES) - set(ACL_STATUSES),
            {"created", "noop_inherited", "skipped_impact_ceiling"},
        )
        self.assertEqual(
            set(ACL_STATUSES) - set(APP_ACL_STATUSES),
            {"skipped_immutable", "skipped_derived", "skipped_private"},
        )

    def test_the_shared_ones_mean_the_same_thing_on_both_sides(self):
        """A status carried by both must not have drifted in meaning: it is the same
        word in the same column of two outputs an operator reads side by side."""
        self.assertEqual(
            set(APP_ACL_STATUSES) & set(ACL_STATUSES),
            {
                "updated", "noop", "dryrun", "rejected", "not_found", "forbidden",
                "invalid_role", "skipped_ceiling", "error",
            },
        )


if __name__ == "__main__":
    unittest.main()
