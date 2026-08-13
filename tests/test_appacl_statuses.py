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
import re
import unittest

from acltools.appacl_model import APP_ACL_STATUSES, APP_ACL_WARNINGS
from acltools.model import ACL_STATUSES

from .test_statuses import (
    APP_SOURCES,
    DESIGN,
    README,
    SOURCES,
    _apply_exemptions,
    _read_document,
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
        expected.add(os.path.join(BIN_DIR, "app_acl_inventory.py"))
        self.assertEqual(set(SOURCES) | set(APP_SOURCES), expected)

    def test_the_three_adapters_are_covered(self):
        """A command file left out of both sets would be scanned by nothing at all."""
        from . import BIN_DIR as _bin

        adapters = {
            path for path in set(SOURCES) | set(APP_SOURCES)
            if os.path.dirname(path) == _bin
        }
        self.assertEqual(len(adapters), 3, sorted(adapters))

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


#: The one turn of phrase in the README that spells the size of the application-level
#: enumeration out in words. It is deliberately NOT the wording used for the other
#: command: a single phrasing would make one anchoring test match the other document's
#: sentence, and the count it checked would be the wrong one.
_COUNT_RE = re.compile(
    r"\bthe\s+([a-z]+)\s+values of `acl_status` that `editappacl` produces",
    re.IGNORECASE,
)

#: Enough cardinals to frame an evolution; a word absent from this table fails, rather
#: than letting an unverified count through.
_CARDINALS = {
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
}


class TheShippedDocumentationIsAnchoredTest(unittest.TestCase):
    """C-2 applied to the second enumeration - and it is the reason phase 2a left the
    README alone.

    `tests/test_statuses.py` anchors the README enumeration of `ACL_STATUSES` and requires
    **exactly one** row spelling it out. Dropping a second enumeration into the same
    document without its own anchoring device would have done two things at once: leave
    the new list unchecked, and make the existing control ambiguous about which row it
    watches. So the application-level row carries a **distinct label**, and this class is
    the device that holds it.

    Where each copy lives, and why:

    - `README.md` carries the enumeration itself, in the output-field table, because the
      set of values an operator may read in `acl_status` is part of the output contract -
      and because it is the only one of the two documents shipped in the deployable
      archive;
    - `DEVNOTES.md` carries the **ordered control table**, which is the second copy and
      the last one. It is the table of ranks that says which status wins when several
      conditions hold, and nobody reads it to interpret a result table.

    One copy each, one anchoring test each. A state diagram was deliberately NOT added to
    `DEVNOTES.md`: the existing anchoring test there requires exactly one such diagram,
    and a second would have made that control ambiguous in the same way.
    """

    @classmethod
    def setUpClass(cls):
        cls.readme = _read_document(README)
        cls.design = _read_document(DESIGN)

    #: Prefix of the enumeration row. It is NOT `| \`acl_status\` |`, which belongs to the
    #: other command and is the row `tests/test_statuses.py` watches.
    ROW_PREFIX = "| `acl_status` (editappacl) |"

    def _table_row(self):
        rows = [
            row for row in self.readme.splitlines()
            if row.startswith(self.ROW_PREFIX)
        ]
        self.assertEqual(
            1, len(rows),
            "the README must carry exactly one table row enumerating the application-"
            "level `acl_status` values; %d found." % len(rows),
        )
        return rows[0]

    def test_the_readme_enumeration_equals_APP_ACL_STATUSES(self):
        """A status added without a README update fails the suite here."""
        cell = self._table_row().split("|")[2]
        enumerated = re.findall(r"`([^`]+)`", cell)
        self.assertEqual(
            list(APP_ACL_STATUSES), enumerated,
            "the output-field table of the README diverges from APP_ACL_STATUSES (order "
            "included). Missing: %s ; extra: %s."
            % (sorted(set(APP_ACL_STATUSES) - set(enumerated)),
               sorted(set(enumerated) - set(APP_ACL_STATUSES))),
        )

    def test_the_two_enumeration_rows_do_not_collide(self):
        """The device of the other command requires exactly one row starting with
        ``| `acl_status` |``. This one must not be a second."""
        plain = [
            row for row in self.readme.splitlines()
            if row.startswith("| `acl_status` |")
        ]
        self.assertEqual(1, len(plain))
        self.assertNotIn(self.ROW_PREFIX, "\n".join(plain))

    def test_the_count_announced_by_the_readme_is_right(self):
        words = _COUNT_RE.findall(self.readme)
        self.assertTrue(
            words,
            "the README no longer announces the number of application-level "
            "`acl_status` values in words; if the wording changed, this control must be "
            "readjusted, not removed.",
        )
        for word in words:
            with self.subTest(word=word):
                self.assertIn(
                    word.lower(), _CARDINALS,
                    'cardinal "%s" absent from the table: count unverifiable, therefore '
                    "refused." % word,
                )
                self.assertEqual(
                    len(APP_ACL_STATUSES), _CARDINALS[word.lower()],
                    'the README announces "%s" values, APP_ACL_STATUSES carries %d.'
                    % (word, len(APP_ACL_STATUSES)),
                )

    def test_every_status_is_explained_outside_the_enumeration_row(self):
        """The row gives a name; the operator also needs a meaning. A status added to the
        row and explained nowhere leaves them with a word and no case."""
        body = self.readme.replace(self._table_row(), "")
        missing = sorted(
            status for status in APP_ACL_STATUSES
            if not re.search(r"(?<![\w.])%s(?![\w.])" % re.escape(status), body)
        )
        self.assertEqual(
            [], missing,
            "status(es) declared in APP_ACL_STATUSES that the README never mentions "
            "outside its enumeration row: %s." % missing,
        )

    def test_the_warning_domain_is_published_whole(self):
        """`acl_warning` is a closed domain (section 8.8): a token emitted outside it is
        indistinguishable from a typo for whoever filters on the field. Publishing the
        list is what lets an operator tell one from the other."""
        rows = [
            row for row in self.readme.splitlines()
            if row.startswith("Warnings carried by `acl_warning` (editappacl)")
        ]
        self.assertEqual(1, len(rows), rows)
        block = self.readme.split(rows[0], 1)[1].split("\n\n", 1)[0]
        published = set(re.findall(r"`([a-z_]+)(?::<list>)?`", rows[0] + block))
        self.assertEqual(
            set(APP_ACL_WARNINGS) - published, set(),
            "warning(s) declared in APP_ACL_WARNINGS and absent from the README: %s"
            % sorted(set(APP_ACL_WARNINGS) - published),
        )

    def test_the_design_notes_carry_the_ordered_control_table(self):
        """The second copy, and the last one. The order of the ranks is what decides
        which status wins when several conditions hold, so a status that appears in no
        rank is a status nothing can produce - or one the table forgot."""
        blocks = re.findall(
            r"\n(%s.*?)\n\n" % re.escape(self.TABLE_HEADER), self.design, re.S
        )
        self.assertEqual(
            1, len(blocks),
            "exactly one ordered control table expected in %s; %d found."
            % (DESIGN, len(blocks)),
        )
        named = set(re.findall(r"`([a-z_]+)`", blocks[0]))
        # The ranks that issue no status of their own are the ones whose target goes on
        # to be written: `updated` and `created` are named in the prose around the table.
        missing = sorted(set(APP_ACL_STATUSES) - named)
        self.assertEqual(
            [], missing,
            "status(es) declared in APP_ACL_STATUSES and absent from the ordered control "
            "table of %s: %s." % (DESIGN, missing),
        )

    #: Header of the application-level control table. It is spelled out in full because
    #: `DEVNOTES.md` already carries the object-level one, whose header opens the same
    #: way: a looser pattern would match both and make this control ambiguous about which
    #: table it watches - the exact failure mode the split of the two documents avoids.
    TABLE_HEADER = "| Rank | Control | Status | Call |"

    def test_the_readme_carries_no_ordered_control_table(self):
        """One copy per document, and the split says which one. Without this, the table
        comes back into the README "for convenience", the anchoring test keeps watching
        the other file, and the copy nobody checks is the one everybody reads."""
        self.assertNotIn(self.TABLE_HEADER, self.readme)


if __name__ == "__main__":
    unittest.main()
