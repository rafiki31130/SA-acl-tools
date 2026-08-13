"""Family table `stanza` -> handler path (v4.2 section 5.2).

The table is a **measurement transcribed**, not a derivation: each of its nineteen
entries comes from a POST that answered `200` and from the stanza that write actually
produced in `local.meta`. The tests below hold three things that a reading of the file
would not: that the transcription is complete, that nothing resolves by analogy, and that
the three families measured **negative** stay out.
"""

import json
import os
import unittest

from acltools.appacl_family import FamilyTable, load_family_table
from acltools.errors import FatalFamilyTableError

from . import BIN_DIR, REPO_ROOT

FAMILY_JSON = os.path.join(BIN_DIR, "app_acl_family_map.json")
OVERRIDE_EXAMPLE = os.path.join(
    REPO_ROOT, "lookups", "app_acl_family_map_override.csv.example"
)


class TheShippedTableTest(unittest.TestCase):
    """The nineteen positive families of Q0-2, and nothing else."""

    #: Transcribed from the measurement table of Q0-2, stanza by stanza. It is written
    #: out here **on purpose**, unlike the status enumeration: this one is not derived
    #: from the code, it is a statement about the platform, and the only way a test can
    #: hold it is by carrying the measured value next to the shipped one.
    MEASURED = {
        "views": "data/ui/views",
        "nav": "data/ui/nav",
        "panels": "data/ui/panels",
        "times": "data/ui/times",
        "viewstates": "data/ui/viewstates",
        "workflow_actions": "data/ui/workflow-actions",
        "savedsearches": "saved/searches",
        "eventtypes": "saved/eventtypes",
        "tags": "saved/fvtags",
        "macros": "data/macros",
        "lookups": "data/lookup-table-files",
        "props": "data/props/lookups",
        "transforms": "data/transforms/lookups",
        "collections": "storage/collections/config",
        "models": "datamodel/model",
        "fields": "admin/fields",
        "commands": "admin/commandsconf",
        "alert_actions": "alerts/alert_actions",
        "global-banner": "admin/global-banner",
    }

    #: Measured **negative** (section 5.3). They are deliberately absent from the table
    #: rather than named in the code: carving a property of the platform into the tool
    #: is what the arbitration of v3.14 section 10.10 refuses.
    NEGATIVE = ("visualizations", "ntags")

    def setUp(self):
        with open(FAMILY_JSON, encoding="utf-8") as handle:
            self.raw = json.load(handle)
        self.table = load_family_table(FAMILY_JSON)

    def test_the_shipped_table_is_the_measured_table(self):
        self.assertEqual(self.raw, self.MEASURED)

    def test_it_carries_nineteen_families(self):
        self.assertEqual(len(self.table), 19)

    def test_every_family_resolves_to_its_measured_handler(self):
        for family, handler in self.MEASURED.items():
            with self.subTest(family=family):
                self.assertEqual(self.table.resolve(family), handler)

    def test_the_stanza_name_follows_the_configuration_file_not_the_uri(self):
        """Measured, Q0-2: `data/ui/workflow-actions` writes `[workflow_actions]`.

        Underscore in the stanza, hyphen in the URI. It is the one entry of the table
        where an analogy of naming would produce the wrong key, so it is the one worth a
        test of its own.
        """
        self.assertEqual(self.table.resolve("workflow_actions"), "data/ui/workflow-actions")
        self.assertIsNone(self.table.resolve("workflow-actions"))

    def test_the_negative_families_are_absent(self):
        for family in self.NEGATIVE:
            with self.subTest(family=family):
                self.assertIsNone(self.table.resolve(family))
                self.assertNotIn(family, self.table)

    def test_a_negative_family_is_not_named_in_the_shipped_code(self):
        """Section 5.3: the refusal must come from **absence**, not from a hardcoded list.

        A `visualizations` written into the core would be a property of 9.4.6 carved into
        the tool, that nothing lets us re-check and that the next version may contradict.
        """
        package = os.path.join(BIN_DIR, "acltools")
        for name in sorted(os.listdir(package)):
            if not name.startswith("appacl_") or not name.endswith(".py"):
                continue
            with open(os.path.join(package, name), encoding="utf-8") as handle:
                source = handle.read()
            code = "\n".join(
                line for line in source.splitlines() if not line.strip().startswith("#")
            )
            for family in self.NEGATIVE:
                with self.subTest(module=name, family=family):
                    self.assertNotIn('"%s"' % family, code)
                    self.assertNotIn("'%s'" % family, code)

    def test_the_canonical_handler_of_an_aliased_family_is_the_one_retained(self):
        """Seven handlers write `[props]`, two write `[savedsearches]` (Q0-2, aliases).

        The inversion is a **choice**, and the choice is frozen here: an override may
        change it, a silent drift may not.
        """
        self.assertEqual(self.table.resolve("props"), "data/props/lookups")
        self.assertEqual(self.table.resolve("savedsearches"), "saved/searches")
        self.assertEqual(self.table.resolve("macros"), "data/macros")
        self.assertEqual(self.table.resolve("tags"), "saved/fvtags")
        self.assertEqual(self.table.resolve("models"), "datamodel/model")
        self.assertEqual(self.table.resolve("transforms"), "data/transforms/lookups")

    def test_every_handler_path_is_pattern_valid(self):
        from acltools.mapping import is_valid_handler_path

        for family, handler in self.raw.items():
            with self.subTest(family=family):
                self.assertTrue(is_valid_handler_path(handler))


class TheTableIsNotAHeuristicTest(unittest.TestCase):

    def setUp(self):
        self.table = load_family_table(FAMILY_JSON)

    def test_an_unknown_family_answers_none(self):
        for family in ("", None, "unknown", "view", "VIEWS", "data/ui/views"):
            with self.subTest(family=family):
                self.assertIsNone(self.table.resolve(family))

    def test_surrounding_whitespace_is_tolerated_but_nothing_else_is(self):
        self.assertEqual(self.table.resolve("  views  "), "data/ui/views")

    def test_the_table_is_not_read_backwards(self):
        """Unlike `Mapping`, this one has no reverse direction, and that is deliberate.

        Going from a handler path back to a family name is a fact of the platform this
        table cannot establish - seven handlers write `[props]` - and inventing it would
        produce exactly the false aplomb `Mapping.type_of_handler` refuses.
        """
        self.assertFalse(hasattr(self.table, "family_of_handler"))
        self.assertFalse(hasattr(self.table, "type_of_handler"))


class TheOverrideTest(unittest.TestCase):
    """Requirement 3 of section 5.2: extension without touching the code."""

    def setUp(self):
        self.tmp = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_tmp_override.csv"
        )
        self.addCleanup(self._remove)

    def _remove(self):
        if os.path.exists(self.tmp):
            os.remove(self.tmp)

    def _write(self, text):
        with open(self.tmp, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def test_a_missing_override_is_normal(self):
        table = load_family_table(FAMILY_JSON, self.tmp)
        self.assertEqual(len(table), 19)

    def test_an_override_adds_a_family(self):
        self._write("family,handler_path\na_new_family,admin/something\n")
        table = load_family_table(FAMILY_JSON, self.tmp)
        self.assertEqual(table.resolve("a_new_family"), "admin/something")
        self.assertEqual(len(table), 20)

    def test_an_override_replaces_a_shipped_family(self):
        self._write("family,handler_path\nprops,configs/conf-props\n")
        table = load_family_table(FAMILY_JSON, self.tmp)
        self.assertEqual(table.resolve("props"), "configs/conf-props")
        self.assertEqual(table.coverage()["overridden"], ("props",))

    def test_a_malformed_handler_is_discarded_and_traced(self):
        traces = []
        self._write("family,handler_path\nbad,../../etc/passwd\n")
        table = load_family_table(
            FAMILY_JSON, self.tmp, diag=lambda level, message: traces.append(level)
        )
        self.assertIsNone(table.resolve("bad"))
        self.assertIn("WARNING", traces)

    def test_a_comment_line_is_ignored(self):
        self._write("family,handler_path\n#a comment,whatever\n")
        table = load_family_table(FAMILY_JSON, self.tmp)
        self.assertEqual(len(table), 19)

    def test_wrong_columns_leave_the_shipped_table_intact(self):
        traces = []
        self._write("eai_type,handler_path\nviews,admin/wrong\n")
        table = load_family_table(
            FAMILY_JSON, self.tmp, diag=lambda level, message: traces.append(level)
        )
        self.assertEqual(table.resolve("views"), "data/ui/views")
        self.assertIn("WARNING", traces)

    def test_the_example_file_overrides_nothing(self):
        """It is shipped, so it is loaded if an operator renames it without editing."""
        table = load_family_table(FAMILY_JSON, OVERRIDE_EXAMPLE)
        self.assertEqual(len(table), 19)

    def test_the_example_declares_the_expected_columns(self):
        with open(OVERRIDE_EXAMPLE, encoding="utf-8") as handle:
            first = handle.readline().strip()
        self.assertEqual(first, "family,handler_path")

    def test_the_real_override_is_never_shipped(self):
        """D-5: the archive carries the example, never the file itself - which is what
        makes an upgrade unable to overwrite the operator's table."""
        self.assertFalse(
            os.path.exists(
                os.path.join(REPO_ROOT, "lookups", "app_acl_family_map_override.csv")
            )
        )


class TheTableIsFatalWhenUnusableTest(unittest.TestCase):
    """Section 13.1: an unreadable family table interrupts the search."""

    def test_a_missing_json_is_fatal(self):
        with self.assertRaises(FatalFamilyTableError):
            load_family_table(os.path.join(BIN_DIR, "does_not_exist.json"))

    def test_a_malformed_json_is_fatal(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.addCleanup(os.remove, path)
        with self.assertRaises(FatalFamilyTableError):
            load_family_table(path)

    def test_a_json_that_is_not_an_object_is_fatal(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_list.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('["views"]')
        self.addCleanup(os.remove, path)
        with self.assertRaises(FatalFamilyTableError):
            load_family_table(path)

    def test_the_error_class_is_not_the_one_of_the_other_table(self):
        """Two tables, two classes: a single one would make a message about one of them
        plausible while the other is at fault."""
        from acltools.errors import FatalMappingError

        self.assertFalse(issubclass(FatalFamilyTableError, FatalMappingError))


class TheCoverageReportTest(unittest.TestCase):

    def test_it_reports_what_the_diagnostic_prints(self):
        table = FamilyTable(
            {"views": "data/ui/views"},
            from_json=("views",),
            from_override=(),
            rejected=(),
        )
        coverage = table.coverage()
        self.assertEqual(coverage["total"], 1)
        self.assertEqual(coverage["families"], ("views",))


if __name__ == "__main__":
    unittest.main()
