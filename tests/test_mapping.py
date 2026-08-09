"""Mapping table (section 6): loading, override, refusal of heuristics."""

import json
import os
import shutil
import tempfile
import unittest

from acltools.errors import FatalMappingError
from acltools.mapping import is_valid_handler_path, load_mapping

from . import BIN_DIR

SHIPPED_TABLE = os.path.join(BIN_DIR, "acl_endpoint_map.json")


class DeliveredTableTest(unittest.TestCase):
    """The shipped table is a **datum** established empirically, not code: this test
    checks its shape, not its correctness - the latter is re-validated on the target
    platform (section 6.5)."""

    def test_the_shipped_table_loads(self):
        mapping = load_mapping(SHIPPED_TABLE)
        self.assertEqual(len(mapping), 28)

    def test_every_entry_has_a_valid_path(self):
        with open(SHIPPED_TABLE, encoding="utf-8") as handle:
            raw = json.load(handle)
        for eai_type, handler_path in raw.items():
            with self.subTest(eai_type=eai_type):
                self.assertTrue(is_valid_handler_path(handler_path))

    def test_the_mappings_that_break_the_naming_analogy(self):
        """Empirical justification of the ban on heuristics in section 6.2."""
        mapping = load_mapping(SHIPPED_TABLE)
        self.assertEqual(mapping.resolve("commands"), "admin/commandsconf")
        self.assertEqual(mapping.resolve("conf-times"), "data/ui/times")

    def test_no_derivation_by_pluralization(self):
        mapping = load_mapping(SHIPPED_TABLE)
        self.assertEqual(mapping.resolve("savedsearch"), "saved/searches")
        self.assertIsNone(mapping.resolve("savedsearches"))
        self.assertIsNone(mapping.resolve("saved-search"))

    def test_unknown_type_yields_none_never_a_guessed_value(self):
        mapping = load_mapping(SHIPPED_TABLE)
        self.assertIsNone(mapping.resolve("nonexistent_type"))
        self.assertIsNone(mapping.resolve(""))
        self.assertIsNone(mapping.resolve(None))

    def test_coverage_is_exposed(self):
        coverage = load_mapping(SHIPPED_TABLE).coverage()
        self.assertEqual(coverage["total"], 28)
        self.assertEqual(coverage["from_override"], 0)
        self.assertEqual(coverage["rejected"], ())
        self.assertIn("savedsearch", coverage["types"])


class HandlerPathValidationTest(unittest.TestCase):

    def test_valid_paths(self):
        for path in ("saved/searches", "admin/commandsconf", "data/ui/nav",
                     "storage/collections/config", "alerts/alert_actions"):
            with self.subTest(path=path):
                self.assertTrue(is_valid_handler_path(path))

    def test_refused_paths(self):
        for path in ("", "/absolute", "../traversal", "saved/searches?x=1",
                     "saved//searches", "saved/searches/", "a b", "http://elsewhere"):
            with self.subTest(path=path):
                self.assertFalse(is_valid_handler_path(path))

    def test_no_traversal_segment_is_admitted(self):
        """A-5: `..` in a later position was admitted by the pattern alone.

        Safety must not depend on splunkd refusing: it answers 404 on Splunk 9.4.6,
        but a platform that normalized the path would take the request out of the
        reconstructed namespace.
        """
        for path in (
            "a/../../services/authentication/users",
            "saved/../admin/directory",
            "saved/searches/..",
            "saved/./searches",
            "a/.../b",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_valid_handler_path(path))

    def test_a_dot_inside_a_segment_stays_admitted(self):
        """The refusal bears on the traversal segment, not on the dot itself."""
        for path in ("data/ui.views", "a.b/c-d_e~f", "saved/searches.v2"):
            with self.subTest(path=path):
                self.assertTrue(is_valid_handler_path(path))


class LoadMappingTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="editacl_map_")
        self.json_path = os.path.join(self.directory, "acl_endpoint_map.json")
        with open(self.json_path, "w", encoding="utf-8") as handle:
            json.dump(
                {"savedsearch": "saved/searches", "views": "data/ui/views"}, handle
            )
        self.csv_path = os.path.join(self.directory, "override.csv")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _write_csv(self, content):
        with open(self.csv_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)

    def test_missing_json_is_fatal(self):
        with self.assertRaises(FatalMappingError):
            load_mapping(os.path.join(self.directory, "nonexistent.json"))

    def test_malformed_json_is_fatal(self):
        path = os.path.join(self.directory, "broken.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        with self.assertRaises(FatalMappingError):
            load_mapping(path)

    def test_json_that_is_not_an_object_is_fatal(self):
        path = os.path.join(self.directory, "list.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        with self.assertRaises(FatalMappingError):
            load_mapping(path)

    def test_missing_override_is_normal(self):
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(len(mapping), 2)

    def test_override_adds_and_overrides(self):
        self._write_csv(
            "eai_type,handler_path\n"
            "an-unheard-of-type,data/ui/unheard-of\n"
            "views,data/ui/other-view\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(mapping.resolve("an-unheard-of-type"), "data/ui/unheard-of")
        self.assertEqual(mapping.resolve("views"), "data/ui/other-view")
        self.assertEqual(mapping.coverage()["overridden"], ("views",))

    def test_override_with_a_forged_path_is_discarded(self):
        """The override file is an untrusted input: a forged handler path could aim at
        an arbitrary endpoint."""
        self._write_csv(
            "eai_type,handler_path\n"
            "malicious,../../services/authentication/users\n"
            "valid,data/ui/views\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertIsNone(mapping.resolve("malicious"))
        self.assertEqual(mapping.resolve("valid"), "data/ui/views")
        self.assertEqual(len(mapping.coverage()["rejected"]), 1)

    def test_comment_lines_are_ignored(self):
        self._write_csv(
            "eai_type,handler_path\n"
            "# a comment\n"
            "#another-comment,data/ui/views\n"
            "valid,data/ui/views\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(mapping.coverage()["rejected"], ())
        self.assertEqual(mapping.resolve("valid"), "data/ui/views")

    def test_override_with_wrong_columns_does_not_prevent_the_run(self):
        self._write_csv("type,path\nx,y\n")
        diagnostics = []
        mapping = load_mapping(
            self.json_path, self.csv_path, diag=lambda l, m: diagnostics.append((l, m))
        )
        self.assertEqual(len(mapping), 2)
        self.assertTrue(diagnostics)

    def test_invalid_json_entry_is_discarded_with_a_trace(self):
        path = os.path.join(self.directory, "partial.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"good": "saved/searches", "bad": "../escape"}, handle)
        diagnostics = []
        mapping = load_mapping(path, diag=lambda l, m: diagnostics.append((l, m)))
        self.assertEqual(len(mapping), 1)
        self.assertIsNone(mapping.resolve("bad"))
        self.assertEqual(len(diagnostics), 1)


class TheTableIsReadBackwardsAndSaysWhereItCannotBeTest(unittest.TestCase):
    """The inverse direction, `handler path -> eai:type`, and its **one** blind spot.

    The command needs it: twenty-four of the twenty-seven native handlers emit no
    `eai:type`, so a batch read natively resolves through `id` and would carry no type
    at all. Inverting the table gives the type back, in the vocabulary the operator
    writes - which is what lets one single designation of that notion travel from the
    pipeline to the journal to the monitoring view.

    The inverse is a **partial function**, and the exception is named here rather than
    guessed at run time: `data/ui/times` is the image of `times` **and** of
    `conf-times`. Every other handler path of the shipped table is the image of exactly
    one key. If a later entry made a second path ambiguous, this test fails - which is
    the whole reason it asserts the exact set instead of a count.
    """

    #: The one ambiguous handler path of the shipped table, and its two keys. Named,
    #: not discovered: a test that recomputed the expected value from the file would
    #: pass on any table whatsoever.
    AMBIGUOUS = {"data/ui/times": ("conf-times", "times")}

    def setUp(self):
        self.mapping = load_mapping(SHIPPED_TABLE)

    def test_the_table_is_invertible_everywhere_except_on_the_named_case(self):
        self.assertEqual(self.mapping.ambiguous_handlers(), self.AMBIGUOUS)

    def test_the_shape_the_ambiguity_comes_from(self):
        """28 keys for 27 distinct handler paths: one path short of a bijection."""
        coverage = self.mapping.coverage()
        self.assertEqual(coverage["total"], 28)
        self.assertEqual(coverage["handlers"], 27)

    def test_every_unambiguous_handler_inverts_to_its_only_key(self):
        for eai_type in self.mapping.types():
            handler_path = self.mapping.resolve(eai_type)
            if handler_path in self.AMBIGUOUS:
                continue
            with self.subTest(eai_type=eai_type):
                self.assertEqual(self.mapping.type_of_handler(handler_path), eai_type)

    def test_the_ambiguous_path_yields_no_type_rather_than_one_of_its_keys(self):
        """Both answers would be defensible, which is exactly why neither is given."""
        for handler_path in self.AMBIGUOUS:
            with self.subTest(handler_path=handler_path):
                self.assertIsNone(self.mapping.type_of_handler(handler_path))

    def test_a_handler_no_key_names_yields_no_type(self):
        """The `id` route of section 5.2 accepts any pattern-valid path, and the set of
        paths it can produce is **not** bounded by this table."""
        self.assertIsNone(self.mapping.type_of_handler("some/future/endpoint"))
        self.assertIsNone(self.mapping.type_of_handler(""))
        self.assertIsNone(self.mapping.type_of_handler(None))

    def test_an_override_that_creates_an_ambiguity_is_reported_and_not_resolved(self):
        """The operator may extend the table (section 6.3), so the ambiguity is not a
        property of the shipped file alone. An override pointing a second key at an
        existing handler makes that handler undecidable, and it must come out that way
        rather than resolving to whichever key was loaded last."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        override = os.path.join(directory, "override.csv")
        with open(override, "w", encoding="utf-8", newline="") as handle:
            handle.write("eai_type,handler_path\nlocal_alias,saved/searches\n")
        mapping = load_mapping(SHIPPED_TABLE, override)
        self.assertEqual(
            mapping.ambiguous_handlers()["saved/searches"],
            ("local_alias", "savedsearch"),
        )
        self.assertIsNone(mapping.type_of_handler("saved/searches"))


class ExampleFileTest(unittest.TestCase):
    """D-5: the archive ships the example, **never** the real file."""

    def test_the_archive_does_not_contain_the_real_override(self):
        lookups = os.path.join(os.path.dirname(BIN_DIR), "lookups")
        self.assertTrue(
            os.path.exists(
                os.path.join(lookups, "acl_endpoint_map_override.csv.example")
            )
        )
        self.assertFalse(
            os.path.exists(os.path.join(lookups, "acl_endpoint_map_override.csv"))
        )


if __name__ == "__main__":
    unittest.main()
