"""Binding of an SPL record to an `AppEventInput` (v4.1 sections 8.3, 8.4).

The presence semantics is decided in **one** place for the whole repository -
`binding.field_present` - and this module checks that the application-level builder goes
through it rather than reinventing it. The failure mode it guards against is not
theoretical: a `get()` with a default, anywhere on this path, erases the difference
between "column absent" and "cell empty" before the rule has settled it, and turns an
explicit clearing order into a preservation.
"""

import ast
import os
import unittest

from acltools.appacl_model import (
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    AppFieldNames,
)
from acltools.binding import build_app_event

from . import BIN_DIR

NAMES = AppFieldNames()


class ThePresenceIsTheKeyTest(unittest.TestCase):

    def test_an_absent_column_is_absent_from_present(self):
        event = build_app_event({"eai:acl.app": "my_app"}, NAMES)
        self.assertEqual(event.present, frozenset())
        self.assertFalse(event.has(TARGET_PERMS_READ))

    def test_a_present_empty_column_is_present(self):
        """Measured on 9.4.6: the command receives either a key absent from the record,
        or a key present holding the empty string. The predicate is exactly
        `key in record`, with no further clause."""
        event = build_app_event({"eai:acl.perms.read": ""}, NAMES)
        self.assertTrue(event.has(TARGET_PERMS_READ))
        self.assertEqual(event.new_perms_read, "")

    def test_a_present_null_column_is_still_present(self):
        event = build_app_event({"eai:acl.perms.write": None}, NAMES)
        self.assertTrue(event.has(TARGET_PERMS_WRITE))

    def test_the_three_target_columns_are_read_for_presence(self):
        record = {
            "eai:acl.perms.read": "a",
            "eai:acl.perms.write": "b",
            "eai:acl.sharing": "app",
        }
        event = build_app_event(record, NAMES)
        self.assertEqual(
            event.present,
            frozenset({TARGET_PERMS_READ, TARGET_PERMS_WRITE, TARGET_SHARING}),
        )

    def test_no_owner_column_is_read(self):
        """**DV-5**: reading one would be the first step towards sending one."""
        event = build_app_event({"eai:acl.owner": "somebody"}, NAMES)
        self.assertFalse(hasattr(event, "new_owner"))
        self.assertEqual(event.present, frozenset())


class TheDesignatingFieldsAreReadForTheirValueTest(unittest.TestCase):

    def test_the_four_designating_fields(self):
        record = {
            "eai:acl.app": " my_app ",
            "acl_stanza_kind": "family_default",
            "acl_handler": "data/ui/views",
            "acl_stanza": "views",
        }
        event = build_app_event(record, NAMES)
        self.assertEqual(event.app, "my_app")
        self.assertEqual(event.stanza_kind, "family_default")
        self.assertEqual(event.handler, "data/ui/views")
        self.assertEqual(event.stanza, "views")

    def test_an_absent_designating_field_reads_as_the_empty_string(self):
        event = build_app_event({}, NAMES)
        self.assertEqual(event.app, "")
        self.assertEqual(event.stanza_kind, "")

    def test_an_empty_stanza_is_carried_as_such(self):
        """It is the legitimate name of the `[]` stanza, which is exactly why
        `stanza_kind` is required and never deduced from it."""
        event = build_app_event(
            {"acl_stanza": "", "acl_stanza_kind": "app_default"}, NAMES
        )
        self.assertEqual(event.stanza, "")
        self.assertEqual(event.stanza_kind, "app_default")

    def test_a_multivalue_designating_field_reduces_to_its_first_value(self):
        event = build_app_event({"eai:acl.app": ["", "my_app", "other"]}, NAMES)
        self.assertEqual(event.app, "my_app")

    def test_the_field_names_are_redirectable(self):
        names = AppFieldNames(app="my_app_column", stanza_kind="kind")
        event = build_app_event({"my_app_column": "x", "kind": "app_default"}, names)
        self.assertEqual(event.app, "x")
        self.assertEqual(event.stanza_kind, "app_default")


class TheRuleHasASingleInjectionPointTest(unittest.TestCase):
    """`field_present` is consulted here and nowhere else, in the whole package."""

    def test_the_builder_calls_the_shared_predicate(self):
        path = os.path.join(BIN_DIR, "acltools", "binding.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "build_app_event":
                calls = {
                    ast.unparse(child.func)
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call)
                }
                self.assertIn("field_present", calls)
                return
        self.fail("build_app_event not found in binding.py")

    def test_no_application_level_module_tests_a_column_by_itself(self):
        """A membership test on a record, anywhere else, would be a second reading of the
        presence rule - and a second chance to read it differently."""
        package = os.path.join(BIN_DIR, "acltools")
        for name in sorted(os.listdir(package)):
            if not name.startswith("appacl_") or not name.endswith(".py"):
                continue
            with open(os.path.join(package, name), encoding="utf-8") as handle:
                source = handle.read()
            with self.subTest(module=name):
                self.assertNotIn("in record", source)
                self.assertNotIn("record.get", source)


if __name__ == "__main__":
    unittest.main()
