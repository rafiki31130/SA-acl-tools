"""`bin/editappacl.py` - adapter, wiring, and the rules that hold on its source.

The adapter is where a business rule slips back in one line at a time, and where a
message reaches the operator without saying which command emitted it. Both are held here
by reading the syntax tree, and the message rule reuses **the extractor of
`tests/test_message_prefix.py`** rather than a copy of it: v4.2 section 13.2 requires
that control to be extended to the new files, and extending it means the same instrument,
not a second one.
"""

import ast
import os
import unittest

from acltools.appacl_model import APP_ACL_OUTPUT_FIELDS

from . import BIN_DIR
from .test_message_prefix import (
    SDK_MESSAGE_METHODS,
    _Extractor,
    _fragment,
)

ADAPTER_PATH = os.path.join(BIN_DIR, "editappacl.py")

#: The one scope allowed to reach an SDK message method, `<class>.<method>` form.
SINGLE_EMISSION_POINT = "EditAppAclCommand._emit_message"


def _source():
    with open(ADAPTER_PATH, encoding="utf-8") as handle:
        return handle.read()


def _analyse():
    source = _source()
    extractor = _Extractor(source)
    extractor.visit(ast.parse(source, filename=ADAPTER_PATH))
    return extractor


class TheSingleEmissionPointTest(unittest.TestCase):
    """v4.2 section 13.2: one prefix, one emission point, checked mechanically.

    A search pipeline concatenates the messages of every command it chains, and the
    interface displays them stripped of their origin. Without the prefix, a warning about
    an irreversible write is indistinguishable from a warning of the macro that feeds the
    pipeline.
    """

    @classmethod
    def setUpClass(cls):
        cls.extractor = _analyse()

    def test_the_extraction_is_not_empty(self):
        """An extraction that reads nothing would pass for ever."""
        self.assertGreaterEqual(
            len(self.extractor.sites),
            3,
            "the extractor found no call to an SDK message method in "
            "bin/editappacl.py: it is reading nothing, or the file changed shape",
        )

    def test_no_construct_is_opaque(self):
        if not self.extractor.opaque:
            return
        detail = "\n".join(
            "  editappacl.py:%d in %s -- %s\n        source: %s"
            % (line, scope, reason, source)
            for scope, line, source, reason in self.extractor.opaque
        )
        self.fail(
            "construct(s) that could reach an SDK message method without the extractor "
            "being able to interpret them:\n%s" % detail
        )

    def test_only_the_single_emission_point_talks_to_the_sdk(self):
        strays = [
            (scope, line, source)
            for scope, line, source in self.extractor.sites
            if scope != SINGLE_EMISSION_POINT
        ]
        self.assertEqual(
            strays,
            [],
            "an SDK message method is reached outside %s, so those messages carry no "
            "prefix: %r" % (SINGLE_EMISSION_POINT, strays),
        )

    def test_every_sdk_message_method_is_covered_by_the_emission_point(self):
        """The emission point is a gateway, not a partial one: a level it does not
        handle would have to be written directly, which the test above forbids."""
        reached = set()
        for scope, _line, source in self.extractor.sites:
            if scope != SINGLE_EMISSION_POINT:
                continue
            for method in SDK_MESSAGE_METHODS:
                if method in source:
                    reached.add(method)
        self.assertIn("write_warning", reached)
        self.assertIn("write_error", reached)

    def test_the_prefix_is_the_command_name_a_colon_and_a_space(self):
        source = _source()
        self.assertIn('MESSAGE_PREFIX = "editappacl: "', source)

    def test_the_prefix_is_not_repeated_on_the_literals(self):
        """Repeating it would make the rule a convention - something that holds until the
        next contributor - instead of something one function guarantees."""
        occurrences = _source().count('"editappacl: ')
        self.assertEqual(occurrences, 1)


class TheAdapterCarriesNoBusinessRuleTest(unittest.TestCase):
    """The adapter wires, it does not decide (v4.2 section 14.1, deliverable 1)."""

    def setUp(self):
        with open(ADAPTER_PATH, encoding="utf-8") as handle:
            self.tree = ast.parse(handle.read(), filename=ADAPTER_PATH)

    def test_no_decision_function_of_the_core_is_redefined_here(self):
        defined = {
            node.name
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        forbidden = {
            "merge", "is_noop", "normalize_roles", "validate_roles", "resolve_target",
            "build_payload", "build_app_default_path", "build_family_default_path",
            "build_app_intent_record", "build_app_outcome_record", "parse_meta",
            "resolve_apps_root", "estimate",
        }
        self.assertEqual(defined & forbidden, set())

    def test_it_compiles_without_the_sdk(self):
        with open(ADAPTER_PATH, encoding="utf-8") as handle:
            compile(handle.read(), ADAPTER_PATH, "exec")

    def test_the_syspath_insertion_precedes_the_first_sdk_import(self):
        """`bin/lib` must be at the head of `sys.path` before the SDK is imported, or the
        platform's copy wins over the vendored one."""
        syspath_line = None
        sdk_line = None
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and syspath_line is None:
                if ast.unparse(node.func) == "sys.path.insert":
                    syspath_line = node.lineno
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("splunk" + "lib") and sdk_line is None:
                    sdk_line = node.lineno
        self.assertIsNotNone(syspath_line)
        self.assertIsNotNone(sdk_line)
        self.assertLess(syspath_line, sdk_line)

    def test_the_read_root_is_resolved_from_this_module_and_the_environment(self):
        """Bound 4 of section 6.2: the fallback route derives from the **command
        module's** own path, which is what the adapter must hand over - the core cannot
        go looking for it without reaching for one of the three misleading routes."""
        source = _source()
        self.assertIn("resolve_apps_root(os.environ, __file__)", source)

    def test_the_carrying_application_is_not_read_from_searchinfo(self):
        """HY-6: `searchinfo.app` names the DISPATCHING app, not the carrying one. It is
        `search` as soon as the search is launched from anywhere else, and must never
        build a path nor identify the app that ships the tool."""
        code = "\n".join(
            line for line in _source().splitlines()
            if not line.strip().startswith("#")
        )
        self.assertNotIn("searchinfo.app", code)
        self.assertIn("_SELF_APP = os.path.basename(_APP_ROOT)", code)


class TheDeclaredOutputFieldsTest(unittest.TestCase):
    """Section 8.8, and v3.14 D-33: the field set is declared, never inferred.

    The SDK writer freezes the header on the keys of the **first** record emitted. Several
    statuses of this command carry no state field at all, so a batch starting with one of
    those would silently drop everything the simulation exists to show.
    """

    def test_the_declaration_covers_every_field_the_adapter_writes(self):
        with open(ADAPTER_PATH, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=ADAPTER_PATH)
        written = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Subscript):
                continue
            if not (isinstance(node.value, ast.Name) and node.value.id == "output"):
                continue
            if isinstance(node.slice, ast.Constant) and isinstance(
                node.slice.value, str
            ):
                written.add(node.slice.value)
        self.assertTrue(written, "no output field read from the adapter")
        self.assertEqual(
            written - set(APP_ACL_OUTPUT_FIELDS),
            set(),
            "the adapter writes a field the declaration does not carry: it would "
            "disappear from the whole output without a word",
        )

    def test_every_declared_field_is_written_by_the_adapter(self):
        """The reverse direction: a declared field nothing fills would add an empty
        column to every result, which is noise dressed as information."""
        with open(ADAPTER_PATH, encoding="utf-8") as handle:
            source = handle.read()
        for field in APP_ACL_OUTPUT_FIELDS:
            with self.subTest(field=field):
                self.assertIn('"%s"' % field, source)

    def test_the_declaration_is_made_on_the_writer(self):
        source = _source()
        self.assertIn("custom_fields", source)
        self.assertIn("APP_ACL_OUTPUT_FIELDS", source)

    def test_no_state_field_names_an_owner(self):
        """**DV-5**: no owner is read, written, compared or published."""
        for field in APP_ACL_OUTPUT_FIELDS:
            with self.subTest(field=field):
                self.assertNotIn("owner", field)


class TheEndOfRunMessagesTest(unittest.TestCase):
    """Sections 9.4, 10.2 and 10.4: single messages, on the last chunk.

    Multi-chunk arrives from about a hundred records and is not predictable from the
    shape of the pipeline (v3.14 section 4.4), so a message emitted per chunk would be
    repeated, and one emitted too early would carry an incomplete number.
    """

    def test_the_four_message_builders_are_wired(self):
        source = _source()
        for builder in (
            "ceiling_message",
            "impact_ceiling_message",
            "simulation_summary_message",
            "creation_message",
        ):
            with self.subTest(builder=builder):
                self.assertIn(builder, source)

    def test_each_of_them_is_guarded_by_a_single_emission_flag(self):
        source = _source()
        for flag in (
            "_ceiling_signaled",
            "_impact_ceiling_signaled",
            "_end_of_run_signaled",
            "_summary_written",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, source)

    def test_they_are_emitted_on_the_last_chunk_only(self):
        source = _source()
        self.assertIn("_is_last_chunk", source)
        self.assertIn("is not False", source)

    def test_the_summary_line_is_not_written_on_the_fatal_path(self):
        """Its absence is what distinguishes an interrupted run from a completed one."""
        source = _source()
        summary_position = source.index("self._write_summary()")
        fatal_position = source.index("except FatalError as exc:")
        self.assertLess(summary_position, fatal_position)


class TheFatalErrorsAreTheContractualOnesTest(unittest.TestCase):
    """Section 13.1, limitative list - checked on what the adapter actually calls."""

    def test_the_capability_checked_is_the_one_the_app_declares(self):
        from acltools.appacl_preflight import REQUIRED_APP_CAPABILITY

        self.assertEqual(REQUIRED_APP_CAPABILITY, "edit_app_acl_bulk")
        self.assertIn("REQUIRED_APP_CAPABILITY", _source())

    def test_the_real_time_safeguard_is_applied(self):
        self.assertIn("check_realtime", _source())

    def test_the_family_table_and_the_read_root_are_loaded_before_any_event(self):
        source = _source()
        setup = source.index("def _setup(self)")
        stream = source.index("def stream(self")
        for marker in ("load_family_table", "resolve_apps_root"):
            with self.subTest(marker=marker):
                position = source.index(marker, setup)
                self.assertLess(position, stream)

    def test_the_journal_failure_is_fatal_only_when_a_real_write_is_planned(self):
        source = _source()
        self.assertIn("if not params.dryrun:", source)


if __name__ == "__main__":
    unittest.main()
