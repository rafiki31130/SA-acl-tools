"""`bin/appaclinventory.py` - adapter, wiring, and the rules that hold on its source.

Same three guard rails as the other two adapters, and deliberately the **same
instruments**: v4.3 section 13.2 asks for the single-emission-point control to be
extended to the new files, and extending a control means reusing it rather than writing a
second one that will drift.

Two things are proper to this adapter, and both are held here:

- it is the third file where the read root of section 6.2 bound 4 is resolved, so it is
  the third place one of the three **misleading localizations** of HY-6 could enter;
- it is the only command of the app that mutates nothing, so its fatal-error list is
  **shorter** than its neighbours' - the unreadable family table is not one of them, and
  section 13.1 says so in as many words.
"""

import ast
import os
import unittest

from acltools.appacl_inventory import INVENTORY_OUTPUT_FIELDS

from . import BIN_DIR
from .test_message_prefix import (
    SDK_MESSAGE_METHODS,
    _Extractor,
)

ADAPTER_PATH = os.path.join(BIN_DIR, "appaclinventory.py")

#: The one scope allowed to reach an SDK message method, `<class>.<method>` form.
SINGLE_EMISSION_POINT = "AppAclInventoryCommand._emit_message"


def _source():
    with open(ADAPTER_PATH, encoding="utf-8") as handle:
        return handle.read()


def _code_only():
    """The source without its comment lines - what the reader of a rule must not find."""
    return "\n".join(
        line for line in _source().splitlines() if not line.strip().startswith("#")
    )


def _analyse():
    source = _source()
    extractor = _Extractor(source)
    extractor.visit(ast.parse(source, filename=ADAPTER_PATH))
    return extractor


class TheSingleEmissionPointTest(unittest.TestCase):
    """v4.3 section 13.2, extended to the third adapter.

    This command is meant to OPEN a pipeline that ends in `editappacl`, so its messages
    sit next to that command's in an interface that strips them of their origin. Without
    the prefix, a reservation about a truncated inventory would be indistinguishable from
    a warning about an irreversible write.
    """

    @classmethod
    def setUpClass(cls):
        cls.extractor = _analyse()

    def test_the_extraction_is_not_empty(self):
        self.assertGreaterEqual(
            len(self.extractor.sites),
            3,
            "the extractor found no call to an SDK message method in "
            "bin/appaclinventory.py: it is reading nothing, or the file changed shape",
        )

    def test_no_construct_is_opaque(self):
        if not self.extractor.opaque:
            return
        detail = "\n".join(
            "  appaclinventory.py:%d in %s -- %s\n        source: %s"
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
        self.assertIn('MESSAGE_PREFIX = "appaclinventory: "', _source())

    def test_the_prefix_is_not_repeated_on_the_literals(self):
        self.assertEqual(_source().count('"appaclinventory: '), 1)

    def test_the_three_prefixes_are_distinct(self):
        """Three commands, three prefixes: a shared one would defeat the whole purpose,
        which is to say WHICH command spoke."""
        from .test_message_prefix import EDITACL_PATH

        prefixes = set()
        for path in (EDITACL_PATH, os.path.join(BIN_DIR, "editappacl.py"), ADAPTER_PATH):
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MESSAGE_PREFIX = "):
                        prefixes.add(line.split("=", 1)[1].strip())
        self.assertEqual(len(prefixes), 3, prefixes)


class TheAdapterCarriesNoBusinessRuleTest(unittest.TestCase):
    """The adapter wires, it does not decide (section 14.1, deliverable 1)."""

    def setUp(self):
        self.tree = ast.parse(_source(), filename=ADAPTER_PATH)

    def test_no_decision_function_of_the_core_is_redefined_here(self):
        defined = {
            node.name
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        forbidden = {
            "governable_of", "families_to_emit", "split_access", "parse_meta",
            "resolve_apps_root", "list_applications", "resolve_member",
            "parse_app_filter", "app_matches", "read_effective_state",
        }
        self.assertEqual(defined & forbidden, set())

    def test_it_compiles_without_the_sdk(self):
        compile(_source(), ADAPTER_PATH, "exec")

    def test_the_syspath_insertion_precedes_the_first_sdk_import(self):
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

    def test_it_declares_itself_a_generating_command(self):
        self.assertIn("GeneratingCommand", _code_only())
        self.assertIn("def generate(self)", _code_only())

    def _configuration_keywords(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if ast.unparse(node.func) != "Configuration":
                continue
            return {k.arg: ast.literal_eval(k.value) for k in node.keywords}
        return None

    def test_it_declares_the_reporting_type(self):
        """**What the command DECLARES, not what it omits** (v4.5 section 7.2).

        Measured: without it the command produced **events** - `eventCount=9`, empty
        `reportSearch` - where the native generating commands produce results, so Splunk
        Web opened the job on the Events tab and rendered rows that have no raw event.
        `| rest` and `| metadata` are the witnesses: `eventCount=0`, `reportSearch` filled.

        The previous version of this test froze the **absence** of the keyword. That is
        exactly the shape friction #413 names: a contract that only states absences cannot
        detect an unsuitable default. Both halves are checked here - the decorator carries
        the value, and `commands.conf` still carries no `type` key, where it would be inert.
        """
        keywords = self._configuration_keywords()
        self.assertIsNotNone(keywords, "no @Configuration call found in the adapter")
        self.assertEqual(
            keywords.get("type"), "reporting",
            "the adapter must declare type=\"reporting\": on a chunked command it is the "
            "ONLY route, the type key of commands.conf being measured without effect.",
        )
        self.assertEqual(keywords.get("local"), True)

    def test_it_does_not_redeclare_the_generating_flag(self):
        """`generating` is read-only on the base class and already true; passing it would
        be refused. The precedent is exact - `@Configuration(type='streaming')` is refused
        on a StreamingCommand, `type` being pinned there."""
        self.assertNotIn("generating", self._configuration_keywords())

    def test_commands_conf_carries_no_type_key(self):
        """The other half. On a `chunked` command the `type` key of `commands.conf` is
        measured **without effect** - tried with a service restart - because the metadata
        the SDK sends in the `getinfo` chunk prevails. A test freezing that key would
        freeze a placebo."""
        from .test_spl_artifacts import read_splunk_conf

        for stanza, keys in read_splunk_conf("default", "commands.conf").items():
            with self.subTest(command=stanza):
                self.assertNotIn("type", keys)

    def test_the_two_write_commands_are_untouched(self):
        """`type` is pinned on `StreamingCommand`, and the setting is carried by each
        class's own decorator: the reporting classification cannot leak sideways."""
        import os

        from . import BIN_DIR

        for name in ("editacl.py", "editappacl.py"):
            with open(os.path.join(BIN_DIR, name), encoding="utf-8") as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and ast.unparse(node.func) == "Configuration":
                    with self.subTest(command=name):
                        self.assertNotIn(
                            "type", {k.arg for k in node.keywords},
                            "%s must not declare a type: the base class pins it" % name,
                        )


class TheMisleadingLocalizationsAreForbiddenHereTooTest(unittest.TestCase):
    """Bound 1 of section 6.2, second family, applied to the **third** file that resolves
    the read root.

    The bound names three expressions HY-6 measured as plausible and false. The provenance
    module is already held by a syntax-tree test of its own; this adapter is the other
    place they could enter, because it is the one holding the SDK objects that carry them.

    - the SDK's `environment.splunk_home` falls back on the **working directory** when the
      variable is missing, and the working directory is the app's `bin/`, under which
      `etc/apps` does not exist;
    - `os.getcwd()` is that same directory, in all three measured executions;
    - `searchinfo.app` names the **dispatching** app, not the carrying one.
    """

    FORBIDDEN = ("environment.splunk_home", "getcwd", "searchinfo.app")

    def test_none_of_the_three_appears_in_the_code(self):
        code = _code_only()
        for expression in self.FORBIDDEN:
            with self.subTest(expression=expression):
                self.assertNotIn(expression, code)

    def test_the_read_root_is_resolved_from_this_module_and_the_environment(self):
        """The two named routes of bound 4, and the adapter hands over its own
        `__file__`: the core cannot go looking for one without reaching for exactly the
        expressions forbidden above."""
        self.assertIn("resolve_apps_root(os.environ, __file__)", _source())

    def test_the_two_routes_are_compared_before_anything_is_read(self):
        source = _source()
        setup = source.index("def _setup(self)")
        generate = source.index("def generate(self)")
        self.assertLess(source.index("resolve_apps_root", setup), generate)


class TheDeclaredOutputFieldsTest(unittest.TestCase):
    """Section 7.4, and v3.14 D-33: the field set is declared, never inferred.

    The trap is sharper on a generating command than on a streaming one: the first record
    of an inventory is ALWAYS an `app_default` row, which is the one row leaving
    `acl_families_with_own_perms` filled from an application fact. Without the
    columns would vanish from the whole table, and a run whose first application has no
    family would lose more still - with no error and no warning.
    """

    def test_the_declaration_is_made_on_the_writer(self):
        source = _source()
        self.assertIn("custom_fields", source)
        self.assertIn("INVENTORY_OUTPUT_FIELDS", source)

    def test_it_is_declared_before_the_first_record(self):
        source = _source()
        self.assertIn("def prepare(self)", source)
        self.assertLess(
            source.index("_declare_output_fields"), source.index("def generate(self)")
        )

    def test_no_declared_field_names_an_owner(self):
        """**DV-5**: no owner is read, written, compared or published - and the inventory
        is the command that would be tempted, the file carrying an `owner` key."""
        for field in INVENTORY_OUTPUT_FIELDS:
            with self.subTest(field=field):
                self.assertNotIn("owner", field)

    def test_the_declaration_has_no_duplicate(self):
        self.assertEqual(
            len(INVENTORY_OUTPUT_FIELDS), len(set(INVENTORY_OUTPUT_FIELDS))
        )


class TheFatalErrorsAreTheContractualOnesTest(unittest.TestCase):
    """Section 13.1, limitative list, **and its scoping**.

    The list is shorter for this command than for `editappacl`, and that is written in the
    contract rather than inferred: "family table unreadable (`editappacl` only)". The
    reason it holds up: the write command cannot resolve a target without the table, the
    inventory reads its decisive columns from the file and only uses the table to fill
    `acl_handler`.
    """

    def test_the_capability_checked_is_the_one_the_app_declares(self):
        from acltools.appacl_preflight import REQUIRED_INVENTORY_CAPABILITY

        self.assertEqual(REQUIRED_INVENTORY_CAPABILITY, "list_app_acl")
        self.assertIn("REQUIRED_INVENTORY_CAPABILITY", _source())

    def test_the_capability_is_checked_before_any_row_is_produced(self):
        source = _source()
        self.assertLess(
            source.index("check_capability"), source.index("def generate(self)")
        )

    def test_the_real_time_safeguard_is_applied(self):
        self.assertIn("check_realtime", _source())

    def test_the_unreadable_family_table_is_a_warning_and_not_a_fatal_error(self):
        source = _source()
        self.assertIn("except FatalFamilyTableError:", source)
        self.assertIn("TABLE_UNREADABLE_WARNING", source)

    def test_the_degraded_mode_is_stated_to_the_operator(self):
        """A degradation nobody announces is a silent one, and the columns it degrades -
        `acl_handler`, and `acl_effective_status` with it - are the ones that say whether
        the tool can act on the family at all."""
        from importlib import import_module

        module = import_module("acltools.appacl_inventory")
        source = _source()
        marker = source.index("TABLE_UNREADABLE_WARNING = (")
        text = source[marker:marker + 700]
        self.assertIn("acl_handler", text)
        self.assertIn(module.EFFECTIVE_UNREADABLE, text)
        self.assertNotIn("no_route", text,
                         "the value left the domain of acl_write_effect in v4.7")

    def test_the_fatal_path_marks_the_job_as_failed(self):
        """The SDK's `error_exit` sends a final chunk carrying `finished: true`, after
        which splunkd ignores the return code: the job comes out DONE and not failed, and
        an interrupted inventory would read as an estate with no application at all."""
        source = _source()
        self.assertIn("write_chunk(finished=False)", source)
        self.assertIn("_abort_process(1)", source)

    def test_it_neither_journals_nor_writes_a_diagnostic_file(self):
        """The command mutates nothing, so there is nothing to journal and no write-ahead
        line to persist. Section 11.1 gives the journal and the diagnostic to `editappacl`
        and to it alone; inventing a third pair here would add two monitor stanzas and two
        sourcetypes that no shipped search reads."""
        source = _source()
        for forbidden in ("JournalWriter", "app_journal_path", "open_app_diagnostics"):
            with self.subTest(symbol=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
