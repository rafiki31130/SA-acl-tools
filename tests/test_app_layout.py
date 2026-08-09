"""App structure and configuration files (sections 2, 2.1, 7, 8.3, D-3, D-5).

These files are normative deliverables just as much as the code: a key missing from
`commands.conf`, or a monitor stanza without its glob, shows up at run time and never
before.
"""

import ast
import configparser
import os
import re
import unittest

from . import BIN_DIR, REPO_ROOT


def read_conf(*parts):
    # `interpolation=None`: the values of props.conf carry `%` characters
    # (TIME_FORMAT), which the interpolation of configparser would reject.
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(os.path.join(REPO_ROOT, *parts), encoding="utf-8")
    return parser


def read_conf_exact(*parts):
    """Same reader, keys **as written**.

    `configparser` lowercases option names, which is harmless when a value is looked up
    by name and unusable when a whole stanza is compared key by key: `KV_MODE` and
    `TIME_PREFIX` would come back as `kv_mode` and `time_prefix`, and the expected
    mapping would stop looking like the file it freezes.
    """
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(os.path.join(REPO_ROOT, *parts), encoding="utf-8")
    return {s: dict(parser.items(s)) for s in parser.sections()}


class LayoutTest(unittest.TestCase):
    """The directory tree of section 2."""

    EXPECTED = (
        ("LICENSE",),
        ("README.md",),
        ("default", "app.conf"),
        ("default", "commands.conf"),
        ("default", "searchbnf.conf"),
        ("default", "authorize.conf"),
        ("default", "inputs.conf"),
        ("default", "props.conf"),
        ("default", "data", "ui", "nav", "default.xml"),
        ("default", "data", "ui", "views", "editacl_runs.xml"),
        ("metadata", "default.meta"),
        ("bin", "editacl.py"),
        ("bin", "acl_endpoint_map.json"),
        ("bin", "acltools", "__init__.py"),
        ("lookups", "acl_endpoint_map_override.csv.example"),
        ("tools", "requirements-vendor.txt"),
        ("tools", "vendor.sh"),
        ("tools", "verify_vendor.sh"),
        ("bin", "lib", "VENDOR.md"),
        ("bin", "lib", "MANIFEST.sha256"),
    )

    def test_expected_files_are_present(self):
        for parts in self.EXPECTED:
            with self.subTest(path="/".join(parts)):
                self.assertTrue(
                    os.path.exists(os.path.join(REPO_ROOT, *parts)),
                    "%s missing" % "/".join(parts),
                )

    def test_core_modules(self):
        expected = {
            "__init__.py", "errors.py", "model.py", "normalize.py", "mapping.py",
            "endpoint.py", "merge.py", "preflight.py", "journal.py", "rest.py",
            "pipeline.py",
        }
        present = {
            f for f in os.listdir(os.path.join(BIN_DIR, "acltools"))
            if f.endswith(".py")
        }
        self.assertEqual(expected - present, set())


class AppConfTest(unittest.TestCase):
    """`default/app.conf` in full.

    Found by the mutation campaign of the second remediation, hunting for the
    nineteenth: `state = disabled` passed the whole suite. One word, and **the app is
    not loaded at all** - no command, no macro, no view, no ingestion - with every test
    green. It is the same failure as `disabled = true` on the journal monitor (R-4,
    N12), one level up, and no control named this file.

    `is_visible = 0` is normative too, and for a reason worth keeping: the metadata
    exports the view to the system precisely so that a hidden app does not make it
    unreachable. Flipping the visibility here would not break anything - it would
    silently contradict the reasoning the metadata comment rests on.
    """

    EXPECTED = {
        "install": {"is_configured": "0", "state": "enabled"},
        "ui": {"is_visible": "0", "label": "SA-acl-tools"},
        "launcher": {
            "author": "SA-acl-tools contributors",
            "description": (
                "editacl search command: bulk rewrite of knowledge object ACLs "
                "through the REST API, with a write-ahead journal and rollback."
            ),
            "version": "1.0.0",
        },
        "package": {"id": "SA-acl-tools", "check_for_updates": "false"},
    }

    def test_the_app_is_enabled(self):
        self.assertEqual(read_conf("default", "app.conf").get("install", "state"),
                         "enabled")

    def test_app_conf_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(read_conf_exact("default", "app.conf"), self.EXPECTED)


class TransformsConfTest(unittest.TestCase):
    """`default/transforms.conf` in full.

    Same campaign, same class of hole: pointing `acl_object_families` at the other
    shipped CSV passed the suite. The inventory would then walk the wrong table and
    return an empty or wrong set of endpoints - `HTTP 200`, no message. The lookup
    definitions are two stanzas of two keys; freezing them whole costs nothing.
    """

    EXPECTED = {
        "acl_object_families": {
            "filename": "acl_object_families.csv",
            "case_sensitive_match": "false",
        },
        "acl_decommissioned_roles": {
            "filename": "acl_decommissioned_roles.csv",
            "case_sensitive_match": "false",
        },
    }

    def test_transforms_conf_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(read_conf_exact("default", "transforms.conf"), self.EXPECTED)


class DeployableArchiveTest(unittest.TestCase):
    """`.gitattributes` decides what `git archive` puts inside the installed app.

    Same campaign: removing `tests/ export-ignore` passed the suite. D-37 makes the
    deployment start from the commit, so this file is what keeps the test suite, the
    maintenance tools and the development notes OUT of a search head. Nothing else states
    that scope, and nothing else would notice it changing.

    `DEVNOTES.md` replaced the `docs/` directory when the README was reduced to an
    operator document: one file at the root instead of a directory, still excluded, for
    the same reason. A **file** rather than a directory matters to this check - a pattern
    written `DEVNOTES` or `docs` without its trailing marker would silently stop matching.
    """

    EXPORT_IGNORED = ("tests/", "tools/", "DEVNOTES.md", ".gitattributes", ".gitignore")

    def setUp(self):
        with open(os.path.join(REPO_ROOT, ".gitattributes"), encoding="utf-8") as f:
            self.lines = [l.strip() for l in f if l.strip()
                          and not l.strip().startswith("#")]

    def test_the_repository_only_directories_stay_out_of_the_archive(self):
        ignored = {
            line.split()[0] for line in self.lines if "export-ignore" in line
        }
        self.assertEqual(ignored, set(self.EXPORT_IGNORED))

    def test_the_vendored_dependencies_are_stored_verbatim(self):
        # A line-ending conversion would invalidate bin/lib/MANIFEST.sha256 at clone
        # time, on a machine nobody is watching.
        self.assertIn("bin/lib/** -text", self.lines)


class CommandsConfTest(unittest.TestCase):
    """Section 2.1: the keys are normative, reproduced identically."""

    EXPECTED = {
        "filename": "editacl.py",
        "chunked": "true",
        "python.version": "python3",
        "local": "true",
        "run_in_preview": "false",
        "is_risky": "true",
        "maxinputs": "0",
    }

    def setUp(self):
        self.conf = read_conf("default", "commands.conf")

    def test_stanza_editacl(self):
        self.assertIn("editacl", self.conf.sections())

    def test_the_normative_keys_are_reproduced_identically(self):
        for key, value in self.EXPECTED.items():
            with self.subTest(key=key):
                self.assertEqual(self.conf.get("editacl", key), value)

    def test_no_extra_key(self):
        self.assertEqual(
            sorted(self.conf.options("editacl")), sorted(self.EXPECTED)
        )


class SearchBnfConfTest(unittest.TestCase):
    """`searchbnf.conf`: syntax highlighting, input assistance, usage example.

    Without this file `editacl` runs, but the search interface ignores it entirely. Its
    absence produces no error at all: that is what let it survive two audits. The tests
    below freeze what would otherwise only be observable by opening a browser on an
    instance.

    The following failure mode is the nastiest one: a file that is valid, loaded, and
    **without effect** because it is only visible in the context of its own app while
    the assistant reads the context of the page. That one is locked down by
    `MetadataTest`.
    """

    #: Primitive terms of the grammar, defined by the platform and not by a stanza.
    #: Any other referenced production must exist in this file.
    PRIMITIVES = frozenset({"bool", "int", "string", "field", "field-list"})

    def setUp(self):
        self.conf = read_conf("default", "searchbnf.conf")

    def _syntaxes(self):
        return {
            section: self.conf.get(section, "syntax")
            for section in self.conf.sections()
            if self.conf.has_option(section, "syntax")
        }

    def test_the_stanza_carries_the_name_of_the_declared_command(self):
        """The `[<command>-command]` convention is imposed by the platform: a badly
        named stanza is loaded without error and highlights nothing."""
        commands = read_conf("default", "commands.conf").sections()
        self.assertEqual(commands, ["editacl"])
        self.assertIn("editacl-command", self.conf.sections())

    def test_usage_public(self):
        """`usage` is required, and the search assistant only acts on `public`."""
        self.assertEqual(self.conf.get("editacl-command", "usage"), "public")

    def test_the_syntax_starts_with_the_command_name(self):
        self.assertTrue(
            self.conf.get("editacl-command", "syntax").startswith("editacl"),
            "the production must open on the literal `editacl`",
        )

    def test_every_referenced_production_is_defined(self):
        """An orphan production breaks syntax analysis on the assistant side, with
        nothing reporting it on the server side."""
        defined = set(self.conf.sections()) | self.PRIMITIVES
        orphans = set()
        for syntax in self._syntaxes().values():
            for term in re.findall(r"<([A-Za-z0-9._-]+)>", syntax):
                if term.split(":")[0] not in defined:
                    orphans.add(term)
        self.assertEqual(sorted(orphans), [])

    def test_the_described_options_are_exactly_those_of_the_code(self):
        """Anti-drift: the assistant must never offer an option the command does not
        know, nor stay silent about an option it accepts.

        The names are read from the source of `bin/editacl.py`, never by import: the
        suite stays runnable without the SDK.
        """
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        options_of_the_code = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "EditAclCommand":
                for element in node.body:
                    if (isinstance(element, ast.Assign)
                            and isinstance(element.value, ast.Call)
                            and isinstance(element.value.func, ast.Name)
                            and element.value.func.id == "Option"):
                        for target in element.targets:
                            if isinstance(target, ast.Name):
                                options_of_the_code.add(target.id)
        self.assertTrue(options_of_the_code, "no Option read from bin/editacl.py")

        options_described = set()
        for section, syntax in self._syntaxes().items():
            if section == "editacl-command":
                continue
            options_described.add(syntax.split("=", 1)[0].strip())
        self.assertEqual(options_described, options_of_the_code)

    def test_every_option_of_the_code_appears_in_the_command_syntax(self):
        syntax = self.conf.get("editacl-command", "syntax")
        for section in self._syntaxes():
            if section == "editacl-command":
                continue
            self.assertIn("<%s>" % section, syntax)

    def test_description_and_summary_are_filled_in(self):
        for key in ("shortdesc", "description"):
            with self.subTest(key=key):
                self.assertTrue(self.conf.get("editacl-command", key).strip())

    def test_at_least_one_example_with_its_comment(self):
        examples = [
            o for o in self.conf.options("editacl-command")
            if re.fullmatch(r"example\d+", o)
        ]
        self.assertTrue(examples, "the assistant shows an example: one must be given")
        for example in examples:
            with self.subTest(example=example):
                self.assertIn(
                    example.replace("example", "comment"),
                    self.conf.options("editacl-command"),
                )
                self.assertIn("editacl", self.conf.get("editacl-command", example))

    def test_the_simulation_default_is_told_to_the_operator(self):
        """The assistant is the first place where the operator reads the syntax: the
        fact that nothing will be written without `dryrun=false` belongs there."""
        text = " ".join(
            self.conf.get(section, key)
            for section in ("editacl-command", "editacl-dryrun")
            for key in ("description",)
        )
        self.assertIn("dryrun=false", text)


class MetadataTest(unittest.TestCase):
    """`metadata/default.meta`: object visibility, on which their effect depends.

    A `searchbnf.conf` confined to the context of its own app is loaded, exposed on
    `/servicesNS/nobody/SA-acl-tools/configs/conf-searchbnf`, and strictly without
    effect where the operator types a search: the assistant reads the namespace of the
    **page**, that is, the `search` app. Measured on Splunk 9.4.6: without the stanza
    below, `/servicesNS/admin/search/configs/conf-searchbnf?search=editacl` returns
    `total=0`; with it, the six stanzas. No error in either case.
    """

    @staticmethod
    def read_meta():
        """Dedicated reader: `configparser` rejects the `[]` stanza of a `.meta` file,
        which is the Splunk default stanza and cannot be removed."""
        stanzas = {}
        current = None
        path = os.path.join(REPO_ROOT, "metadata", "default.meta")
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1]
                    stanzas.setdefault(current, {})
                elif "=" in line and current is not None:
                    key, value = line.split("=", 1)
                    stanzas[current][key.strip()] = value.strip()
        return stanzas

    def setUp(self):
        self.meta = self.read_meta()

    def test_the_search_assistant_follows_the_command(self):
        self.assertIn("searchbnf", self.meta)
        self.assertEqual(self.meta["searchbnf"].get("export"), "system")

    def test_the_command_is_exported(self):
        self.assertEqual(self.meta["commands"].get("export"), "system")


class AuthorizeConfTest(unittest.TestCase):

    def test_capability_is_declared(self):
        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::edit_acl_bulk", conf.sections())

    def test_the_capability_name_is_the_one_checked_by_the_code(self):
        from acltools.preflight import REQUIRED_CAPABILITY

        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::%s" % REQUIRED_CAPABILITY, conf.sections())


class InputsConfTest(unittest.TestCase):
    """D-3: one file per `sid`, therefore a monitor stanza written as a **glob**.

    R-4 of the re-audit of 2026-08-09. Everything below used to check that the EXPECTED
    keys carried the expected value, and nothing checked what else the file said. The
    mutation that put `disabled = true` on the journal monitor passed 689 tests: the
    write-ahead journal would never be ingested again, the restore macro would return
    nothing, the monitoring view would be empty, and **the safety net of an irreversible
    operation would no longer exist** - with the whole suite green.

    The stanza set and every key of it are therefore frozen exhaustively, the same way
    `authorize.conf` is. `disabled` also gets a control of its own, because that one is
    not an inconsistency between two files: it is the deliverable ceasing to work.
    """

    #: `default/inputs.conf` in full, stanza by stanza and key by key.
    EXPECTED = {
        "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log": {
            "disabled": "false",
            "index": "_internal",
            "sourcetype": "editacl:journal",
        },
        "monitor://$SPLUNK_HOME/var/log/splunk/editacl.log": {
            "disabled": "false",
            "index": "_internal",
            "sourcetype": "editacl:diag",
        },
    }

    def setUp(self):
        self.conf = read_conf("default", "inputs.conf")

    def test_neither_monitor_is_disabled(self):
        for stanza in self.EXPECTED:
            with self.subTest(stanza=stanza):
                self.assertEqual(self.conf.get(stanza, "disabled"), "false")

    def test_inputs_conf_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(read_conf_exact("default", "inputs.conf"), self.EXPECTED)

    def test_journal_stanza_is_a_glob(self):
        expected = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertIn(expected, self.conf.sections())

    def test_the_glob_matches_the_filename_produced_by_the_code(self):
        from acltools.journal import journal_filename

        name = journal_filename("1754483000.1")
        self.assertTrue(name.startswith("editacl_journal"))
        self.assertTrue(name.endswith(".log"))

    def test_dedicated_sourcetypes(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        diag = "monitor://$SPLUNK_HOME/var/log/splunk/editacl.log"
        self.assertEqual(self.conf.get(journal, "sourcetype"), "editacl:journal")
        self.assertEqual(self.conf.get(diag, "sourcetype"), "editacl:diag")

    def test_index_configurable_in_a_single_place(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertEqual(self.conf.get(journal, "index"), "_internal")


class PropsConfTest(unittest.TestCase):
    """R-4 of the re-audit of 2026-08-09: the journal stanza was guarded by halves.

    `TRUNCATE` and `KV_MODE` were checked; `TIME_PREFIX` and `MAX_TIMESTAMP_LOOKAHEAD`
    were not, and a mutation of either passed 689 tests. Both decide **when** an event
    happened: broken, the platform falls back to the ingestion time, and every
    time-bounded search over the journal - the restore macro first among them, which the
    README already warns "will not see yesterday's run and will restore nothing, without
    an error" - drifts silently. Freezing the two stanzas whole is cheaper than arguing
    about which key deserves a test.
    """

    #: `default/props.conf` in full, stanza by stanza and key by key.
    EXPECTED = {
        "editacl:journal": {
            "KV_MODE": "json",
            "SHOULD_LINEMERGE": "false",
            "LINE_BREAKER": "([\\r\\n]+)",
            "TIME_PREFIX": '\\"ts\\":\\"',
            "TIME_FORMAT": "%Y-%m-%dT%H:%M:%S.%3N%:z",
            "MAX_TIMESTAMP_LOOKAHEAD": "40",
            "TRUNCATE": "0",
        },
        "editacl:diag": {
            "SHOULD_LINEMERGE": "false",
            "LINE_BREAKER": "([\\r\\n]+)",
            "KV_MODE": "none",
            "EXTRACT-editacl_diag_run":
                "^\\S+\\s+(?<level>[A-Z]+)\\s+sid=(?<sid>\\S+)",
            "EXTRACT-editacl_diag_startup":
                "\\bversion=(?<version>\\S+)\\s+user=(?<user>\\S+)\\s",
            "EXTRACT-editacl_diag_target":
                "\\bsplunkd=(?<splunkd>\\S+)\\s+verify_ssl=(?<verify_ssl>\\S+)",
            "EXTRACT-editacl_diag_params":
                "\\bdryrun=(?<dryrun>\\S+)\\s+validate_roles=(?<validate_roles>\\S+)"
                "\\s+journal=(?<journal>\\S+)\\s+max_objects=(?<max_objects>\\S+)",
            "EXTRACT-editacl_diag_journal":
                "(?<journal_file>editacl_journal\\S*\\.log)",
        },
    }

    def setUp(self):
        self.conf = read_conf("default", "props.conf")

    def test_props_conf_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(read_conf_exact("default", "props.conf"), self.EXPECTED)

    def test_the_timestamp_of_the_journal_is_read_from_the_journal(self):
        # Without `TIME_PREFIX`, the platform timestamps the event with something else -
        # often the ingestion time - and says nothing about it.
        self.assertEqual(self.conf.get("editacl:journal", "TIME_PREFIX"), '\\"ts\\":\\"')

    def test_the_lookahead_covers_the_timestamp_it_has_to_read(self):
        # The value has to be at least as long as the timestamp that follows the prefix.
        # Shortened, the parse fails and falls back, silently.
        lookahead = int(self.conf.get("editacl:journal", "MAX_TIMESTAMP_LOOKAHEAD"))
        self.assertEqual(lookahead, 40)
        self.assertGreaterEqual(
            lookahead, len("2026-08-09T07:57:52.075+00:00")
        )

    def test_json_extraction_of_the_journal(self):
        self.assertEqual(self.conf.get("editacl:journal", "KV_MODE"), "json")

    def test_timestamp_format_aligned_with_the_journal(self):
        self.assertEqual(
            self.conf.get("editacl:journal", "TIME_FORMAT"),
            "%Y-%m-%dT%H:%M:%S.%3N%:z",
        )

    def test_truncation_disabled(self):
        self.assertEqual(self.conf.get("editacl:journal", "TRUNCATE"), "0")

    def test_the_diagnostic_is_not_read_as_key_value(self):
        # The diagnostic file is free text, and the automatic extractor invents fields
        # out of whatever looks like `key=value` in a message. Measured consequence and
        # full reasoning: `default/props.conf`, and `tests/test_dashboard.py`
        # `TheDiagnosticIsReadAsFreeTextTest`.
        self.assertEqual(self.conf.get("editacl:diag", "KV_MODE"), "none")

    def test_the_diagnostic_declares_what_it_takes_back(self):
        keys = [k for k in self.conf.options("editacl:diag") if k.startswith("extract-")]
        self.assertTrue(keys, "KV_MODE=none with no declared extraction reads nothing")


class NoShippedStanzaIsNeutralizedTest(unittest.TestCase):
    """Every shipped stanza is one attribute away from doing nothing at all.

    S-2 of the second re-audit of 2026-08-09. `disabled = 1` on the shipped search that
    is the entry point of the restore (section 12.8) passed all 713 tests: the search
    never runs again, and nothing anywhere says so. It is the very class the previous
    remediation closed **one file further along** - `disabled = true` on the journal
    monitor of `inputs.conf`, which got a control of its own and only of its own.

    Naming the case a second time would leave the third one open. What is checked here
    is the **family**: no stanza of any shipped `.conf` file may carry a truthy
    `disabled`, whatever the file, whatever the spelling of the boolean. The signature
    of the class is always the same - the artifact is still installed, still correct,
    still exposed by the API, and it does not run.

    The three other members of the family are already held, each by a control that
    names the thing it protects, and the mutation campaign exercises them alongside
    these ones:

      - the **app** itself, by `AppConfTest.test_the_app_is_enabled` (`state = disabled`
        loads nothing at all);
      - a **panel of the view**, by
        `tests/test_dashboard.py::test_every_token_used_in_depends_or_rejects_is_set_somewhere`
        (a `depends` on a token nobody sets hides the panel for good);
      - the **view in the navigation**, by
        `tests/test_dashboard.py::test_the_nav_declares_the_view`.
    """

    #: How Splunk reads a boolean, `normalizeBoolean` style. `disabled = 0` and
    #: `disabled = false` are the shipped values and stay legal; everything below is
    #: the artifact switched off.
    TRUTHY = ("1", "t", "true", "y", "yes", "on")

    @staticmethod
    def shipped_conf_files():
        directory = os.path.join(REPO_ROOT, "default")
        return sorted(n for n in os.listdir(directory) if n.endswith(".conf"))

    def test_the_sweep_reaches_every_shipped_configuration_file(self):
        # A sweep whose input set silently empties passes for ever after. The set is
        # therefore frozen: a new shipped `.conf` file has to be added here, which is
        # the moment somebody decides it is covered.
        self.assertEqual(
            self.shipped_conf_files(),
            [
                "app.conf",
                "authorize.conf",
                "commands.conf",
                "inputs.conf",
                "macros.conf",
                "props.conf",
                "savedsearches.conf",
                "searchbnf.conf",
                "transforms.conf",
            ],
        )

    def test_no_shipped_stanza_is_switched_off(self):
        from .test_spl_artifacts import read_splunk_conf

        for name in self.shipped_conf_files():
            for stanza, keys in read_splunk_conf("default", name).items():
                for key, value in keys.items():
                    if key.strip().lower() != "disabled":
                        continue
                    with self.subTest(file=name, stanza=stanza):
                        self.assertNotIn(
                            value.strip().lower(),
                            self.TRUTHY,
                            "default/%s [%s] is switched off" % (name, stanza),
                        )

    def test_every_shipped_search_declares_itself_enabled(self):
        """Absence is not a defence here.

        `savedsearches.conf` is the one file of the app where the operator is expected
        to override stanza by stanza, and a missing `disabled` leaves the value to
        whatever the layer beneath says. The shipped file states it, and stating it is
        what makes the sweep above meaningful for these stanzas.
        """
        from .test_spl_artifacts import read_splunk_conf

        searches = read_splunk_conf("default", "savedsearches.conf")
        self.assertEqual(len(searches), 4, "the shipped search set changed")
        for stanza, keys in searches.items():
            with self.subTest(stanza=stanza):
                self.assertEqual(keys.get("disabled"), "0")


class SplArtifactsTest(unittest.TestCase):
    """SPL deliverables of phase 2b. Their content is exercised by
    `tests/test_spl_artifacts.py`; here only their presence is checked."""

    EXPECTED = (
        ("default", "macros.conf"),
        ("default", "savedsearches.conf"),
        ("default", "transforms.conf"),
        ("lookups", "acl_object_families.csv"),
        ("lookups", "acl_decommissioned_roles.csv"),
        ("tools", "revalidate_mapping.py"),
        ("tools", "acl_probe_bootstrap.sh"),
        ("tools", "acl_probe_bootstrap_rest.py"),
    )

    def test_the_spl_artifacts_are_shipped(self):
        for parts in self.EXPECTED:
            path = os.path.join(REPO_ROOT, *parts)
            self.assertTrue(os.path.exists(path), path)
            self.assertTrue(os.path.getsize(path) > 0, path)


if __name__ == "__main__":
    unittest.main()
