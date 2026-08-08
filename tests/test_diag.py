"""Diagnostic log `editacl.log` (section 8.1, A-3).

The file was announced by section 8.1, by `inputs.conf` and by `props.conf`, and was
**never written**: there was no `import logging` anywhere in `bin/`. These tests freeze
the three things that matter: that it is produced, that it carries what section 8.1
enumerates, and that it carries **no secret**.

They also freeze a negative property: losing the diagnostic never costs a run. The
diagnostic file is not the rollback journal; confusing the two would reproduce, on the
observability side, the design error that D-3 avoided.
"""

import ast
import configparser
import logging
import os
import shutil
import tempfile
import unittest
from logging.handlers import RotatingFileHandler

from acltools import diag as diag_module
from acltools.diag import (
    BACKUP_COUNT,
    DIAG_BASENAME,
    MAX_BYTES,
    Diagnostics,
    NullDiagnostics,
    diag_path,
    open_diagnostics,
    redact,
)
from acltools.mapping import load_mapping
from acltools.model import FieldNames, Params

from . import BIN_DIR, REPO_ROOT

#: Dummy value, shaped like a Splunk session key. It is a secret nowhere.
FAKE_KEY = "vBkTFCbEXAMPLEnotarealkey0123456789abcdefABCDEF0123456789xyz"


class DiagTree(object):
    """Throwaway log directory."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="acl_diag_")
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def content(self):
        path = diag_path(self.dir)
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as handle:
            return handle.read()


def params(names=None, warnings=()):
    return Params(
        names=names or FieldNames(),
        dryrun=False,
        validate_roles=True,
        journal=True,
        max_objects=10,
        warnings=tuple(warnings),
    )


class FileIsProducedTest(unittest.TestCase):
    """A-3: the file must exist and must not be empty."""

    def test_the_file_is_created_and_written(self):
        with DiagTree() as tree:
            diag = open_diagnostics(tree.dir, sid="1786033792.6")
            self.assertTrue(diag.enabled)
            diag.startup(version="1.0.0", user="operator")
            diag.close()

            self.assertTrue(os.path.exists(diag_path(tree.dir)))
            self.assertTrue(tree.content().strip())

    def test_the_file_name_is_the_one_the_confs_monitor(self):
        """`inputs.conf` declares the monitor and `props.conf` the sourcetype: the name
        of the file actually opened must be that one, otherwise nothing is
        collected."""
        parser = configparser.ConfigParser(strict=False)
        parser.read(os.path.join(REPO_ROOT, "default", "inputs.conf"), encoding="utf-8")
        stanzas = [s for s in parser.sections() if DIAG_BASENAME in s]
        self.assertEqual(
            len(stanzas), 1,
            "no monitor stanza carries %r" % DIAG_BASENAME,
        )
        self.assertEqual(parser.get(stanzas[0], "sourcetype"), "editacl:diag")

    def test_rotation_conforms_to_section_8_1(self):
        """Section 8.1 taken literally: "`RotatingFileHandler`, 5 MB x 5"."""
        self.assertEqual(MAX_BYTES, 5 * 1024 * 1024)
        self.assertEqual(BACKUP_COUNT, 5)
        with DiagTree() as tree:
            diag = open_diagnostics(tree.dir)
            try:
                handler = diag._handler
                self.assertIsInstance(handler, RotatingFileHandler)
                self.assertEqual(handler.maxBytes, MAX_BYTES)
                self.assertEqual(handler.backupCount, BACKUP_COUNT)
            finally:
                diag.close()

    def test_one_line_per_record_and_iso_timestamp(self):
        with DiagTree() as tree:
            diag = open_diagnostics(tree.dir, sid="s1")
            diag.info("first line")
            diag.warning("message\non two lines")
            diag.close()

            lines = [l for l in tree.content().splitlines() if l.strip()]
            self.assertEqual(len(lines), 2)
            for line in lines:
                timestamp = line.split(" ", 1)[0]
                self.assertRegex(
                    timestamp,
                    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$",
                )
                self.assertIn("sid=s1", line)


class ContentRequiredBySection81Test(unittest.TestCase):
    """The five headings section 8.1 enumerates, by name: "startup, capability check,
    parameters, mapping table resolution, fatal errors"."""

    def test_the_five_headings_are_present(self):
        with DiagTree() as tree:
            diag = open_diagnostics(tree.dir, sid="1786033792.6")
            diag.startup(version="1.0.0", user="operator", splunkd_uri="https://x:8089")
            diag.params(params(warnings=("dryrun=false with no explicit max_objects",)))
            diag.capability(True)
            diag.realtime("batch")
            diag.mapping(load_mapping(os.path.join(BIN_DIR, "acl_endpoint_map.json"))
                         .coverage())
            diag.journal("/var/log/splunk/editacl_journal_1786033792.6.log", True)
            diag.fatal("capability 'edit_acl_bulk' missing")
            diag.close()

            text = tree.content()

        for expected in (
            "editacl startup",
            "version=1.0.0",
            "parameters dryrun=false",
            # The nine field-naming parameters are recorded: without them, a run in
            # which a field name was redirected is unreadable after the fact.
            "field names title=title",
            "new_owner=eai:acl.owner",
            "max_objects=10",
            "capability check",
            "mapping table: 28 entries",
            "rollback journal opened",
            "fatal error: capability 'edit_acl_bulk' missing",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

        self.assertIn("WARNING", text)
        self.assertIn("CRITICAL", text)

    def test_the_table_loading_callback_does_write_into_the_file(self):
        """Section 8.1, "table resolution": `load_mapping` must receive the diagnostic.

        This is the exact point raised by the audit: `load_mapping()` was called
        without `diag`, so the discarded entries left no trace at all.
        """
        with DiagTree() as tree:
            directory = tempfile.mkdtemp(prefix="acl_map_")
            try:
                path = os.path.join(directory, "map.json")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write('{"good": "saved/searches", "bad": "../escape"}')
                diag = open_diagnostics(tree.dir)
                load_mapping(path, diag=diag)
                diag.close()
            finally:
                shutil.rmtree(directory, ignore_errors=True)

            text = tree.content()
        self.assertIn("table entry discarded", text)
        self.assertIn("WARNING", text)


class NoSecretTest(unittest.TestCase):
    """R5: a diagnostic file collected into an index is read by far more people than
    the disk of the search head."""

    def test_redaction_of_the_known_forms(self):
        for message in (
            "Authorization: Splunk %s" % FAKE_KEY,
            "header Authorization=%s" % FAKE_KEY,
            "session_key=%s" % FAKE_KEY,
            "session-key: %s" % FAKE_KEY,
            "password=notarealpassword123",
            "api_key: %s" % FAKE_KEY,
            "Bearer %s" % FAKE_KEY,
            "token=%s" % FAKE_KEY,
        ):
            with self.subTest(message=message):
                output = redact(message)
                self.assertNotIn(FAKE_KEY, output)
                self.assertNotIn("notarealpassword123", output)
                self.assertIn("[redacted]", output)

    def test_no_truncation_of_a_secret(self):
        """A truncated secret is still a partially disclosed secret."""
        output = redact("session_key=%s" % FAKE_KEY)
        for length in (8, 12, 20):
            self.assertNotIn(FAKE_KEY[:length], output)

    def test_the_file_does_not_carry_the_key_even_if_it_is_passed_by_mistake(self):
        with DiagTree() as tree:
            diag = open_diagnostics(tree.dir, sid="s1")
            diag.info("call refused (Authorization: Splunk %s)" % FAKE_KEY)
            diag.fatal("capability check impossible, session_key=%s" % FAKE_KEY)
            diag.close()
            text = tree.content()
        self.assertNotIn(FAKE_KEY, text)
        self.assertNotIn(FAKE_KEY[:16], text)

    def test_no_diagnostic_method_accepts_a_secret_as_a_parameter(self):
        """The main guarantee is **structural**, not textual: the module never
        receives the session key."""
        forbidden = {
            "session_key", "sessionkey", "token", "password", "secret", "api_key",
            "authorization", "credential",
        }
        path = os.path.join(BIN_DIR, "acltools", "diag.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = {a.arg.lower() for a in node.args.args}
                names |= {a.arg.lower() for a in node.args.kwonlyargs}
                with self.subTest(function=node.name):
                    self.assertEqual(names & forbidden, set())

    def test_the_wrapper_passes_no_secret_to_the_diagnostic(self):
        """Mechanical audit of `bin/editacl.py`: no `self._diag.*` call carries
        `session_key` nor any related name."""
        forbidden = ("session_key", "password", "token", "secret", "api_key")
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                target = ast.unparse(node.func)
                if target.startswith("self._diag"):
                    calls.append(ast.unparse(node))
        self.assertTrue(calls, "the wrapper calls no diagnostic at all")
        for call in calls:
            with self.subTest(call=call):
                for banned in forbidden:
                    self.assertNotIn(banned, call)


class LosingTheDiagnosticNeverCostsARunTest(unittest.TestCase):
    """The diagnostic file is **not** the safety net. None of its failures is fatal,
    which is the difference in kind with the rollback journal (D-3)."""

    def test_a_missing_directory_yields_an_inert_diagnostic(self):
        diag = open_diagnostics(
            os.path.join(tempfile.gettempdir(), "acl_nonexistent_zz", "deep")
        )
        self.assertIsInstance(diag, NullDiagnostics)
        self.assertFalse(diag.enabled)

    def test_a_missing_splunk_home_yields_an_inert_diagnostic(self):
        self.assertIsInstance(open_diagnostics(""), NullDiagnostics)
        self.assertIsInstance(open_diagnostics(None), NullDiagnostics)

    def test_the_inert_diagnostic_absorbs_every_call(self):
        diag = NullDiagnostics()
        diag("WARNING", "x")
        diag.startup(version="1")
        diag.params(params())
        diag.capability(False, "detail")
        diag.realtime("unknown")
        diag.mapping({})
        diag.journal("/x", False)
        diag.info("x")
        diag.warning("x")
        diag.fatal("x")
        diag.close()

    def test_a_write_failure_does_not_raise(self):
        class BrokenHandler(logging.Handler):
            def emit(self, record):
                raise IOError("disk full")

        diag = Diagnostics("/nonexistent/editacl.log", sid="s", handler=BrokenHandler())
        diag.info("message")
        diag.fatal("message")
        diag.close()

    def test_the_module_does_not_use_the_global_logging_registry(self):
        """Attaching a handler to it would let the records of other libraries into the
        file, and we do not control their freedom from secrets."""
        path = os.path.join(BIN_DIR, "acltools", "diag.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        for banned in ("logging.getLogger", "getLogger", "logging.basicConfig"):
            with self.subTest(call=banned):
                self.assertNotIn(banned, calls)

    def test_the_package_exposes_the_module(self):
        self.assertTrue(hasattr(diag_module, "open_diagnostics"))


class TheWrapperWiresTheDiagnosticTest(unittest.TestCase):
    """Mechanical audit of the wiring: `bin/editacl.py` must really produce the file,
    and produce it early enough for an invalid parameter to appear in it."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            cls.tree = ast.parse(handle.read(), filename=path)

    def _function(self, name):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        self.fail("function %s not found" % name)

    def _calls(self, node):
        return [
            (ast.unparse(n.func), n)
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
        ]

    def test_setup_opens_the_diagnostic(self):
        targets = [name for name, _ in self._calls(self._function("_setup"))]
        self.assertIn("open_diagnostics", targets)

    def test_the_diagnostic_is_opened_before_parameter_validation(self):
        """An invalid `fields` is a fatal error of section 9: it must be recorded."""
        opening = validation = None
        for name, node in self._calls(self._function("_setup")):
            if name == "open_diagnostics" and opening is None:
                opening = node.lineno
            if name == "validate_params" and validation is None:
                validation = node.lineno
        self.assertIsNotNone(opening)
        self.assertIsNotNone(validation)
        self.assertLess(opening, validation)

    def test_load_mapping_receives_the_diagnostic(self):
        """Section 8.1, "table resolution": this is the omission raised by the audit."""
        for name, node in self._calls(self._function("_setup")):
            if name == "load_mapping":
                keywords = {kw.arg for kw in node.keywords}
                self.assertIn("diag", keywords)
                return
        self.fail("no call to load_mapping in _setup")

    def test_fatal_errors_are_recorded_in_stream(self):
        targets = [name for name, _ in self._calls(self._function("stream"))]
        self.assertIn("self._diag.fatal", targets)


if __name__ == "__main__":
    unittest.main()
