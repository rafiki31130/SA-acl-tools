"""The fatal diagnostic - one function, one shape, both contracted commands (v4.8 13.2).

**What this file exists to catch, and it is a measured defect rather than a hypothesis.**
Friction #435: on a fresh installation with no `local/editacl.conf` - a platform with a
self-signed certificate, `verify_ssl` at its default - `appaclinventory` failed with
`isFailed=True` and, for its whole diagnosis, *"External search command exited unexpectedly
with non-zero error code 1"*. That sentence is what splunkd writes when the command says
**nothing**.

The arrival property PA of section 13.2 is verified on the **job**, on the lab, by scenario
16 and its negative control. This file holds what runs without an instance:

1. every fatal error class of the core has a remedy, the list being **derived** from the
   core and never recopied here;
2. the message carries a cause segment and a remedy segment, both non-empty, for every one
   of those classes;
3. the two contracted commands leave through **one** function - read on the syntax tree,
   because a second implementation is exactly what a text-level check would miss.
"""

import ast
import os
import unittest

from acltools import errors
from acltools.fatal import (
    FALLBACK_REMEDY,
    FATAL_REMEDIES,
    REMEDY_SEPARATOR,
    fatal_diagnostic,
    fatal_error_classes,
    remedy_for,
)

from . import BIN_DIR

#: The two commands this contract binds. `editacl` is contracted by v3.14 and is the
#: **witness** of the measurement, not one of its subjects.
CONTRACTED_ADAPTERS = ("appaclinventory.py", "editappacl.py")


def _source(name):
    with open(os.path.join(BIN_DIR, name), encoding="utf-8") as handle:
        return handle.read()


class TheErrorListComesFromTheCoreTest(unittest.TestCase):
    """Section 14.2 asks for the error list to be **derived from the core** and never
    recopied into the test. A class added to the taxonomy without a remedy must fail here,
    rather than reach an operator with half a message."""

    def test_the_enumeration_walks_the_taxonomy_rather_than_listing_it(self):
        classes = fatal_error_classes()
        self.assertTrue(classes)
        for klass in classes:
            with self.subTest(error=klass.__name__):
                self.assertTrue(issubclass(klass, errors.FatalError))
        # Every fatal class declared in the errors module is reached by the walk.
        declared = [
            value for value in vars(errors).values()
            if isinstance(value, type)
            and issubclass(value, errors.FatalError)
            and value is not errors.FatalError
        ]
        self.assertEqual(set(declared), set(classes))

    def test_every_fatal_error_of_the_core_has_a_remedy(self):
        for klass in fatal_error_classes():
            with self.subTest(error=klass.__name__):
                self.assertIn(klass, FATAL_REMEDIES,
                              "%s has no remedy: an operator would read what stopped and "
                              "not what to do" % klass.__name__)
                self.assertTrue(FATAL_REMEDIES[klass].strip())

    def test_the_session_error_names_the_certificate_remedy(self):
        """The error of a first deployment, and the one the measurement was made on. Its
        remedy names the file to create and the setting to write in it."""
        remedy = FATAL_REMEDIES[errors.FatalSessionError]
        self.assertIn("verify_ssl", remedy)
        self.assertIn("local/editacl.conf", remedy)


class TheMessageCarriesBothSegmentsTest(unittest.TestCase):
    """A cause with no remedy tells the operator he is stuck, which he knew."""

    def _split(self, text):
        self.assertIn(REMEDY_SEPARATOR, text)
        cause, remedy = text.split(REMEDY_SEPARATOR, 1)
        return cause.strip(), remedy.strip()

    def test_every_fatal_error_yields_two_non_empty_segments(self):
        for klass in fatal_error_classes():
            with self.subTest(error=klass.__name__):
                cause, remedy = self._split(fatal_diagnostic(klass("boom")))
                self.assertTrue(cause)
                self.assertTrue(remedy)
                self.assertIn("boom", cause)

    def test_an_error_with_no_message_still_names_its_cause(self):
        """Total by construction: a diagnostic that can come out empty comes out empty on
        the day it matters."""
        cause, remedy = self._split(fatal_diagnostic(errors.FatalConfigError()))
        self.assertIn("FatalConfigError", cause)
        self.assertTrue(remedy)

    def test_a_subclass_inherits_the_remedy_of_its_family(self):
        class FatalSessionSubcase(errors.FatalSessionError):
            pass

        self.assertEqual(remedy_for(FatalSessionSubcase("x")),
                         FATAL_REMEDIES[errors.FatalSessionError])

    def test_the_fallback_is_unreachable_through_the_declared_taxonomy(self):
        """It exists so a message is never remedy-less, not to excuse an omission."""
        for klass in fatal_error_classes():
            with self.subTest(error=klass.__name__):
                self.assertNotEqual(remedy_for(klass("x")), FALLBACK_REMEDY)
        self.assertEqual(remedy_for(RuntimeError("outside the taxonomy")),
                         FALLBACK_REMEDY)


class TheTwoCommandsStopThroughOneFunctionTest(unittest.TestCase):
    """Section 14.2 asks that the stop pass through **one shared function**, read on the
    syntax tree. Two wordings of one rule are two answers to a question both commands must
    answer identically."""

    def test_both_adapters_import_the_shared_diagnostic(self):
        for name in CONTRACTED_ADAPTERS:
            with self.subTest(adapter=name):
                self.assertIn("from acltools.fatal import fatal_diagnostic",
                              _source(name))

    def test_each_adapter_builds_the_text_in_exactly_one_place(self):
        for name in CONTRACTED_ADAPTERS:
            with self.subTest(adapter=name):
                tree = ast.parse(_source(name))
                calls = [
                    node for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "fatal_diagnostic"
                ]
                self.assertEqual(len(calls), 1)

    def test_neither_adapter_reformats_the_message_beside_it(self):
        """`str(exc)` reaching a message method would be the second implementation: the
        remedy would silently disappear from that path."""
        for name in CONTRACTED_ADAPTERS:
            with self.subTest(adapter=name):
                tree = ast.parse(_source(name))
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr in (
                        "_error", "write_error", "write_fatal"
                    ):
                        for arg in node.args:
                            self.assertFalse(
                                isinstance(arg, ast.Call)
                                and isinstance(arg.func, ast.Name)
                                and arg.func.id == "str",
                                "%s emits str(exc) instead of the shared diagnostic"
                                % name,
                            )

    def test_the_remedy_table_is_not_duplicated_in_the_adapters(self):
        for name in CONTRACTED_ADAPTERS:
            with self.subTest(adapter=name):
                self.assertNotIn("FATAL_REMEDIES", _source(name))


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
