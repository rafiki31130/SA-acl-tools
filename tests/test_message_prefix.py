"""Every operator-facing message is prefixed `editacl: `, from a single emission point.

A search pipeline concatenates the messages of every command it chains, and the search
interface displays them stripped of their origin. A warning about an irreversible ACL
write was therefore indistinguishable from a warning of the inventory macro, of `map`,
or of the platform itself. The prefix restores that origin.

**The interesting part of this module is not the prefix, it is where the prefix is
applied.** Repeating a literal `"editacl: "` on every message would be a convention:
it holds until the next contributor writes one more `self.write_warning(...)`, and
nothing fails. The rule is therefore made structural - one method, `_emit_message`,
is the only place in `bin/editacl.py` that touches an SDK message method - and this
module reads the syntax tree to check it.

Same discipline as `tests/test_statuses.py`, and for the same reason: **a control must
name what it cannot analyse instead of ignoring it silently.** The extractor here does
not classify "what it recognizes" against "the rest". It classifies every construct
that could reach an SDK message method into three exhaustive categories:

1. **emission site**: an attribute access `<expr>.write_warning` (or `write_error`,
   `write_info`, `write_fatal`), whatever it is then used for - called, aliased, passed
   as an argument. Its enclosing scope is collected;
2. **opaque**: any dynamic attribute access whose name is not a literal
   (`getattr(self, name)`, `setattr(obj, computed, ...)`), and any string literal in
   the module equal to one of those method names - both of which could reach a message
   method without an `Attribute` node ever naming it. **Opaque fails the suite**, naming
   the line and the source fragment;
3. everything else, which cannot name a message method.

What this control does NOT guarantee. It is static, and its reach stops where the
reading of a syntax tree stops: it covers `bin/editacl.py` alone, which is the only
file of the repository that talks to the SDK (`tests/test_layering.py` holds that
boundary). A message emitted by a module added outside that file, or one produced at
run time through `exec`, `importlib` or a metaclass, escapes it. The guard rail
`test_the_extraction_is_not_empty` exists because a dead instrument returns reassuring
zeros.
"""

import ast
import importlib.util
import os
import re
import sys
import types
import unittest

from . import BIN_DIR

EDITACL_PATH = os.path.join(BIN_DIR, "editacl.py")

#: Methods through which the SDK sends a message to the search interface. Every one of
#: them is an operator-facing channel, hence every one of them must carry the prefix.
SDK_MESSAGE_METHODS = ("write_warning", "write_error", "write_info", "write_fatal")

#: The one scope allowed to reach them. `<class>.<method>` form, as the extractor
#: builds it.
SINGLE_EMISSION_POINT = "EditAclCommand._emit_message"

#: Builtins that take an attribute name as an argument. With a literal name they are
#: analysable; with anything else they are opaque.
_DYNAMIC_ATTRIBUTE_BUILTINS = ("getattr", "setattr", "hasattr", "delattr")


def _read_source():
    with open(EDITACL_PATH, "r", encoding="utf-8") as handle:
        return handle.read()


def _fragment(source, node):
    """Normalized source fragment of a node, for a diagnosable failure message."""
    try:
        text = ast.get_source_segment(source, node) or ""
    except Exception:                                                # pragma: no cover
        text = ""
    return " ".join(text.split())


class _Extractor(ast.NodeVisitor):
    """Classifies every construct of `bin/editacl.py` that could name a message method.

    `sites` holds the enclosing scope of each attribute access naming one of
    `SDK_MESSAGE_METHODS`. `opaque` holds what the extractor refuses to interpret.
    """

    def __init__(self, source):
        self._source = source
        self._scope = []
        self.sites = []
        self.opaque = []

    # -- scope tracking ---------------------------------------------------- #

    def _enter(self, node):
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_ClassDef(self, node):                                  # noqa: N802
        self._enter(node)

    def visit_FunctionDef(self, node):                               # noqa: N802
        self._enter(node)

    def visit_AsyncFunctionDef(self, node):                          # noqa: N802
        self._enter(node)

    def _scope_name(self):
        return ".".join(self._scope) or "<module>"

    # -- classification ---------------------------------------------------- #

    def visit_Attribute(self, node):                                 # noqa: N802
        if node.attr in SDK_MESSAGE_METHODS:
            self.sites.append(
                (self._scope_name(), node.lineno, _fragment(self._source, node))
            )
        self.generic_visit(node)

    def visit_Constant(self, node):                                  # noqa: N802
        if isinstance(node.value, str) and node.value in SDK_MESSAGE_METHODS:
            # A message method reached by name rather than by attribute access. The
            # `Attribute` visit above would never see it.
            self.opaque.append(
                (
                    self._scope_name(),
                    node.lineno,
                    _fragment(self._source, node),
                    "the name of an SDK message method appears as a string literal",
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node):                                      # noqa: N802
        func = node.func
        if isinstance(func, ast.Name) and func.id in _DYNAMIC_ATTRIBUTE_BUILTINS:
            name_arg = node.args[1] if len(node.args) > 1 else None
            literal = isinstance(name_arg, ast.Constant) and isinstance(
                name_arg.value, str
            )
            if not literal:
                self.opaque.append(
                    (
                        self._scope_name(),
                        node.lineno,
                        _fragment(self._source, node),
                        "%s() with a non-literal attribute name: it may reach a "
                        "message method without naming it" % func.id,
                    )
                )
        self.generic_visit(node)


def _analyse():
    source = _read_source()
    extractor = _Extractor(source)
    extractor.visit(ast.parse(source, filename=EDITACL_PATH))
    return extractor


# --------------------------------------------------------------------------- #
# Static control - the single emission point
# --------------------------------------------------------------------------- #

class SingleEmissionPointTest(unittest.TestCase):
    """`bin/editacl.py` reaches an SDK message method from one method only."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = _analyse()

    def test_the_extraction_is_not_empty(self):
        """An extraction that reads nothing would pass forever.

        The emission point dispatches over the four levels, so it holds at least two
        attribute accesses; requiring three keeps the guard rail meaningful without
        pinning the exact shape of the dispatch.
        """
        self.assertGreaterEqual(
            len(self.extractor.sites),
            3,
            "the extractor found no call to an SDK message method in bin/editacl.py: "
            "it is reading nothing, or the file has changed shape",
        )

    def test_the_emission_point_names_the_decision_that_founds_it(self):
        """A-8 of the audit of 2026-08-09: the docstring named D-39, not D-41.

        That comment is the only place in `bin/editacl.py` that names the decision behind
        the rule it implements, so a wrong number there sends the next reader to a
        decision about something else - D-39 bears on the degradation of `id` by the
        field filter. The check is cheap and it closes the class: any renumbering of the
        rule has to pass through here.
        """
        with open(EDITACL_PATH, encoding="utf-8") as handle:
            source = handle.read()
        docstring = re.search(
            r"def _emit_message\(self[^)]*\):\s*\"\"\"(.*?)\"\"\"", source, re.S
        )
        self.assertIsNotNone(docstring, "the emission point has lost its docstring")
        self.assertIn("D-41", docstring.group(1))
        self.assertNotIn("D-39", docstring.group(1))

    def test_no_construct_is_opaque(self):
        """What the extractor cannot analyse fails the suite instead of passing."""
        if not self.extractor.opaque:
            return
        detail = "\n".join(
            "  %s:%d in %s -- %s\n        source: %s"
            % (os.path.basename(EDITACL_PATH), ligne, portee, motif, source)
            for portee, ligne, source, motif in self.extractor.opaque
        )
        self.fail(
            "construct(s) that could reach an SDK message method without the "
            "extractor being able to interpret them:\n%s" % detail
        )

    def test_only_the_single_emission_point_talks_to_the_sdk(self):
        """Every `write_warning` / `write_error` / `write_info` / `write_fatal` sits in
        `EditAclCommand._emit_message`.

        This is the test the change exists for: reintroducing a direct
        `self.write_warning(...)` anywhere else fails here, with the offending line.
        """
        strays = [
            (portee, ligne, source)
            for portee, ligne, source in self.extractor.sites
            if portee != SINGLE_EMISSION_POINT
        ]
        detail = "\n".join(
            "  %s:%d in %s\n        source: %s"
            % (os.path.basename(EDITACL_PATH), ligne, portee, source)
            for portee, ligne, source in strays
        )
        self.assertEqual(
            strays,
            [],
            "an SDK message method is reached outside %s, so those messages carry no "
            "prefix:\n%s" % (SINGLE_EMISSION_POINT, detail),
        )

    def test_every_sdk_message_method_is_covered_by_the_emission_point(self):
        """The emission point is a gateway, not a partial one.

        If it handled only warnings, a later `write_error` would have nowhere to go and
        would be written directly - which is exactly what the previous test forbids.
        """
        reached = set()
        for portee, _ligne, source in self.extractor.sites:
            if portee != SINGLE_EMISSION_POINT:
                continue
            for method in SDK_MESSAGE_METHODS:
                if method in source:
                    reached.add(method)
        self.assertIn("write_warning", reached)
        self.assertIn("write_error", reached)


class TheExtractorSeesWhatItClaimsTest(unittest.TestCase):
    """Self-tests of the extractor: an instrument is checked on known inputs."""

    def _run(self, source):
        extractor = _Extractor(source)
        extractor.visit(ast.parse(source))
        return extractor

    def test_a_direct_call_is_seen_with_its_scope(self):
        extractor = self._run(
            "class C:\n"
            "    def m(self):\n"
            "        self.write_warning('x')\n"
        )
        self.assertEqual([site[0] for site in extractor.sites], ["C.m"])

    def test_an_alias_is_seen_too(self):
        """Aliasing is not a hole: `w = self.write_error` names the method."""
        extractor = self._run(
            "class C:\n"
            "    def m(self):\n"
            "        w = self.write_error\n"
            "        w('x')\n"
        )
        self.assertEqual([site[0] for site in extractor.sites], ["C.m"])

    def test_a_dynamic_getattr_is_opaque(self):
        extractor = self._run(
            "class C:\n"
            "    def m(self, name):\n"
            "        getattr(self, name)('x')\n"
        )
        self.assertEqual(len(extractor.opaque), 1)

    def test_a_literal_getattr_is_not_opaque(self):
        """The adapter legitimately uses `getattr(obj, 'literal', default)`."""
        extractor = self._run(
            "class C:\n"
            "    def m(self):\n"
            "        getattr(self, '_record_writer', None)\n"
        )
        self.assertEqual(extractor.opaque, [])
        self.assertEqual(extractor.sites, [])

    def test_a_method_name_as_a_string_is_opaque(self):
        extractor = self._run(
            "class C:\n"
            "    def m(self):\n"
            "        getattr(self, 'write_warning')('x')\n"
        )
        self.assertEqual(len(extractor.opaque), 1)


# --------------------------------------------------------------------------- #
# Functional control - the prefix is actually carried
# --------------------------------------------------------------------------- #

class _FakeOption(object):
    """Minimal option descriptor. Reproduces the SDK storage-field naming rule."""

    def __init__(self, doc=None, require=False, default=None, validate=None):
        self.default = default

    def __set_name__(self, owner, name):
        self.backing_field_name = "_" + name

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return getattr(instance, self.backing_field_name, self.default)

    def __set__(self, instance, value):
        setattr(instance, self.backing_field_name, value)


class _FakeSearchCommand(object):
    """Collects what the command sends to the search interface, per channel."""

    def __init__(self):
        self._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace())
        self._record_writer = None
        self.warnings = []
        self.errors = []
        self.infos = []

    def prepare(self):
        pass

    def write_warning(self, message):
        self.warnings.append(message)

    def write_error(self, message):
        self.errors.append(message)

    def write_info(self, message):
        self.infos.append(message)


def _load_editacl():
    """Load `bin/editacl.py` under a fake SDK.

    Deliberately self-contained rather than borrowing the harness of
    `tests/test_editacl_adapter.py`: a control over an emission rule must not break
    because a neighbouring test module was refactored.
    """
    sdk = "splunk" + "lib"
    path_before = list(sys.path)
    added = [key for key in (sdk, sdk + ".searchcommands") if key not in sys.modules]

    root = types.ModuleType(sdk)
    module = types.ModuleType(sdk + ".searchcommands")
    module.Option = _FakeOption
    module.StreamingCommand = _FakeSearchCommand
    module.Configuration = lambda **kwargs: (lambda cls: cls)
    module.dispatch = lambda *args, **kwargs: None
    module.validators = types.SimpleNamespace(Boolean=lambda: (lambda value: value))
    root.searchcommands = module
    sys.modules[sdk] = root
    sys.modules[sdk + ".searchcommands"] = module

    try:
        spec = importlib.util.spec_from_file_location(
            "editacl_under_fake_sdk_for_prefix", EDITACL_PATH
        )
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        return loaded
    finally:
        # `bin/editacl.py` inserts `bin/lib` at the head of `sys.path`: undo it, so the
        # vendored SDK never enters the path of the suite (section 11.1).
        sys.path[:] = path_before
        for key in added:
            sys.modules.pop(key, None)


class PrefixIsCarriedTest(unittest.TestCase):
    """The prefix reaches the interface, on every channel, exactly once."""

    @classmethod
    def setUpClass(cls):
        cls.module = _load_editacl()

    def _command(self):
        return self.module.EditAclCommand()

    def test_the_prefix_is_the_command_name_a_colon_and_a_space(self):
        """It must read as a source, not as a decoration."""
        self.assertEqual(self.module.MESSAGE_PREFIX, "editacl: ")

    def test_a_warning_is_prefixed(self):
        command = self._command()
        command._warn("ceiling reached")
        self.assertEqual(command.warnings, ["editacl: ceiling reached"])
        self.assertEqual(command.errors, [])

    def test_an_error_is_prefixed(self):
        command = self._command()
        command._error("capability missing")
        self.assertEqual(command.errors, ["editacl: capability missing"])
        self.assertEqual(command.warnings, [])

    def test_the_info_channel_is_prefixed_too(self):
        command = self._command()
        command._emit_message("info", "nothing to do")
        self.assertEqual(command.infos, ["editacl: nothing to do"])

    def test_an_unknown_level_degrades_to_a_warning_rather_than_being_lost(self):
        """A message must never disappear because a level was mistyped."""
        command = self._command()
        command._emit_message("whatever", "still visible")
        self.assertEqual(command.warnings, ["editacl: still visible"])

    def test_the_prefix_is_applied_once_and_not_per_word(self):
        command = self._command()
        command._warn("a: b: c")
        self.assertEqual(command.warnings, ["editacl: a: b: c"])

    def test_a_none_message_does_not_raise(self):
        """The emission point is on the fatal error path: it must never fail there."""
        command = self._command()
        command._warn(None)
        self.assertEqual(command.warnings, ["editacl: "])

    def test_the_shipped_messages_go_through_the_emission_point(self):
        """End to end on the two messages the operator sees most often.

        The texts come from the core (`acltools`), which knows nothing of the prefix:
        that separation is what lets the core stay testable without the SDK.
        """
        from acltools.pipeline import RUNTIME_DIVERGENCE_MESSAGE, ceiling_message
        from acltools.preflight import DRYRUN_WARNING

        command = self._command()
        command._warn(DRYRUN_WARNING)
        command._warn(ceiling_message(10, 3))
        command._warn(RUNTIME_DIVERGENCE_MESSAGE)
        for message in command.warnings:
            self.assertTrue(
                message.startswith("editacl: "),
                "message not prefixed: %r" % message,
            )
        self.assertNotIn("editacl: editacl: ", "".join(command.warnings))


if __name__ == "__main__":                                           # pragma: no cover
    unittest.main()
