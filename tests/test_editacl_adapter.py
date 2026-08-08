"""The `bin/editacl.py` wrapper - fatal error path and attribute name collision.

This module is the only one that exercises `bin/editacl.py` itself. It loads it with a
**fake SDK** injected into `sys.modules`, never with the vendored SDK: `bin/lib`
therefore never enters the `sys.path` of the suite, and section 11.1 stays satisfied -
outside Splunk, with no network.

The fake SDK reproduces **one single thing, but exactly**: the naming rule of the
backing field of an `Option`, `backing_field_name = "_" + name`
(`splunklib/searchcommands/decorators.py`). It is that rule which makes an option named
`journal` occupy the `_journal` attribute of the instance - the very one where the
adapter used to store its `JournalWriter`.

The collision is **two-way**:

- before `_setup()`, the attribute carries the boolean of the option, and any `close()`
  on it raises `AttributeError`;
- after `_setup()`, writing the writer **overwrites the value of the option**, which
  then can no longer be read.

It only shows up on the fatal error path prior to the opening of the journal -
typically the failure of the capability check - that is, at exactly the moment when the
operator needs the message. It replaces that message with a Python traceback.
"""

import ast
import os
import sys
import types
import unittest

from . import BIN_DIR, REPO_ROOT

SDK_DIR = os.path.join(BIN_DIR, "lib", "splunk" + "lib", "searchcommands")


# --------------------------------------------------------------------------- #
# Fake SDK - strictly what `bin/editacl.py` imports
# --------------------------------------------------------------------------- #

class _FakeOption(object):
    """Descriptor reproducing the naming rule of the SDK's backing field."""

    def __init__(self, doc=None, require=False, default=None, validate=None):
        self.default = default
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name
        self.backing_field_name = "_" + name        # the SDK rule, literally

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return getattr(instance, self.backing_field_name, self.default)

    def __set__(self, instance, value):
        setattr(instance, self.backing_field_name, value)


class _FakeRecordWriter(object):
    """Fake chunk writer. It records the `finished` state of each chunk: that state is
    what decides whether splunkd marks the job as failed (section 4.3, A-4).

    It also reproduces **one single other thing, but exactly**: the rule by which
    `RecordWriter._write_record` builds the header of the stream
    (`splunklib/searchcommands/internals.py`).

        fieldnames = self._fieldnames
        if fieldnames is None:
            self._fieldnames = fieldnames = list(record.keys())
            self._fieldnames.extend(
                [i for i in self.custom_fields if i not in self._fieldnames]
            )
        for fieldname in fieldnames:
            value = get_value(fieldname, None)

    Two consequences, and they are the ones the tests exercise: the header is frozen on
    the keys of the **first** record emitted, and the names declared in `custom_fields`
    are added to it **whatever** the content of that first record.
    `TheDoubleReproducesTheSdkTest` backs this double against the source of the vendored
    SDK, which the suite does not load (section 11.1).
    """

    def __init__(self):
        self.chunks = []
        self.custom_fields = set()
        self._fieldnames = None
        self.rows = []

    def write_chunk(self, finished=None):
        self.chunks.append(finished)

    def write_record(self, record):
        fieldnames = self._fieldnames
        if fieldnames is None:
            self._fieldnames = fieldnames = list(record.keys())
            self._fieldnames.extend(
                [i for i in self.custom_fields if i not in self._fieldnames]
            )
        self.rows.append(
            dict((name, record.get(name, None)) for name in fieldnames)
        )

    def write_records(self, records):
        for record in records:
            self.write_record(record)

    @property
    def header(self):
        """Column set of the stream, that is, what the operator sees."""
        return list(self._fieldnames or [])


class _FakeSearchCommand(object):
    def __init__(self):
        self._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace())
        self._record_writer = _FakeRecordWriter()
        self.warnings = []
        self.errors = []
        self.flushes = 0
        self.finishes = 0

    def prepare(self):
        """SDK extension point, invoked before any execution. Inert here."""

    def write_warning(self, message):
        self.warnings.append(message)

    def write_error(self, message):
        self.errors.append(message)

    def flush(self):
        self.flushes += 1

    def finish(self):
        self.finishes += 1

    def error_exit(self, error, message=None):
        self.errors.append(message or str(error))
        raise SystemExit(message or str(error))


class Abort(Exception):
    """Stand-in for `os._exit` in the tests: the real one kills the test process."""

    def __init__(self, code):
        super(Abort, self).__init__("abort(%s)" % code)
        self.code = code


def _intercept_the_abort(module):
    """Replace the process exit by an observable exception."""
    def _abort(code=1):
        raise Abort(code)

    module._abort_process = _abort


class _FakeBoolean(object):
    def __call__(self, value):
        return value


def _install_fake_sdk():
    """Inject the fake SDK into `sys.modules` and return the keys added."""
    name = "splunk" + "lib"
    added = []
    for key in (name, name + ".searchcommands"):
        if key not in sys.modules:
            added.append(key)
    root = types.ModuleType(name)
    module = types.ModuleType(name + ".searchcommands")
    module.Option = _FakeOption
    module.StreamingCommand = _FakeSearchCommand
    module.Configuration = lambda **kwargs: (lambda cls: cls)
    module.dispatch = lambda *args, **kwargs: None
    module.validators = types.SimpleNamespace(Boolean=_FakeBoolean)
    root.searchcommands = module
    sys.modules[name] = root
    sys.modules[name + ".searchcommands"] = module
    return added


def _load_editacl():
    """Load `bin/editacl.py` under the fake SDK, without lastingly polluting `sys.path`.
    """
    import importlib.util

    lib_path = os.path.join(BIN_DIR, "lib")
    path_before = list(sys.path)
    added_modules = _install_fake_sdk()
    try:
        spec = importlib.util.spec_from_file_location(
            "editacl_under_fake_sdk", os.path.join(BIN_DIR, "editacl.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        # `bin/editacl.py` inserts `bin/lib` at the head of `sys.path`: we undo that,
        # otherwise the suite would stop proving that the core imports without the
        # vendored SDK.
        sys.path[:] = [p for p in path_before if p != lib_path]
        for key in added_modules:
            sys.modules.pop(key, None)


class FatalErrorPathTest(unittest.TestCase):
    """A fatal error prior to the opening of the journal must come up **as it is**. The
    cleanup of the `finally` must never supplant it."""

    MESSAGE = (
        "capability check impossible: unusable response from "
        "/services/authentication/current-context (HTTP 0)"
    )

    def setUp(self):
        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        from acltools.errors import FatalCapabilityError

        self.command = self.module.EditAclCommand()
        self.command.journal = True           # what the SDK does on `journal=t`
        self.command.dryrun = True

        def _setup_that_fails():
            raise FatalCapabilityError(self.MESSAGE)

        self.command._setup = _setup_that_fails

    def test_the_original_message_is_not_replaced_by_a_python_traceback(self):
        with self.assertRaises(Abort):
            list(self.command.stream([{"title": "an_object"}]))
        self.assertEqual(
            self.command.errors, [self.module.MESSAGE_PREFIX + self.MESSAGE]
        )

    def test_no_attributeerror_on_the_cleanup(self):
        try:
            list(self.command.stream([{"title": "an_object"}]))
        except Abort:
            pass
        except AttributeError as exc:                            # pragma: no cover
            self.fail(
                "the cleanup of the `finally` raised an AttributeError and masked "
                "the fatal error: %s" % exc
            )

    def test_the_value_of_the_journal_option_stays_readable(self):
        """The option and the writer are two distinct things: writing one must not make
        the other unreadable."""
        self.assertIs(self.command.journal, True)
        self.command._journal_writer = object()
        self.assertIs(self.command.journal, True)


class JobFailureMarkingTest(unittest.TestCase):
    """A-4 - a fatal error of section 9 must mark the job as failed.

    Measured on Splunk 9.4.6: the marking depends on a single fact, the final chunk
    `finished: true`. The SDK's `error_exit()` sends it before quitting, and splunkd
    then ignores the return code of the process. Emitting the message in a **non-final**
    chunk then quitting with a non-zero code gives `dispatchState=FAILED`,
    `isFailed=true`, **and** keeps the message.

    The `max_objects` ceiling **no longer goes through here** (D-28): it is no longer
    fatal. The path is now exercised by the missing capability, which stays in
    section 9.
    """

    MESSAGE = "capability 'edit_acl_bulk' missing. Roles of the user: (none)"

    def setUp(self):
        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        from acltools.errors import FatalCapabilityError

        self.command = self.module.EditAclCommand()
        self.command.journal = True
        self.command.dryrun = False

        message = self.MESSAGE

        def _setup_that_fails():
            raise FatalCapabilityError(message)

        self.command._setup = _setup_that_fails

    def _run(self):
        with self.assertRaises(Abort) as raised:
            list(self.command.stream([{"title": "an_object"}]))
        return raised.exception

    def test_the_process_exits_with_a_non_zero_code(self):
        self.assertEqual(self._run().code, 1)

    def test_the_emitted_chunk_is_not_final(self):
        """The substance of it: `finished: true` would make the return code ignored."""
        self._run()
        self.assertEqual(self.command._record_writer.chunks, [False])
        self.assertEqual(self.command.finishes, 0)

    def test_the_message_is_kept(self):
        """Marking the job as failed must not cost the operator the message."""
        self._run()
        self.assertEqual(len(self.command.errors), 1)
        self.assertIn("edit_acl_bulk", self.command.errors[0])

    def test_the_sdk_error_exit_is_no_longer_used(self):
        """`error_exit()` sends `finished: true`: it cannot mark the failure."""
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        self.assertNotIn("self.error_exit", calls)
        self.assertNotIn("self.finish", calls)

    def test_journal_and_diagnostic_are_closed_before_the_abort(self):
        """`os._exit` short-circuits the `finally`: the cleanup must come first."""
        state = {"journal": False, "diag": False}

        class _Journal(object):
            def close(self):
                state["journal"] = True

        from acltools.diag import NullDiagnostics

        class _Diag(NullDiagnostics):
            def close(self):
                state["diag"] = True

        self.command._journal_writer = _Journal()
        self.command._diag = _Diag()
        self._run()
        self.assertEqual(state, {"journal": True, "diag": True})


class NameCollisionTest(unittest.TestCase):
    """Mechanical audit: no private attribute of the adapter may bear the name of the
    backing field of an `Option` or of a `Configuration` setting, nor that of a private
    attribute of the SDK base class.

    The SDK is read as a **source file**, never imported: the suite stays runnable
    without it."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            cls.tree = ast.parse(handle.read(), filename=path)

    def _command_class(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and node.name == "EditAclCommand":
                return node
        self.fail("class EditAclCommand not found")

    def _assigned_private_attributes(self):
        """Every `self._x = ...` of the class."""
        names = set()
        for node in ast.walk(self._command_class()):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AugAssign):
                targets = [node.target]
            for target in targets:
                for element in ([target] if not isinstance(target, ast.Tuple)
                                else target.elts):
                    if (isinstance(element, ast.Attribute)
                            and isinstance(element.value, ast.Name)
                            and element.value.id == "self"
                            and element.attr.startswith("_")):
                        names.add(element.attr)
        return names

    def _option_names(self):
        """Every `x = Option(...)` at class level."""
        names = set()
        for node in self._command_class().body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                function = node.value.func
                if isinstance(function, ast.Name) and function.id == "Option":
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
        return names

    def _configuration_settings(self):
        """Keywords passed to the `@Configuration(...)` decorator."""
        names = set()
        for decorator in self._command_class().decorator_list:
            if (isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Name)
                    and decorator.func.id == "Configuration"):
                for keyword in decorator.keywords:
                    if keyword.arg:
                        names.add(keyword.arg)
        return names

    def _sdk_private_attributes(self):
        """`self._x = ...` of `SearchCommand` and `StreamingCommand`, read in the source
        of the vendored SDK. No import."""
        names = set()
        for filename in ("search_command.py", "streaming_command.py"):
            path = os.path.join(SDK_DIR, filename)
            if not os.path.exists(path):                         # pragma: no cover
                continue
            with open(path, encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (isinstance(target, ast.Attribute)
                                and isinstance(target.value, ast.Name)
                                and target.value.id == "self"
                                and target.attr.startswith("_")):
                            names.add(target.attr)
        return names

    def test_the_declared_options_are_those_of_section_4_1(self):
        self.assertEqual(
            self._option_names(),
            {
                # field-naming parameters - reference fields (section 3.1)
                "title", "app", "id", "type", "sharing",
                # field-naming parameters - target values (section 3.3)
                "new_perms_read", "new_perms_write", "new_sharing", "new_owner",
                # functional parameters (section 4.1)
                "dryrun", "validate_roles", "journal", "max_objects",
            },
        )

    def test_the_fields_parameter_is_gone(self):
        """D-23 - it is no longer declared, and its eighteen-row matrix went with it."""
        self.assertNotIn("fields", self._option_names())

    def test_no_private_attribute_collides_with_a_backing_field(self):
        # `backing_field_name = "_" + name`, decorators.py. An option named `journal`
        # therefore occupies `_journal`: that is what turned a usable fatal error into
        # `AttributeError: 'bool' object has no attribute 'close'`.
        fields = {"_" + name for name in self._option_names()}
        fields |= {"_" + name for name in self._configuration_settings()}
        collisions = sorted(self._assigned_private_attributes() & fields)
        self.assertEqual(
            collisions, [],
            "private attribute(s) of the adapter colliding with the backing field of "
            "an Option or of a Configuration setting: %s" % collisions,
        )

    def test_no_private_attribute_collides_with_the_base_class(self):
        sdk = self._sdk_private_attributes()
        self.assertTrue(sdk, "the source of the vendored SDK was not read")
        collisions = sorted(self._assigned_private_attributes() & sdk)
        self.assertEqual(
            collisions, [],
            "private attribute(s) of the adapter colliding with an attribute of "
            "SearchCommand / StreamingCommand: %s" % collisions,
        )

    def _method(self, name):
        for node in ast.walk(self._command_class()):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        self.fail("method %s() not found" % name)

    def test_the_finally_of_stream_delegates_to_the_cleanup(self):
        tries = [n for n in ast.walk(self._method("stream")) if isinstance(n, ast.Try)]
        finallys = [n for n in tries if n.finalbody]
        self.assertTrue(finallys, "`stream()` has no `finally` block")
        calls = {
            ast.unparse(n.func)
            for block in finallys
            for f in block.finalbody
            for n in ast.walk(f)
            if isinstance(n, ast.Call)
        }
        self.assertIn("self._cleanup", calls)

    def test_the_cleanup_cannot_mask_the_error_in_flight(self):
        """Every `close()` of the cleanup must be guarded: an exception raised in the
        `finally` would replace the fatal error being propagated."""
        cleanup = self._method("_cleanup")
        closes = [
            n for n in ast.walk(cleanup)
            if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(".close")
        ]
        self.assertTrue(closes, "the cleanup closes nothing")
        protected = {
            n.lineno
            for attempt in ast.walk(cleanup)
            if isinstance(attempt, ast.Try) and attempt.handlers
            for body in attempt.body
            for n in ast.walk(body)
            if isinstance(n, ast.Call)
        }
        for close_call in closes:
            self.assertIn(
                close_call.lineno, protected,
                "a `close()` of the cleanup is not guarded: an exception there would "
                "supplant the fatal error being propagated",
            )


class FatalErrorRecordingTest(unittest.TestCase):
    """A-3 - section 8.1 requires the fatal errors to appear in `editacl.log`.

    That is the only place where a fatal error survives the end of the search: the user
    message is ephemeral, and the job disappears when it expires.
    """

    def setUp(self):
        from acltools.diag import NullDiagnostics
        from acltools.errors import FatalCapabilityError

        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        self.command = self.module.EditAclCommand()
        self.command.journal = True
        self.command.dryrun = True
        self.recorded = []

        recorded = self.recorded

        class _FakeDiag(NullDiagnostics):
            def fatal(self, message):
                recorded.append(message)

        self.command._diag = _FakeDiag()
        self.FatalCapabilityError = FatalCapabilityError

    def _fail_with(self, exception):
        def _setup_that_fails():
            raise exception

        self.command._setup = _setup_that_fails
        try:
            list(self.command.stream([{"title": "an_object"}]))
        except Abort:
            pass

    def test_a_fatal_preflight_error_is_recorded(self):
        self._fail_with(self.FatalCapabilityError("capability missing"))
        self.assertEqual(self.recorded, ["capability missing"])

    def test_the_ceiling_is_no_longer_a_fatal_error(self):
        """D-28 - the exception class is gone, and nothing must resurrect it.

        Looking for `MaxObjectsReached` in `acltools.errors` is the mistake a reader of
        the v1 would make; this test makes it impossible to make silently.
        """
        import acltools.errors as errors

        self.assertFalse(hasattr(errors, "MaxObjectsReached"))

    def test_the_diagnostic_is_closed_at_the_end_of_the_run(self):
        closes = []
        from acltools.diag import NullDiagnostics

        class _CountingDiag(NullDiagnostics):
            def close(self):
                closes.append(True)

        self.command._diag = _CountingDiag()
        self.command._setup = lambda: setattr(self.command, "_ready", True)
        self.command._processor = None
        self.command._handle = lambda record: record
        list(self.command.stream([{"title": "an_object"}]))
        self.assertEqual(closes, [True])


class RuntimeDivergenceWarningTest(unittest.TestCase):
    """A-2 - the operator must read, at the level of the search, what the `acl_warning`
    token cannot say.

    `acl_warning` is a set of tokens concatenated with `;`: the sentence explaining that
    a persistence `HTTP 500` leaves a diverging runtime view, out of reach of
    `editacl_rollback`, does not fit there. It is emitted **once** per run, by the
    wrapper.
    """

    def setUp(self):
        from acltools.model import EventResult
        from acltools.pipeline import RUNTIME_DIVERGENCE_WARNING

        from acltools.preflight import validate_params

        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        self.command = self.module.EditAclCommand()
        self.command._ready = True
        # `_handle` reads the field-naming parameters: the command is wired as it would
        # be after a successful `_setup()`, with no network.
        self.command._params = validate_params()

        class _DivergingProcessor(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(
                    status="error",
                    title="an_object",
                    endpoint="/servicesNS/nobody/my_app/saved/searches/an_object",
                    http_code=500,
                    error="post_failed:500:Could not flush changes to disk",
                    warnings=(RUNTIME_DIVERGENCE_WARNING,),
                )

        class _NominalProcessor(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(status="updated", title="an_object", http_code=200)

        self.diverging = _DivergingProcessor()
        self.nominal = _NominalProcessor()

    def _batch(self, processor, size):
        self.command._processor = processor
        return list(
            self.command.stream([{"title": "an_object"} for _ in range(size)])
        )

    def test_the_message_is_emitted_and_names_both_facts(self):
        self._batch(self.diverging, 1)
        self.assertEqual(len(self.command.warnings), 1)
        text = self.command.warnings[0].lower()
        self.assertIn("runtime", text)
        self.assertIn("disk", text)
        self.assertIn("editacl_rollback", text)

    def test_the_message_is_emitted_only_once_per_run(self):
        self._batch(self.diverging, 5)
        self.assertEqual(len(self.command.warnings), 1)

    def test_no_message_without_a_divergence(self):
        self._batch(self.nominal, 3)
        self.assertEqual(self.command.warnings, [])


class SimulationWarningTest(unittest.TestCase):
    """The simulation reminder is emitted **once per run**, not per event.

    `dryrun` is `true` by default and was signaled nowhere: a run that writes nothing
    returns the same full table as a run that wrote everything.

    Its correctness rests on two properties, and both are exercised here on a batch of
    several objects **and over several chunks** - the SDK calls `stream()` once per
    chunk, so a counter carried by the loop would not hold:

    1. a single message for the whole batch - a warning repeated over several hundred
       objects is noise, and noise gets filtered out mentally;
    2. it is a warning, never an error: no `write_error`, no abort chunk, no call to the
       process exit. The status of the job is intact.

    The setup substitutes the network collaborators of `_setup()` - there is neither a
    socket nor a Splunk instance in this suite (section 11.1) - but leaves the real
    emission path in place: `validate_params`, then the loop over `params.warnings`.
    """

    def setUp(self):
        from acltools.model import EventResult
        from acltools.preflight import DRYRUN_WARNING

        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        # Every message reaching the search interface carries `MESSAGE_PREFIX`, applied
        # at the single emission point of the adapter (D-39).
        self.expected = self.module.MESSAGE_PREFIX + DRYRUN_WARNING

        class _NominalProcessor(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(status="dryrun", title="an_object", http_code=0)

        self.module.RestClient = lambda *a, **k: object()
        self.module.check_capability = lambda rest: None
        self.module.check_realtime = lambda rest, sid: "batch"
        self.module.load_roles_catalog = lambda rest: frozenset()
        self.module.resolve_server_name = lambda rest: "sh01"
        self.module.AppStateCache = lambda rest: types.SimpleNamespace(
            is_app_disabled=lambda app: False
        )
        self.module.EventProcessor = lambda **kwargs: _NominalProcessor()

    def _command(self, dryrun):
        command = self.module.EditAclCommand()
        command.dryrun = dryrun
        command.validate_roles = False
        command.journal = False               # no file written by this test
        command.max_objects = 10
        command._metadata = types.SimpleNamespace(
            searchinfo=types.SimpleNamespace(
                sid="1700000000.1",
                username="an_operator",
                splunkd_uri="https://127.0.0.1:8089",
                session_key="fake-session-key",
            )
        )
        return command

    def _run(self, command, objects, chunks=1):
        """Run the batch through `chunks` successive calls to `stream()`, like the SDK.
        """
        outputs = []
        per_chunk = max(1, objects // chunks)
        remaining = objects
        while remaining > 0:
            size = min(per_chunk, remaining)
            outputs.extend(
                command.stream([{"title": "object_%d" % i} for i in range(size)])
            )
            remaining -= size
        return outputs

    def test_the_reminder_is_emitted_on_a_batch_of_several_objects(self):
        command = self._command(dryrun=True)
        outputs = self._run(command, 250)
        self.assertEqual(len(outputs), 250)
        self.assertIn(self.expected, command.warnings)

    def test_the_reminder_is_emitted_only_once_for_the_whole_batch(self):
        command = self._command(dryrun=True)
        self._run(command, 250)
        self.assertEqual(command.warnings.count(self.expected), 1)

    def test_a_single_reminder_even_spread_over_several_chunks(self):
        command = self._command(dryrun=True)
        self._run(command, 250, chunks=5)
        self.assertEqual(command.warnings.count(self.expected), 1)

    def test_the_reminder_is_not_an_error(self):
        command = self._command(dryrun=True)
        self._run(command, 10)
        self.assertEqual(command.errors, [])
        self.assertEqual(command._record_writer.chunks, [])

    def test_no_reminder_on_a_real_write(self):
        command = self._command(dryrun=False)
        self._run(command, 10)
        self.assertNotIn(self.expected, command.warnings)


class _OrderedJournal(object):
    """Journal port recording **every** line in one list, in write order.

    Two lists indexed by phase would hide the property under test: the end-of-run line
    is the last one of the file, and there is at most one of it.

    It reproduces one behaviour of `JournalWriter` exactly, and it matters here: **a
    write after `close()` fails**. On the real writer the underlying file object raises
    `ValueError`, which `_write` catches and turns into `False`. A double that kept
    accepting lines after being closed would hide what
    `TheJournalDoesNotSurviveASecondChunkTest` measures.
    """

    def __init__(self, fail_summary=False):
        self.lines = []
        self.fail_summary = fail_summary
        self.closed = False

    def _append(self, record):
        if self.closed:
            return False
        self.lines.append(record)
        return True

    def write_intent(self, record):
        return self._append(record)

    def write_outcome(self, record):
        return self._append(record)

    def write_summary(self, record):
        if self.fail_summary:
            return False
        return self._append(record)

    def close(self):
        self.closed = True

    def phases(self):
        return [line["phase"] for line in self.lines]


class _AdapterRunHarness(object):
    """Wiring of a complete run of the adapter over the doubles of the suite.

    The network collaborators of `_setup()` are substituted - there is neither a socket
    nor a Splunk instance here (section 11.1) - but the processor is the **real** one,
    so the journal lines and the counters are produced by the state machine and not by
    a fixture.
    """

    def setUp(self):
        from acltools.pipeline import EventProcessor
        from acltools.rest import RestResponse

        from .helpers import FIXTURE_MAPPING, FakeClock, FakeRest, acl_body

        self.module = _load_editacl()
        _intercept_the_abort(self.module)
        self.journal = _OrderedJournal()

        def _processor(**kwargs):
            arguments = dict(kwargs)
            arguments["rest"] = FakeRest(
                default_get=RestResponse(200, acl_body(write=("legacy_role",))),
                default_post=RestResponse(200, b"{}"),
            )
            arguments["mapping"] = FIXTURE_MAPPING
            arguments["app_disabled_fn"] = None
            arguments["clock"] = FakeClock()
            return EventProcessor(**arguments)

        self.module.RestClient = lambda *a, **k: object()
        self.module.check_capability = lambda rest: None
        self.module.check_realtime = lambda rest, sid: "batch"
        self.module.load_roles_catalog = lambda rest: frozenset()
        self.module.resolve_server_name = lambda rest: "sh01"
        self.module.AppStateCache = lambda rest: types.SimpleNamespace(
            is_app_disabled=lambda app: False
        )
        self.module.EventProcessor = _processor
        self.module.JournalWriter = lambda path: self.journal

    def _command(self):
        command = self.module.EditAclCommand()
        command.dryrun = False
        command.validate_roles = False
        command.journal = True
        command.max_objects = 1000
        command._metadata = types.SimpleNamespace(
            searchinfo=types.SimpleNamespace(
                sid="1700000000.1",
                username="an_operator",
                splunkd_uri="https://127.0.0.1:8089",
                session_key="fake-session-key",
            )
        )
        return command

    @staticmethod
    def _records(count, prefix="object"):
        return [
            {
                "title": "%s_%d" % (prefix, index),
                "eai:acl.app": "my_app",
                "eai:type": "savedsearch",
                "eai:acl.sharing": "global",
                "eai:acl.perms.write": "new_role_admin",
            }
            for index in range(count)
        ]

    def _summaries(self):
        return [line for line in self.journal.lines if line["phase"] == "summary"]


class EndOfRunLineTest(_AdapterRunHarness, unittest.TestCase):
    """Section 8.2, D-46 - the `phase=summary` line, and **where** it is written.

    Until now no line marked the end of a job: an interrupted run - fatal error,
    process killed - and a completed one were indistinguishable, which is precisely the
    distinction a monitoring view exists to carry.

    The line is only worth something if its absence means something. That makes its
    position in the control flow the substance of the change, and this class the place
    where it is checked: the write sits inside the `try` of `stream()`, after the loop,
    on the branch a `FatalError` skips. The fatal branch calls `_cleanup()` then
    `_fatal_exit()`, which leaves through `os._exit` - the `finally` never runs and
    nothing more can be appended. Had the write been placed in `_cleanup()`, which
    **both** paths call, the two states would be indistinguishable again.

    The processor is the real one, wired onto the REST double of the suite: the
    counters carried by the line are then produced by the state machine and not by a
    fixture.
    """

    # -- normal end --------------------------------------------------------- #

    def test_the_line_is_written_at_the_end_of_a_normal_run(self):
        command = self._command()
        outputs = list(command.stream(self._records(3)))
        self.assertEqual(len(outputs), 3)
        self.assertEqual(len(self._summaries()), 1)

    def test_it_is_the_last_line_of_the_file(self):
        command = self._command()
        list(command.stream(self._records(3)))
        self.assertEqual(self.journal.phases()[-1], "summary")
        self.assertEqual(self.journal.phases().count("summary"), 1)

    def test_it_carries_the_counters_of_the_run(self):
        from acltools.journal import SUMMARY_COUNT_PREFIX

        command = self._command()
        list(command.stream(self._records(4)))
        summary = self._summaries()[0]
        self.assertEqual(summary[SUMMARY_COUNT_PREFIX + "updated"], 4)
        self.assertEqual(
            sum(
                value for field, value in summary.items()
                if field.startswith(SUMMARY_COUNT_PREFIX)
            ),
            4,
        )

    def test_it_carries_the_run_fields_and_no_object_field(self):
        command = self._command()
        list(command.stream(self._records(2)))
        summary = self._summaries()[0]
        self.assertEqual(summary["sid"], "1700000000.1")
        self.assertEqual(summary["user"], "an_operator")
        self.assertEqual(summary["member"], "sh01")
        self.assertIs(summary["dryrun"], False)
        for field in ("endpoint", "app", "title", "eai_type", "host"):
            self.assertNotIn(field, summary)

    def test_no_line_of_the_run_holds_a_null(self):
        command = self._command()
        list(command.stream(self._records(2)))
        for line in self.journal.lines:
            with self.subTest(phase=line["phase"]):
                self.assertEqual([f for f, v in line.items() if v is None], [])

    def test_the_line_is_deferred_while_more_chunks_are_announced(self):
        """The SDK calls `stream()` once per chunk and fills `_finished` from the chunk
        metadata: the counters are only complete on the last one.

        The guard is exercised on its own, and not through two successive calls to
        `stream()`, because of the defect pinned by
        `TheJournalDoesNotSurviveASecondChunkTest`: today no chunk after the first has
        a journal at all.
        """
        command = self._command()
        list(command.stream(self._records(2)))
        self.assertEqual(len(self._summaries()), 1)

        # Same command, rewound to the state of a chunk that is not the last one: a
        # live journal, a processor with its tally, nothing written yet.
        self.journal = _OrderedJournal()
        command._summary_written = False
        command._journal_writer = self.journal
        command._finished = False
        command._write_summary()
        self.assertEqual(self._summaries(), [])
        command._finished = True
        command._write_summary()
        self.assertEqual(len(self._summaries()), 1)
        command._write_summary()
        self.assertEqual(len(self._summaries()), 1, "and only once")

    def test_a_run_with_no_record_at_all_opens_nothing_and_writes_nothing(self):
        command = self._command()
        self.assertEqual(list(command.stream([])), [])
        self.assertEqual(self.journal.lines, [])

    def test_a_failure_to_write_it_is_recorded_in_the_diagnostic(self):
        from acltools.diag import NullDiagnostics

        recorded = []

        class _Diag(NullDiagnostics):
            def warning(self, message):
                recorded.append(message)

        # `_setup()` opens the diagnostic itself: substituting the instance before the
        # run would be overwritten right away.
        self.module.open_diagnostics = lambda log_dir, sid: _Diag()
        self.journal.fail_summary = True
        command = self._command()
        list(command.stream(self._records(1)))
        self.assertEqual(self._summaries(), [])
        self.assertEqual(len(recorded), 1)
        self.assertIn("interrupted", recorded[0])

    # -- fatal exit --------------------------------------------------------- #

    def test_no_line_on_the_fatal_error_path(self):
        """The substance of it: the absence of the line **is** the interruption
        signal."""
        from acltools.errors import FatalConfigError

        command = self._command()
        handle = command._handle
        state = {"seen": 0}

        def _handle_then_fail(record):
            state["seen"] += 1
            if state["seen"] > 2:
                raise FatalConfigError("a fatal error of section 9")
            return handle(record)

        command._handle = _handle_then_fail
        with self.assertRaises(Abort):
            list(command.stream(self._records(5)))
        self.assertEqual(self._summaries(), [])
        self.assertNotIn("summary", self.journal.phases())
        # The lines of the two objects that did go through are there: what is missing
        # is the end-of-run line, and only it.
        self.assertEqual(self.journal.phases(), ["intent", "outcome"] * 2)

    def test_the_journal_is_closed_before_the_abort_even_without_the_line(self):
        from acltools.errors import FatalConfigError

        command = self._command()

        def _handle_that_fails(record):
            raise FatalConfigError("a fatal error of section 9")

        command._handle = _handle_that_fails
        with self.assertRaises(Abort):
            list(command.stream(self._records(1)))
        self.assertTrue(self.journal.closed)
        self.assertEqual(self.journal.lines, [])

    def test_the_write_point_is_not_in_the_cleanup(self):
        """Mechanical reading: `_cleanup()` is called by **both** paths, so a write
        placed there would make an interrupted run indistinguishable from a complete
        one. The check is on the syntax tree so that no later refactor can move it back
        without saying so."""
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        callers = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    callers.setdefault(ast.unparse(inner.func), set()).add(node.name)
        scopes = callers.get("self._write_summary", set())
        self.assertEqual(scopes, {"stream"})


class TheJournalDoesNotSurviveASecondChunkTest(_AdapterRunHarness, unittest.TestCase):
    """**This class pins a DEFECT, not a contract. Delete it when the defect is fixed.**

    Found while placing the end-of-run line, and it is older than that line.

    `stream()` closes the journal and the diagnostic in its `finally`. The SDK calls
    `stream()` **once per chunk** and drains the generator each time
    (`_execute_chunk_v2`: `write_records(process(records))`), so that `finally` fires at
    the end of **every** chunk, not at the end of the run. `_ready` stays true, so
    `_setup()` is not run again and `_journal_writer` stays `None` for the rest of the
    run.

    Consequences, measured below and not deduced:

    - every object of the second chunk onward comes out `acl_status = "error"` with
      `acl_error = "journal_intent_failed"` - section 8.4 cancels the POST when the
      write-ahead line cannot be persisted. **Nothing is written for those objects, and
      the run reports errors that have no other cause than this;**
    - the end-of-run line can therefore never be written on a run of more than one
      chunk, since the guard that defers it to the last chunk lands on a run that no
      longer has a journal.

    Why it was never seen: a chunk holds tens of thousands of records, and the largest
    lab job was 1 495 objects - one chunk. The `_finished` guard of `_signal_ceiling`
    shows the multi-chunk case **was** in the author's mind; the cleanup in the
    `finally` defeats it.

    Fixing it means changing the lifecycle of the journal and the diagnostic on a run,
    which touches the fatal error path. That is an arbitration, not a side effect of the
    present change, so it is reported rather than improvised.
    """

    def test_the_journal_is_closed_at_the_end_of_the_first_chunk(self):
        command = self._command()
        command._finished = False
        list(command.stream(self._records(2)))
        self.assertTrue(self.journal.closed)
        self.assertIsNone(command._journal_writer)

    def test_the_objects_of_the_second_chunk_are_not_written_at_all(self):
        command = self._command()
        command._finished = False
        first = list(command.stream(self._records(2, prefix="first")))
        self.assertEqual([r["acl_status"] for r in first], ["updated"] * 2)
        command._finished = True
        second = list(command.stream(self._records(2, prefix="second")))
        self.assertEqual([r["acl_status"] for r in second], ["error"] * 2)
        self.assertEqual(
            [r["acl_error"] for r in second], ["journal_intent_failed"] * 2
        )

    def test_and_therefore_no_end_of_run_line_beyond_one_chunk(self):
        command = self._command()
        command._finished = False
        list(command.stream(self._records(2, prefix="first")))
        command._finished = True
        list(command.stream(self._records(2, prefix="second")))
        self.assertEqual(self._summaries(), [])


class DeclaredOutputFieldSetTest(unittest.TestCase):
    """Section 5.7, D-33 - the output field set is **declared, never inferred**.

    The anomaly these tests freeze is not in the code of the app: it is in the
    transport. The SDK writer builds the header of the stream from the keys of the
    **first** record emitted, then projects every later one onto it. Since the eight
    `acl_before_*` / `acl_after_*` fields are only carried by the records whose merge
    was computed, a batch whose first line is a `skipped_private` deprives the operator
    of **everything** the simulation exists to show - with no error, no warning, and
    without the journal carrying the slightest trace of it.

    **A single degree of freedom separates the two measurements: the order of the
    batch.** Same objects, same statuses, same command. A test that did not reverse the
    order would prove nothing.
    """

    def setUp(self):
        from acltools.model import ACL_OUTPUT_FIELDS, ACL_STATE_FIELDS, AclState, EventResult

        self.declared_fields = ACL_OUTPUT_FIELDS
        self.state_fields = ACL_STATE_FIELDS
        self.module = _load_editacl()
        _intercept_the_abort(self.module)

        before = AclState(owner="nobody", sharing="app",
                          perms_read=("*",), perms_write=("legacy_role",))
        after = AclState(owner="nobody", sharing="app",
                         perms_read=("*",), perms_write=("new_role_admin",))

        #: One status **without** a state - the object is skipped before the merge - and
        #: one status that carries a state. This is exactly the batch the inventory
        #: macro produces: it lists private objects on the same footing as the others.
        results = {
            "private_object": EventResult(
                status="skipped_private",
                title="private_object",
                error="private_object_out_of_scope",
            ),
            "shared_object": EventResult(
                status="dryrun",
                title="shared_object",
                http_code=200,
                before=before,
                after=after,
            ),
        }

        class _ProcessorByTitle(object):
            skipped_ceiling = 0

            def process(self, event):
                return results[event.title]

        self.module.RestClient = lambda *a, **k: object()
        self.module.check_capability = lambda rest: None
        self.module.check_realtime = lambda rest, sid: "batch"
        self.module.load_roles_catalog = lambda rest: frozenset()
        self.module.resolve_server_name = lambda rest: "sh01"
        self.module.AppStateCache = lambda rest: types.SimpleNamespace(
            is_app_disabled=lambda app: False
        )
        self.module.EventProcessor = lambda **kwargs: _ProcessorByTitle()

    def _stream(self, titles, declare=True):
        """Run a batch and return the writer, header frozen as the SDK would do it."""
        command = self.module.EditAclCommand()
        command.dryrun = True
        command.validate_roles = False
        command.journal = False
        command.max_objects = 10
        command._metadata = types.SimpleNamespace(
            searchinfo=types.SimpleNamespace(
                sid="1700000000.1",
                username="an_operator",
                splunkd_uri="https://127.0.0.1:8089",
                session_key="fake-session-key",
            )
        )
        outputs = list(command.stream([{"title": title} for title in titles]))
        if not declare:
            # Control: the declaration is removed just before the write, to prove that
            # the double does reproduce the anomaly it is supposed to reproduce.
            command._record_writer.custom_fields.clear()
        command._record_writer.write_records(outputs)
        return command._record_writer

    # -- the proof, in both orders ------------------------------------------ #

    def test_a_batch_starting_with_a_stateless_status_carries_every_field(self):
        writer = self._stream(["private_object", "shared_object"])
        for field in self.declared_fields:
            self.assertIn(field, writer.header, field)

    def test_a_batch_starting_with_a_stateful_status_carries_every_field(self):
        writer = self._stream(["shared_object", "private_object"])
        for field in self.declared_fields:
            self.assertIn(field, writer.header, field)

    def test_the_header_is_the_same_in_both_orders(self):
        """The property that matters: the output no longer depends on batch order."""
        forward = self._stream(["private_object", "shared_object"]).header
        reverse = self._stream(["shared_object", "private_object"]).header
        self.assertEqual(sorted(forward), sorted(reverse))

    def test_the_useful_value_is_carried_when_the_private_object_comes_first(self):
        """Presence of the column is not enough: the value must be in it."""
        writer = self._stream(["private_object", "shared_object"])
        self.assertEqual(writer.rows[1]["acl_before_perms_write"], "legacy_role")
        self.assertEqual(writer.rows[1]["acl_after_perms_write"], "new_role_admin")

    def test_the_stateless_status_carries_no_state_value(self):
        """The declaration adds the column, it does not invent content (section 8.2)."""
        writer = self._stream(["private_object", "shared_object"])
        for field in self.state_fields:
            self.assertIsNone(writer.rows[0][field], field)

    # -- control: without the declaration, the anomaly is reproduced -------- #

    def test_without_the_declaration_the_eight_fields_disappear(self):
        """What the auditor measured on `191d5e8`, and what closes the control.

        If this test stopped passing, the double would no longer reproduce the anomaly
        and the five tests above would no longer prove anything.
        """
        writer = self._stream(["private_object", "shared_object"], declare=False)
        for field in self.state_fields:
            self.assertNotIn(field, writer.header, field)

    def test_without_the_declaration_the_reverse_order_keeps_them(self):
        writer = self._stream(["shared_object", "private_object"], declare=False)
        for field in self.state_fields:
            self.assertIn(field, writer.header, field)

    # -- the declaration cannot drift away from the projection -------------- #

    def test_the_declaration_covers_exactly_what_the_adapter_projects(self):
        """Two lists that drifted apart would make the fix silent.

        The projected names are collected from the source of `_handle`, the declared
        ones from `ACL_OUTPUT_FIELDS`. The equality of the two sets is the only thing
        that guarantees that no field added tomorrow falls back into today's defect.
        """
        source = os.path.join(BIN_DIR, "editacl.py")
        with open(source, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        projected = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != "_handle":
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Assign):
                    continue
                for target in inner.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "output"
                        and isinstance(target.slice, ast.Constant)
                    ):
                        projected.add(target.slice.value)

        self.assertEqual(projected, set(self.declared_fields))

    def test_the_declaration_is_made_from_the_sdk_extension_point(self):
        """`prepare()` is invoked by the SDK before any execution.

        `_setup()` does it again - it runs before the first `yield` - but relying on it
        alone would make the output depend on a path that is not the one the SDK
        documents.
        """
        command = self.module.EditAclCommand()
        command.prepare()
        self.assertEqual(
            set(self.declared_fields) - command._record_writer.custom_fields, set()
        )


class TheDoubleReproducesTheSdkTest(unittest.TestCase):
    """Backs `_FakeRecordWriter` against the source of the vendored SDK, without loading
    it.

    The suite does not put `bin/lib` in `sys.path` (section 11.1): the A-1 tests
    therefore rest on a double. A double that had drifted away from the SDK would prove
    something other than what it claims. These three controls read the source of the SDK
    and freeze the three facts the double - and the fix - rest on.
    """

    @classmethod
    def setUpClass(cls):
        path = os.path.join(SDK_DIR, "internals.py")
        with open(path, encoding="utf-8") as handle:
            cls.source = handle.read()
        cls.tree = ast.parse(cls.source)

    def test_the_header_is_frozen_on_the_keys_of_the_first_record(self):
        self.assertIn(
            "self._fieldnames = fieldnames = list(record.keys())", self.source
        )

    def test_the_header_is_extended_by_custom_fields(self):
        self.assertIn(
            "[i for i in self.custom_fields if i not in self._fieldnames]", self.source
        )

    def test_custom_fields_survives_the_end_of_chunk(self):
        """`_clear()` resets the header, never the declaration.

        That is what makes a **single** declaration valid for every chunk of a run -
        without it the declaration would have to be redone on each chunk.
        """
        clears = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_clear"
        ]
        self.assertTrue(clears)
        for node in clears:
            body = ast.dump(node)
            self.assertNotIn("custom_fields", body)


if __name__ == "__main__":
    unittest.main()
