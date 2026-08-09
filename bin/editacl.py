#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`editacl` search command - adapter, **no business rule here**.

This file does three things and nothing else:

1. it inserts `bin/lib` then `bin` at the head of `sys.path`, before any other import;
2. it declares the command and its parameters (section 4.1) and wires the `acltools`
   core;
3. it turns fatal exceptions into an error output and projects the `acl_*` fields of
   section 5.7 into the output record.

All the logic - normalization, merge, endpoint resolution, journal, state machine -
lives in `acltools`, which depends neither on the SDK nor on the network and is tested
outside Splunk.
"""

import os
import sys

# --------------------------------------------------------------------------- #
# sys.path - BEFORE any import of the project or of the SDK (spec section 8.3)
# `bin/lib` first: the vendored version takes precedence over the platform's.
# `bin` as well, so that `acltools` is importable independently of the working
# directory of the search process, which the platform does not guarantee.
# The path is derived from `__file__`, never from an environment variable nor from an
# absolute path.
# --------------------------------------------------------------------------- #
_BIN = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_BIN, "lib"), _BIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import configparser  # noqa: E402
import socket  # noqa: E402

from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    Option,
    StreamingCommand,
    dispatch,
    validators,
)

from acltools.binding import build_event  # noqa: E402
from acltools.diag import NullDiagnostics, open_diagnostics  # noqa: E402
from acltools.errors import FatalError  # noqa: E402
from acltools.journal import JournalWriter, journal_path  # noqa: E402
from acltools.mapping import load_mapping  # noqa: E402
from acltools.model import (  # noqa: E402
    ACL_OUTPUT_FIELDS,
    DEFAULT_FIELD_NAMES,
    RunContext,
)
from acltools.normalize import serialize_roles  # noqa: E402
from acltools.pipeline import (  # noqa: E402
    RUNTIME_DIVERGENCE_MESSAGE,
    RUNTIME_DIVERGENCE_WARNING,
    EventProcessor,
    ceiling_message,
)
from acltools.preflight import (  # noqa: E402
    DEFAULT_MAX_OBJECTS,
    AppStateCache,
    check_capability,
    check_realtime,
    load_roles_catalog,
    resolve_server_name,
    validate_params,
)
from acltools.rest import RestClient  # noqa: E402

_APP_ROOT = os.path.dirname(_BIN)
_MAP_JSON = os.path.join(_BIN, "acl_endpoint_map.json")
_OVERRIDE_CSV = os.path.join(_APP_ROOT, "lookups", "acl_endpoint_map_override.csv")

#: Prefix carried by **every** message addressed to the operator through the search
#: interface: the name of the command, a colon, one space.
#:
#: A search pipeline concatenates the messages of every command it chains, and the
#: interface displays them stripped of their origin. Until now an `editacl` warning was
#: indistinguishable from a warning of the macro that feeds it, of `map`, or of the
#: platform itself - which is precisely the situation where an operator dismisses a
#: message that concerns an irreversible write.
#:
#: The prefix is applied at a **single emission point**, `_emit_message`, and never
#: repeated on the literals: the day the form changes, it changes in one place. The
#: repository already has that culture of the single injection point - see
#: `field_present` in `acltools/binding.py`.
#:
#: It does **not** apply to `editacl.log` nor to the write-ahead journal: their origin
#: is already established by their dedicated sourcetypes, `editacl:diag` and
#: `editacl:journal` (section 8.3), and prefixing every line there would add noise to a
#: stream that is parsed, not read.
MESSAGE_PREFIX = "editacl: "


def _read_app_setting(name, default):
    """Read `default/editacl.conf` then `local/editacl.conf`.

    Deliberately from the files and not through the `configs/conf-editacl` REST
    endpoint: `verify_ssl` conditions the construction of the TLS context, so it cannot
    be read through a call that depends on it.
    """
    parser = configparser.ConfigParser()
    for layer in ("default", "local"):
        path = os.path.join(_APP_ROOT, layer, "editacl.conf")
        if os.path.exists(path):
            try:
                parser.read(path, encoding="utf-8")
            except (configparser.Error, OSError):
                continue
    if parser.has_option("editacl", name):
        return parser.get("editacl", name)
    return default


def _app_version():
    """Version declared by `default/app.conf`, for the startup line of section 8.1."""
    parser = configparser.ConfigParser()
    try:
        parser.read(os.path.join(_APP_ROOT, "default", "app.conf"), encoding="utf-8")
    except (configparser.Error, OSError):
        return ""
    for section in ("launcher", "id"):
        if parser.has_option(section, "version"):
            return parser.get(section, "version")
    return ""


def _abort_process(code=1):
    """Leave the process **without** unwinding the `finally` blocks nor the SDK protocol.

    A single point of indirection, for two reasons. The first is to name what `os._exit`
    does: there is no return, no cleanup, no final chunk. The second is to make the
    failure path **exercisable** - a hardcoded `os._exit` would kill the test process
    instead of failing it.
    """
    os._exit(code)                                                   # pragma: no cover


def _truthy(value, default=True):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y", "on")


# `type` is not passed to `@Configuration`: the `StreamingCommand` base class pins it to
# `streaming`, and the SDK refuses any redeclaration. Section 2.1 of the specification
# states `@Configuration(type='streaming', ...)`; the effect is identical, the form is
# imposed by the SDK. `local = true` is carried by `commands.conf`.
@Configuration(local=True)
class EditAclCommand(StreamingCommand):
    """Rewrites the ACLs of the knowledge objects described by the input pipeline.

    ##Syntax

    .. code-block::
        editacl [title=<field>] [app=<field>] [id=<field>] [type=<field>]
                [sharing=<field>] [new_perms_read=<field>] [new_perms_write=<field>]
                [new_sharing=<field>] [new_owner=<field>] [dryrun=<bool>]
                [validate_roles=<bool>] [journal=<bool>] [max_objects=<int>]

    ##Description

    Each parameter names the SPL field to read one piece of information from, and
    defaults to the platform's native field name: an operator who uses those writes no
    parameter at all.

    It is the **presence of the column** in the result set that decides: column absent,
    attribute preserved; column present and cell empty, attribute emptied; column
    present and valued, value applied.

    ##Example

    .. code-block::
        | `acl_inventory` | search "eai:acl.perms.write"="legacy_role"
        | eval "eai:acl.perms.write" = "new_role_admin"
        | editacl dryrun=f max_objects=200
    """

    # -- field-naming parameters (section 3.1): designate the object ---------- #
    title = Option(
        doc="Field carrying the name of the object. Default: title.",
        require=False,
        default=None,
    )
    app = Option(
        doc="Field carrying the application of the namespace. Default: eai:acl.app.",
        require=False,
        default=None,
    )
    id = Option(
        doc="Field carrying the full URI of the object. Default: id.",
        require=False,
        default=None,
    )
    type = Option(
        doc="Field carrying the object type, resolved through the table. "
            "Default: eai:type.",
        require=False,
        default=None,
    )
    sharing = Option(
        doc="Field carrying the CURRENT sharing scope, used to skip private objects. "
            "Default: eai:acl.sharing.",
        require=False,
        default=None,
    )

    # -- field-naming parameters (section 3.3): target values ---------------- #
    new_perms_read = Option(
        doc="Field carrying the target value of perms.read. "
            "Default: eai:acl.perms.read.",
        require=False,
        default=None,
    )
    new_perms_write = Option(
        doc="Field carrying the target value of perms.write. "
            "Default: eai:acl.perms.write.",
        require=False,
        default=None,
    )
    new_sharing = Option(
        doc="Field carrying the target value of sharing. Default: eai:acl.sharing.",
        require=False,
        default=None,
    )
    new_owner = Option(
        doc="Field carrying the target value of owner. Default: eai:acl.owner.",
        require=False,
        default=None,
    )

    dryrun = Option(
        doc="Simulation: no write at all. Default: true.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    validate_roles = Option(
        doc="Check that the added roles exist before writing. Default: true.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    journal = Option(
        doc="Record into the indexed journal. Default: true.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    max_objects = Option(
        doc="Maximum number of objects WRITTEN per run. Default: 10. No effect in "
            "simulation, which sends no POST and therefore covers the whole batch.",
        require=False,
        default=None,
    )

    def __init__(self):
        super(EditAclCommand, self).__init__()
        self._processor = None
        # `_journal_writer`, and above all NOT `_journal`: the SDK stores the value of
        # an `Option` in the attribute `"_" + <option name>`
        # (`searchcommands/decorators.py`). The `journal` option therefore occupies
        # `_journal`. Storing the writer there created a two-way collision - the
        # boolean of the option got closed like a file on the fatal error path, and
        # writing the writer made the value of the option unreadable.
        # `tests/test_editacl_adapter.py` mechanically forbids the return of the
        # defect.
        self._journal_writer = None
        self._params = None
        self._ready = False
        # Inert diagnostic as long as the file is not open: no diagnostic call can
        # raise before `_setup()`.
        self._diag = NullDiagnostics()
        # The runtime/disk divergence message (section 5.6) is emitted **once** per
        # run: a batch whose file system refuses every write would otherwise produce it
        # on every object, and drown it.
        self._runtime_divergence_signaled = False
        # The ceiling warning (section 4.3, D-28) is emitted **once**, at the end of
        # the run: that is the only moment at which the number of skipped objects is
        # known to a command that receives its input through successive chunks. Emitted
        # earlier, it could not carry that number; emitted per object, it would be
        # noise.
        self._ceiling_signaled = False
        # The end-of-run journal line (section 8.2, D-46) is written **once**, after
        # the last record of the run. Same reason as the ceiling warning: the command
        # receives its input through successive chunks, and the counters are only
        # complete on the last one.
        self._summary_written = False

    # -- single emission point of the operator-facing messages -------------- #

    def _emit_message(self, level, message):
        """**The** point where a message reaches the search interface (D-41).

        Every message the operator reads goes through here, and it is here - and
        nowhere else - that `MESSAGE_PREFIX` is applied. No other method of this file
        calls `write_warning`, `write_error`, `write_info` or `write_fatal`;
        `tests/test_editacl_adapter.py` reads the syntax tree of this module and fails
        if one of them is called outside this method, or through a construct it cannot
        analyse.

        The concentration is what makes the rule verifiable. Repeating the prefix on
        each literal would make it a convention, that is, something that holds until
        the next contributor.
        """
        text = MESSAGE_PREFIX + ("" if message is None else str(message))
        if level == "error":
            self.write_error(text)
        elif level == "info":
            self.write_info(text)
        else:
            self.write_warning(text)

    def _warn(self, message):
        """Warning addressed to the operator, prefixed."""
        self._emit_message("warning", message)

    def _error(self, message):
        """Error addressed to the operator, prefixed."""
        self._emit_message("error", message)

    # -- declaration of the output field set (section 5.7, D-33) ------------ #

    def _declare_output_fields(self):
        """Declare to the writer the whole field set of section 5.7.

        The SDK writer builds the stream header from the **keys of the first record
        emitted** (`RecordWriter._write_record`), then projects every later record onto
        it: a field absent from that first record disappears from the entire output,
        **with no error and no warning**. Since the eight `acl_before_*` /
        `acl_after_*` fields are only carried by the records whose merge was computed, a
        batch starting with a `skipped_private` deprives the operator of everything the
        simulation exists to show - and the inventory macro, which lists private objects
        alongside the others, routinely produces such batches.

        The SDK exposes `RecordWriter.custom_fields` for exactly this purpose: the names
        listed there are added to the header whatever the content of the first record.
        **The vendored SDK is therefore not modified**; the declaration is made from the
        app, and `custom_fields` survives the end-of-chunk `_clear()`, which makes it
        valid for every chunk of the run.

        Called by `prepare()` - the extension point the SDK provides, invoked before any
        execution - **and** by `_setup()`, which runs before the first `yield` and
        therefore covers the case of a protocol where `prepare()` would not be reached.
        The declaration is idempotent.

        No failure of this declaration must interrupt the command: it improves the
        output, it conditions no write.
        """
        writer = getattr(self, "_record_writer", None)
        declared = getattr(writer, "custom_fields", None)
        if declared is None:                                         # pragma: no cover
            return
        try:
            declared.update(ACL_OUTPUT_FIELDS)
        except AttributeError:                                       # pragma: no cover
            pass

    def prepare(self):
        super(EditAclCommand, self).prepare()
        self._declare_output_fields()

    # -- wiring ------------------------------------------------------------- #

    def _setup(self):
        self._declare_output_fields()
        info = self._metadata.searchinfo
        sid = str(getattr(info, "sid", "") or "")
        splunk_home = os.environ.get("SPLUNK_HOME")
        log_dir = (
            os.path.join(splunk_home, "var", "log", "splunk") if splunk_home else ""
        )

        # Opened first of all, so that the startup line and **every** later fatal
        # error - including an invalid parameter - are recorded. Its failure to open
        # costs nothing: `open_diagnostics` does not raise and returns an inert
        # diagnostic (section 8.1, the diagnostic file is not the safety net).
        self._diag = open_diagnostics(log_dir, sid)
        verify_ssl = _truthy(_read_app_setting("verify_ssl", "true"), default=True)
        self._diag.startup(
            version=_app_version(),
            user=str(getattr(info, "username", "") or ""),
            splunkd_uri=str(getattr(info, "splunkd_uri", "") or ""),
            verify_ssl=verify_ssl,
        )

        params = validate_params(
            names_raw={
                "title": self.title,
                "app": self.app,
                "id": self.id,
                "type": self.type,
                "sharing": self.sharing,
                "new_perms_read": self.new_perms_read,
                "new_perms_write": self.new_perms_write,
                "new_sharing": self.new_sharing,
                "new_owner": self.new_owner,
            },
            dryrun=self.dryrun,
            validate_roles=self.validate_roles,
            journal=self.journal,
            max_objects=(
                DEFAULT_MAX_OBJECTS if self.max_objects is None else self.max_objects
            ),
            max_objects_explicit=self.max_objects is not None,
        )
        self._params = params
        self._diag.params(params)
        for warning in params.warnings:
            self._warn(warning)

        # The session key never leaves this scope towards the diagnostic: no method of
        # `Diagnostics` has a parameter that carries it (section 8.1, R5).
        session_key = getattr(info, "session_key", None)
        splunkd_uri = getattr(info, "splunkd_uri", None)
        if not session_key or not splunkd_uri:
            from acltools.errors import FatalConfigError

            raise FatalConfigError(
                "splunkd_uri or session_key unavailable: the command cannot address "
                "the platform."
            )

        ca_file = None
        if verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not verify_ssl:
            self._diag.warning(
                "verify_ssl=false: verification of the splunkd certificate is "
                "disabled by local/editacl.conf."
            )
            self._warn(
                "verify_ssl=false: verification of the splunkd certificate is "
                "disabled by local/editacl.conf."
            )

        rest = RestClient(splunkd_uri, session_key, verify_ssl=verify_ssl, ca_file=ca_file)

        check_capability(rest)
        self._diag.capability(True)

        verdict = check_realtime(rest, sid)
        self._diag.realtime(verdict)
        if verdict == "unknown":
            self._warn(
                "real-time mode could not be determined for this sid: the safeguard "
                "of section 4.2 could not be applied."
            )

        roles_catalog = load_roles_catalog(rest) if params.validate_roles else frozenset()
        mapping = load_mapping(_MAP_JSON, _OVERRIDE_CSV, diag=self._diag)
        self._diag.mapping(mapping.coverage())

        member = resolve_server_name(rest) or socket.gethostname()
        self._diag.info("member: %s" % member)
        ctx = RunContext(
            sid=sid,
            user=str(getattr(info, "username", "") or ""),
            dryrun=params.dryrun,
        )

        if params.journal:
            path = journal_path(log_dir, sid)
            try:
                self._journal_writer = JournalWriter(path)
                self._diag.journal(path, True)
            except FatalError:
                # Failing to open is only fatal if a real write is planned
                # (section 5.1 step 7, section 9). In simulation it degrades to a
                # warning.
                self._diag.journal(path, False)
                if not params.dryrun:
                    raise
                self._journal_writer = None
                self._warn(
                    "journal not openable (%s): the run carries on in simulation "
                    "without a journal." % path
                )

        self._processor = EventProcessor(
            params=params,
            ctx=ctx,
            rest=rest,
            journal=self._journal_writer,
            mapping=mapping,
            roles_catalog=roles_catalog,
            app_disabled_fn=AppStateCache(rest).is_app_disabled,
        )
        self._ready = True

    # -- processing loop ---------------------------------------------------- #

    def stream(self, records):
        try:
            for record in records:
                if not self._ready:
                    self._setup()
                yield self._handle(record)
            self._signal_ceiling()
            self._write_summary()
        except FatalError as exc:
            # Single recording point of the fatal errors of section 9. `_setup()` is
            # called from within this `try`, so its errors pass through here. The
            # ceiling no longer appears there: since D-28 it does not raise, it
            # produces a status.
            #
            # The cleanup here is **unconditional**, and it is the only one that is:
            # `_fatal_exit()` leaves through `os._exit`, which runs no `finally`. It is
            # therefore the last chance to close the files, and that holds on a chunk
            # that is not the last one just as much as on the last one.
            self._diag.fatal(str(exc))
            self._cleanup()
            self._fatal_exit(exc)
        finally:
            # **Only at the end of the run, never at the end of a chunk.** The SDK
            # calls `stream()` once per chunk and drains the generator each time
            # (`_execute_v2`), so an unconditional cleanup here closed the journal at
            # the end of the *first* chunk. `_ready` staying true, `_setup()` was not
            # replayed and the journal stayed closed for the rest of the batch: from
            # the second chunk on, every object came out `error` /
            # `journal_intent_failed` and was **not** written, since section 8.4
            # cancels the POST when the write-ahead line cannot be persisted.
            if self._is_last_chunk():
                self._cleanup()

    def _is_last_chunk(self):
        """Is the chunk being processed the last one of the run?

        `self._finished` is filled in by the SDK from the metadata of each chunk of
        protocol v2, **before** `stream()` is called. It is `False` while more chunks
        are announced, `True` on the last one - and it stays at its initial `None`
        under protocol v1, which has no chunk at all.

        Hence the test on `is not False` rather than on `is True`, and that asymmetry
        is the whole point: under v1 the run is always its own last chunk, so reading
        the flag positively would defer the cleanup to a chunk that never comes - the
        end-of-run line would never be written and the journal never closed.

        The ceiling warning of section 4.3 already reasoned this way; the reasoning is
        named here once, and the three places that need it read it from here.
        """
        return getattr(self, "_finished", None) is not False

    def _signal_ceiling(self):
        """Single ceiling warning, after the last record (section 4.3).

        The command receives its input through successive chunks: `stream()` is
        re-invoked on each chunk, and the counter of the processor accumulates them. The
        number of skipped objects is therefore only right on the **last** chunk - which
        the SDK signals through `self._finished`, filled in from the chunk metadata
        before the call.

        Emitting earlier would undercount; emitting on each chunk would multiply a
        warning that section 4.3 wants to be unique. `_ceiling_signaled` closes the case
        of protocol v1, where `_finished` is never filled in.
        """
        processor = self._processor
        if processor is None or self._ceiling_signaled:
            return
        if processor.skipped_ceiling <= 0:
            return
        if not self._is_last_chunk():
            return
        self._ceiling_signaled = True
        message = ceiling_message(
            self._params.max_objects, processor.skipped_ceiling
        )
        self._diag.warning(message)
        self._warn(message)

    def _write_summary(self):
        """Single `phase=summary` journal line, after the last record (8.2, D-46).

        **Its position in the control flow is the whole point.** It sits inside the
        `try` of `stream()`, after the loop over the records - therefore on the branch a
        `FatalError` skips. That branch calls `_cleanup()` then `_fatal_exit()`, which
        ends the process through `os._exit`: the `finally` never runs, and no line can
        be appended afterwards. A run interrupted by a fatal error therefore leaves a
        journal **with no summary line**, and it is that absence which distinguishes it
        from a run that reached its end. Placing this write in `_cleanup()` would have
        made the two indistinguishable again, since the fatal path does call the
        cleanup.

        Same two guards as the ceiling warning, for the same reason: the input arrives
        in successive chunks, `self._finished` says whether this is the last one, and
        `_summary_written` closes the case of protocol v1 where it is never filled in.

        A failure to write is recorded in the diagnostic and nowhere else. There is no
        output record left to carry an `acl_warning`, and the loss costs no write - only
        the ability to tell a completed run from an interrupted one for this `sid`.
        """
        if self._summary_written or self._processor is None:
            return
        if self._journal_writer is None:
            return
        if not self._is_last_chunk():
            return
        self._summary_written = True
        if not self._journal_writer.write_summary(self._processor.build_summary()):
            self._diag.warning(
                "end-of-run journal line not written: this run will look interrupted "
                "to any view built on the absence of that line."
            )

    def _cleanup(self):
        """Close the journal and the diagnostic. Idempotent, and never raises.

        A fatal error must not leave an unwritten line in the buffer. And the cleanup
        must NEVER supplant the error being propagated: an exception raised inside a
        `finally` replaces the one that was travelling up, that is, the message the
        operator is waiting for. Each `close()` is therefore guarded, and the attribute
        detached before the call so that a second pass does not close it again.
        """
        writer, self._journal_writer = self._journal_writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception:                                        # noqa: BLE001
                pass
        diag, self._diag = self._diag, NullDiagnostics()
        try:
            diag.close()
        except Exception:                                            # noqa: BLE001
            pass

    def _fatal_exit(self, exc):
        """Interrupt the search **marking the job as failed** (section 4.3, A-4).

        The SDK's `error_exit()` writes the message then raises `SystemExit`, which the
        SDK turns into a `finish()` - a final chunk with `finished: true` - followed by
        exit code 1. That chunk tells splunkd the command ended normally, and splunkd
        then ignores the return code. Measured on Splunk 9.4.6: the job comes out with
        `dispatchState=DONE`, `isFailed=false`, `resultCount=0`. A scheduler or an alert
        built on that pipeline therefore cannot tell an interruption from an empty
        batch - the `MSG[ERROR]` is only visible to whoever inspects the job.

        The message is therefore emitted in a **non-final** chunk, then the process
        exits with a non-zero code without ever sending `finished: true`. splunkd then
        marks `dispatchState=FAILED` / `isFailed=true` **and keeps the message**; it
        adds its own, "External search command exited unexpectedly with non-zero error
        code 1", which is accurate.

        `os._exit` short-circuits the `finally` blocks: the cleanup is done by the
        caller **before** this call. The journal loses nothing for all that - each line
        is already `flush()`ed on write, and the `intent` line `fsync()`ed
        (section 8.4).
        """
        message = str(exc)
        try:
            self._error(message)
            record_writer = getattr(self, "_record_writer", None)
            write_chunk = getattr(record_writer, "write_chunk", None)
            if write_chunk is not None:
                # **Non-final** chunk: the message leaves, the end of stream is not
                # announced. `_write_chunk` empties the output buffer itself.
                write_chunk(finished=False)
            else:                                                    # pragma: no cover
                # Protocol v1: no chunk, the flush is enough to push the message
                # header.
                self.flush()
        except Exception:                                            # noqa: BLE001
            # No failure of the output must prevent the failure marking: that is the
            # only thing this method must guarantee.
            pass
        _abort_process(1)

    def _handle(self, record):
        # `record` is the raw record of the chunk: the presence of a key in it is
        # exactly the presence of the column in the result set (section 3.2). This is
        # the only place where the record is read, and it is passed as is to
        # `build_event` - no `get()` with a default comes and erases the distinction
        # between "column absent" and "cell empty" before the rule has settled it.
        event = build_event(record, self._params.names)
        result = self._processor.process(event)

        if (
            RUNTIME_DIVERGENCE_WARNING in result.warnings
            and not self._runtime_divergence_signaled
        ):
            self._runtime_divergence_signaled = True
            self._warn(RUNTIME_DIVERGENCE_MESSAGE)

        output = dict(record)
        output["acl_status"] = result.status
        output["acl_endpoint"] = result.endpoint
        # The type the command settled on, in the vocabulary of the input contract. It
        # is the exact analogue of `acl_endpoint`: the command publishes the address it
        # resolved, and it publishes the type it resolved, rather than leaving the
        # operator to compare an empty `eai:type` column in the simulation output with
        # a filled one in the journal and in the monitoring view. On a row that carried
        # a type, it repeats it; on a row that carried none, it is the only place the
        # operator sees one before the write.
        output["acl_type"] = result.eai_type
        output["acl_http_code"] = result.http_code
        output["acl_error"] = result.error or ""
        output["acl_warning"] = ";".join(result.warnings)
        output["acl_journaled"] = "true" if result.journaled else "false"
        if result.before is not None:
            output["acl_before_owner"] = result.before.owner
            output["acl_before_perms_read"] = serialize_roles(result.before.perms_read)
            output["acl_before_perms_write"] = serialize_roles(result.before.perms_write)
            output["acl_before_sharing"] = result.before.sharing
        if result.after is not None:
            output["acl_after_owner"] = result.after.owner
            output["acl_after_perms_read"] = serialize_roles(result.after.perms_read)
            output["acl_after_perms_write"] = serialize_roles(result.after.perms_write)
            output["acl_after_sharing"] = result.after.sharing
        return output


dispatch(EditAclCommand, sys.argv, sys.stdin, sys.stdout, __name__)
