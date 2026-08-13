#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`editappacl` search command - adapter, **no business rule here**.

This file does three things and nothing else:

1. it inserts `bin/lib` then `bin` at the head of `sys.path`, before any other import;
2. it declares the command and its parameters (v4.3 section 8.5) and wires the
   `acltools` core;
3. it turns fatal exceptions into an error output and projects the `acl_*` fields of
   section 8.8 into the output record.

All the logic - target resolution, provenance, merge, impact, journal, state machine -
lives in `acltools`, which depends neither on the SDK nor on the network and is tested
outside Splunk.
"""

import os
import sys

# --------------------------------------------------------------------------- #
# sys.path - BEFORE any import of the project or of the SDK
# `bin/lib` first: the vendored version takes precedence over the platform's.
# `bin` as well, so that `acltools` is importable independently of the working
# directory of the search process, which the platform does not guarantee.
# The path is derived from `__file__`, never from an environment variable nor from an
# absolute path - and that same derivation is the fallback route of the read root
# (v4.3 section 6.2, bound 4).
# --------------------------------------------------------------------------- #
_BIN = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_BIN, "lib"), _BIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import configparser  # noqa: E402

from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    Option,
    StreamingCommand,
    dispatch,
    validators,
)

from acltools.appacl_family import load_family_table  # noqa: E402
from acltools.appacl_impact import ImpactEstimator  # noqa: E402
from acltools.appacl_model import (  # noqa: E402
    APP_ACL_OUTPUT_FIELDS,
    AppRunContext,
)
from acltools.appacl_pipeline import (  # noqa: E402
    RUNTIME_DIVERGENCE_MESSAGE,
    RUNTIME_DIVERGENCE_WARNING,
    AppEventProcessor,
    ceiling_message,
    creation_message,
    impact_ceiling_message,
    simulation_summary_message,
)
from acltools.appacl_preflight import (  # noqa: E402
    DEFAULT_MAX_IMPACTED_OBJECTS,
    DEFAULT_MAX_STANZAS,
    REQUIRED_APP_CAPABILITY,
    validate_app_params,
)
from acltools.appacl_provenance import ProvenanceReader, resolve_apps_root  # noqa: E402
from acltools.binding import build_app_event  # noqa: E402
from acltools.diag import NullDiagnostics, open_app_diagnostics  # noqa: E402
from acltools.errors import FatalError  # noqa: E402
from acltools.journal import JournalWriter, app_journal_path  # noqa: E402
from acltools.normalize import serialize_roles  # noqa: E402
from acltools.preflight import (  # noqa: E402
    AppStateCache,
    check_capability,
    check_realtime,
    load_roles_catalog,
)
from acltools.rest import RestClient  # noqa: E402

_APP_ROOT = os.path.dirname(_BIN)
_FAMILY_JSON = os.path.join(_BIN, "app_acl_family_map.json")
_FAMILY_OVERRIDE_CSV = os.path.join(
    _APP_ROOT, "lookups", "app_acl_family_map_override.csv"
)

#: Name of the application carrying the tool, for the `self_app_target` warning of
#: section 13.4 point 5. It is read from the directory name rather than from
#: `searchinfo.app`: that field names the **dispatching** app, not the carrying one
#: (HY-6), and it would be `search` as soon as the search is launched from anywhere else.
_SELF_APP = os.path.basename(_APP_ROOT)

#: Prefix carried by **every** message addressed to the operator through the search
#: interface: the name of the command, a colon, one space.
#:
#: A search pipeline concatenates the messages of every command it chains, and the
#: interface displays them stripped of their origin. Without the prefix, a warning of
#: this command is indistinguishable from a warning of the macro that feeds it, of
#: `editacl` in the same pipeline, or of the platform itself - which is precisely the
#: situation where an operator dismisses a message that concerns an irreversible write.
#:
#: The prefix is applied at a **single emission point**, `_emit_message`, and never
#: repeated on the literals: the day the form changes, it changes in one place.
#:
#: It does **not** apply to `editappacl.log` nor to the write-ahead journal: their origin
#: is already established by their dedicated sourcetypes, `editappacl:diag` and
#: `editappacl:journal` (section 11.1).
MESSAGE_PREFIX = "editappacl: "


def _read_app_setting(name, default):
    """Read `default/editacl.conf` then `local/editacl.conf`.

    **The same file as the previous command, deliberately.** `verify_ssl` describes the
    platform's certificate, not a command: an operator who disabled verification for one
    command has no reason to do it twice, and two settings for one fact would drift.
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
    """Version declared by `default/app.conf`, for the startup line."""
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
# `streaming` and the SDK refuses any redeclaration. `local = true` is carried by
# `commands.conf`.
@Configuration(local=True)
class EditAppAclCommand(StreamingCommand):
    """Rewrites the GENERIC ACL stanzas of the applications the pipeline describes.

    ##Syntax

    .. code-block::
        editappacl [app=<field>] [stanza_kind=<field>] [handler=<field>]
                   [stanza=<field>] [new_perms_read=<field>] [new_perms_write=<field>]
                   [new_sharing=<field>] [dryrun=<bool>] [allow_create=<bool>]
                   [validate_roles=<bool>] [journal=<bool>] [max_stanzas=<int>]
                   [max_impacted_objects=<int>]

    ##Description

    One input row designates one generic stanza: the application default `[]` or a family
    header such as `[views]`. Writing one moves the effective rights of objects the
    pipeline does NOT enumerate, which is what the command is for and what makes its two
    ceilings count different things - acts, and estimated blast radius.

    CREATING a generic stanza is IRREVERSIBLE: no measured REST path removes one. The
    command refuses to create by default; `allow_create=true` is the deliberate act.

    Governance order: generic first, specific by exception. Every object `editacl` writes
    is an object permanently removed from generic governance.

    ##Example

    .. code-block::
        | appaclinventory apps=my_app | where acl_stanza_kind="family_default"
        | eval "eai:acl.perms.read" = "power"
        | editappacl dryrun=f max_stanzas=3
    """

    # -- field-naming parameters (section 8.3): designate the target ---------- #
    app = Option(
        doc="Field carrying the target application. Default: eai:acl.app.",
        require=False,
        default=None,
    )
    stanza_kind = Option(
        doc="Field carrying app_default or family_default. REQUIRED value, never "
            "deduced. Default: acl_stanza_kind.",
        require=False,
        default=None,
    )
    handler = Option(
        doc="Field carrying the handler path, primary resolution route for a family. "
            "Default: acl_handler.",
        require=False,
        default=None,
    )
    stanza = Option(
        doc="Field carrying the family name, secondary resolution route through the "
            "shipped table. Default: acl_stanza.",
        require=False,
        default=None,
    )

    # -- field-naming parameters (section 8.4): target values ---------------- #
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
        doc="Field carrying the target value of sharing, app or global only. "
            "Default: eai:acl.sharing.",
        require=False,
        default=None,
    )

    dryrun = Option(
        doc="Simulation: no write at all. Default: true.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    allow_create = Option(
        doc="Authorize the IRREVERSIBLE creation of a missing stanza. Default: false.",
        require=False,
        default=False,
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
    max_stanzas = Option(
        doc="Maximum number of stanzas WRITTEN per run. Default: 5, a choice and not a "
            "measurement. No effect in simulation, which sends no POST.",
        require=False,
        default=None,
    )
    max_impacted_objects = Option(
        doc="Maximum sum of the ESTIMATED impacts of the stanzas written per run. "
            "Default: 200, a choice and not a measurement. No effect in simulation.",
        require=False,
        default=None,
    )

    def __init__(self):
        super(EditAppAclCommand, self).__init__()
        self._processor = None
        # `_journal_writer`, and above all NOT `_journal`: the SDK stores the value of an
        # `Option` in the attribute `"_" + <option name>`, so the `journal` option
        # already occupies `_journal`. The previous command paid for that collision
        # twice - the boolean got closed like a file, and the option became unreadable.
        self._journal_writer = None
        self._params = None
        self._ready = False
        self._diag = NullDiagnostics()
        self._runtime_divergence_signaled = False
        # The three end-of-run messages are emitted **once**, on the last chunk: the
        # command receives its input through successive chunks, and the numbers they
        # carry are only complete on the last one.
        self._ceiling_signaled = False
        self._impact_ceiling_signaled = False
        self._end_of_run_signaled = False
        self._summary_written = False

    # -- single emission point of the operator-facing messages -------------- #

    def _emit_message(self, level, message):
        """**The** point where a message reaches the search interface (v3.14 D-41).

        Every message the operator reads goes through here, and it is here - and nowhere
        else - that `MESSAGE_PREFIX` is applied. No other method of this file calls
        `write_warning`, `write_error`, `write_info` or `write_fatal`;
        `tests/test_appacl_message_prefix.py` reads the syntax tree of this module and
        fails if one of them is reached outside this method, or through a construct it
        cannot analyse.

        The concentration is what makes the rule verifiable. Repeating the prefix on each
        literal would make it a convention, that is, something that holds until the next
        contributor.
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

    # -- declaration of the output field set (section 8.8) ------------------ #

    def _declare_output_fields(self):
        """Declare to the writer the whole field set of section 8.8.

        The SDK writer builds the stream header from the **keys of the first record
        emitted**, then projects every later record onto it: a field absent from that
        first record disappears from the entire output, **with no error and no warning**.
        Several statuses of this command carry no state field at all - a rejection
        upstream of the GET, a `skipped_ceiling` - and a batch starting with one of those
        would deprive the operator of everything the simulation exists to show.

        No failure of this declaration must interrupt the command: it improves the
        output, it conditions no write.
        """
        writer = getattr(self, "_record_writer", None)
        declared = getattr(writer, "custom_fields", None)
        if declared is None:                                         # pragma: no cover
            return
        try:
            declared.update(APP_ACL_OUTPUT_FIELDS)
        except AttributeError:                                       # pragma: no cover
            pass

    def prepare(self):
        super(EditAppAclCommand, self).prepare()
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

        self._diag = open_app_diagnostics(log_dir, sid)
        verify_ssl = _truthy(_read_app_setting("verify_ssl", "true"), default=True)
        self._diag.startup(
            version=_app_version(),
            user=str(getattr(info, "username", "") or ""),
            splunkd_uri=str(getattr(info, "splunkd_uri", "") or ""),
            verify_ssl=verify_ssl,
        )

        params = validate_app_params(
            names_raw={
                "app": self.app,
                "stanza_kind": self.stanza_kind,
                "handler": self.handler,
                "stanza": self.stanza,
                "new_perms_read": self.new_perms_read,
                "new_perms_write": self.new_perms_write,
                "new_sharing": self.new_sharing,
            },
            dryrun=self.dryrun,
            allow_create=self.allow_create,
            validate_roles=self.validate_roles,
            journal=self.journal,
            max_stanzas=(
                DEFAULT_MAX_STANZAS if self.max_stanzas is None else self.max_stanzas
            ),
            max_impacted_objects=(
                DEFAULT_MAX_IMPACTED_OBJECTS
                if self.max_impacted_objects is None
                else self.max_impacted_objects
            ),
            max_stanzas_explicit=self.max_stanzas is not None,
        )
        self._params = params
        self._diag.params(params)
        for warning in params.warnings:
            self._warn(warning)

        # The session key never leaves this scope towards the diagnostic: no method of
        # the diagnostic has a parameter that carries it.
        session_key = getattr(info, "session_key", None)
        splunkd_uri = getattr(info, "splunkd_uri", None)
        if not session_key or not splunkd_uri:
            from acltools.errors import FatalConfigError

            raise FatalConfigError(
                "splunkd_uri or session_key unavailable: the command cannot address the "
                "platform."
            )

        ca_file = None
        if verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not verify_ssl:
            self._diag.warning(
                "verify_ssl=false: verification of the splunkd certificate is disabled "
                "by local/editacl.conf."
            )
            self._warn(
                "verify_ssl=false: verification of the splunkd certificate is disabled "
                "by local/editacl.conf."
            )

        rest = RestClient(
            splunkd_uri, session_key, verify_ssl=verify_ssl, ca_file=ca_file
        )

        check_capability(rest, REQUIRED_APP_CAPABILITY)
        self._diag.capability(True)

        verdict = check_realtime(rest, sid)
        self._diag.realtime(verdict)
        if verdict == "unknown":
            self._warn(
                "real-time mode could not be determined for this sid: the safeguard "
                "could not be applied."
            )

        roles_catalog = (
            load_roles_catalog(rest) if params.validate_roles else frozenset()
        )
        table = load_family_table(
            _FAMILY_JSON, _FAMILY_OVERRIDE_CSV, diag=self._diag
        )
        self._diag.family_table(table.coverage())

        # **The read root of section 6.2, bound 4.** Two independent routes, compared:
        # the environment variable, and the derivation from this module's own path. A
        # divergence, or the absence of both, is fatal - an ambiguous root would make the
        # command read a tree other than the one splunkd serves, with no symptom.
        apps_root = resolve_apps_root(os.environ, __file__)
        self._diag.provenance_root(apps_root)
        provenance = ProvenanceReader(apps_root)

        ctx = AppRunContext(
            sid=sid,
            user=str(getattr(info, "username", "") or ""),
            dryrun=params.dryrun,
        )

        if params.journal:
            path = app_journal_path(log_dir, sid)
            try:
                self._journal_writer = JournalWriter(path)
                self._diag.journal(path, True)
            except FatalError:
                # Failing to open is only fatal if a real write is planned
                # (section 13.1). In simulation it degrades to a warning.
                self._diag.journal(path, False)
                if not params.dryrun:
                    raise
                self._journal_writer = None
                self._warn(
                    "journal not openable (%s): the run carries on in simulation "
                    "without a journal." % path
                )

        self._processor = AppEventProcessor(
            params=params,
            ctx=ctx,
            rest=rest,
            journal=self._journal_writer,
            table=table,
            provenance=provenance,
            impact=ImpactEstimator(rest, provenance, table),
            roles_catalog=roles_catalog,
            app_disabled_fn=AppStateCache(rest).is_app_disabled,
            self_app=_SELF_APP,
        )
        self._ready = True

    # -- processing loop ---------------------------------------------------- #

    def stream(self, records):
        try:
            for record in records:
                if not self._ready:
                    self._setup()
                yield self._handle(record)
            self._signal_end_of_run()
            self._write_summary()
        except FatalError as exc:
            # Single recording point of the fatal errors of section 13.1. `_setup()` is
            # called from within this `try`, so its errors pass through here - the
            # missing capability, the unreadable family table and the ambiguous read root
            # among them.
            #
            # The cleanup here is **unconditional**, and it is the only one that is:
            # `_fatal_exit()` leaves through `os._exit`, which runs no `finally`.
            self._diag.fatal(str(exc))
            self._cleanup()
            self._fatal_exit(exc)
        finally:
            # **Only at the end of the run, never at the end of a chunk.** The SDK calls
            # `stream()` once per chunk and drains the generator each time, so an
            # unconditional cleanup here would close the journal at the end of the
            # *first* chunk - and from the second on, every target would come out
            # `error` / `journal_intent_failed` and would NOT be written, since the
            # write-ahead line cancels the POST when it cannot be persisted.
            if self._is_last_chunk():
                self._cleanup()

    def _is_last_chunk(self):
        """Is the chunk being processed the last one of the run?

        `self._finished` is filled in by the SDK from the metadata of each chunk of
        protocol v2, **before** `stream()` is called. It is `False` while more chunks are
        announced, `True` on the last one - and it stays at its initial `None` under
        protocol v1, which has no chunk at all.

        Hence the test on `is not False` rather than on `is True`: under v1 the run is
        always its own last chunk, so reading the flag positively would defer the
        end-of-run messages to a chunk that never comes.
        """
        return getattr(self, "_finished", None) is not False

    def _signal_end_of_run(self):
        """The three single end-of-run messages (sections 9.4, 10.2, 10.4).

        They are emitted after the last record, because that is the only moment at which
        their numbers are complete for a command receiving its input in successive
        chunks. `_ceiling_signaled` and its siblings close the case of protocol v1, where
        `_finished` is never filled in.
        """
        processor = self._processor
        if processor is None or not self._is_last_chunk():
            return

        if processor.skipped_ceiling > 0 and not self._ceiling_signaled:
            self._ceiling_signaled = True
            message = ceiling_message(
                self._params.max_stanzas, processor.skipped_ceiling
            )
            self._diag.warning(message)
            self._warn(message)

        if processor.skipped_impact_ceiling > 0 and not self._impact_ceiling_signaled:
            self._impact_ceiling_signaled = True
            message = impact_ceiling_message(
                self._params.max_impacted_objects, processor.skipped_impact_ceiling
            )
            self._diag.warning(message)
            self._warn(message)

        if self._end_of_run_signaled:
            return
        self._end_of_run_signaled = True

        if self._params.dryrun:
            # The three numbers the operator sees BEFORE writing: what would be written,
            # the aggregate blast radius, and the volume of irreversible acts
            # (section 10.4, point 5).
            message = simulation_summary_message(
                processor.planned_writes,
                processor.planned_impact,
                processor.planned_creations,
            )
            self._diag.info(message)
            self._warn(message)
            return

        created = processor.counts.get("created", 0)
        if created > 0:
            # Section 9.4, dispositif 3: the only one of the four that reaches the
            # operator at the moment they are looking.
            message = creation_message(created)
            self._diag.warning(message)
            self._warn(message)

    def _write_summary(self):
        """Single `phase=summary` journal line, after the last record (section 11.2).

        **Its position in the control flow is the whole point.** It sits inside the `try`
        of `stream()`, after the loop over the records - therefore on the branch a
        `FatalError` skips. That branch ends the process through `os._exit`, so no line
        can be appended afterwards: a run interrupted by a fatal error leaves a journal
        **with no summary line**, and it is that absence which distinguishes it from a run
        that reached its end.
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
                "end-of-run journal line not written: this run will look interrupted to "
                "any view built on the absence of that line."
            )

    def _cleanup(self):
        """Close the journal and the diagnostic. Idempotent, and never raises.

        The cleanup must NEVER supplant the error being propagated: an exception raised
        inside a `finally` replaces the one that was travelling up, that is, the message
        the operator is waiting for.
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
        """Interrupt the search **marking the job as failed**.

        The SDK's `error_exit()` writes the message then raises `SystemExit`, which the
        SDK turns into a final chunk with `finished: true` followed by exit code 1. That
        chunk tells splunkd the command ended normally, and splunkd then ignores the
        return code: measured on 9.4.6, the job comes out `dispatchState=DONE`,
        `isFailed=false`. A scheduler built on that pipeline could not tell an
        interruption from an empty batch.

        The message is therefore emitted in a **non-final** chunk, then the process exits
        with a non-zero code without ever sending `finished: true`.

        `os._exit` short-circuits the `finally` blocks: the cleanup is done by the caller
        **before** this call. The journal loses nothing for all that - each line is
        already flushed on write, and the `intent` line fsynced.
        """
        message = str(exc)
        try:
            self._error(message)
            record_writer = getattr(self, "_record_writer", None)
            write_chunk = getattr(record_writer, "write_chunk", None)
            if write_chunk is not None:
                write_chunk(finished=False)
            else:                                                    # pragma: no cover
                self.flush()
        except Exception:                                            # noqa: BLE001
            # No failure of the output must prevent the failure marking: that is the only
            # thing this method must guarantee.
            pass
        _abort_process(1)

    def _handle(self, record):
        # `record` is the raw record of the chunk: the presence of a key in it is exactly
        # the presence of the column in the result set (section 8.4). This is the only
        # place where the record is read, and it is passed as is to `build_app_event` -
        # no `get()` with a default comes and erases the distinction between "column
        # absent" and "cell empty" before the rule has settled it.
        event = build_app_event(record, self._params.names)
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
        output["acl_stanza_kind"] = result.stanza_kind
        output["acl_stanza"] = result.stanza
        output["acl_handler"] = result.handler
        output["acl_reversible"] = result.reversible
        output["acl_impacted_estimate"] = (
            "" if result.impacted_estimate is None else result.impacted_estimate
        )
        output["acl_http_code"] = result.http_code
        output["acl_error"] = result.error or ""
        output["acl_warning"] = ";".join(result.warnings)
        output["acl_journaled"] = "true" if result.journaled else "false"
        if result.before is not None:
            # The **effective** state read, inherited value included (section 8.8). The
            # journal is the place where an inherited value is kept apart from a
            # restorable one; the output publishes what the operator has to see.
            output["acl_before_perms_read"] = serialize_roles(result.before.perms_read)
            output["acl_before_perms_write"] = serialize_roles(result.before.perms_write)
            output["acl_before_sharing"] = result.before.sharing
        if result.after is not None:
            output["acl_after_perms_read"] = serialize_roles(result.after.perms_read)
            output["acl_after_perms_write"] = serialize_roles(result.after.perms_write)
            output["acl_after_sharing"] = result.after.sharing
        return output


dispatch(EditAppAclCommand, sys.argv, sys.stdin, sys.stdout, __name__)
