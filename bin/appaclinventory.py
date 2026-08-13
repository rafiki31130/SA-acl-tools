#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`appaclinventory` search command - adapter, **no business rule here**.

Same three jobs as the other two adapters, and nothing else:

1. it inserts `bin/lib` then `bin` at the head of `sys.path`, before any other import;
2. it declares the command and its three parameters (v4.3 section 7.3) and wires the
   `acltools` core;
3. it turns fatal exceptions into an error output and yields the rows of section 7.4.

The command is **generating**: it takes no input and opens the pipeline. Under the
chunked protocol that character is carried by the SDK - `GeneratingCommand` declares
`generating` as a read-only configuration setting fixed to `True`, announced for both
protocol versions - and **not** by a key of `commands.conf` (HY-1). Nothing was added to
the normative key set of the repository, which is what the test that freezes that set
would have caught either way.

It writes nothing, anywhere: no POST, no journal, no diagnostic file. It reads REST, it
reads two `.meta` files per application inside the bounds of section 6.2, and it emits
rows.
"""

import os
import sys

# --------------------------------------------------------------------------- #
# sys.path - BEFORE any import of the project or of the SDK
# Identical to the other two adapters, and for the same reason: the vendored SDK takes
# precedence over the platform's, and `acltools` must be importable independently of the
# working directory of the search process, which the platform does not guarantee.
# The derivation from `__file__` is also the fallback route of the read root
# (v4.3 section 6.2, bound 4) - which is why this file passes its own `__file__` to the
# resolver rather than letting the resolver go looking for one.
# --------------------------------------------------------------------------- #
_BIN = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_BIN, "lib"), _BIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import configparser  # noqa: E402

from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)

from acltools.appacl_family import load_family_table  # noqa: E402
from acltools.appacl_inventory import (  # noqa: E402
    INVENTORY_OUTPUT_FIELDS,
    InventoryBuilder,
    resolve_member,
)
from acltools.appacl_preflight import (  # noqa: E402
    REQUIRED_INVENTORY_CAPABILITY,
    validate_inventory_params,
)
from acltools.appacl_provenance import ProvenanceReader, resolve_apps_root  # noqa: E402
from acltools.errors import FatalError, FatalFamilyTableError  # noqa: E402
from acltools.preflight import (  # noqa: E402
    AppStateCache,
    check_capability,
    check_realtime,
)
from acltools.rest import RestClient  # noqa: E402

_APP_ROOT = os.path.dirname(_BIN)
_FAMILY_JSON = os.path.join(_BIN, "app_acl_family_map.json")
_FAMILY_OVERRIDE_CSV = os.path.join(
    _APP_ROOT, "lookups", "app_acl_family_map_override.csv"
)

#: Prefix carried by **every** message this command addresses to the operator, applied
#: at a **single emission point** and never repeated on the literals (section 13.2).
#:
#: A search pipeline concatenates the messages of every command it chains and the
#: interface shows them stripped of their origin. This command is meant to open a
#: pipeline that ends in `editappacl`, so its messages sit next to that command's -
#: without the prefix, a reservation about a truncated inventory would be indistinguishable
#: from a warning about an irreversible write.
MESSAGE_PREFIX = "appaclinventory: "

#: Emitted once when the family table could not be loaded.
#:
#: **It is a warning here and a fatal error in `editappacl`**, and the asymmetry is the
#: contract's, not a leniency: section 13.1 scopes "family table unreadable" to
#: `editappacl` explicitly. The reason it holds up: the write command cannot resolve a
#: target without the table, whereas the inventory reads its decisive columns from the
#: file and only uses the table to fill `acl_handler`. Without it, every family comes out
#: `unmapped` - degraded, stated, and still useful.
TABLE_UNREADABLE_WARNING = (
    "family table unreadable: the inventory carries on, every family coming out with an "
    "empty acl_handler and acl_effective_status=no_handler. The reach columns are "
    "unaffected - they are read from the metadata files, not from the table."
)


def _read_app_setting(name, default):
    """Read `default/editacl.conf` then `local/editacl.conf`.

    **The same file as the other two commands, deliberately.** `verify_ssl` describes the
    platform's certificate, not a command: an operator who disabled verification once has
    no reason to do it three times, and three settings for one fact would drift.
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


def _abort_process(code=1):
    """Leave the process **without** unwinding the SDK protocol. See `editappacl.py`."""
    os._exit(code)                                                   # pragma: no cover


def _truthy(value, default=True):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y", "on")


# `type="reporting"` is the whole of what this decorator carries beyond `local`, and it is
# not a preference: it is the ONLY route. Measured (v4.5 section 7.2) - the command used to
# produce EVENTS (`eventCount=9`, empty `reportSearch`) where the native generating commands
# produce results, so Splunk Web opened it on the Events tab and showed a raw-event view of
# rows that have no raw event. On a `chunked` command the `type` key of `commands.conf` is
# measured WITHOUT EFFECT - tried with a service restart - because the metadata the SDK
# sends in the `getinfo` chunk prevails. A test that froze that key would freeze a placebo.
#
# `generating` says the command OPENS the pipeline; `type` says WHICH pipeline. The two
# settings are independent, and `type` is modifiable here where `StreamingCommand` pins it -
# which is why the two write commands are untouched.
@Configuration(local=True, type="reporting")
class AppAclInventoryCommand(GeneratingCommand):
    """Inventories the GENERIC ACL stanzas of the applications and their PROVENANCE.

    ##Syntax

    .. code-block::
        appaclinventory [apps=<string>] [families=<string>]

    ##Description

    One row per application default `[]`, plus one per family that carries a header or a
    frozen object. It answers one question: is this application still governable through
    its generic stanzas, or is it already frozen object by object?

    The provenance columns come from the metadata FILE, read only: an object that
    inherits and an object carrying its own stanza of the same value are indistinguishable
    through REST.

    It emits the input contract of `editappacl`, so a pipeline built on it needs no
    parameter at all.

    ##Example

    .. code-block::
        | appaclinventory apps=my_app
        | where acl_reach!="all"
    """

    apps = Option(
        doc="Comma-separated application filter, `*` patterns allowed. Default: *.",
        require=False,
        default=None,
    )
    families = Option(
        doc="Comma-separated families to emit even when they carry neither a stanza "
            "nor a frozen object. Default: none.",
        require=False,
        default=None,
    )
    def __init__(self):
        super(AppAclInventoryCommand, self).__init__()
        self._builder = None
        self._params = None

    # -- single emission point of the operator-facing messages -------------- #

    def _emit_message(self, level, message):
        """**The** point where a message reaches the search interface (v3.14 D-41).

        Every message the operator reads goes through here, and it is here - and nowhere
        else - that `MESSAGE_PREFIX` is applied. `tests/test_appacl_inventory_adapter.py`
        reads the syntax tree of this module and fails if `write_warning`, `write_error`,
        `write_info` or `write_fatal` is reached outside this method.
        """
        text = MESSAGE_PREFIX + ("" if message is None else str(message))
        if level == "error":
            self.write_error(text)
        elif level == "info":
            self.write_info(text)
        else:
            self.write_warning(text)

    def _warn(self, message):
        self._emit_message("warning", message)

    def _error(self, message):
        self._emit_message("error", message)

    # -- declaration of the output field set (section 7.4) ------------------ #

    def _declare_output_fields(self):
        """Declare the whole field set of section 7.4 to the writer, **in order**.

        The SDK writer builds the stream header from the keys of the **first** record
        emitted, then projects every later record onto it: a field absent from that record
        disappears from the entire output with no error and no warning.

        The **order** matters as much as the set, and a test freezes it. Measured before
        the v4.5 revision: the emitted order did not match the declared one, `acl_member`
        coming out ninth instead of last - so the seven columns that form the input
        contract of `editappacl` were not the seven an operator saw first.
        """
        writer = getattr(self, "_record_writer", None)
        declared = getattr(writer, "custom_fields", None)
        if declared is None:                                         # pragma: no cover
            return
        try:
            declared.update(INVENTORY_OUTPUT_FIELDS)
        except AttributeError:                                       # pragma: no cover
            pass

    def prepare(self):
        super(AppAclInventoryCommand, self).prepare()
        self._declare_output_fields()

    # -- wiring ------------------------------------------------------------- #

    def _setup(self):
        self._declare_output_fields()
        info = self._metadata.searchinfo
        sid = str(getattr(info, "sid", "") or "")

        self._params = validate_inventory_params(
            apps=self.apps,
            families=self.families,
        )

        session_key = getattr(info, "session_key", None)
        splunkd_uri = getattr(info, "splunkd_uri", None)
        if not session_key or not splunkd_uri:
            from acltools.errors import FatalConfigError

            raise FatalConfigError(
                "splunkd_uri or session_key unavailable: the command cannot address the "
                "platform."
            )

        verify_ssl = _truthy(_read_app_setting("verify_ssl", "true"), default=True)
        splunk_home = os.environ.get("SPLUNK_HOME")
        ca_file = None
        if verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not verify_ssl:
            self._warn(
                "verify_ssl=false: verification of the splunkd certificate is disabled "
                "by local/editacl.conf."
            )

        rest = RestClient(
            splunkd_uri, session_key, verify_ssl=verify_ssl, ca_file=ca_file
        )

        # Section 7.6: the capability is checked in the code, at the head of the run,
        # because Splunk gates no search command by capability. It is the counterpart of
        # the file-reading exception - the file short-circuits the filtering REST applies.
        check_capability(rest, REQUIRED_INVENTORY_CAPABILITY)

        verdict = check_realtime(rest, sid)
        if verdict == "unknown":
            self._warn(
                "real-time mode could not be determined for this sid: the safeguard "
                "could not be applied."
            )

        try:
            table = load_family_table(_FAMILY_JSON, _FAMILY_OVERRIDE_CSV)
        except FatalFamilyTableError:
            table = None
            self._warn(TABLE_UNREADABLE_WARNING)

        # **The read root of section 6.2, bound 4.** Two independent routes, compared. A
        # divergence, or the absence of both, is fatal: an ambiguous root would make the
        # command read a tree other than the one splunkd serves, with no symptom at all.
        provenance = ProvenanceReader(resolve_apps_root(os.environ, __file__))

        self._builder = InventoryBuilder(
            rest=rest,
            provenance_reader=provenance,
            table=table,
            member=resolve_member(rest),
            # Consulted only when a platform read has already failed, so that a row can say
            # `app_disabled` rather than the undifferentiated `unreadable`. Memoized per
            # application, and never called on the nominal path.
            app_disabled_fn=AppStateCache(rest).is_app_disabled,
        )

    # -- generation --------------------------------------------------------- #

    def generate(self):
        try:
            self._setup()
            for row in self._builder.rows(self._params):
                yield row
        except FatalError as exc:
            # Single recording point of the fatal errors of section 13.1: the missing
            # capability, an invalid parameter, a real-time search, unavailable platform
            # credentials, and the ambiguous or unresolved read root. The unreadable
            # family table is NOT one of them for this command - section 13.1 scopes that
            # error to `editappacl`.
            self._fatal_exit(exc)

    def _fatal_exit(self, exc):
        """Interrupt the search **marking the job as failed**.

        The SDK's `error_exit()` writes the message then raises `SystemExit`, which the
        SDK turns into a final chunk carrying `finished: true` followed by exit code 1.
        That chunk tells splunkd the command ended normally, and splunkd then ignores the
        return code: the job comes out `dispatchState=DONE`, `isFailed=false`, and a
        scheduler built on that pipeline could not tell an interruption from an empty
        inventory - which for this command would read as *no application at all*.

        The message is therefore emitted in a **non-final** chunk, then the process exits
        with a non-zero code without ever sending `finished: true`.
        """
        try:
            self._error(str(exc))
            record_writer = getattr(self, "_record_writer", None)
            write_chunk = getattr(record_writer, "write_chunk", None)
            if write_chunk is not None:
                write_chunk(finished=False)
            else:                                                    # pragma: no cover
                self.flush()
        except Exception:                                            # noqa: BLE001
            # No failure of the output must prevent the failure marking: that is the only
            # thing this method has to guarantee.
            pass
        _abort_process(1)


dispatch(AppAclInventoryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
