"""Run diagnostic log - `editacl.log` (section 8.1).

**This file is not the rollback journal.** The write-ahead journal
(`editacl_journal_<sid>.log`) is the only safety net of an irreversible operation:
losing it is not acceptable, and that is why D-3 forbids rotation for it and imposes
one file per run. The present file carries no restorable state; **losing it is not
critical**. It therefore stays single and rotating as section 8.1 requires, and - as a
direct consequence - **none of its failures is fatal, none cancels or delays a write**.
A diagnostic that interrupts the operation it observes would be a second failure added
to the first.

Contents, as enumerated by section 8.1: startup, capability check, parameters, mapping
table resolution, fatal errors.

**No secret enters it.** The guarantee is first of all **structural**: this module
never receives the session key - neither `Diagnostics` nor any of its methods has a
parameter that carries it, and `rest.py` does not talk to it. The redaction below is a
second line: platform error messages are copied into the file, and a diagnostic file
collected into an index is read by far more people than the disk of a search head.
"""

import logging
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler

#: File name, single and rotating (section 8.1). The monitor stanza of section 8.3
#: names it.
DIAG_BASENAME = "editacl.log"

#: Rotation imposed by section 8.1: 5 MB, 5 backups.
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5

LOGGER_NAME = "editacl.diag"

#: Diagnostic file of the application-level command (v4.1 section 11.1, **DV-3**). A
#: file of its own, for the same three reasons the journal has one: a shared `sid` would
#: make the two commands write the same path, the unit of account differs - a stanza is
#: not an object - and the format is not versioned, so adding keys to an existing
#: sourcetype aggravates a limit already paid for.
APP_DIAG_BASENAME = "editappacl.log"

APP_LOGGER_NAME = "editappacl.diag"

REDACTED = "[redacted]"

#: Redaction patterns. Deliberately broad: a false positive makes one diagnostic line
#: less readable, a false negative publishes a secret into an index.
_SECRET_PATTERNS = (
    # Splunk authentication header, in all its forms.
    re.compile(r"(?i)\bSplunk\s+[A-Za-z0-9+/=._-]{20,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9+/=._-]{10,}"),
    # `key: value` or `key=value` for any key that names a secret.
    re.compile(
        r"(?i)\b(session[_-]?key|authorization|api[_-]?key|access[_-]?token|token"
        r"|password|passwd|pwd|secret|credential)\b\s*[:=]\s*\S+"
    ),
)


def redact(message):
    """Remove from a message every recognizable form of secret.

    Truncation is ruled out: a truncated secret is still a partially disclosed secret,
    and it is often enough to shrink a search space.
    """
    text = "" if message is None else str(message)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    # A diagnostic line is one line: a multiline message would break the
    # `LINE_BREAKER` of the `editacl:diag` sourcetype (section 8.3).
    return text.replace("\r", " ").replace("\n", " ")


def diag_path(log_dir):
    return os.path.join(log_dir or "", DIAG_BASENAME)


def app_diag_path(log_dir):
    return os.path.join(log_dir or "", APP_DIAG_BASENAME)


class _Formatter(logging.Formatter):
    """ISO 8601 timestamp with zone and milliseconds, aligned on the journal (8.2)."""

    def formatTime(self, record, datefmt=None):                      # noqa: N802
        return (
            datetime.fromtimestamp(record.created)
            .astimezone()
            .isoformat(timespec="milliseconds")
        )


class NullDiagnostics(object):
    """Inert diagnostic: same surface, no effect.

    This is the default value of the wrapper. It guarantees that no diagnostic call can
    raise before the file is opened, nor after it failed to open - losing the
    diagnostic must never cost a run.
    """

    path = None
    enabled = False

    def __call__(self, level, message):
        pass

    def info(self, message):
        pass

    def warning(self, message):
        pass

    def fatal(self, message):
        pass

    def startup(self, **kwargs):
        pass

    def params(self, params):
        pass

    def capability(self, granted, detail=""):
        pass

    def realtime(self, verdict):
        pass

    def mapping(self, coverage):
        pass

    def journal(self, path, opened):
        pass

    def family_table(self, coverage):
        pass

    def provenance_root(self, root):
        pass

    def close(self):
        pass


class Diagnostics(NullDiagnostics):
    """Writer of the diagnostic file.

    A `logging.Logger` is **built directly**, never obtained from
    `logging.getLogger`: the global registry is shared by the whole search process, and
    attaching a handler to it would expose us to receiving the records of other
    libraries - whose content, and whose freedom from secrets, we do not control.
    """

    enabled = True

    #: Name of the command, written into the startup line and used as the logger name.
    #: It is a class attribute so that the application-level subclass changes it without
    #: touching a single line of what the previous command writes - the `editacl:diag`
    #: sourcetype extracts on those exact anchors.
    COMMAND = "editacl"
    LOGGER = LOGGER_NAME

    _LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "FATAL": logging.CRITICAL,
        "CRITICAL": logging.CRITICAL,
    }

    def __init__(self, path, sid="", handler=None):
        self.path = path
        self._sid = str(sid or "")
        self._logger = logging.Logger(self.LOGGER, logging.INFO)
        self._logger.propagate = False
        self._handler = handler or RotatingFileHandler(
            path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        self._handler.setFormatter(
            _Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        self._logger.addHandler(self._handler)

    # -- primitives --------------------------------------------------------- #

    def __call__(self, level, message):
        """Signature of the `diag` callback `load_mapping` expects: `(level, message)`."""
        self._emit(self._LEVELS.get(str(level).upper(), logging.INFO), message)

    def _emit(self, level, message):
        try:
            self._logger.log(
                level, "sid=%s %s", self._sid or "-", redact(message)
            )
        except Exception:                                            # noqa: BLE001
            # A diagnostic cannot make what it observes fail (section 8.1).
            pass

    def info(self, message):
        self._emit(logging.INFO, message)

    def warning(self, message):
        self._emit(logging.WARNING, message)

    def fatal(self, message):
        self._emit(logging.CRITICAL, "fatal error: %s" % message)

    # -- events enumerated by section 8.1 ----------------------------------- #

    def startup(self, version="", user="", splunkd_uri="", verify_ssl=None):
        """Startup line. The member is logged separately: `serverName` is only known
        after a REST call, and this line must precede everything that can fail."""
        self.info(
            "%s startup version=%s user=%s splunkd=%s verify_ssl=%s"
            % (
                self.COMMAND,
                version or "?",
                user or "-",
                splunkd_uri or "-",
                "?" if verify_ssl is None else str(bool(verify_ssl)).lower(),
            )
        )

    def params(self, params):
        self.info(
            "parameters dryrun=%s validate_roles=%s journal=%s max_objects=%s"
            % (
                str(bool(params.dryrun)).lower(),
                str(bool(params.validate_roles)).lower(),
                str(bool(params.journal)).lower(),
                params.max_objects,
            )
        )
        # The nine field-naming parameters are recorded separately: they determine
        # which column of the result set is read for what, hence which attributes will
        # be modified and which preserved (section 3.2). Without them, a run in which a
        # field name was redirected is unreadable after the fact.
        names = params.names
        self.info(
            "field names title=%s app=%s id=%s type=%s sharing=%s new_perms_read=%s "
            "new_perms_write=%s new_sharing=%s new_owner=%s"
            % (
                names.title,
                names.app,
                names.id,
                names.type,
                names.sharing,
                names.new_perms_read,
                names.new_perms_write,
                names.new_sharing,
                names.new_owner,
            )
        )
        for warning in params.warnings or ():
            self.warning("parameters: %s" % warning)

    def capability(self, granted, detail=""):
        if granted:
            self.info("capability check: capability granted")
        else:
            self.warning("capability check: denied (%s)" % (detail or "?"))

    def realtime(self, verdict):
        self.info("real-time check: %s" % verdict)

    def mapping(self, coverage):
        self.info(
            "mapping table: %d entries (%d shipped, %d from override, "
            "%d overridden, %d discarded)"
            % (
                coverage.get("total", 0),
                coverage.get("from_json", 0),
                coverage.get("from_override", 0),
                len(coverage.get("overridden") or ()),
                len(coverage.get("rejected") or ()),
            )
        )

    def journal(self, path, opened):
        if opened:
            self.info("rollback journal opened: %s" % path)
        else:
            self.warning("rollback journal not openable: %s" % path)

    def close(self):
        try:
            self._logger.removeHandler(self._handler)
            self._handler.close()
        except Exception:                                            # noqa: BLE001
            pass


class AppDiagnostics(Diagnostics):
    """Writer of `editappacl.log` (v4.1 section 11.1).

    Same machinery, same redaction, same tolerance to its own failures. What differs is
    what there is to say: the parameters are not the same, the table is not the same, and
    the read root of section 6.2 is a fact worth recording - it decides **which tree**
    the command reads the provenance from, and an ambiguity there is fatal.
    """

    COMMAND = "editappacl"
    LOGGER = APP_LOGGER_NAME

    def params(self, params):
        self.info(
            "parameters dryrun=%s allow_create=%s validate_roles=%s journal=%s "
            "max_stanzas=%s max_impacted_objects=%s"
            % (
                str(bool(params.dryrun)).lower(),
                str(bool(params.allow_create)).lower(),
                str(bool(params.validate_roles)).lower(),
                str(bool(params.journal)).lower(),
                params.max_stanzas,
                params.max_impacted_objects,
            )
        )
        # The seven field-naming parameters are recorded separately, for the reason the
        # previous command already had: they determine which column is read for what,
        # hence which attributes are modified and which preserved. Without them, a run in
        # which a field name was redirected is unreadable after the fact.
        names = params.names
        self.info(
            "field names app=%s stanza_kind=%s handler=%s stanza=%s new_perms_read=%s "
            "new_perms_write=%s new_sharing=%s"
            % (
                names.app,
                names.stanza_kind,
                names.handler,
                names.stanza,
                names.new_perms_read,
                names.new_perms_write,
                names.new_sharing,
            )
        )
        for warning in params.warnings or ():
            self.warning("parameters: %s" % warning)

    def family_table(self, coverage):
        self.info(
            "family table: %d entries (%d shipped, %d from override, %d overridden, "
            "%d discarded)"
            % (
                coverage.get("total", 0),
                coverage.get("from_json", 0),
                coverage.get("from_override", 0),
                len(coverage.get("overridden") or ()),
                len(coverage.get("rejected") or ()),
            )
        )

    def provenance_root(self, root):
        self.info("provenance read root: %s" % (root or "-"))


def open_diagnostics(log_dir, sid=""):
    """Open the diagnostic file, or return an inert diagnostic.

    **Never raises.** The absence of a diagnostic degrades observability; it calls into
    question neither the safety of the operation nor its reversibility: both of those
    properties rest entirely on the rollback journal, which is another file with other
    guarantees.
    """
    if not log_dir:
        return NullDiagnostics()
    try:
        return Diagnostics(diag_path(log_dir), sid=sid)
    except Exception:                                                # noqa: BLE001
        return NullDiagnostics()


def open_app_diagnostics(log_dir, sid=""):
    """Open `editappacl.log`, or return an inert diagnostic. **Never raises.**"""
    if not log_dir:
        return NullDiagnostics()
    try:
        return AppDiagnostics(app_diag_path(log_dir), sid=sid)
    except Exception:                                                # noqa: BLE001
        return NullDiagnostics()
