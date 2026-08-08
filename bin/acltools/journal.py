"""Write-ahead journal (section 8).

The journal serves **two distinct needs** that a single line cannot satisfy: the
persistence of the prior state **before** the mutation (the rollback set) and the
trace of the outcome **after** the mutation (execution control). A `phase` field
discriminates between them.

**Building** the records is pure and separated from **writing** them: that is what
allows compliance with section 8.2 and the feeding of the section 8.6 macro to be
exercised without touching the disk.

**One file per `sid`, with no size-based rotation** (D-3). A shared rotating handler
is not safe across processes: two concurrent runs on the same member can lose lines at
the moment of a rotation. Since the journal is the only safety net of an irreversible
operation, a known window of line loss is not acceptable when the fix costs a file
name.
"""

import json
import os
import re

from .errors import FatalJournalError
from .normalize import serialize_roles

#: File name of the journal. The monitor stanza of section 8.3 is a matching glob.
JOURNAL_BASENAME = "editacl_journal_%s.log"

#: Characters allowed in a `sid` used as a file name component.
_SAFE_SID = re.compile(r"[^A-Za-z0-9._-]")


def journal_filename(sid):
    """File name of a run's journal, with a sanitized `sid`."""
    token = _SAFE_SID.sub("_", str(sid or "unknown"))
    return JOURNAL_BASENAME % (token or "unknown")


def journal_path(log_dir, sid):
    return os.path.join(log_dir, journal_filename(sid))


def _state_fields(prefix, state):
    """The **four** attributes of a state, prefixed `before_` or `after_` (8.2).

    `owner` is among them since D-22: it is now a target value, and the rollback macro
    of section 8.6 reads `before_owner` to re-emit `eai:acl.owner`. Carrying it in the
    state block rather than as a common field is what gives the journal a distinct
    `before_owner` **and** `after_owner` when ownership changes.
    """
    return {
        prefix + "_owner": state.owner or "",
        prefix + "_perms_read": serialize_roles(state.perms_read),
        prefix + "_perms_write": serialize_roles(state.perms_write),
        prefix + "_sharing": state.sharing or "",
    }


def _common_record(ctx, result, phase):
    """Fields common to both phases (section 8.2).

    Format constraints applied without exception: no colon in a field name, an empty
    value serialized as the empty string and never as `null` (`null` is reserved for
    `error`).
    """
    return {
        "ts": "",  # filled in by the calling builder
        "phase": phase,
        "sid": str(ctx.sid or ""),
        "user": str(ctx.user or ""),
        "host": str(ctx.host or ""),
        "dryrun": bool(ctx.dryrun),
        "endpoint": str(result.endpoint or ""),
        "app": str(result.app or ""),
        "title": str(result.title or ""),
        "eai_type": str(result.eai_type or ""),
    }


def build_intent_record(ctx, result, ts):
    """`phase=intent` line: full prior state and intended payload.

    The `title` field is journaled **unencoded**: the rollback re-injects it as is, and
    an already encoded title would be encoded twice.
    """
    record = _common_record(ctx, result, "intent")
    record["ts"] = ts
    record.update(_state_fields("before", result.before))
    record.update(_state_fields("after", result.after))
    return record


def build_outcome_record(ctx, result, ts):
    """`phase=outcome` line: status, HTTP code, error.

    It carries the six `before_*` / `after_*` fields **if and only if** the merge was
    computed **and** no `intent` line already carries them (section 8.2). Statuses
    coming from an upstream rejection do not carry them: they were never computed.
    """
    record = _common_record(ctx, result, "outcome")
    record["ts"] = ts
    record["status"] = str(result.status)
    record["http_code"] = int(result.http_code or 0)
    record["error"] = result.error if result.error else None

    merged = result.before is not None and result.after is not None
    if merged and not result.journaled:
        record.update(_state_fields("before", result.before))
        record.update(_state_fields("after", result.after))
    return record


def dumps(record):
    """One compact JSON line, with no newline inside a value."""
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


class JournalWriter(object):
    """Implementation of the `JournalPort` port over a local file.

    `write_intent` guarantees **durability** (write + flush + fsync): that is the
    precondition to the write of section 8.4. `write_outcome` settles for a flush - the
    POST has already happened, there is nothing left to guarantee, and one fsync per
    object would double the write cost of an already serialized operation.

    Neither of them raises: a write failure is a fact to record, not an interruption.
    Only **opening** the file can be fatal (section 9).
    """

    def __init__(self, path):
        self.path = path
        try:
            self._handle = open(path, "a", encoding="utf-8", newline="\n")
        except (IOError, OSError) as exc:
            raise FatalJournalError(
                "journal not openable for writing (%s): %s" % (path, exc)
            )

    def _write(self, record, sync):
        try:
            self._handle.write(dumps(record) + "\n")
            self._handle.flush()
            if sync:
                os.fsync(self._handle.fileno())
            return True
        except (IOError, OSError, ValueError):
            return False

    def write_intent(self, record):
        return self._write(record, sync=True)

    def write_outcome(self, record):
        return self._write(record, sync=False)

    def close(self):
        try:
            self._handle.close()
        except (IOError, OSError, ValueError):
            pass
