"""Write-ahead journal (section 8).

The journal serves **two distinct needs** that a single line cannot satisfy: the
persistence of the prior state **before** the mutation (the rollback set) and the
trace of the outcome **after** the mutation (execution control). A `phase` field
discriminates between them. A third phase, `summary`, marks the **end of a normal
run** (D-46): a run that was interrupted - fatal error, process killed - carries no
such line, and it is that absence which tells the two apart.

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

from . import model
from .errors import FatalJournalError
from .normalize import serialize_roles

#: File name of the journal. The monitor stanza of section 8.3 is a matching glob.
JOURNAL_BASENAME = "editacl_journal_%s.log"

#: Prefix of the per-status counters of the `summary` line (section 8.2, D-46). No
#: colon, as every field name of the journal.
SUMMARY_COUNT_PREFIX = "count_"

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


def _run_fields(ctx, phase, ts):
    """Fields carried by **every** line of the journal, whatever its phase (8.2).

    They describe the run, not an object: that is why they are the only ones the
    `summary` line carries besides its counters.

    `ts` comes first, and that is a constraint and not a habit: `props.conf` extracts
    the event time with `TIME_PREFIX = \\"ts\\":\\"` and
    `MAX_TIMESTAMP_LOOKAHEAD = 40` (section 8.3). A `ts` pushed further into the line
    would fall outside that window.

    `member` and not `host` (D-46): the `host` key collided with the `host` metadata
    Splunk stamps on every event, and the field came out **multivalued** at search
    time. Nothing was visible in the file, which was correct.

    Format constraints applied without exception: no colon in a field name, and an
    empty value serialized as the empty string - **never** as `null`, including for
    `error`, whose exception D-46 removed.
    """
    return {
        "ts": str(ts),
        "phase": phase,
        "sid": str(ctx.sid or ""),
        "user": str(ctx.user or ""),
        "member": str(ctx.member or ""),
        "dryrun": bool(ctx.dryrun),
    }


def _object_fields(result):
    """Fields designating the **object** processed, common to `intent` and `outcome`.

    The `summary` line carries none of them: it designates no object. Emitting them
    empty there would enrol it into the population of lines with an empty `endpoint`,
    which section 8.5 and the job-listing views already have to reason about - a
    summary line would then be counted as one more object by any `dc()` over those
    fields.
    """
    return {
        "endpoint": str(result.endpoint or ""),
        "app": str(result.app or ""),
        "title": str(result.title or ""),
        "eai_type": str(result.eai_type or ""),
    }


def _common_record(ctx, result, phase, ts):
    """Fields common to the `intent` and `outcome` phases (section 8.2)."""
    record = _run_fields(ctx, phase, ts)
    record.update(_object_fields(result))
    return record


def build_intent_record(ctx, result, ts):
    """`phase=intent` line: full prior state and intended payload.

    The `title` field is journaled **unencoded**: the rollback re-injects it as is, and
    an already encoded title would be encoded twice.
    """
    record = _common_record(ctx, result, "intent", ts)
    record.update(_state_fields("before", result.before))
    record.update(_state_fields("after", result.after))
    return record


def build_outcome_record(ctx, result, ts):
    """`phase=outcome` line: status, HTTP code, error.

    It carries the six `before_*` / `after_*` fields **if and only if** the merge was
    computed **and** no `intent` line already carries them (section 8.2). Statuses
    coming from an upstream rejection do not carry them: they were never computed.
    """
    record = _common_record(ctx, result, "outcome", ts)
    record["status"] = str(result.status)
    record["http_code"] = int(result.http_code or 0)
    # The empty string, and no longer `null` (D-46). The reservation of `null` for
    # this one field aimed at telling "no error" from "empty error"; that distinction
    # had no consumer, and the transport destroyed it anyway - `KV_MODE = json`
    # extracts a JSON `null` as **the four-character string "null"**, so the obvious
    # predicate `isnotnull(error)` was true on every line. Measured in the lab: eight
    # objects reported in error out of eight, where there were two.
    record["error"] = str(result.error or "")

    merged = result.before is not None and result.after is not None
    if merged and not result.journaled:
        record.update(_state_fields("before", result.before))
        record.update(_state_fields("after", result.after))
    return record


def build_summary_record(ctx, counts, ts):
    """`phase=summary` line: the run's counters, one per `acl_status` (D-46).

    **Written once, at the end of a normal run, and never on the fatal error path.**
    Its absence is what signals an interruption - a job that stopped on a fatal error
    and a job that ran to completion used to be indistinguishable, which is exactly the
    distinction a monitoring view exists to carry. The write point therefore sits in
    the adapter, after the last record and before the cleanup, on the branch
    `_fatal_exit()` short-circuits.

    **The enumeration of the counters is derived from `model.ACL_STATUSES`**, the
    single source of the statuses, and never written out by hand (D-35). It is read
    through the module rather than bound at import time, so that the derivation holds
    for whatever that source says at the moment of the call and not for what it said
    when this module was loaded.

    **Every** status is emitted, including at zero: a consumer that has to deal with an
    absent field writes a predicate on the absence, and that is a predicate nobody
    tests. A count carried by no declared status - which `tests/test_statuses.py` makes
    unreachable - is emitted all the same, sorted after the others: losing a count in
    silence is the failure class this journal exists to close.

    The line carries no object field (section 8.5): it designates no object.
    """
    record = _run_fields(ctx, "summary", ts)
    tallies = dict(counts or {})
    declared = tuple(model.ACL_STATUSES)
    for status in declared:
        record[SUMMARY_COUNT_PREFIX + status] = int(tallies.get(status, 0))
    for extra in sorted(set(tallies) - set(declared)):
        record[SUMMARY_COUNT_PREFIX + str(extra)] = int(tallies[extra])
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

    def write_summary(self, record):
        """End-of-run line. A flush is enough: the run is over, nothing is guarded.

        Like the other two, it does not raise. Its failure costs the ability to tell a
        completed run from an interrupted one for this `sid`; it costs no write.
        """
        return self._write(record, sync=False)

    def close(self):
        try:
            self._handle.close()
        except (IOError, OSError, ValueError):
            pass
