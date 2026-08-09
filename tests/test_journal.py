"""Journal format and rollback-macro feeding contract (sections 8.2 and 8.6)."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from acltools.errors import FatalJournalError
from acltools import journal as journal_module
from acltools import model as model_module
from acltools.journal import (
    SUMMARY_COUNT_PREFIX,
    JournalWriter,
    build_intent_record,
    build_outcome_record,
    build_summary_record,
    dumps,
    journal_filename,
)
from acltools.merge import merge
from acltools.model import ACL_STATUSES, EventResult

from .helpers import ABSENT, FakeClock, make_ctx, make_event, state

#: Fields consumed by `editacl_rollback` (section 8.6). The list is **hardcoded**: any
#: change to the journal schema or to the macro breaks this test, which is the point.
ROLLBACK_FIELDS_FROM_INTENT = (
    "sid",
    "phase",
    "endpoint",
    "before_owner",
    "before_perms_read",
    "before_perms_write",
    "before_sharing",
    "app",
    "title",
    "eai_type",
    "ts",
)

CTX = make_ctx(sid="1754483000.1", user="operator", member="sh01", dryrun=False)


def result(status="updated", **kwargs):
    base = dict(
        title="My search",
        app="my_app",
        eai_type="savedsearch",
        endpoint="/servicesNS/nobody/my_app/saved/searches/My%20search",
        http_code=200,
        before=state(sharing="global", read=("role_a",), write=("legacy_role",)),
        after=state(sharing="global", read=("role_a",), write=("new_role_admin",)),
    )
    base.update(kwargs)
    return EventResult(status=status, **base)


class IntentRecordTest(unittest.TestCase):

    def test_common_and_specific_fields(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        for field in (
            "ts", "phase", "sid", "user", "member", "dryrun", "endpoint", "app",
            "title", "eai_type",
        ):
            self.assertIn(field, record)
        for field in (
            "before_owner", "before_perms_read", "before_perms_write",
            "before_sharing",
            "after_owner", "after_perms_read", "after_perms_write", "after_sharing",
        ):
            self.assertIn(field, record)
        self.assertEqual(record["phase"], "intent")

    def test_intent_does_not_carry_status(self):
        """The absence of `status` on `intent` is **required**: otherwise an `intent`
        line could count as 1 in the `max(_restorable)` of the macro."""
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        self.assertNotIn("status", record)

    def test_journaled_title_is_not_encoded(self):
        record = build_intent_record(
            CTX, result(title="Report/Monthly"), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(record["title"], "Report/Monthly")
        self.assertNotIn("%2F", record["title"])

    def test_no_field_name_contains_a_colon(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        for field in record:
            self.assertNotIn(":", field)

    def test_empty_values_serialized_as_the_empty_string(self):
        record = build_intent_record(
            CTX,
            result(before=state(sharing="global", read=(), write=())),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertEqual(record["before_perms_read"], "")
        self.assertIsNot(record["before_perms_read"], None)

    def test_endpoint_without_scheme_host_or_acl_suffix(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        self.assertTrue(record["endpoint"].startswith("/servicesNS/"))
        self.assertNotIn("://", record["endpoint"])
        self.assertFalse(record["endpoint"].endswith("/acl"))


class OutcomeRecordTest(unittest.TestCase):

    def test_own_fields(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(record["phase"], "outcome")
        self.assertEqual(record["status"], "updated")
        self.assertEqual(record["http_code"], 200)
        self.assertEqual(record["error"], "")

    def test_updated_does_not_repeat_before_after_already_carried_by_intent(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertNotIn("before_perms_read", record)

    def test_noop_dryrun_invalid_role_skipped_immutable_carry_before_after(self):
        for status in ("noop", "dryrun", "invalid_role", "skipped_immutable"):
            with self.subTest(status=status):
                record = build_outcome_record(
                    CTX,
                    result(status=status, journaled=False),
                    "2026-01-01T00:00:00.000+01:00",
                )
                self.assertIn("before_perms_read", record)
                self.assertIn("after_sharing", record)

    def test_upstream_rejection_does_not_carry_before_after(self):
        for status in ("rejected", "not_found", "forbidden"):
            with self.subTest(status=status):
                record = build_outcome_record(
                    CTX,
                    result(status=status, before=None, after=None, http_code=404),
                    "2026-01-01T00:00:00.000+01:00",
                )
                self.assertNotIn("before_perms_read", record)

    def test_intent_journaling_failure_reports_the_previous_state(self):
        """Without this the previous state would be lost for good."""
        record = build_outcome_record(
            CTX,
            result(status="error", journaled=False, error="journal_intent_failed"),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertIn("before_perms_read", record)

    def test_http_code_sentinel_zero_when_no_exchange_took_place(self):
        record = build_outcome_record(
            CTX,
            result(status="rejected", before=None, after=None, http_code=0),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertEqual(record["http_code"], 0)
        self.assertIsInstance(record["http_code"], int)

    def test_no_field_is_ever_null_error_included(self):
        """D-46 - `error` was the last exception, and the transport destroyed it.

        `KV_MODE = json` extracts a JSON `null` as the four-character string `"null"`:
        `isnull(error)` was false on every line and `isnotnull(error)` true on every
        line. Measured in the lab, a panel counting objects in error the obvious way
        displayed the whole job. The empty string carries the same meaning and survives
        indexing.
        """
        for status, error in (
            ("updated", None),
            ("noop", None),
            ("error", "post_failed:500:boom"),
            ("rejected", "missing_field:title"),
        ):
            with self.subTest(status=status):
                record = build_outcome_record(
                    CTX,
                    result(status=status, journaled=True, error=error),
                    "2026-01-01T00:00:00.000+01:00",
                )
                nulls = [f for f, value in record.items() if value is None]
                self.assertEqual(nulls, [])
                self.assertIsInstance(record["error"], str)
                self.assertNotIn(":null", dumps(record))

    def test_an_absent_error_is_the_empty_string_and_not_the_word_null(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(record["error"], "")
        self.assertNotEqual(record["error"], "null")


class SummaryRecordTest(unittest.TestCase):
    """`phase=summary`, the end-of-run line (section 8.2, D-46).

    A run interrupted - fatal error, ceiling, process killed - and a run that reached
    its end used to be indistinguishable. This line is written once at the end of a
    normal run, and it is its **absence** that signals the interruption; the control
    over that placement lives in `tests/test_editacl_adapter.py`, which is where the
    control flow is.
    """

    TS = "2026-01-01T00:00:00.000+01:00"

    def test_phase_and_run_fields(self):
        record = build_summary_record(CTX, {"updated": 3}, self.TS)
        self.assertEqual(record["phase"], "summary")
        for field in ("ts", "phase", "sid", "user", "member", "dryrun"):
            self.assertIn(field, record)
        self.assertEqual(record["sid"], "1754483000.1")
        self.assertEqual(record["member"], "sh01")

    def test_the_timestamp_is_the_first_key(self):
        """`props.conf` reads the time with `TIME_PREFIX` and a 40-character
        lookahead (section 8.3): a `ts` pushed further in would fall outside it."""
        record = build_summary_record(CTX, {}, self.TS)
        self.assertEqual(list(record)[0], "ts")

    def test_it_designates_no_object(self):
        """Section 8.5: the line carries no `endpoint`, therefore lands in an
        aggregation group of its own. Emitting the object fields empty would enrol it
        into the population of lines with an empty `endpoint`, which any `dc()` over
        those fields would then count as one more object."""
        record = build_summary_record(CTX, {"updated": 1}, self.TS)
        for field in ("endpoint", "app", "title", "eai_type", "status", "http_code"):
            self.assertNotIn(field, record)

    def test_every_declared_status_is_emitted_zeros_included(self):
        """A consumer must not have to deal with an absent field: a predicate on an
        absence is a predicate nobody tests."""
        record = build_summary_record(CTX, {"updated": 2, "noop": 1}, self.TS)
        for status in ACL_STATUSES:
            self.assertIn(SUMMARY_COUNT_PREFIX + status, record)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + "updated"], 2)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + "noop"], 1)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + "forbidden"], 0)

    def test_the_counters_are_exactly_the_declared_statuses(self):
        record = build_summary_record(CTX, {}, self.TS)
        counters = tuple(
            field[len(SUMMARY_COUNT_PREFIX):]
            for field in record
            if field.startswith(SUMMARY_COUNT_PREFIX)
        )
        self.assertEqual(counters, tuple(ACL_STATUSES))

    def test_the_enumeration_is_derived_from_the_single_source_of_the_statuses(self):
        """D-35, and this is the mechanical proof of it.

        A status added to `acltools.model.ACL_STATUSES` appears in the line **with no
        enumeration edited anywhere**. The fictional status below exists for the
        duration of this test only; if `build_summary_record` held a list of its own,
        this test would be the one to fail.
        """
        invented = "invented_status_for_this_test"
        original = model_module.ACL_STATUSES
        try:
            model_module.ACL_STATUSES = original + (invented,)
            record = build_summary_record(CTX, {"updated": 1}, self.TS)
        finally:
            model_module.ACL_STATUSES = original
        self.assertIn(SUMMARY_COUNT_PREFIX + invented, record)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + invented], 0)
        self.assertNotIn(SUMMARY_COUNT_PREFIX + invented,
                         build_summary_record(CTX, {}, self.TS))

    def test_the_builder_reads_the_source_and_holds_no_copy_of_it(self):
        """The complement of the test above: `journal.py` names no status."""
        source = journal_module.build_summary_record.__code__.co_consts
        literals = [c for c in source if isinstance(c, str)]
        for status in ACL_STATUSES:
            self.assertNotIn(status, literals)

    def test_a_count_carried_by_an_undeclared_status_is_not_lost(self):
        """Unreachable while `tests/test_statuses.py` holds, and emitted all the same:
        losing a count in silence is the failure class this journal exists to close."""
        record = build_summary_record(CTX, {"a_status_nobody_declared": 4}, self.TS)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + "a_status_nobody_declared"], 4)

    def test_no_field_name_contains_a_colon_and_no_value_is_null(self):
        record = build_summary_record(CTX, {"updated": 1}, self.TS)
        for field, value in record.items():
            self.assertNotIn(":", field)
            self.assertIsNotNone(value)
        self.assertNotIn(":null", dumps(record))

    def test_the_counters_are_integers(self):
        record = build_summary_record(CTX, {"updated": "3"}, self.TS)
        self.assertIsInstance(record[SUMMARY_COUNT_PREFIX + "updated"], int)
        self.assertEqual(record[SUMMARY_COUNT_PREFIX + "updated"], 3)

    def test_a_run_with_no_event_carries_only_zeros(self):
        record = build_summary_record(CTX, {}, self.TS)
        self.assertEqual(
            sum(
                value for field, value in record.items()
                if field.startswith(SUMMARY_COUNT_PREFIX)
            ),
            0,
        )


class MemberKeyTest(unittest.TestCase):
    """D-46 - the `host` key is gone, on every phase.

    It collided with the `host` metadata Splunk stamps on every event, and the field
    came out **multivalued** at search time. Nothing was visible in the file, which was
    correct; the defect only existed where the journal is meant to be read.
    """

    TS = "2026-01-01T00:00:00.000+01:00"

    def test_no_phase_carries_a_host_key(self):
        records = (
            build_intent_record(CTX, result(), self.TS),
            build_outcome_record(CTX, result(journaled=True), self.TS),
            build_summary_record(CTX, {"updated": 1}, self.TS),
        )
        for record in records:
            with self.subTest(phase=record["phase"]):
                self.assertNotIn("host", record)
                self.assertEqual(record["member"], "sh01")


class RollbackContractTest(unittest.TestCase):
    """The macro of section 8.6 is the only way to undo an irreversible operation: a
    missing field makes it ineffective, with no visible error."""

    def test_intent_carries_every_field_consumed_by_the_macro(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        missing = [f for f in ROLLBACK_FIELDS_FROM_INTENT if f not in record]
        self.assertEqual(missing, [])

    def test_outcome_carries_status_and_endpoint_for_the_pairing(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertIn("status", record)
        self.assertIn("endpoint", record)
        self.assertIn("phase", record)

    def test_identical_endpoint_on_intent_and_outcome(self):
        res = result(journaled=True)
        intent = build_intent_record(CTX, res, "2026-01-01T00:00:00.000+01:00")
        outcome = build_outcome_record(CTX, res, "2026-01-01T00:00:00.001+01:00")
        self.assertEqual(intent["endpoint"], outcome["endpoint"])

    def test_restoring_an_empty_permission_does_clear_the_attribute_again(self):
        """Full in-memory round trip, on the case the `coalesce` DOES cover.

        The scenario simulated here, the empty permission column being lost between the
        journal and the reinjection, **is not the platform's**: measured on 9.4.6, an
        empty permission is extracted at indexing time AND survives the `stats` of the
        macro (D-32). It is simulated because it is exactly the behavior the `coalesce`
        of section 8.6 protects against AS DEFENSE IN DEPTH, and because nothing
        obliges another version of the platform to keep the one that was measured.

        Initial state with `perms.read` empty -> `intent` line -> HYPOTHETICAL loss of
        the empty field -> reinjection -> the merge does clear `perms.read` again (row
        4 of the matrix).
        """
        before = state(sharing="global", read=(), write=("legacy_role",))
        after = state(sharing="global", read=(), write=("new_role_admin",))
        intent = build_intent_record(
            CTX, result(before=before, after=after), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(intent["before_perms_read"], "")

        # Simulation of the behavior we guard AGAINST, not of the one that was
        # measured: a journaling chain that did not materialize an empty-valued field
        # would produce no `eai:acl.perms.read` column at all when every object of the
        # batch is in that case.
        macro_output = {
            "title": intent["title"],
            "eai:acl.app": intent["app"],
            "eai:acl.owner": intent["before_owner"],
            "eai:type": intent["eai_type"],
        }
        if intent["before_perms_read"]:
            macro_output["eai:acl.perms.read"] = intent["before_perms_read"]
        if intent["before_perms_write"]:
            macro_output["eai:acl.perms.write"] = intent["before_perms_write"]
        if intent["before_sharing"]:
            macro_output["eai:acl.sharing"] = intent["before_sharing"]
        self.assertNotIn("eai:acl.perms.read", macro_output)

        # Absent column = attribute PRESERVED (section 3.2). In that configuration,
        # and with no precaution, the restore would leave `perms.read` intact while
        # reporting a success: the class of defect the rework corrects elsewhere,
        # reintroduced through the back door.
        without_coalesce = merge(
            state(sharing="global", read=("added_role",),
                  write=("new_role_admin",)),
            make_event(
                read=macro_output.get("eai:acl.perms.read", ABSENT),
                write=macro_output.get("eai:acl.perms.write", ABSENT),
                sharing=macro_output.get("eai:acl.sharing", ABSENT),
                owner=macro_output.get("eai:acl.owner", ABSENT),
            ),
        )
        self.assertEqual(
            without_coalesce.payload["perms.read"], "added_role",
            "without the coalesce of the macro the column is absent and the attribute "
            "is preserved: the restore would clear nothing",
        )

        # The `coalesce(..., "")` of `editacl_rollback(1)` materializes the column
        # unconditionally: it exists, empty, and the attribute is indeed emptied.
        macro_output.setdefault("eai:acl.perms.read", "")
        macro_output.setdefault("eai:acl.perms.write", "")
        self.assertIn("eai:acl.perms.read", macro_output)

        # Reinjection: `| editacl fields="perms.read,perms.write,sharing"`
        current_state = state(sharing="global", read=("added_role",),
                              write=("new_role_admin",))
        reinjection = merge(
            current_state,
            make_event(
                read=macro_output.get("eai:acl.perms.read"),
                write=macro_output.get("eai:acl.perms.write"),
                sharing=macro_output.get("eai:acl.sharing"),
                owner=macro_output.get("eai:acl.owner"),
            ),
        )
        self.assertIsNone(reinjection.rejection)
        self.assertEqual(reinjection.payload["perms.read"], "")
        self.assertEqual(reinjection.payload["perms.write"], "legacy_role")
        self.assertEqual(reinjection.payload["sharing"], "global")


class SerializationTest(unittest.TestCase):

    def test_compact_json_line_with_no_newline(self):
        line = dumps(build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00"))
        self.assertNotIn("\n", line)
        self.assertNotIn(", ", line)
        json.loads(line)

    def test_non_ascii_characters_are_preserved(self):
        line = dumps({"title": "Résumé"})
        self.assertIn("Résumé", line)

    def test_timestamp_with_milliseconds_and_zone(self):
        from acltools.pipeline import default_clock

        stamp = default_clock()
        self.assertRegex(
            stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$"
        )


class JournalWriterTest(unittest.TestCase):
    """One file per `sid`, with no size-based rotation (D-3)."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="editacl_test_")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_file_name_per_sid(self):
        self.assertEqual(
            journal_filename("1754483000.1"), "editacl_journal_1754483000.1.log"
        )

    def test_sid_sanitized_so_it_cannot_traverse_the_tree(self):
        name = journal_filename("../../etc/passwd")
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)
        self.assertEqual(os.path.basename(name), name)
        self.assertTrue(name.startswith("editacl_journal_"))
        self.assertTrue(name.endswith(".log"))

    def test_empty_sid_yields_a_usable_name(self):
        self.assertEqual(journal_filename(""), "editacl_journal_unknown.log")

    def test_write_and_read_back(self):
        path = os.path.join(self.directory, journal_filename("test_sid"))
        writer = JournalWriter(path)
        self.assertTrue(writer.write_intent({"phase": "intent", "a": 1}))
        self.assertTrue(writer.write_outcome({"phase": "outcome", "b": 2}))
        self.assertTrue(writer.write_summary({"phase": "summary", "c": 3}))
        writer.close()
        with open(path, encoding="utf-8") as handle:
            lines = [json.loads(l) for l in handle if l.strip()]
        self.assertEqual(
            [l["phase"] for l in lines], ["intent", "outcome", "summary"]
        )

    def test_a_write_failure_is_reported_and_never_raised(self):
        path = os.path.join(self.directory, journal_filename("closed_sid"))
        writer = JournalWriter(path)
        writer.close()
        self.assertFalse(writer.write_summary({"phase": "summary"}))

    def test_an_impossible_opening_is_fatal(self):
        path = os.path.join(self.directory, "nonexistent-subdirectory", "j.log")
        with self.assertRaises(FatalJournalError):
            JournalWriter(path)

    def test_deterministic_test_clock(self):
        clock = FakeClock()
        self.assertNotEqual(clock(), clock())


class _SyncSpy(object):
    """Stand-in for `os.fsync` recording every durability barrier the writer raises.

    It records **two** things per call: the descriptor the barrier is placed on, and
    what an independent reader sees in the file **at that instant**. The second is what
    makes the ordering observable from outside the writer: at the moment of the sync,
    the line must already have left the interpreter's buffer. A `flush()` removed, or a
    sync moved ahead of it, leaves nothing to read here - and syncing a buffer the
    kernel has never been handed guarantees exactly nothing.
    """

    def __init__(self, path):
        self.path = path
        self.calls = []
        self._real = os.fsync

    def __call__(self, fd):
        with open(self.path, encoding="utf-8") as handle:
            self.calls.append((fd, handle.read()))
        return self._real(fd)

    def contents_at_each_barrier(self):
        return [content for _, content in self.calls]


def _sync_that_cannot_complete(fd):
    """`os.fsync` on a device that cannot take the write.

    This is the failure section 8.4 turns into `acl_status = "error"` with **no POST
    attempted**: the whole pipeline behaviour rests on this call reporting rather than
    raising, and every pipeline test of it runs against a double that never touches a
    disk.
    """
    raise OSError(28, "no space left on device")


class TheDurabilityBarrierTest(unittest.TestCase):
    """Section 8.4 on the real writer: the write-ahead barrier of the `intent` line.

    S-1 of the second re-audit of 2026-08-09. The journal was covered abundantly for
    what its lines **say**, and not at all for the one property that makes it a
    write-ahead journal rather than a log file: `write_intent` could be turned from
    `sync=True` to `sync=False` and all 713 tests stayed green. The lines were still
    correct, the file was still written, and the guarantee section 8.4 rests on - the
    prior state is on the platter before the POST is attempted - was gone. A power cut
    between the write and the POST would then leave the mutation done and the state to
    restore it from in a filesystem buffer.

    Why nothing saw it: every test of that precondition runs at pipeline level against
    `FakeJournal`, which returns `True` without touching a disk. Those doubles prove
    what the pipeline does with the answer; they cannot prove that the answer means
    anything. **The journal is the only safety net of an irreversible operation**, and
    its most critical property was guarded by nothing.
    """

    RECORD = {"phase": "intent", "sid": "barrier_sid", "endpoint": "/x"}

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="editacl_test_")
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.path = os.path.join(self.directory, journal_filename("barrier_sid"))
        self.writer = JournalWriter(self.path)
        self.addCleanup(self.writer.close)

    def _spy_on(self, method, record):
        spy = _SyncSpy(self.path)
        with mock.patch.object(journal_module.os, "fsync", spy):
            written = getattr(self.writer, method)(record)
        self.assertTrue(written)
        return spy

    def test_the_intent_line_raises_a_durability_barrier(self):
        spy = self._spy_on("write_intent", self.RECORD)
        self.assertEqual(
            len(spy.calls), 1, "no durability barrier raised on the intent line"
        )

    def test_the_intent_line_is_already_in_the_file_when_the_barrier_is_raised(self):
        # The flush precedes the sync, seen from an independent descriptor.
        spy = self._spy_on("write_intent", self.RECORD)
        self.assertIn('"phase":"intent"', spy.contents_at_each_barrier()[0])

    def test_the_barrier_is_raised_on_the_descriptor_of_the_journal_itself(self):
        spy = self._spy_on("write_intent", self.RECORD)
        fd = spy.calls[0][0]
        witness = os.open(self.path, os.O_RDONLY)
        try:
            self.assertTrue(os.path.sameopenfile(fd, witness))
        finally:
            os.close(witness)

    def test_the_outcome_line_does_not_pay_for_a_barrier(self):
        # Section 8.4: the POST has already happened, there is nothing left to
        # guarantee, and one fsync per object would double the write cost of an
        # already serialized operation. The line is still flushed.
        spy = self._spy_on("write_outcome", {"phase": "outcome", "status": "updated"})
        self.assertEqual(spy.calls, [])
        with open(self.path, encoding="utf-8") as handle:
            self.assertIn('"phase":"outcome"', handle.read())

    def test_the_summary_line_does_not_pay_for_a_barrier(self):
        spy = self._spy_on("write_summary", {"phase": "summary"})
        self.assertEqual(spy.calls, [])

    def test_a_barrier_that_cannot_complete_is_reported_and_never_raised(self):
        with mock.patch.object(
            journal_module.os, "fsync", _sync_that_cannot_complete
        ):
            self.assertFalse(self.writer.write_intent(self.RECORD))
        # And the writer stays usable: the pipeline writes the `outcome` line of the
        # object it has just refused to POST (section 8.2, first invariant).
        self.assertTrue(self.writer.write_outcome({"phase": "outcome"}))

    def test_a_second_run_on_the_same_file_keeps_the_lines_already_there(self):
        """The rollback set of an earlier run is not what a later one costs.

        One file per `sid` (D-3), and a `sid` is not guaranteed unique for ever. The
        file is opened for **appending**; opening it for writing would truncate a
        journal that is by construction the only copy of a prior state.
        """
        self.writer.write_intent(dict(self.RECORD, rank=1))
        self.writer.close()
        again = JournalWriter(self.path)
        self.addCleanup(again.close)
        again.write_intent(dict(self.RECORD, rank=2))
        again.close()
        with open(self.path, encoding="utf-8") as handle:
            lines = [json.loads(l) for l in handle if l.strip()]
        self.assertEqual([line["rank"] for line in lines], [1, 2])


if __name__ == "__main__":
    unittest.main()
