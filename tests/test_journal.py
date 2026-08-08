"""Journal format and rollback-macro feeding contract (sections 8.2 and 8.6)."""

import json
import os
import shutil
import tempfile
import unittest

from acltools.errors import FatalJournalError
from acltools.journal import (
    JournalWriter,
    build_intent_record,
    build_outcome_record,
    dumps,
    journal_filename,
)
from acltools.merge import merge
from acltools.model import EventResult

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

CTX = make_ctx(sid="1754483000.1", user="operator", host="sh01", dryrun=False)


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
            "ts", "phase", "sid", "user", "host", "dryrun", "endpoint", "app",
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
        self.assertIsNone(record["error"])

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

    def test_error_is_the_only_field_that_may_be_null(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        nulls = [field for field, value in record.items() if value is None]
        self.assertEqual(nulls, ["error"])


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
        writer.close()
        with open(path, encoding="utf-8") as handle:
            lines = [json.loads(l) for l in handle if l.strip()]
        self.assertEqual([l["phase"] for l in lines], ["intent", "outcome"])

    def test_an_impossible_opening_is_fatal(self):
        path = os.path.join(self.directory, "nonexistent-subdirectory", "j.log")
        with self.assertRaises(FatalJournalError):
            JournalWriter(path)

    def test_deterministic_test_clock(self):
        clock = FakeClock()
        self.assertNotEqual(clock(), clock())


if __name__ == "__main__":
    unittest.main()
