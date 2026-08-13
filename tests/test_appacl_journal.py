"""Application-level journal (v4.1 sections 11.1, 11.2, 11.3).

The line that matters most in this file is the `intent` of a **creation**. The effective
state of a target that had no stanza is useful information - it says what the objects saw
before - but it is **not a restorable prior state**: re-injecting it would create the
stanza a second time, under cover of a restore. Keeping it under `inherited_*` keys,
which the restore macro does not read, is the mechanism that closes the hole the previous
project paid a whole remediation for.
"""

import json
import unittest

from acltools.appacl_model import (
    APP_ACL_STATUSES,
    REVERSIBLE_FALSE,
    REVERSIBLE_TRUE,
    REVERSIBLE_UNKNOWN,
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    AppEventResult,
)
from acltools.journal import (
    APP_JOURNAL_BASENAME,
    JOURNAL_BASENAME,
    SUMMARY_COUNT_PREFIX,
    SUMMARY_IMPACT_TOTAL,
    app_journal_filename,
    app_journal_path,
    app_write_asserted,
    build_app_intent_record,
    build_app_outcome_record,
    build_app_summary_record,
    dumps,
)

from .appacl_helpers import app_state, make_app_ctx

#: Keys of the `intent` line, **hardcoded** - same discipline as
#: `ROLLBACK_FIELDS_FROM_INTENT` on the object side, and for the same reason: the three
#: restore macros of section 11.4 consume these names, so a schema change that nobody
#: carried over to the SPL must break a test rather than produce an empty rollback set
#: reported as a success.
#:
#: `tests/test_spl_artifacts.py` imports this tuple to check that the macros consume
#: nothing else, and `TheIntentLineKeysAreTheDeclaredOnesTest` below checks that the
#: builder produces exactly these. Both directions, so neither list can drift alone.
APP_INTENT_KEYS = (
    "ts", "phase", "sid", "user", "dryrun",
    "endpoint", "app", "stanza_kind", "stanza", "handler", "reversible",
    "impacted_estimate",
    "before_perms_read", "before_perms_write", "before_sharing",
    "inherited_perms_read", "inherited_perms_write", "inherited_sharing",
    "after_perms_read", "after_perms_write", "after_sharing",
)

BEFORE = app_state(sharing="app", read=("power",), write=("admin",))
AFTER = app_state(sharing="global", read=("user",), write=("admin",))


def result(
    status="updated",
    reversible=REVERSIBLE_TRUE,
    stanza_kind=STANZA_KIND_FAMILY,
    stanza="views",
    handler="data/ui/views",
    endpoint="/servicesNS/nobody/my_app/data/ui/views/_acl",
    before=BEFORE,
    after=AFTER,
    inherited=None,
    impacted_estimate=7,
    http_code=200,
    error=None,
    post_attempted=True,
):
    return AppEventResult(
        status=status,
        app="my_app",
        stanza_kind=stanza_kind,
        stanza=stanza,
        handler=handler,
        endpoint=endpoint,
        reversible=reversible,
        impacted_estimate=impacted_estimate,
        http_code=http_code,
        error=error,
        before=before,
        after=after,
        inherited=inherited,
        post_attempted=post_attempted,
    )


class TheFileIsItsOwnTest(unittest.TestCase):
    """Section 11.1, **DV-3**: separate files and separate sourcetypes."""

    def test_the_two_basenames_differ(self):
        self.assertNotEqual(JOURNAL_BASENAME, APP_JOURNAL_BASENAME)

    def test_one_file_per_run(self):
        self.assertIn("%s", APP_JOURNAL_BASENAME)
        self.assertNotEqual(
            app_journal_filename("1.1"), app_journal_filename("1.2")
        )

    def test_the_sid_is_sanitized_into_the_file_name(self):
        """A `sid` reaching a file name unfiltered is a path, not an identifier."""
        self.assertEqual(
            app_journal_filename("../../etc/passwd"),
            "editappacl_journal_.._.._etc_passwd.log",
        )

    def test_an_empty_sid_still_produces_a_name(self):
        self.assertEqual(app_journal_filename(""), "editappacl_journal_unknown.log")

    def test_the_path_joins_the_log_directory(self):
        self.assertTrue(
            app_journal_path("/var/log", "1.1").endswith("editappacl_journal_1.1.log")
        )


class TheRunFieldsTest(unittest.TestCase):
    """Section 11.2: `ts` first, and no `host` nor `member` key."""

    def test_ts_comes_first(self):
        """A hard constraint: `TIME_PREFIX` and `MAX_TIMESTAMP_LOOKAHEAD` depend on it,
        and a `ts` pushed further into the line falls outside the window."""
        record = build_app_intent_record(make_app_ctx(), result(), "2026-01-01T00:00:00.000+01:00")
        self.assertEqual(list(record)[0], "ts")
        self.assertLess(dumps(record).index('"ts"'), 10)

    def test_no_member_key(self):
        record = build_app_outcome_record(make_app_ctx(), result(), "t")
        for key in ("host", "member", "serverName"):
            with self.subTest(key=key):
                self.assertNotIn(key, record)

    def test_the_run_fields_are_on_every_phase(self):
        for record in (
            build_app_intent_record(make_app_ctx(), result(), "t"),
            build_app_outcome_record(make_app_ctx(), result(), "t"),
            build_app_summary_record(make_app_ctx(), {}, 0, "t"),
        ):
            with self.subTest(phase=record["phase"]):
                for key in ("ts", "phase", "sid", "user", "dryrun"):
                    self.assertIn(key, record)

    def test_no_field_name_carries_a_colon(self):
        for record in (
            build_app_intent_record(make_app_ctx(), result(), "t"),
            build_app_outcome_record(make_app_ctx(), result(), "t"),
            build_app_summary_record(make_app_ctx(), {"updated": 1}, 3, "t"),
        ):
            for key in record:
                with self.subTest(key=key):
                    self.assertNotIn(":", key)

    def test_the_line_is_compact_json_on_one_line(self):
        rendered = dumps(build_app_intent_record(make_app_ctx(), result(), "t"))
        self.assertNotIn("\n", rendered)
        self.assertNotIn(", ", rendered)
        json.loads(rendered)


class TheTargetFieldsTest(unittest.TestCase):
    """Section 11.2, and the trap this journal carries of its own."""

    def test_the_empty_stanza_is_a_legitimate_value(self):
        """It is the name of the `[]` stanza. Everywhere else an empty value signals an
        absent information - hence the normative clause: no consumer infers the target
        from `stanza` alone."""
        record = build_app_intent_record(
            make_app_ctx(),
            result(stanza_kind=STANZA_KIND_APP, stanza="", handler=""),
            "t",
        )
        self.assertEqual(record["stanza"], "")
        self.assertEqual(record["stanza_kind"], STANZA_KIND_APP)

    def test_the_stanza_kind_is_never_empty_on_a_resolved_target(self):
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            with self.subTest(kind=kind):
                record = build_app_outcome_record(
                    make_app_ctx(), result(stanza_kind=kind), "t"
                )
                self.assertTrue(record["stanza_kind"])

    def test_the_handler_is_journaled_at_resolution_time(self):
        """That is what makes the restore independent of the family table's coverage -
        the direct correction of the defect closed on 2026-08-10."""
        record = build_app_intent_record(make_app_ctx(), result(), "t")
        self.assertEqual(record["handler"], "data/ui/views")

    def test_the_endpoint_is_identical_on_the_two_phases(self):
        """Section 11.3: a **string contract**, computed once, never recomputed."""
        one = build_app_intent_record(make_app_ctx(), result(), "t")
        two = build_app_outcome_record(make_app_ctx(), result(), "t")
        self.assertEqual(one["endpoint"], two["endpoint"])

    def test_the_endpoint_carries_no_scheme_host_or_port(self):
        record = build_app_outcome_record(make_app_ctx(), result(), "t")
        self.assertTrue(record["endpoint"].startswith("/"))
        self.assertNotIn("://", record["endpoint"])

    def test_the_reversible_field_is_on_both_phases(self):
        for record in (
            build_app_intent_record(make_app_ctx(), result(), "t"),
            build_app_outcome_record(make_app_ctx(), result(), "t"),
        ):
            self.assertEqual(record["reversible"], REVERSIBLE_TRUE)


class TheIntentLineTellsRestorableFromInheritedTest(unittest.TestCase):
    """**The mechanism that closes the hole** (section 11.2).

    A creation must never leave a restorable-looking prior state behind: the restore
    would then re-create the stanza instead of removing it - which no REST path can do
    anyway.
    """

    def test_a_modification_carries_before_and_no_inherited(self):
        record = build_app_intent_record(
            make_app_ctx(), result(reversible=REVERSIBLE_TRUE), "t"
        )
        self.assertEqual(record["before_perms_read"], "power")
        self.assertEqual(record["before_sharing"], "app")
        self.assertEqual(record["inherited_perms_read"], "")
        self.assertEqual(record["inherited_sharing"], "")

    def test_a_creation_carries_inherited_and_an_empty_before(self):
        record = build_app_intent_record(
            make_app_ctx(),
            result(
                status="created",
                reversible=REVERSIBLE_FALSE,
                before=BEFORE,
                inherited=BEFORE,
            ),
            "t",
        )
        self.assertEqual(record["before_perms_read"], "")
        self.assertEqual(record["before_perms_write"], "")
        self.assertEqual(record["before_sharing"], "")
        self.assertEqual(record["inherited_perms_read"], "power")
        self.assertEqual(record["inherited_sharing"], "app")

    def test_an_unknown_provenance_behaves_like_a_creation(self):
        """It is excluded from the restore set for the same reason: nothing establishes
        that the value read was carried by a stanza of its own."""
        record = build_app_intent_record(
            make_app_ctx(),
            result(reversible=REVERSIBLE_UNKNOWN, inherited=BEFORE),
            "t",
        )
        self.assertEqual(record["before_perms_read"], "")
        self.assertEqual(record["inherited_perms_read"], "power")

    def test_the_transmitted_state_is_carried_in_all_three_cases(self):
        for reversible in (REVERSIBLE_TRUE, REVERSIBLE_FALSE, REVERSIBLE_UNKNOWN):
            with self.subTest(reversible=reversible):
                record = build_app_intent_record(
                    make_app_ctx(), result(reversible=reversible, inherited=BEFORE), "t"
                )
                self.assertEqual(record["after_perms_read"], "user")
                self.assertEqual(record["after_sharing"], "global")

    def test_a_restore_built_on_before_star_skips_creations_by_construction(self):
        """The property the restore macro rests on, checked on the record rather than on
        the macro: a creation's `before_*` are empty, so a filter on
        `reversible="true"` and a `coalesce` on the two permissions cannot resurrect
        one."""
        creation = build_app_intent_record(
            make_app_ctx(),
            result(reversible=REVERSIBLE_FALSE, inherited=BEFORE),
            "t",
        )
        restorable = [
            key for key in creation if key.startswith("before_") and creation[key]
        ]
        self.assertEqual(restorable, [])

    def test_the_impact_estimate_is_journaled(self):
        record = build_app_intent_record(make_app_ctx(), result(), "t")
        self.assertEqual(record["impacted_estimate"], 7)

    def test_an_uncomputed_estimate_is_the_empty_string(self):
        """Empty is not zero: zero is a **measured** answer carrying
        `no_inheriting_object`, and confusing the two would let a target nobody counted
        pass for a target that moves nothing."""
        record = build_app_intent_record(
            make_app_ctx(), result(impacted_estimate=None), "t"
        )
        self.assertEqual(record["impacted_estimate"], "")


class TheOutcomeLineTest(unittest.TestCase):

    def test_it_carries_the_status_the_code_and_the_error(self):
        record = build_app_outcome_record(
            make_app_ctx(), result(status="error", http_code=403, error="boom"), "t"
        )
        self.assertEqual(record["status"], "error")
        self.assertEqual(record["http_code"], 403)
        self.assertEqual(record["error"], "boom")

    def test_the_error_is_never_null(self):
        """D-46: `KV_MODE = json` extracts a JSON `null` as the four-character string
        "null", which made `isnotnull(error)` true on every line."""
        record = build_app_outcome_record(make_app_ctx(), result(error=None), "t")
        self.assertEqual(record["error"], "")
        self.assertNotIn("null", dumps(record))

    def test_the_http_code_is_an_integer(self):
        record = build_app_outcome_record(make_app_ctx(), result(http_code=None), "t")
        self.assertEqual(record["http_code"], 0)

    def test_write_asserted_has_three_values_and_only_three(self):
        cases = (
            (result(http_code=200, post_attempted=True), "yes"),
            (result(http_code=403, post_attempted=True), "unknown"),
            (result(http_code=0, post_attempted=False), "no"),
        )
        for event, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(app_write_asserted(event), expected)
                self.assertEqual(
                    build_app_outcome_record(make_app_ctx(), event, "t")[
                        "write_asserted"
                    ],
                    expected,
                )

    def test_a_5xx_after_a_post_is_unknown_too(self):
        self.assertEqual(
            app_write_asserted(result(http_code=503, post_attempted=True)), "unknown"
        )

    def test_a_get_failure_asserts_nothing(self):
        """No POST was sent, so nothing can have been written by this command."""
        self.assertEqual(
            app_write_asserted(
                result(status="not_found", http_code=404, post_attempted=False)
            ),
            "no",
        )


class TheSummaryLineTest(unittest.TestCase):
    """Section 11.2: counters derived from the single source, all of them emitted."""

    def test_every_declared_status_has_its_counter(self):
        record = build_app_summary_record(make_app_ctx(), {"updated": 2}, 9, "t")
        for status in APP_ACL_STATUSES:
            with self.subTest(status=status):
                self.assertIn(SUMMARY_COUNT_PREFIX + status, record)

    def test_a_status_at_zero_is_emitted_all_the_same(self):
        """A consumer that has to deal with an absent field writes a predicate on the
        absence, and that is a predicate nobody tests."""
        record = build_app_summary_record(make_app_ctx(), {}, 0, "t")
        self.assertEqual(record["count_created"], 0)

    def test_the_enumeration_is_derived_and_not_copied(self):
        """It is read from the module at call time, so it holds for whatever the single
        source says at that moment - not for what it said at import."""
        counters = {
            key[len(SUMMARY_COUNT_PREFIX):]
            for key in build_app_summary_record(make_app_ctx(), {}, 0, "t")
            if key.startswith(SUMMARY_COUNT_PREFIX)
        }
        self.assertEqual(counters, set(APP_ACL_STATUSES))

    def test_an_undeclared_count_is_emitted_rather_than_lost(self):
        record = build_app_summary_record(make_app_ctx(), {"a_ghost": 4}, 0, "t")
        self.assertEqual(record["count_a_ghost"], 4)

    def test_the_aggregate_blast_radius_is_carried(self):
        record = build_app_summary_record(make_app_ctx(), {}, 42, "t")
        self.assertEqual(record[SUMMARY_IMPACT_TOTAL], 42)

    def test_the_summary_designates_no_target(self):
        """It designates no stanza: emitting empty target fields there would enrol it
        into the population of lines with an empty endpoint."""
        record = build_app_summary_record(make_app_ctx(), {}, 0, "t")
        for key in ("endpoint", "app", "stanza", "stanza_kind", "handler"):
            with self.subTest(key=key):
                self.assertNotIn(key, record)


class TheIntentLineKeysAreTheDeclaredOnesTest(unittest.TestCase):
    """The schema the three restore macros read, frozen from both ends.

    A key renamed here and not in `default/macros.conf` produces an EMPTY rollback set,
    reported as a success, on the only safety net of an irreversible operation. That is
    not a hypothetical failure mode: it is the one the previous project shipped.
    """

    def test_the_builder_produces_exactly_the_declared_keys(self):
        record = build_app_intent_record(make_app_ctx(), result(), "t")
        self.assertEqual(sorted(record), sorted(APP_INTENT_KEYS))

    def test_the_shape_holds_for_a_creation_too(self):
        """The keys are the same on the three natures of operation; what changes is which
        of them carry a value (section 11.2)."""
        record = build_app_intent_record(
            make_app_ctx(),
            result(reversible=REVERSIBLE_FALSE, before=None, inherited=BEFORE),
            "t",
        )
        self.assertEqual(sorted(record), sorted(APP_INTENT_KEYS))
        self.assertEqual(record["before_perms_read"], "")
        self.assertNotEqual(record["inherited_perms_read"], "")

    def test_no_declared_key_carries_a_colon(self):
        """Format constraint reprised from v3.14 section 8.2: a colon in a field name
        breaks the search-time extraction of the journal."""
        for key in APP_INTENT_KEYS:
            with self.subTest(key=key):
                self.assertNotIn(":", key)


class TheCountCreatedIsTheCountOfIrreversibleActsTest(unittest.TestCase):
    """Section 9.4, dispositif 2."""

    def test_it_is_one_of_the_derived_counters(self):
        record = build_app_summary_record(make_app_ctx(), {"created": 3}, 0, "t")
        self.assertEqual(record["count_created"], 3)
        self.assertIn("created", APP_ACL_STATUSES)


if __name__ == "__main__":
    unittest.main()
