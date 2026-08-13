"""State machine of `editappacl` (v4.1 sections 8.6, 8.7, 9, 10, 11.2).

Three things are held here, and the third is the one the increment exists for:

1. **the normative order of the fifteen ranks** of section 8.7, including the two
   precedences the contract states explicitly - `noop` before `irreversible_creation`,
   and `irreversible_creation` before the ceilings;
2. **each of the twelve statuses observed on a real case**. Combined with the syntax-tree
   extraction of `tests/test_appacl_statuses.py`, that attacks the drift of the
   enumeration from both ends: a status added to the code fails there, a status declared
   without a case fails here;
3. **the irreversibility dispositif**: refusal by default, explicit authorization, a
   status of its own, and a journal that records the inherited state OUTSIDE the fields
   the restore reads.
"""

import unittest

from acltools.appacl_model import (
    APP_ACL_STATUSES,
    APP_ACL_WARNINGS,
    REVERSIBLE_FALSE,
    REVERSIBLE_TRUE,
    REVERSIBLE_UNKNOWN,
    STANZA_KIND_APP,
)
from acltools.appacl_pipeline import AppEventProcessor
from acltools.rest import RestResponse

from .appacl_helpers import (
    FIXTURE_TABLE,
    FakeAppRest,
    FakeImpact,
    FakeProvenanceReader,
    app_acl_body,
    make_app_ctx,
    make_app_event,
    make_app_params,
    provenance,
)
from .helpers import FakeClock, FakeJournal

VIEWS_ENDPOINT = "/servicesNS/nobody/my_app/data/ui/views/_acl"
APP_ENDPOINT = "/services/apps/local/my_app/acl"

#: A `local.meta` carrying both generic stanzas: every target of the tests below is a
#: **modification** unless the test says otherwise.
LOCAL_WITH_BOTH = "[]\naccess = read : [ power ]\n\n[views]\naccess = read : [ power ]\n"


def build(
    rest=None,
    journal=None,
    params=None,
    prov=None,
    impact=None,
    roles=(),
    app_disabled_fn=None,
    self_app=None,
):
    return AppEventProcessor(
        params=params or make_app_params(),
        ctx=make_app_ctx(),
        rest=rest or FakeAppRest(),
        journal=journal,
        table=FIXTURE_TABLE,
        provenance=FakeProvenanceReader(
            prov if prov is not None else provenance(local=LOCAL_WITH_BOTH)
        ),
        impact=impact or FakeImpact(3),
        roles_catalog=roles,
        app_disabled_fn=app_disabled_fn,
        self_app=self_app,
        clock=FakeClock(),
    )


class TheNominalWriteTest(unittest.TestCase):

    def test_a_modification_comes_out_updated(self):
        rest = FakeAppRest()
        result = build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(result.status, "updated")
        self.assertEqual(result.reversible, REVERSIBLE_TRUE)
        self.assertEqual(rest.count("POST"), 1)

    def test_the_post_goes_to_the_resolved_endpoint(self):
        rest = FakeAppRest()
        build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(rest.posts()[0][1], VIEWS_ENDPOINT)

    def test_the_namespace_segment_is_nobody_on_every_call(self):
        """Section 4.1, checked on what actually leaves the command."""
        rest = FakeAppRest()
        processor = build(rest=rest)
        processor.process(make_app_event(read="user"))
        for _method, path, _payload in rest.calls:
            with self.subTest(path=path):
                if path.startswith("/servicesNS/"):
                    self.assertTrue(path.startswith("/servicesNS/nobody/"))

    def test_no_owner_is_ever_sent_to_the_family_path(self):
        rest = FakeAppRest()
        build(rest=rest).process(make_app_event(read="user"))
        self.assertNotIn("owner", rest.posts()[0][2])

    def test_the_application_path_carries_the_inert_owner(self):
        rest = FakeAppRest()
        build(rest=rest).process(
            make_app_event(stanza_kind=STANZA_KIND_APP, read="user")
        )
        self.assertEqual(rest.posts()[0][1], APP_ENDPOINT)
        self.assertEqual(rest.posts()[0][2]["owner"], "nobody")

    def test_the_state_read_is_published_before_and_after(self):
        result = build().process(make_app_event(read="user"))
        self.assertEqual(result.before.perms_read, ("power",))
        self.assertEqual(result.after.perms_read, ("user",))


class TheControlOrderTest(unittest.TestCase):
    """The fifteen ranks of section 8.7, and which status wins when several hold."""

    def test_rank_0_invalid_stanza_kind_before_everything(self):
        rest = FakeAppRest()
        result = build(rest=rest).process(
            make_app_event(stanza_kind="", app="", stanza="unknown")
        )
        self.assertEqual(result.status, "rejected")
        self.assertTrue(result.error.startswith("invalid_stanza_kind"))
        self.assertEqual(rest.calls, [])

    def test_rank_1_missing_application(self):
        result = build().process(make_app_event(app=""))
        self.assertEqual(result.error, "app_missing")

    def test_rank_2_the_system_application(self):
        result = build().process(make_app_event(app="system"))
        self.assertEqual(result.error, "app_system_forbidden")

    def test_rank_3_a_duplicate_target_is_refused(self):
        """**DV-2**: a generic stanza has no natural multiplicity, and the last writer
        would win in silence over an operation that may be irreversible."""
        rest = FakeAppRest()
        processor = build(rest=rest)
        first = processor.process(make_app_event(read="user"))
        second = processor.process(make_app_event(read="other"))
        self.assertEqual(first.status, "updated")
        self.assertEqual(second.status, "rejected")
        self.assertEqual(second.error, "duplicate_target")
        self.assertEqual(rest.count("POST"), 1)

    def test_rank_3_precedes_rank_4(self):
        """Two identical unresolvable rows: the second is a duplicate, not a second
        `unresolved_family`."""
        processor = build()
        first = processor.process(make_app_event(handler="", stanza="unknown_family"))
        second = processor.process(make_app_event(handler="", stanza="unknown_family"))
        self.assertEqual(first.error, "unresolved_family:unknown_family")
        self.assertEqual(second.error, "duplicate_target")

    def test_rank_3_also_catches_two_routes_to_the_same_endpoint(self):
        """One row designating the family by handler, the other by name: different
        designations, same stanza - and the second one is still refused."""
        rest = FakeAppRest()
        processor = build(rest=rest)
        processor.process(make_app_event(handler="data/ui/views", stanza="", read="a"))
        second = processor.process(
            make_app_event(handler="", stanza="views", read="b")
        )
        self.assertEqual(second.error, "duplicate_target")
        self.assertEqual(rest.count("POST"), 1)

    def test_rank_4_unresolved_family(self):
        rest = FakeAppRest()
        result = build(rest=rest).process(
            make_app_event(handler="", stanza="visualizations")
        )
        self.assertEqual(result.error, "unresolved_family:visualizations")
        self.assertEqual(rest.calls, [])

    def test_rank_5_a_404_is_not_found(self):
        rest = FakeAppRest(get_responses={VIEWS_ENDPOINT: RestResponse(404, b"")})
        result = build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(result.status, "not_found")
        self.assertEqual(rest.count("POST"), 0)

    def test_rank_5bis_a_403_is_forbidden(self):
        rest = FakeAppRest(get_responses={VIEWS_ENDPOINT: RestResponse(403, b"")})
        result = build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(result.status, "forbidden")

    def test_rank_5ter_a_5xx_on_the_read_is_an_error(self):
        rest = FakeAppRest(get_responses={VIEWS_ENDPOINT: RestResponse(503, b"")})
        result = build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(result.status, "error")
        self.assertTrue(result.error.startswith("get_failed:503"))

    def test_an_unparseable_read_is_an_error(self):
        rest = FakeAppRest(get_responses={VIEWS_ENDPOINT: RestResponse(200, b"{no")})
        result = build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(result.status, "error")
        self.assertTrue(result.error.startswith("get_parse_failed"))

    def test_rank_6_an_empty_sharing(self):
        result = build().process(make_app_event(sharing=""))
        self.assertEqual(result.error, "sharing_empty_not_allowed")

    def test_rank_7_an_invalid_sharing(self):
        result = build().process(make_app_event(sharing="user"))
        self.assertEqual(result.error, "invalid_sharing:user")

    def test_rank_8_unreadable_provenance_without_allow_create(self):
        rest = FakeAppRest()
        result = build(
            rest=rest,
            prov=provenance(local_error="PermissionError"),
            params=make_app_params(allow_create=False),
        ).process(make_app_event(read="user"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "provenance_unavailable")
        self.assertEqual(rest.count("POST"), 0)

    def test_rank_8_unreadable_provenance_with_allow_create(self):
        result = build(
            prov=provenance(local_error="PermissionError"),
            params=make_app_params(allow_create=True),
        ).process(make_app_event(read="user"))
        self.assertEqual(result.reversible, REVERSIBLE_UNKNOWN)
        self.assertIn("provenance_unavailable", result.warnings)

    def test_rank_9_an_identical_state_is_a_noop(self):
        rest = FakeAppRest()
        result = build(rest=rest).process(make_app_event(read="power"))
        self.assertEqual(result.status, "noop")
        self.assertEqual(rest.count("POST"), 0)

    def test_rank_9bis_an_identical_inherited_state(self):
        """The heart of what the file read buys: the value is already right, but it is
        INHERITED. Materializing it would change no right today and would remove the
        family from the reach of `[]` for good (Q0-3)."""
        result = build(prov=provenance(local=None)).process(
            make_app_event(read="power")
        )
        self.assertEqual(result.status, "noop_inherited")
        self.assertIn("not_materialized", result.warnings)

    def test_rank_9_precedes_rank_10(self):
        """A target already compliant never triggers the irreversibility refusal: no
        write would take place."""
        result = build(
            prov=provenance(local=None), params=make_app_params(allow_create=False)
        ).process(make_app_event(read="power"))
        self.assertEqual(result.status, "noop_inherited")

    def test_rank_10_a_creation_is_refused_by_default(self):
        rest = FakeAppRest()
        result = build(
            rest=rest,
            prov=provenance(local=None),
            params=make_app_params(allow_create=False),
        ).process(make_app_event(read="user"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "irreversible_creation")
        self.assertEqual(rest.count("POST"), 0)

    def test_rank_10_precedes_rank_12(self):
        """The irreversibility refusal is a property of the target, the ceiling a
        property of the batch: an operator must see the first even when the second
        would bite."""
        rest = FakeAppRest()
        processor = build(
            rest=rest,
            prov=provenance(local=None),
            params=make_app_params(allow_create=False, max_stanzas=1),
        )
        processor.counter = 5
        result = processor.process(make_app_event(read="user"))
        self.assertEqual(result.error, "irreversible_creation")

    def test_rank_11_an_added_unknown_role(self):
        result = build(
            params=make_app_params(validate_roles=True), roles=("power",)
        ).process(make_app_event(read="ghost"))
        self.assertEqual(result.status, "invalid_role")
        self.assertEqual(result.error, "invalid_role:ghost")

    def test_rank_11_a_preserved_unknown_role_only_warns(self):
        result = build(
            params=make_app_params(validate_roles=True), roles=("user",)
        ).process(make_app_event(write="user"))
        self.assertEqual(result.status, "updated")
        self.assertIn("stale_role_preserved:power", " ".join(result.warnings))

    def test_rank_12_the_stanza_ceiling(self):
        rest = FakeAppRest()
        processor = build(rest=rest, params=make_app_params(max_stanzas=1))
        first = processor.process(
            make_app_event(stanza="views", handler="", read="user")
        )
        second = processor.process(
            make_app_event(stanza="macros", handler="", read="user")
        )
        self.assertEqual(first.status, "updated")
        self.assertEqual(second.status, "skipped_ceiling")
        self.assertEqual(rest.count("POST"), 1)
        self.assertEqual(processor.skipped_ceiling, 1)

    def test_rank_13_the_impact_ceiling(self):
        rest = FakeAppRest()
        processor = build(
            rest=rest,
            params=make_app_params(max_impacted_objects=5),
            impact=FakeImpact(4),
        )
        first = processor.process(
            make_app_event(stanza="views", handler="", read="user")
        )
        second = processor.process(
            make_app_event(stanza="macros", handler="", read="user")
        )
        self.assertEqual(first.status, "updated")
        self.assertEqual(second.status, "skipped_impact_ceiling")
        self.assertEqual(processor.skipped_impact_ceiling, 1)

    def test_rank_13_a_single_target_larger_than_the_ceiling(self):
        """It is up to the operator to state the volume they are about to move."""
        processor = build(
            params=make_app_params(max_impacted_objects=10), impact=FakeImpact(999)
        )
        result = processor.process(make_app_event(read="user"))
        self.assertEqual(result.status, "skipped_impact_ceiling")

    def test_rank_12_precedes_rank_13(self):
        processor = build(
            params=make_app_params(max_stanzas=1, max_impacted_objects=1),
            impact=FakeImpact(50),
        )
        processor.counter = 1
        result = processor.process(make_app_event(read="user"))
        self.assertEqual(result.status, "skipped_ceiling")

    def test_rank_14_dryrun(self):
        rest = FakeAppRest()
        result = build(rest=rest, params=make_app_params(dryrun=True)).process(
            make_app_event(read="user")
        )
        self.assertEqual(result.status, "dryrun")
        self.assertEqual(rest.count("POST"), 0)


class TheSimulationWritesNothingTest(unittest.TestCase):
    """Section 10.2: neither ceiling ever fires in simulation, which sends no POST.

    That property is what makes a ceiling as low as five tenable - the friction is on the
    write, never on the review - and it is what lets the end-of-run message carry three
    numbers about the **whole** batch.
    """

    def test_no_post_is_ever_sent(self):
        rest = FakeAppRest()
        processor = build(rest=rest, params=make_app_params(dryrun=True, max_stanzas=1))
        for family in ("views", "macros", "savedsearches"):
            processor.process(make_app_event(stanza=family, handler="", read="user"))
        self.assertEqual(rest.count("POST"), 0)

    def test_no_ceiling_fires(self):
        processor = build(
            params=make_app_params(
                dryrun=True, max_stanzas=1, max_impacted_objects=1
            ),
            impact=FakeImpact(100),
        )
        statuses = [
            processor.process(
                make_app_event(stanza=family, handler="", read="user")
            ).status
            for family in ("views", "macros", "savedsearches")
        ]
        self.assertEqual(statuses, ["dryrun", "dryrun", "dryrun"])
        self.assertEqual(processor.skipped_ceiling, 0)
        self.assertEqual(processor.skipped_impact_ceiling, 0)

    def test_the_three_numbers_of_the_end_of_simulation_message(self):
        """Section 10.4 point 5: what would be written, what it would move, and how much
        of it cannot be undone."""
        processor = build(
            params=make_app_params(dryrun=True, allow_create=True),
            prov=provenance(local="[views]\na = 1\n"),
            impact=FakeImpact(7),
        )
        processor.process(make_app_event(stanza="views", handler="", read="user"))
        processor.process(make_app_event(stanza="macros", handler="", read="user"))
        self.assertEqual(processor.planned_writes, 2)
        self.assertEqual(processor.planned_impact, 14)
        self.assertEqual(processor.planned_creations, 1)

    def test_a_refused_creation_is_visible_in_simulation(self):
        """Section 9.3: the operator learns BEFORE writing which targets demand the
        explicit act, and which are simple modifications."""
        result = build(
            params=make_app_params(dryrun=True, allow_create=False),
            prov=provenance(local=None),
        ).process(make_app_event(read="user"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "irreversible_creation")

    def test_the_impact_is_estimated_in_simulation_too(self):
        """Section 10.3: the calculation happens for every target a real run would
        write. Making it optional would restore the blindness the increment lifts."""
        result = build(
            params=make_app_params(dryrun=True), impact=FakeImpact(42)
        ).process(make_app_event(read="user"))
        self.assertEqual(result.impacted_estimate, 42)


class TheIrreversibilityTest(unittest.TestCase):
    """Section 9: refusal by default, explicit authorization, distinct status."""

    def test_an_authorized_creation_comes_out_created(self):
        result = build(
            prov=provenance(local=None), params=make_app_params(allow_create=True)
        ).process(make_app_event(read="user"))
        self.assertEqual(result.status, "created")
        self.assertEqual(result.reversible, REVERSIBLE_FALSE)
        self.assertIn("irreversible_creation", result.warnings)

    def test_a_modification_is_reversible(self):
        result = build().process(make_app_event(read="user"))
        self.assertEqual(result.reversible, REVERSIBLE_TRUE)

    def test_the_three_states_of_reversible_are_reachable(self):
        cases = {
            REVERSIBLE_TRUE: provenance(local=LOCAL_WITH_BOTH),
            REVERSIBLE_FALSE: provenance(local=None),
            REVERSIBLE_UNKNOWN: provenance(local_error="OSError"),
        }
        for expected, prov in cases.items():
            with self.subTest(reversible=expected):
                result = build(
                    prov=prov, params=make_app_params(allow_create=True)
                ).process(make_app_event(read="user"))
                self.assertEqual(result.reversible, expected)

    def test_a_created_stanza_is_counted_apart(self):
        """Section 9.4 dispositif 2: `count_created` makes the irreversible act
        countable in any `stats count by acl_status`."""
        processor = build(
            prov=provenance(local=None), params=make_app_params(allow_create=True)
        )
        processor.process(make_app_event(stanza="views", handler="", read="user"))
        processor.process(make_app_event(stanza="macros", handler="", read="user"))
        self.assertEqual(processor.counts.get("created"), 2)

    def test_the_application_default_creation_is_irreversible_too(self):
        """Writing `[]` into an app that had none masks the `[]` of its `default.meta`
        for good - that is, the default rights shipped with the application."""
        result = build(
            prov=provenance(local=None), params=make_app_params(allow_create=True)
        ).process(make_app_event(stanza_kind=STANZA_KIND_APP, read="user"))
        self.assertEqual(result.status, "created")


class TheJournalOrderingTest(unittest.TestCase):
    """Section 11.2: intent before the call, outcome after every event."""

    def test_an_intent_line_precedes_every_post(self):
        journal = FakeJournal()
        build(journal=journal).process(make_app_event(read="user"))
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(len(journal.outcomes), 1)

    def test_a_failed_intent_cancels_the_post(self):
        """Section 11.2: without the write-ahead line, a write that answered non-2xx
        while writing anyway would leave no trace at all."""
        rest = FakeAppRest()
        journal = FakeJournal(fail_intent=True)
        result = build(rest=rest, journal=journal).process(make_app_event(read="user"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error, "journal_intent_failed")
        self.assertEqual(rest.count("POST"), 0)
        self.assertFalse(result.journaled)

    def test_a_failed_outcome_only_warns(self):
        journal = FakeJournal(fail_outcome=True)
        result = build(journal=journal).process(make_app_event(read="user"))
        self.assertEqual(result.status, "updated")
        self.assertIn("journal_outcome_failed", result.warnings)

    def test_one_outcome_line_per_output_event_whatever_the_status(self):
        """Invariant 1 of section 11.2, on statuses that never reach the POST."""
        journal = FakeJournal()
        processor = build(journal=journal)
        processor.process(make_app_event(stanza_kind=""))
        processor.process(make_app_event(app=""))
        processor.process(make_app_event(handler="", stanza="unknown"))
        processor.process(make_app_event(read="user"))
        self.assertEqual(len(journal.outcomes), 4)
        self.assertEqual(len(journal.intents), 1)

    def test_no_intent_line_in_simulation(self):
        journal = FakeJournal()
        build(journal=journal, params=make_app_params(dryrun=True)).process(
            make_app_event(read="user")
        )
        self.assertEqual(journal.intents, [])
        self.assertEqual(len(journal.outcomes), 1)

    def test_the_summary_counts_every_declared_status(self):
        processor = build(journal=FakeJournal())
        processor.process(make_app_event(read="user"))
        summary = processor.build_summary()
        for status in APP_ACL_STATUSES:
            with self.subTest(status=status):
                self.assertIn("count_%s" % status, summary)
        self.assertEqual(summary["count_updated"], 1)
        self.assertEqual(summary["count_created"], 0)

    def test_the_summary_carries_the_aggregate_blast_radius(self):
        processor = build(impact=FakeImpact(6))
        processor.process(make_app_event(stanza="views", handler="", read="user"))
        processor.process(make_app_event(stanza="macros", handler="", read="user"))
        self.assertEqual(processor.build_summary()["impacted_estimate_total"], 12)


class TheNonTwoXxAnswerTest(unittest.TestCase):
    """Section 4.3: a non-2xx does NOT prove that nothing was written.

    Measured: a `POST` answering `403 Not removable: ...` wrote a stanza anyway. Every
    artifact of this app must treat the state of such a target as **undetermined**.
    """

    def _refused(self, code):
        rest = FakeAppRest(post_responses={VIEWS_ENDPOINT: RestResponse(code, b"no")})
        journal = FakeJournal()
        result = build(rest=rest, journal=journal).process(make_app_event(read="user"))
        return result, journal

    def test_the_target_carries_write_may_have_occurred(self):
        result, _journal = self._refused(403)
        self.assertEqual(result.status, "error")
        self.assertIn("write_may_have_occurred", result.warnings)

    def test_the_journal_records_an_unknown_write(self):
        _result, journal = self._refused(403)
        self.assertEqual(journal.outcomes[0]["write_asserted"], "unknown")

    def test_a_5xx_also_warns_about_the_runtime_divergence(self):
        result, _journal = self._refused(503)
        self.assertIn("runtime_divergence_possible", result.warnings)
        self.assertIn("write_may_have_occurred", result.warnings)

    def test_a_2xx_asserts_the_write(self):
        journal = FakeJournal()
        build(journal=journal).process(make_app_event(read="user"))
        self.assertEqual(journal.outcomes[0]["write_asserted"], "yes")

    def test_a_status_without_a_call_asserts_nothing(self):
        journal = FakeJournal()
        build(journal=journal).process(make_app_event(read="power"))
        self.assertEqual(journal.outcomes[0]["write_asserted"], "no")

    def test_the_counter_is_incremented_by_a_refused_post_too(self):
        """The ceiling counts POSTs **sent**: a refused one may have written."""
        rest = FakeAppRest(post_responses={VIEWS_ENDPOINT: RestResponse(403, b"")})
        processor = build(rest=rest)
        processor.process(make_app_event(read="user"))
        self.assertEqual(processor.counter, 1)


class TheWarningsAreDeclaredTest(unittest.TestCase):
    """Section 8.8: `acl_warning` has a closed domain."""

    def test_every_warning_the_pipeline_emits_is_declared(self):
        processors = []
        rest = FakeAppRest(post_responses={VIEWS_ENDPOINT: RestResponse(503, b"")})
        processors.append(
            (build(rest=rest, journal=FakeJournal(fail_outcome=True)),
             make_app_event(read="user"))
        )
        processors.append(
            (build(prov=provenance(local=None),
                   params=make_app_params(allow_create=True)),
             make_app_event(read="user"))
        )
        processors.append(
            (build(prov=provenance(local_error="OSError"),
                   params=make_app_params(allow_create=True)),
             make_app_event(read="user"))
        )
        processors.append(
            (build(prov=provenance(local=None)), make_app_event(read="power"))
        )
        processors.append((build(impact=FakeImpact(0)), make_app_event(read="user")))
        processors.append((build(), make_app_event(read="user", sharing="global")))
        processors.append(
            (build(params=make_app_params(validate_roles=True), roles=("user",)),
             make_app_event(write="user"))
        )
        processors.append(
            (build(app_disabled_fn=lambda app: True), make_app_event(read="user"))
        )
        processors.append(
            (build(self_app="my_app"), make_app_event(read="user"))
        )
        seen = set()
        for processor, event in processors:
            for warning in processor.process(event).warnings:
                seen.add(warning.split(":", 1)[0])
        for warning in seen:
            with self.subTest(warning=warning):
                self.assertIn(warning, APP_ACL_WARNINGS)
        # The set is not empty, otherwise the loop above proves nothing.
        self.assertGreaterEqual(len(seen), 8)

    def test_the_self_application_is_warned_and_not_refused(self):
        """Section 13.4 point 5: the state stays recoverable outside the tool, and
        refusing would remove a legitimate capability."""
        result = build(self_app="my_app").process(make_app_event(read="user"))
        self.assertEqual(result.status, "updated")
        self.assertIn("self_app_target", result.warnings)

    def test_a_disabled_application_is_warned_and_not_refused(self):
        result = build(app_disabled_fn=lambda app: True).process(
            make_app_event(read="user")
        )
        self.assertEqual(result.status, "updated")
        self.assertIn("app_disabled", result.warnings)

    def test_a_target_moving_nothing_today_is_still_written(self):
        result = build(impact=FakeImpact(0)).process(make_app_event(read="user"))
        self.assertEqual(result.status, "updated")
        self.assertIn("no_inheriting_object", result.warnings)


class EveryDeclaredStatusIsObservedTest(unittest.TestCase):
    """Invariant of section 11.2, and the second half of the anti-drift device.

    A status declared in `APP_ACL_STATUSES` with no real case fails here; a status
    produced by the code and undeclared fails in `tests/test_appacl_statuses.py`.
    """

    def _observe(self):
        seen = {}

        def record(processor, event):
            seen[processor.process(event).status] = True

        record(build(), make_app_event(read="user"))                      # updated
        record(
            build(prov=provenance(local=None),
                  params=make_app_params(allow_create=True)),
            make_app_event(read="user"),
        )                                                                 # created
        record(build(), make_app_event(read="power"))                     # noop
        record(build(prov=provenance(local=None)),
               make_app_event(read="power"))                              # noop_inherited
        record(build(params=make_app_params(dryrun=True)),
               make_app_event(read="user"))                               # dryrun
        record(build(), make_app_event(app=""))                           # rejected
        record(
            build(rest=FakeAppRest(
                get_responses={VIEWS_ENDPOINT: RestResponse(404, b"")})),
            make_app_event(read="user"),
        )                                                                 # not_found
        record(
            build(rest=FakeAppRest(
                get_responses={VIEWS_ENDPOINT: RestResponse(403, b"")})),
            make_app_event(read="user"),
        )                                                                 # forbidden
        record(
            build(params=make_app_params(validate_roles=True), roles=()),
            make_app_event(read="ghost"),
        )                                                                 # invalid_role
        ceiling = build(params=make_app_params(max_stanzas=1))
        ceiling.counter = 1
        record(ceiling, make_app_event(read="user"))                      # skipped_ceiling
        impact = build(
            params=make_app_params(max_impacted_objects=1), impact=FakeImpact(9)
        )
        record(impact, make_app_event(read="user"))            # skipped_impact_ceiling
        record(
            build(rest=FakeAppRest(
                get_responses={VIEWS_ENDPOINT: RestResponse(500, b"")})),
            make_app_event(read="user"),
        )                                                                 # error
        return set(seen)

    def test_each_of_the_twelve_statuses_is_produced_by_a_real_case(self):
        observed = self._observe()
        for status in APP_ACL_STATUSES:
            with self.subTest(status=status):
                self.assertIn(status, observed)

    def test_no_status_outside_the_enumeration_is_produced(self):
        self.assertEqual(self._observe() - set(APP_ACL_STATUSES), set())


class TheStateIsReReadForEveryTargetTest(unittest.TestCase):
    """Section 13.4 point 7: no ACL is cached from one row to the next.

    The two read paths have **independent** handler caches - measured, one up to date
    while the other is stale at the same instant - and their consistency after a REST
    write has not been measured (O-3).
    """

    def test_two_different_targets_are_two_reads(self):
        rest = FakeAppRest()
        processor = build(rest=rest)
        processor.process(make_app_event(stanza="views", handler="", read="user"))
        processor.process(make_app_event(stanza="macros", handler="", read="user"))
        self.assertEqual(rest.count("GET"), 2)

    def test_the_read_uses_the_same_string_as_the_write(self):
        """The endpoint is a string contract: computed once, never recomputed."""
        rest = FakeAppRest()
        build(rest=rest).process(make_app_event(read="user"))
        self.assertEqual(rest.gets()[0][1], rest.posts()[0][1])


class TheInternalErrorIsContainedTest(unittest.TestCase):
    """No unexpected exception crosses the pipeline (section 13.1)."""

    def test_a_broken_rest_port_becomes_an_event_error(self):
        class Exploding(object):
            def get_app_acl(self, path):
                raise RuntimeError("boom")

        processor = build()
        processor._rest = Exploding()
        result = processor.process(make_app_event(read="user"))
        self.assertEqual(result.status, "error")
        self.assertTrue(result.error.startswith("internal:RuntimeError"))


if __name__ == "__main__":
    unittest.main()
