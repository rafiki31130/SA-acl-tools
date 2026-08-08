"""Abstention on objects derived from an `eventtype` (sections 3.4, 5.4 rank 0, D-18).

Two levels:

- the identification itself (`acltools.derived`), and above all the proof that it is
  **discovered** and not constructed - that is the third normative property of
  section 3.4;
- its insertion at rank 0 of the order of section 5.4, with the invariants that come
  with it: no POST, counter not incremented, `outcome` line present.
"""

import unittest

from acltools.derived import (
    CarrierProbe,
    designated_carrier,
    split_composite_key,
)
from acltools.pipeline import EventProcessor, _Work
from acltools.rest import RestResponse

from .helpers import (
    FIXTURE_MAPPING,
    FakeJournal,
    FakeRest,
    acl_body,
    make_ctx,
    make_event,
    make_params,
)

#: Application of the witness objects, and role held before the write. Both are set
#: explicitly below so the paths and the idempotence case do not silently depend on
#: the defaults of `make_event` and `acl_body`.
APP = "my_app"
CURRENT_WRITE_ROLE = "legacy_role"

#: Path of the witness derived object, as `build_object_path` produces it.
DERIVED_PATH = "/servicesNS/nobody/my_app/saved/fvtags/eventtype%3Dmy_eventtype"

#: Path of the confirmation GET on the carrier. This is the call that makes the
#: relation **observed**: without it, it would merely be assumed.
CARRIER_PATH = "/servicesNS/nobody/my_app/saved/eventtypes/my_eventtype"


def derived_rest(carrier_status=200, **kwargs):
    """`FakeRest` serving an `fvtags` object whose identity splunkd names."""
    return FakeRest(
        default_get=RestResponse(
            200,
            acl_body(
                app=APP,
                name="eventtype=my_eventtype",
                write=(CURRENT_WRITE_ROLE,),
            ),
        ),
        json_responses={CARRIER_PATH: RestResponse(carrier_status, b'{"entry":[]}')},
        default_json=RestResponse(404, b"{}"),
        **kwargs
    )


def derived_event(**kwargs):
    kwargs.setdefault("title", "eventtype=my_eventtype")
    kwargs.setdefault("app", APP)
    kwargs.setdefault("eai_type", "fvtags")
    kwargs.setdefault("write", "new_role_admin")
    return make_event(**kwargs)


def run(rest, event, params=None, journal=None):
    processor = EventProcessor(
        params or make_params(),
        make_ctx(),
        rest,
        journal=journal,
        mapping=FIXTURE_MAPPING,
    )
    return processor.process(event), processor


class CompositeKeyTest(unittest.TestCase):
    """The `<field>=<value>` grammar of the `fvtags` family."""

    def test_split_on_the_first_equals_sign(self):
        self.assertEqual(
            split_composite_key("eventtype=my_eventtype"),
            ("eventtype", "my_eventtype"),
        )

    def test_a_value_may_contain_an_equals_sign(self):
        """Measured on the reference platform: the cascade follows this reading.

        An `eventtype` named `a=b` gives rise to a derived object named
        `eventtype=a=b`, and the ACL POST on the carrier does cascade to it. A split on
        the **last** equals sign, or a rejection of names holding several equals signs,
        would miss this case.
        """
        self.assertEqual(split_composite_key("eventtype=a=b"), ("eventtype", "a=b"))

    def test_forms_outside_the_grammar(self):
        for name in (None, "", "no_equals_sign", "=value_without_field",
                     "field_without_value="):
            with self.subTest(name=name):
                self.assertIsNone(split_composite_key(name))


class CarrierDesignationTest(unittest.TestCase):
    """`designated_carrier` reads a designation; it concludes nothing about
    existence."""

    def test_an_eventtype_derived_object_designates_its_carrier(self):
        self.assertEqual(
            designated_carrier("saved/fvtags", "eventtype=my_eventtype"),
            "my_eventtype",
        )

    def test_the_administration_handler_is_recognized(self):
        self.assertEqual(
            designated_carrier("admin/fvtags", "eventtype=my_eventtype"),
            "my_eventtype",
        )

    def test_an_ordinary_field_value_tag_designates_no_eventtype(self):
        """`my_field=my_value` is a field tag, not an object derived from an
        `eventtype`."""
        self.assertIsNone(
            designated_carrier("saved/fvtags", "my_field=my_value")
        )

    def test_the_family_is_a_precondition(self):
        """An object of another family named `eventtype=...` is not a derived object.

        Without this guard rail, a saved search for which the operator had picked that
        name would be skipped from any modification. The family comes from the resolved
        handler path (section 5.2), a platform datum and not the name.
        """
        for handler in ("saved/searches", "data/ui/views", "admin/tags"):
            with self.subTest(handler=handler):
                self.assertIsNone(
                    designated_carrier(handler, "eventtype=my_eventtype")
                )


class CarrierProbeTest(unittest.TestCase):
    """The relation is **confirmed by the platform**, never assumed."""

    def test_the_carrier_is_confirmed_by_a_real_get(self):
        rest = derived_rest()
        carrier, warning = CarrierProbe(rest).carrier_of(
            APP, "saved/fvtags", "eventtype=my_eventtype"
        )
        self.assertEqual(carrier, "my_eventtype")
        self.assertIsNone(warning)
        self.assertIn(
            ("JSON", CARRIER_PATH, None),
            rest.calls,
            "the existence of the carrier must be asked of the platform",
        )

    def test_orphan_derived_object_the_carrier_does_not_exist(self):
        """HTTP 404: no carrier can cascade, the object stays modifiable.

        This is the counterpart that makes the identification a discovery: a naming
        heuristic would answer "derived" here as well.
        """
        rest = derived_rest(carrier_status=404)
        carrier, warning = CarrierProbe(rest).carrier_of(
            APP, "saved/fvtags", "eventtype=my_eventtype"
        )
        self.assertIsNone(carrier)
        self.assertIsNone(warning)

    def test_inconclusive_response_conservative_abstention_and_traced(self):
        for code in (403, 500, 503, 0):
            with self.subTest(code=code):
                rest = derived_rest(carrier_status=code)
                carrier, warning = CarrierProbe(rest).carrier_of(
                    APP, "saved/fvtags", "eventtype=my_eventtype"
                )
                self.assertEqual(carrier, "my_eventtype")
                self.assertEqual(
                    warning, "carrier_probe_inconclusive:%d" % code
                )

    def test_a_single_call_per_distinct_carrier(self):
        rest = derived_rest()
        probe = CarrierProbe(rest)
        for _ in range(3):
            probe.carrier_of(
                APP, "saved/fvtags", "eventtype=my_eventtype"
            )
        self.assertEqual(rest.count("JSON"), 1)

    def test_no_call_outside_the_fvtags_family(self):
        rest = derived_rest()
        CarrierProbe(rest).carrier_of(
            APP, "saved/searches", "eventtype=my_eventtype"
        )
        self.assertEqual(rest.count("JSON"), 0)


class Rank0Test(unittest.TestCase):
    """Insertion of the check at rank 0 of the normative order of section 5.4."""

    def test_status_and_error(self):
        result, _ = run(derived_rest(), derived_event())
        self.assertEqual(result.status, "skipped_derived")
        self.assertEqual(result.error, "derived_object:my_eventtype")

    def test_no_post_and_counter_not_incremented(self):
        rest = derived_rest()
        _, processor = run(rest, derived_event())
        self.assertEqual(rest.posts(), [])
        self.assertEqual(processor.counter, 0)
        self.assertFalse(processor._written)

    def test_outcome_line_present_and_no_intent_line(self):
        journal = FakeJournal()
        result, _ = run(derived_rest(), derived_event(), journal=journal)
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.intents, [])
        self.assertEqual(journal.outcomes[0]["status"], "skipped_derived")
        self.assertEqual(journal.outcomes[0]["endpoint"], DERIVED_PATH)
        self.assertFalse(result.journaled)

    def test_the_outcome_line_carries_no_state(self):
        """The merge was not computed: section 8.2 therefore excludes
        `before_*` / `after_*`."""
        journal = FakeJournal()
        run(derived_rest(), derived_event(), journal=journal)
        for key in journal.outcomes[0]:
            self.assertFalse(
                key.startswith("before_") or key.startswith("after_"), key
            )

    def test_rank_0_precedes_can_change_perms(self):
        rest = derived_rest()
        rest.default_get = RestResponse(
            200, acl_body(name="eventtype=my_eventtype", can_change_perms=False)
        )
        result, _ = run(rest, derived_event())
        self.assertEqual(result.status, "skipped_derived")

    def test_rank_0_precedes_the_refusal_of_an_empty_sharing(self):
        result, _ = run(
            derived_rest(),
            derived_event(sharing=""),
            params=make_params(),
        )
        self.assertEqual(result.status, "skipped_derived")

    def test_rank_0_precedes_dryrun(self):
        result, _ = run(
            derived_rest(), derived_event(), params=make_params(dryrun=True)
        )
        self.assertEqual(result.status, "skipped_derived")

    def test_rank_0_precedes_noop(self):
        """An already-conforming derived object exits as `skipped_derived`, not as
        `noop`.

        The useful information is that the object is out of the write perimeter.
        """
        result, _ = run(derived_rest(), derived_event(write=CURRENT_WRITE_ROLE))
        self.assertEqual(result.status, "skipped_derived")

    def test_an_orphan_derived_object_is_processed_normally(self):
        rest = derived_rest(carrier_status=404)
        result, _ = run(rest, derived_event())
        self.assertEqual(result.status, "updated")
        self.assertEqual(len(rest.posts()), 1)

    def test_the_identity_comes_from_the_get_not_from_the_title(self):
        """Section 5.3 lays down that the GET is authoritative.

        The `title` of the event designates an `eventtype`, but splunkd returns another
        identity: the object is not a derived one. Relying on the `title` would make
        rank 0 bypassable, and above all triggerable, by an upstream `eval`.
        """
        rest = derived_rest()
        rest.default_get = RestResponse(200, acl_body(name="my_field=my_value"))
        result, _ = run(rest, derived_event())
        self.assertEqual(result.status, "updated")

    def test_the_inconclusive_probe_warning_is_exposed_in_the_output(self):
        rest = derived_rest(carrier_status=503)
        result, _ = run(rest, derived_event())
        self.assertEqual(result.status, "skipped_derived")
        self.assertIn("carrier_probe_inconclusive:503", result.warnings)

    def test_no_cost_on_a_batch_without_derived_objects(self):
        """Rank 0 emits no call on the families that are not concerned."""
        rest = derived_rest()
        run(rest, make_event(eai_type="savedsearch", write="new_role_admin"))
        self.assertEqual(rest.count("JSON"), 0)


class RankZeroAndDeduplicationTest(unittest.TestCase):
    """A-11: rank 0 must not depend on a property of section 10.8.

    The deduplication short circuit hands back without emitting a GET. It must
    therefore restore the platform identity itself, failing which `designated_carrier`
    would receive `None` and rank 0 would be ineffective on a second occurrence of the
    same endpoint.

    The path **is not reachable** in the delivered state: a derived object is skipped
    at rank 0, it emits no POST, so it enters neither `_written` nor `_failed`. The
    consistency holds, but it holds by a property of **another** mechanism. These two
    tests reach the path deliberately, by injecting the run memory that an evolution of
    the deduplication would produce, and freeze the **local** guarantee that replaces
    it.
    """

    def _processor(self, rest):
        return EventProcessor(
            make_params(), make_ctx(), rest, mapping=FIXTURE_MAPPING
        )

    def test_the_short_circuit_restores_the_identity_returned_by_splunkd(self):
        """Invariant of `_read_state`: the same `platform_name` by both paths."""
        rest = derived_rest()
        processor = self._processor(rest)

        first = _Work(derived_event())
        first.endpoint = DERIVED_PATH
        state = processor._read_state(first)
        self.assertEqual(first.platform_name, "eventtype=my_eventtype")

        # Memory that a completed POST on this endpoint would leave behind.
        processor._written[DERIVED_PATH] = state

        second = _Work(derived_event())
        second.endpoint = DERIVED_PATH
        processor._read_state(second)
        self.assertEqual(len(rest.gets()), 1)          # the short circuit did its work
        self.assertEqual(second.platform_name, first.platform_name)

    def test_an_already_memorized_derived_object_stays_skipped_at_rank_0(self):
        """The consequence: the abstention survives deduplication.

        Without the restoration, this second pass would come out `updated`, with a
        POST.
        """
        rest = derived_rest()
        processor = self._processor(rest)

        seed = _Work(derived_event())
        seed.endpoint = DERIVED_PATH
        processor._written[DERIVED_PATH] = processor._read_state(seed)

        result = processor.process(derived_event(write="yet_another_role"))
        self.assertEqual(result.status, "skipped_derived")
        self.assertEqual(result.error, "derived_object:my_eventtype")
        self.assertEqual(len(rest.posts()), 0)


if __name__ == "__main__":                                   # pragma: no cover
    unittest.main()
