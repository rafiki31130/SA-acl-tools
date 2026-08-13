"""Impact estimate (v4.3 section 10.3).

The estimate is what makes the second ceiling mean anything: `max_stanzas` bounds the
number of acts, `max_impacted_objects` bounds what those acts **move**, and neither is
enough alone - one write on the default of a large application is a single act with an
immense reach, twenty writes on empty families move nothing.

Two implementation points are frozen here because they are decisions rather than
transcriptions: the subtraction is on **counts** (bound 3 of section 6.2 forbids listing
object stanza names), and the enumeration excludes what this application's stanzas do not
govern - objects belonging to another app, and private objects.
"""

import unittest

from acltools.appacl_impact import NO_INHERITING_OBJECT, ImpactEstimator
from acltools.appacl_model import STANZA_KIND_APP, STANZA_KIND_FAMILY, AppTarget
from acltools.rest import RestResponse

from .appacl_helpers import (
    FIXTURE_TABLE,
    FakeAppRest,
    FakeProvenanceReader,
    frozen_stanza,
    object_listing_body,
    provenance,
    touched_stanza,
)

VIEWS_LISTING = "/servicesNS/nobody/my_app/data/ui/views"
SEARCHES_LISTING = "/servicesNS/nobody/my_app/saved/searches"


def _target(kind=STANZA_KIND_FAMILY, stanza="views", handler="data/ui/views"):
    return AppTarget(
        app="my_app",
        stanza_kind=kind,
        stanza=stanza,
        handler=handler,
        endpoint="/endpoint/%s" % (stanza or "app_default"),
    )


class TheFamilyEstimateTest(unittest.TestCase):

    def _estimator(self, listing, local=None, default=None):
        rest = FakeAppRest(
            json_responses={VIEWS_LISTING: RestResponse(200, listing)},
            default_json=RestResponse(200, b'{"entry":[]}'),
        )
        reader = FakeProvenanceReader(provenance(local=local, default=default))
        return ImpactEstimator(rest, reader, FIXTURE_TABLE), rest

    def test_objects_of_the_family_minus_the_frozen_ones(self):
        listing = object_listing_body(
            [("one", "my_app"), ("two", "my_app"), ("three", "my_app")]
        )
        estimator, _rest = self._estimator(listing, local=frozen_stanza("views/one"))
        self.assertEqual(estimator.estimate(_target()), 2)

    def test_a_frozen_stanza_present_in_both_files_counts_once(self):
        """HY-2: specificity wins between layers, so the two files are a **union**."""
        listing = object_listing_body([("one", "my_app"), ("two", "my_app")])
        estimator, _rest = self._estimator(
            listing,
            local=frozen_stanza("views/one"),
            default=frozen_stanza("views/one"),
        )
        self.assertEqual(estimator.estimate(_target()), 1)

    def test_an_object_of_another_application_is_not_counted(self):
        """It is visible in this namespace through global sharing, and it is governed by
        ITS application's stanzas: counting it would attribute to this write objects it
        cannot move."""
        listing = object_listing_body([("mine", "my_app"), ("theirs", "another_app")])
        estimator, _rest = self._estimator(listing)
        self.assertEqual(estimator.estimate(_target()), 1)

    def test_a_private_object_is_not_counted(self):
        """Its metadata lives under `etc/users/`, outside the read perimeter, and whether
        it inherits the generic stanzas at all is unmeasured (HY-3)."""
        private = object_listing_body([("private", "my_app")], sharing="user")
        estimator, _rest = self._estimator(private)
        self.assertEqual(estimator.estimate(_target()), 0)

        shared = object_listing_body([("shared", "my_app")], sharing="app")
        estimator, _rest = self._estimator(shared)
        self.assertEqual(estimator.estimate(_target()), 1)

    def test_the_count_never_goes_negative(self):
        """A frozen stanza may name an object that no longer exists. A negative estimate
        would be worse than an approximate one - the column is named `estimate`."""
        listing = object_listing_body([("one", "my_app")])
        estimator, _rest = self._estimator(
            listing,
            local=(frozen_stanza("views/one") + frozen_stanza("views/gone")
                  + frozen_stanza("views/also_gone")),
        )
        self.assertEqual(estimator.estimate(_target()), 0)

    def test_a_failed_enumeration_yields_zero_rather_than_an_exception(self):
        """The estimate is an aid to decision: losing it must not cost the write. And
        zero is visible, since it carries `no_inheriting_object`."""
        rest = FakeAppRest(
            json_responses={VIEWS_LISTING: RestResponse(503, b"")},
        )
        estimator = ImpactEstimator(
            rest, FakeProvenanceReader(provenance()), FIXTURE_TABLE
        )
        self.assertEqual(estimator.estimate(_target()), 0)

    def test_a_malformed_body_yields_zero(self):
        rest = FakeAppRest(
            json_responses={VIEWS_LISTING: RestResponse(200, b"{not json")}
        )
        estimator = ImpactEstimator(
            rest, FakeProvenanceReader(provenance()), FIXTURE_TABLE
        )
        self.assertEqual(estimator.estimate(_target()), 0)

    def test_a_target_with_no_handler_estimates_zero(self):
        estimator, _rest = self._estimator(object_listing_body([]))
        self.assertEqual(estimator.estimate(_target(handler="")), 0)

    def test_the_enumeration_is_memoized_per_application_and_family(self):
        """Section 13.4 point 7: the enumeration is the ONLY thing memoized, because it
        depends on none of the handler caches the caution clause is about."""
        listing = object_listing_body([("one", "my_app")])
        estimator, rest = self._estimator(listing)
        estimator.estimate(_target())
        estimator.estimate(_target())
        estimator.estimate(_target())
        self.assertEqual(
            len([call for call in rest.calls if call[1] == VIEWS_LISTING]), 1
        )

    def test_the_enumeration_asks_for_the_whole_collection(self):
        listing = object_listing_body([("one", "my_app")])
        estimator, rest = self._estimator(listing)
        estimator.estimate(_target())
        params = [call[2] for call in rest.calls if call[1] == VIEWS_LISTING][0]
        self.assertEqual(params.get("count"), "0")


class TheApplicationDefaultEstimateTest(unittest.TestCase):
    """Union over the families **with no header** in either file (section 10.3).

    A family carrying a header is out of the blast radius of `[]`: its objects read the
    header, not the application default. That is the measured inheritance chain.
    """

    def _estimator(self, local=None, default=None, listings=None):
        rest = FakeAppRest(
            json_responses={
                path: RestResponse(200, body) for path, body in (listings or {}).items()
            },
            default_json=RestResponse(200, object_listing_body([])),
        )
        reader = FakeProvenanceReader(provenance(local=local, default=default))
        return ImpactEstimator(rest, reader, FIXTURE_TABLE), rest

    def test_a_family_with_a_header_is_excluded(self):
        estimator, _rest = self._estimator(
            local=frozen_stanza("views"),
            listings={
                VIEWS_LISTING: object_listing_body([("one", "my_app")]),
                SEARCHES_LISTING: object_listing_body([("two", "my_app")]),
            },
        )
        self.assertEqual(estimator.estimate(_target(kind=STANZA_KIND_APP)), 1)

    def test_a_header_in_the_default_layer_excludes_too(self):
        estimator, _rest = self._estimator(
            default=frozen_stanza("views"),
            listings={VIEWS_LISTING: object_listing_body([("one", "my_app")])},
        )
        self.assertEqual(estimator.estimate(_target(kind=STANZA_KIND_APP)), 0)

    def test_the_frozen_objects_of_the_remaining_families_are_subtracted(self):
        estimator, _rest = self._estimator(
            local=frozen_stanza("savedsearches/two"),
            listings={
                SEARCHES_LISTING: object_listing_body(
                    [("two", "my_app"), ("three", "my_app")]
                )
            },
        )
        self.assertEqual(estimator.estimate(_target(kind=STANZA_KIND_APP)), 1)

    def test_with_no_table_the_estimate_is_zero(self):
        estimator = ImpactEstimator(
            FakeAppRest(), FakeProvenanceReader(provenance()), None
        )
        self.assertEqual(estimator.estimate(_target(kind=STANZA_KIND_APP)), 0)


class TheAuditCasesOfAnomalyA2Test(unittest.TestCase):
    """**The three cases the pre-delivery audit measured on the lab, reproduced here.**

    They are the regression net of anomaly A-2, and each one is a real fixture the auditor
    built and wrote to, not a construction of the imagination:

        [views]         12 objects created by REST, 12 stanzas, none carrying `access`
        [savedsearches]  3 objects, 3 stanzas, ONE of them really frozen
        [views]          6 objects delivered in `default/`, no stanza at all

    Before the correction the first two estimated **0** against a real effect of **12** and
    **2** - a hundred per cent off, in the direction that reassures - while the third was
    already exact. That third case is what localises the defect: the subtraction of counts
    is the right mechanism, its definition of "frozen" was not.
    """

    def _estimator(self, listing, local=None):
        rest = FakeAppRest(
            json_responses={VIEWS_LISTING: RestResponse(200, listing)},
            default_json=RestResponse(200, b'{"entry":[]}'),
        )
        reader = FakeProvenanceReader(provenance(local=local))
        return ImpactEstimator(rest, reader, FIXTURE_TABLE)

    def test_twelve_objects_created_by_rest_are_twelve_impacted(self):
        names = [("auditview%02d" % i, "my_app") for i in range(1, 13)]
        stanzas = "".join(touched_stanza("views/%s" % name) for name, _ in names)
        estimator = self._estimator(object_listing_body(names), local=stanzas)
        self.assertEqual(estimator.estimate(_target()), 12)

    def test_three_objects_of_which_one_is_really_frozen_are_two_impacted(self):
        names = [("auditsearch%d" % i, "my_app") for i in (1, 2, 3)]
        stanzas = (frozen_stanza("views/auditsearch1")
                   + touched_stanza("views/auditsearch2")
                   + touched_stanza("views/auditsearch3"))
        estimator = self._estimator(object_listing_body(names), local=stanzas)
        self.assertEqual(estimator.estimate(_target()), 2)

    def test_six_objects_delivered_in_a_package_stay_exact(self):
        """The counter-witness: the formula was already right where the objects carried no
        stanza at all, which is why the correction is a predicate and not an algorithm."""
        names = [("pkgview%d" % i, "my_app") for i in range(1, 7)]
        estimator = self._estimator(object_listing_body(names), local=None)
        self.assertEqual(estimator.estimate(_target()), 6)

    def test_the_warning_no_longer_fires_when_the_write_moves_the_family(self):
        """`no_inheriting_object` said "this write moves nothing today" while the write
        moved every object of the family. A non-zero estimate is what withdraws it."""
        names = [("auditview%02d" % i, "my_app") for i in range(1, 13)]
        stanzas = "".join(touched_stanza("views/%s" % name) for name, _ in names)
        estimator = self._estimator(object_listing_body(names), local=stanzas)
        self.assertGreater(estimator.estimate(_target()), 0)


class ZeroIsNotANoopTest(unittest.TestCase):
    """Section 10.3, and it is instructive.

    A target with no inheriting object today still changes the **default applicable to
    objects created later** - measured, a family header writes successfully into an app
    holding no object of that family. The write happens, and the warning says it moves
    nothing today.
    """

    def test_the_warning_token_exists_and_is_the_declared_one(self):
        from acltools.appacl_model import APP_ACL_WARNINGS

        self.assertEqual(NO_INHERITING_OBJECT, "no_inheriting_object")
        self.assertIn(NO_INHERITING_OBJECT, APP_ACL_WARNINGS)


if __name__ == "__main__":
    unittest.main()
