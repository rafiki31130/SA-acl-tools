"""State machine, journal invariants (section 8.2), ceiling (section 4.3) and
deduplication (section 10.8)."""

import unittest

from acltools.endpoint import build_object_path
from acltools.model import ACL_STATUSES
from acltools.pipeline import (
    PRIVATE_BY_ID_WARNING,
    RUNTIME_DIVERGENCE_MESSAGE,
    RUNTIME_DIVERGENCE_WARNING,
    SCOPE_UNDETERMINED_WARNING,
    EventProcessor,
    ceiling_message,
)
from acltools.rest import RestResponse

from .helpers import (
    FIXTURE_MAPPING,
    FakeClock,
    FakeJournal,
    FakeRest,
    acl_body,
    make_ctx,
    make_event,
    make_params,
)

ENDPOINT = "/servicesNS/nobody/my_app/saved/searches/My%20search"


def processor(rest=None, journal=None, params=None, roles=frozenset({"*"})):
    return EventProcessor(
        params=params or make_params(),
        ctx=make_ctx(),
        rest=rest or FakeRest(),
        journal=journal,
        mapping=FIXTURE_MAPPING,
        roles_catalog=roles,
        clock=FakeClock(),
    )


class StatusTest(unittest.TestCase):

    def test_updated(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("legacy_role",)))
        )
        result = processor(rest).process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertEqual(result.endpoint, ENDPOINT)
        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(rest.posts()[0][1], ENDPOINT)

    def test_the_post_always_carries_the_four_attributes(self):
        rest = FakeRest()
        processor(rest).process(make_event(write="new_role_admin"))
        payload = rest.posts()[0][2]
        self.assertEqual(
            sorted(payload), ["owner", "perms.read", "perms.write", "sharing"]
        )

    def test_noop(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(read=("role_a",), write=("w",)))
        )
        result = processor(rest).process(make_event(read="role_a", write="w"))
        self.assertEqual(result.status, "noop")
        self.assertEqual(rest.posts(), [])

    def test_noop_wins_over_dryrun(self):
        """Rank 6 before rank 7: an object already compliant is a `noop`, even in
        simulation."""
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(read=("role_a",), write=("w",)))
        )
        proc = processor(rest, params=make_params(dryrun=True))
        result = proc.process(make_event(read="role_a", write="w"))
        self.assertEqual(result.status, "noop")

    def test_dryrun_emits_no_write(self):
        rest = FakeRest()
        proc = processor(rest, params=make_params(dryrun=True))
        result = proc.process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "dryrun")
        self.assertEqual(rest.posts(), [])

    def test_not_found(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "not_found")
        self.assertEqual(result.http_code, 404)

    def test_forbidden(self):
        rest = FakeRest(default_get=RestResponse(403, b"{}"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "forbidden")

    def test_error_on_get_5xx(self):
        rest = FakeRest(default_get=RestResponse(503, b"unavailable"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 503)

    def test_error_on_transport_failure(self):
        rest = FakeRest(default_get=RestResponse(0, b"", "transport:TimeoutError: x"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 0)

    def test_error_on_non_2xx_post(self):
        rest = FakeRest(default_post=RestResponse(409, b"conflict"))
        result = processor(rest).process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 409)
        self.assertTrue(result.post_attempted)
        self.assertTrue(result.counted)

    def test_rejected_mandatory_field_absent(self):
        for field in ("title", "app"):
            with self.subTest(field=field):
                result = processor().process(make_event(**{field: ""}))
                self.assertEqual(result.status, "rejected")
                self.assertTrue(result.error.startswith("missing_field:"))

    def test_the_owner_is_no_longer_a_mandatory_field(self):
        """D-25: addressing goes through the fixed context, nothing is left to require.

        A pipeline that carries no owner must work end to end: that is the nominal case
        since the redesign.
        """
        rest = FakeRest(
            default_get=RestResponse(
                200, acl_body(owner="a_third_party", write=("legacy_role",))
            )
        )
        result = processor(rest).process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertEqual(rest.posts()[0][2]["owner"], "a_third_party")

    def test_rejected_app_system(self):
        result = processor().process(make_event(app="system"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "app_system_forbidden")
        self.assertEqual(result.http_code, 0)

    def test_rejected_unresolved_endpoint(self):
        result = processor().process(make_event(eai_type="nonexistent_type"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "unresolved_endpoint:nonexistent_type")

    def test_rejected_empty_sharing(self):
        result = processor().process(make_event(sharing=""))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "sharing_empty_not_allowed")

    def test_rejected_empty_owner(self):
        """Section 3.3 - exact counterpart of the refusal on `sharing`, per-event
        status."""
        rest = FakeRest()
        result = processor(rest).process(make_event(owner=""))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "owner_empty_not_allowed")
        self.assertEqual(rest.posts(), [])

    def test_skipped_immutable(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(can_change_perms=False))
        )
        result = processor(rest).process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "skipped_immutable")
        self.assertEqual(rest.posts(), [])

    def test_invalid_role(self):
        proc = processor(
            params=make_params(validate_roles=True), roles=frozenset({"*", "role_a"})
        )
        result = proc.process(make_event(write="nonexistent_role"))
        self.assertEqual(result.status, "invalid_role")
        self.assertEqual(result.error, "invalid_role:nonexistent_role")

    def test_a_preserved_dead_role_does_not_block_but_warns(self):
        rest = FakeRest(
            default_get=RestResponse(
                200, acl_body(read=("dead_role",), write=("legacy_role",))
            )
        )
        proc = processor(
            rest,
            params=make_params(validate_roles=True),
            roles=frozenset({"*", "dead_role_absent", "new_role_admin"}),
        )
        result = proc.process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("stale_role_preserved:dead_role", result.warnings)


class SkippedPrivateTest(unittest.TestCase):
    """Section 3.5, D-26 - private objects fall out of scope.

    An object in `sharing=user` is visible only to its owner and to administrators: the
    permissions it would carry grant nothing to anybody.
    """

    def test_a_private_object_is_skipped_with_no_get_and_no_post(self):
        rest = FakeRest()
        result = processor(rest).process(
            make_event(current_sharing="user", write="new_role_admin")
        )
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.error, "private_object_out_of_scope")
        self.assertEqual(rest.gets(), [])
        self.assertEqual(rest.posts(), [])

    def test_a_private_object_does_not_increment_the_ceiling(self):
        proc = processor(params=make_params(max_objects=1))
        proc.process(make_event(current_sharing="user"))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_a_private_object_carries_its_journal_line(self):
        journal = FakeJournal()
        proc = processor(journal=journal)
        proc.process(make_event(current_sharing="user"))
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.outcomes[0]["status"], "skipped_private")
        self.assertEqual(journal.intents, [])

    def test_the_current_scope_is_read_case_insensitively(self):
        result = processor().process(make_event(current_sharing=" User "))
        self.assertEqual(result.status, "skipped_private")

    def test_no_scope_and_no_usable_id_the_get_happens_and_decides(self):
        """Section 3.5, D-38 - no current scope, no `id`: the command **carries on**.

        It has nothing left to discriminate with: it resolves through the fixed context
        and emits the GET. Here the object does not exist under that path, so it comes
        out as `not_found` - but that `not_found` is the verdict of the GET, **not a
        guaranteed fallback**: let a shared homonym exist and the GET succeeds (see
        `UndeterminedScopeTest`). That is exactly the promise that earlier versions of
        section 3.5 took for granted and that measurement disproved.
        """
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        result = processor(rest).process(
            make_event(current_sharing=None, id_value=None)
        )
        self.assertEqual(result.status, "not_found")
        self.assertEqual(len(rest.gets()), 1)
        self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_a_shared_object_is_not_skipped(self):
        for scope in ("app", "global"):
            with self.subTest(scope=scope):
                result = processor().process(
                    make_event(current_sharing=scope, write="new_role_admin")
                )
                self.assertEqual(result.status, "updated")


class PrivateDetectedByIdNamespaceTest(unittest.TestCase):
    """Section 3.5, D-34 - second detection path, and it is **necessary**.

    The fallback announced up to v2.4 - "scope column absent, the GET by fixed context
    answers 404, the object comes out as `not_found`" - **is wrong as soon as a shared
    homonym exists**. Fixed-context addressing then reaches the shared object: the
    command reads, and on a real write would write, **an object other than the one the
    input names**. That is the defect class that section 5.2 declares closed,
    reintroduced by the fallback.

    The setup reproduces exactly that configuration: the input row names the private
    object by its `id` (`/servicesNS/an_operator/...`), the shared homonym exists and
    answers `200` on the fixed-context path - which is the default of `FakeRest`. The
    only thing that must happen is **nothing**: no GET, no POST.
    """

    ID_PRIVATE = (
        "https://base.invalid:0/servicesNS/an_operator/my_app/saved/searches/"
        "My%2520search"
    )
    ID_SHARED = (
        "https://base.invalid:0/servicesNS/nobody/my_app/saved/searches/"
        "My%2520search"
    )

    def _event(self, id_value, current_sharing=None):
        return make_event(
            id_value=id_value,
            current_sharing=current_sharing,
            write="new_role_admin",
        )

    def test_the_private_object_named_by_its_id_comes_out_skipped_private(self):
        result = processor().process(self._event(self.ID_PRIVATE))
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.error, "private_object_out_of_scope")

    def test_the_shared_homonym_is_not_touched(self):
        """The criterion that counts: **no** HTTP exchange, therefore no read and no
        write on the shared object that fixed addressing would have reached."""
        rest = FakeRest()
        result = processor(rest).process(self._event(self.ID_PRIVATE))
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(rest.calls, [])
        self.assertEqual(result.http_code, 0)

    def test_the_same_batch_without_the_fix_would_reach_the_shared_object(self):
        """Explicit witness of the defect: the path that fixed addressing produces for
        this row is indeed the one of the **shared** object, not the one of the private
        object. That is what the auditor measured - and it is precisely why the command
        does not publish it in `acl_endpoint` (next test)."""
        self.assertEqual(
            build_object_path("my_app", "saved/searches", "My search"),
            "/servicesNS/nobody/my_app/saved/searches/My%20search",
        )

    def test_acl_endpoint_does_not_name_the_shared_homonym(self):
        """B-6 - the `acl_endpoint` of a `skipped_private` must be **empty**.

        Filled in, it would carry the path of the homonymous shared object, that is, an
        object *other* than the one the input row names, in an output that is made to be
        read back. The path of the private object actually named is not a fallback
        option: it would require a named addressing context, which `build_object_path`
        does not accept - a structural guarantee of D-25.

        Empty is therefore the only correct value, and it is **consistent with the rest
        of the output**: `acl_http_code = 0` already says that no exchange took place.
        """
        result = processor().process(self._event(self.ID_PRIVATE))
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.endpoint, "")
        self.assertEqual(result.http_code, 0)

    def test_acl_endpoint_is_empty_through_both_detection_paths(self):
        """The skip reason is the same through both paths (`PRIVATE_ERROR`); so is the
        endpoint field. An operator filtering on the status must not have to know which
        path was taken."""
        result = processor().process(
            make_event(current_sharing="user", write="new_role_admin")
        )
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.endpoint, "")

    def test_the_journal_line_carries_the_same_empty_endpoint(self):
        """Section 8.5 - `acl_endpoint` and the `endpoint` field of the journal are
        **the same string**, computed once. Fixing one without the other would
        reintroduce the divergence that section 8.5 forbids."""
        journal = FakeJournal()
        proc = processor(journal=journal)
        result = proc.process(self._event(self.ID_PRIVATE))
        self.assertEqual(journal.outcomes[0]["endpoint"], result.endpoint)
        self.assertEqual(journal.outcomes[0]["endpoint"], "")

    def test_a_status_that_did_target_correctly_keeps_its_endpoint(self):
        """The fix is **confined** to abstention without an HTTP exchange: a status
        whose GET did bear on the named object keeps its `acl_endpoint`."""
        result = processor().process(self._event(self.ID_SHARED))
        self.assertEqual(result.status, "updated")
        self.assertEqual(result.endpoint, ENDPOINT)

    def test_the_skip_is_reported_to_the_operator(self):
        """The status does not say through which path the object was skipped; the
        warning does, and names at the same time what the pipeline is missing."""
        result = processor().process(self._event(self.ID_PRIVATE))
        self.assertIn(PRIVATE_BY_ID_WARNING, result.warnings)

    def test_an_id_in_the_fixed_context_is_not_skipped(self):
        """Detection bears on a **named** namespace, not on the presence of an `id`. A
        shared object keeps its nominal handling."""
        result = processor().process(self._event(self.ID_SHARED))
        self.assertEqual(result.status, "updated")

    def test_the_current_scope_takes_precedence_over_the_namespace(self):
        """Path 2 is a **complement**, not an override: when the result set carries the
        scope, the scope is what decides."""
        result = processor().process(
            self._event(self.ID_PRIVATE, current_sharing="app")
        )
        self.assertEqual(result.status, "updated")
        self.assertNotIn(PRIVATE_BY_ID_WARNING, result.warnings)

    def test_a_present_but_empty_scope_tells_no_more(self):
        """An empty cell does not say that the object is shared: it says nothing. The
        second path therefore applies, as if the column were absent."""
        result = processor().process(
            self._event(self.ID_PRIVATE, current_sharing="  ")
        )
        self.assertEqual(result.status, "skipped_private")

    def test_the_skip_precedes_the_ceiling_in_its_effects(self):
        proc = processor(params=make_params(max_objects=1))
        proc.process(self._event(self.ID_PRIVATE))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_the_skipped_object_carries_its_journal_line(self):
        journal = FakeJournal()
        proc = processor(journal=journal)
        proc.process(self._event(self.ID_PRIVATE))
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.outcomes[0]["status"], "skipped_private")
        self.assertEqual(journal.intents, [])


class UndeterminedScopeTest(unittest.TestCase):
    """Section 3.5, D-38 - an undetermined scope is **made visible**.

    When neither the scope column nor a usable `id` is available, the command has only a
    name and an application. It resolves through the fixed context and therefore reaches
    the **shared** object if one of that name exists, whereas the input row may have
    been naming a private homonym. Section 3.5 does not ask for that behavior to change
    - without a scope designation, nothing allows discrimination - but for it to be
    **reported**.

    What these tests exercise is as much the emission of the warning as its
    **correctness**: a warning that fired in the nominal case would be noise, and noise
    gets filtered out mentally. It would be worth nothing on the day it counts. The half
    that says "it does not appear" therefore counts as much as the other.
    """

    #: `id` with no namespace: the `/services/...` form does not carry the scope data.
    ID_WITHOUT_NAMESPACE = (
        "https://base.invalid:0/services/saved/searches/My%2520search"
    )

    #: Truncated `id`: fewer than four segments after the marker, nothing is usable.
    ID_TRUNCATED = "https://base.invalid:0/servicesNS/nobody/my_app"

    ID_PRIVATE = PrivateDetectedByIdNamespaceTest.ID_PRIVATE
    ID_SHARED = PrivateDetectedByIdNamespaceTest.ID_SHARED

    # -- the undetermined case: the warning is there ----------------------- #

    def test_no_scope_and_no_id_at_all(self):
        result = processor().process(
            make_event(current_sharing=None, id_value=None, write="new_role_admin")
        )
        self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_scope_present_but_empty_and_no_id(self):
        """An empty cell does not say that the object is shared: it says nothing."""
        for scope in ("", "   "):
            with self.subTest(scope=repr(scope)):
                result = processor().process(
                    make_event(current_sharing=scope, id_value=None,
                               write="new_role_admin")
                )
                self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_id_present_but_with_no_usable_namespace(self):
        """The `id` exists but does not carry the data: what counts is not the presence
        of the field, it is what the field allows to be established."""
        for id_value in (self.ID_WITHOUT_NAMESPACE, self.ID_TRUNCATED, ""):
            with self.subTest(id_value=id_value):
                result = processor().process(
                    make_event(current_sharing=None, id_value=id_value,
                               write="new_role_admin")
                )
                self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_the_warning_accompanies_the_real_write_and_does_not_prevent_it(self):
        """The behavior is not changed: the object is indeed written, and that is
        exactly what the warning makes visible. A warning that blocked would be a
        different contract from the one of section 3.5."""
        rest = FakeRest()
        result = processor(rest).process(
            make_event(current_sharing=None, id_value=None, write="new_role_admin")
        )
        self.assertEqual(result.status, "updated")
        self.assertEqual(len(rest.posts()), 1)
        self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_the_warning_survives_every_downstream_status(self):
        """It is placed before the GET: it does not depend on the outcome of the
        processing, and a `not_found` or a `noop` carries it as well as an `updated`."""
        cases = (
            ("not_found", FakeRest(default_get=RestResponse(404, b"{}")), "w"),
            ("noop", FakeRest(default_get=RestResponse(200, acl_body(write=("w",)))), "w"),
            ("dryrun", None, "new_role_admin"),
        )
        for status, rest, target in cases:
            with self.subTest(status=status):
                params = make_params(dryrun=(status == "dryrun"))
                result = processor(rest, params=params).process(
                    make_event(current_sharing=None, id_value=None, write=target)
                )
                self.assertEqual(result.status, status)
                self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_it_is_emitted_only_once_per_event(self):
        result = processor().process(
            make_event(current_sharing=None, id_value=None, write="new_role_admin")
        )
        self.assertEqual(
            list(result.warnings).count(SCOPE_UNDETERMINED_WARNING), 1
        )

    def test_it_does_not_disturb_the_other_warnings(self):
        """`acl_warning` is a set of tokens joined by `;`: the new token adds itself to
        it, it replaces none of the others."""
        rest = FakeRest(default_get=RestResponse(200, acl_body(sharing="app")))
        result = processor(rest).process(
            make_event(current_sharing=None, id_value=None, sharing="global")
        )
        self.assertIn(SCOPE_UNDETERMINED_WARNING, result.warnings)
        self.assertIn("sharing_change", result.warnings)

    # -- the nominal case: the warning is not there ------------------------ #

    def test_a_usable_shared_scope_does_not_trigger_it(self):
        for scope in ("app", "global", " App "):
            with self.subTest(scope=scope):
                result = processor().process(
                    make_event(current_sharing=scope, id_value=None,
                               write="new_role_admin")
                )
                self.assertNotIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_a_private_object_detected_by_the_scope_does_not_trigger_it(self):
        """The scope is known - it is `user`. Nothing is undetermined."""
        result = processor().process(
            make_event(current_sharing="user", write="new_role_admin")
        )
        self.assertEqual(result.status, "skipped_private")
        self.assertNotIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_an_id_in_a_named_namespace_does_not_trigger_it(self):
        """The second path has decided: the object is private and it is skipped. The
        scope is established, the warning would have nothing to say."""
        result = processor().process(
            make_event(current_sharing=None, id_value=self.ID_PRIVATE,
                       write="new_role_admin")
        )
        self.assertEqual(result.status, "skipped_private")
        self.assertNotIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_an_id_in_the_fixed_context_does_not_trigger_it(self):
        """The case that counts most for correctness: the scope is not in the result
        set, but the `id` carries it - `nobody` says the object is shared. The
        discrimination took place, the object written is indeed the one the row
        names."""
        result = processor().process(
            make_event(current_sharing=None, id_value=self.ID_SHARED,
                       write="new_role_admin")
        )
        self.assertEqual(result.status, "updated")
        self.assertNotIn(SCOPE_UNDETERMINED_WARNING, result.warnings)

    def test_the_recommended_pipeline_never_triggers_it(self):
        """The inventory macro **always** emits the scope and an `id`: the undetermined
        case is out of its reach. This is the usage clause of section 3.5, checked on
        the combination that the macro produces."""
        for scope in ("app", "global", "user"):
            with self.subTest(scope=scope):
                result = processor().process(
                    make_event(current_sharing=scope, id_value=self.ID_SHARED,
                               write="new_role_admin")
                )
                self.assertNotIn(SCOPE_UNDETERMINED_WARNING, result.warnings)


class AddressingWithoutOwnerTest(unittest.TestCase):
    """Section 5.2, D-25 - the URI that gets built never carries an owner.

    This is the targeting defect of v1: a private object **masks** a homonymous shared
    object in the namespace of its holder. The command then reached the private object
    and wrote its ACL, reporting `updated`.
    """

    def test_the_get_uri_carries_the_fixed_context(self):
        rest = FakeRest()
        processor(rest).process(make_event(title="My search", app="my_app"))
        self.assertEqual(
            rest.gets()[0][1],
            "/servicesNS/nobody/my_app/saved/searches/My%20search",
        )

    def test_the_post_uri_carries_the_fixed_context(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="a_third_party")))
        processor(rest).process(make_event(write="new_role_admin"))
        self.assertTrue(rest.posts()[0][1].startswith("/servicesNS/nobody/"))

    def test_the_real_owner_from_the_get_does_not_leak_into_the_address(self):
        """The GET **always** returns the real owner, never the addressing context.
        Reinjecting it into the URI would reintroduce the defect of v1."""
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="a_third_party")))
        processor(rest).process(make_event(write="new_role_admin"))
        for _, path, _ in rest.calls:
            self.assertNotIn("a_third_party", path)

    def test_the_wildcard_context_is_never_used(self):
        rest = FakeRest()
        processor(rest).process(make_event(write="new_role_admin"))
        for _, path, _ in rest.calls:
            self.assertNotIn("/servicesNS/-/", path)

    def test_an_ownership_takeover_does_not_change_the_address(self):
        """`new_owner` is a **target value**, not an address: the URI stays identical
        with and without it."""
        without = FakeRest()
        processor(without).process(make_event(write="new_role_admin"))
        with_owner = FakeRest()
        processor(with_owner).process(
            make_event(write="new_role_admin", owner="another_owner")
        )
        self.assertEqual(without.posts()[0][1], with_owner.posts()[0][1])


class WarningTest(unittest.TestCase):

    def test_sharing_change(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(sharing="app")))
        result = processor(rest).process(make_event(sharing="global"))
        self.assertIn("sharing_change", result.warnings)

    def test_owner_change(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="an_owner")))
        result = processor(rest).process(make_event(owner="another_owner"))
        self.assertIn("owner_change", result.warnings)

    def test_app_disabled(self):
        proc = EventProcessor(
            params=make_params(),
            ctx=make_ctx(),
            rest=FakeRest(),
            mapping=FIXTURE_MAPPING,
            app_disabled_fn=lambda app: True,
            clock=FakeClock(),
        )
        result = proc.process(make_event(write="new_role_admin"))
        self.assertIn("app_disabled", result.warnings)


class JournalInvariantTest(unittest.TestCase):
    """The three verifiable invariants of section 8.2."""

    #: **The enumeration is not written here**: it is imported from
    #: `acltools.model.ACL_STATUSES`, itself anchored to the code by
    #: `tests/test_statuses.py`. The manual constant that used to sit in this place
    #: announced twelve statuses and carried eleven - `skipped_derived` was missing -
    #: which made the closed set below silent on that status. That was the fourth wrong
    #: writing of the same list; a copied list drifts, an import does not.
    #:
    #: Intended consequence: adding a status to the code without adding a case below
    #: **makes this test fail**.

    def test_invariant_1_one_outcome_line_per_output_event_every_status(self):
        journal = FakeJournal()
        seen = []

        def path(title):
            return (
                "/servicesNS/nobody/my_app/saved/searches/"
                + title.replace(" ", "%20")
            )

        rest = FakeRest(
            get_responses={
                path("obj_updated"): RestResponse(200, acl_body(write=("legacy_role",))),
                path("obj_noop"): RestResponse(200, acl_body(read=(), write=("w",))),
                path("obj_notfound"): RestResponse(404, b"{}"),
                path("obj_forbidden"): RestResponse(403, b"{}"),
                path("obj_error"): RestResponse(500, b"boom"),
                path("obj_immutable"): RestResponse(
                    200, acl_body(can_change_perms=False)
                ),
                path("obj_invalidrole"): RestResponse(200, acl_body(write=("legacy_role",))),
                # Derived: splunkd names the object `eventtype=<carrier>`, and the
                # carrier exists - the confirmation GET below is what establishes it.
                "/servicesNS/nobody/my_app/saved/fvtags/eventtype%3Da_carrier":
                    RestResponse(200, acl_body(name="eventtype=a_carrier")),
            },
            json_responses={
                "/servicesNS/nobody/my_app/saved/eventtypes/a_carrier":
                    RestResponse(200, b'{"entry":[]}'),
            },
            default_json=RestResponse(404, b"{}"),
        )
        proc = EventProcessor(
            params=make_params(validate_roles=True),
            ctx=make_ctx(),
            rest=rest,
            journal=journal,
            mapping=FIXTURE_MAPPING,
            roles_catalog=frozenset({"*", "w", "role_a", "new_role_admin",
                                     "legacy_role"}),
            clock=FakeClock(),
        )
        seen.append(proc.process(make_event(title="obj_updated", write="new_role_admin")).status)
        seen.append(proc.process(make_event(title="obj_noop", write="w")).status)
        seen.append(proc.process(make_event(title="obj_notfound", write="w")).status)
        seen.append(proc.process(make_event(title="obj_forbidden", write="w")).status)
        seen.append(proc.process(make_event(title="obj_error", write="w")).status)
        seen.append(proc.process(make_event(title="obj_immutable", write="w")).status)
        seen.append(
            proc.process(make_event(title="obj_invalidrole", write="nonexistent_role")).status
        )
        seen.append(proc.process(make_event(title="obj_rejected", app="system")).status)
        seen.append(
            proc.process(make_event(title="obj_private", current_sharing="user")).status
        )
        # `skipped_derived` - the status that the manual enumeration omitted, and that
        # the closed set below therefore made invisible to this invariant.
        seen.append(
            proc.process(
                make_event(
                    title="eventtype=a_carrier",
                    eai_type="fvtags",
                    write="new_role_admin",
                )
            ).status
        )
        # Ceiling at 1, on a dedicated processor: the first object is written, the
        # second is skipped. Sharing the journal brings its lines into the same count.
        proc_ceiling = EventProcessor(
            params=make_params(max_objects=1),
            ctx=make_ctx(),
            rest=FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",)))),
            journal=journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        seen.append(
            proc_ceiling.process(
                make_event(title="obj_written", write="new_role_admin")
            ).status
        )
        seen.append(
            proc_ceiling.process(
                make_event(title="obj_ceiling", write="new_role_admin")
            ).status
        )

        proc_dryrun = EventProcessor(
            params=make_params(dryrun=True),
            ctx=make_ctx(dryrun=True),
            rest=FakeRest(),
            journal=journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        seen.append(
            proc_dryrun.process(
                make_event(title="obj_dryrun", write="new_role_admin")
            ).status
        )

        self.assertEqual(
            sorted(set(seen)), sorted(ACL_STATUSES),
            "every acl_status declared by the core must be observed here on a real "
            "case: this is what forbids a status entering the command without its "
            "test case",
        )
        self.assertEqual(
            len(journal.outcomes), len(seen),
            "one outcome line per output event, no exception",
        )
        self.assertEqual(
            [o["phase"] for o in journal.outcomes], ["outcome"] * len(seen)
        )

    def test_invariant_2_one_intent_line_per_attempted_post(self):
        journal = FakeJournal()
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("legacy_role",))),
            default_post=RestResponse(200, b"{}"),
        )
        proc = processor(rest, journal=journal)
        for index in range(4):
            proc.process(
                make_event(title="object_%d" % index, write="new_role_admin")
            )
        self.assertEqual(len(journal.intents), len(rest.posts()))
        self.assertEqual(len(journal.intents), 4)

    def test_invariant_2_no_intent_without_a_post(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(read=(), write=("w",))))
        proc = processor(rest, journal=journal)
        proc.process(make_event(write="w"))                        # noop
        self.assertEqual(journal.intents, [])
        self.assertEqual(rest.posts(), [])
        self.assertEqual(len(journal.outcomes), 1)

    def test_invariant_3_an_intent_without_an_outcome_signals_an_interruption(self):
        """An interruption between the sync to disk and the response to the POST leaves
        exactly one `intent` with no `outcome`."""

        class InterruptedRest(FakeRest):
            def post_object_acl(self, object_path, payload):
                raise KeyboardInterrupt("interruption between fsync and response")

        journal = FakeJournal()
        proc = processor(InterruptedRest(), journal=journal)
        with self.assertRaises(KeyboardInterrupt):
            proc.process(make_event(write="new_role_admin"))
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(journal.outcomes, [])

    def test_invariant_3_the_ceiling_does_not_add_noise_to_the_signal(self):
        """An object skipped by the ceiling produces an `outcome` and **no** `intent`:
        the ceiling check precedes any journal write."""
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",))))
        proc = processor(rest, journal=journal, params=make_params(max_objects=2))
        for index in range(4):
            proc.process(make_event(title="object_%d" % index, write="new_role_admin"))
        self.assertEqual(len(journal.intents), 2)
        self.assertEqual(len(journal.outcomes), 4)

    def test_an_outcome_write_failure_is_reported_without_cancelling_anything(self):
        journal = FakeJournal(fail_outcome=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal)
        result = proc.process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("journal_outcome_failed", result.warnings)
        self.assertEqual(len(rest.posts()), 1)

    def test_the_journal_carries_before_owner_and_after_owner(self):
        """Section 8.2, D-22 - the journal picks up the owner, on both phases."""
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="an_owner")))
        proc = processor(rest, journal=journal)
        proc.process(make_event(owner="another_owner"))
        intent = journal.intents[0]
        self.assertEqual(intent["before_owner"], "an_owner")
        self.assertEqual(intent["after_owner"], "another_owner")


class IntentFailureTest(unittest.TestCase):

    def test_an_fsync_failure_cancels_the_post(self):
        journal = FakeJournal(fail_intent=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal)
        result = proc.process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error, "journal_intent_failed")
        self.assertFalse(result.journaled)
        self.assertEqual(rest.posts(), [])
        self.assertEqual(len(journal.outcomes), 1)
        self.assertIn("before_perms_read", journal.outcomes[0])


class NonFatalCeilingTest(unittest.TestCase):
    """Section 4.3, D-28 - on reaching the ceiling the command stops writing **without**
    interrupting the pipeline.

    In its earlier form, reaching the ceiling raised a fatal error: the search stopped,
    the output was lost in full, and the operator was left with a partial mutation
    **and** blindness about what had just happened. A guard rail must inform, not blind.
    """

    def _batch(self, size, max_objects, dryrun=False):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",))))
        journal = FakeJournal()
        proc = processor(
            rest, journal=journal,
            params=make_params(max_objects=max_objects, dryrun=dryrun),
        )
        results = [
            proc.process(make_event(title="object_%02d" % i, write="new_role_admin"))
            for i in range(size)
        ]
        return proc, rest, journal, results

    def test_the_number_of_writes_is_exactly_max_objects(self):
        proc, rest, _, _ = self._batch(size=7, max_objects=3)
        self.assertEqual(len(rest.posts()), 3)
        self.assertEqual(proc.counter, 3)

    def test_the_output_stays_complete(self):
        """One output event per input event, ceiling or not (section 5.7)."""
        _, _, _, results = self._batch(size=7, max_objects=3)
        self.assertEqual(len(results), 7)

    def test_the_skipped_objects_come_out_as_skipped_ceiling(self):
        _, _, _, results = self._batch(size=7, max_objects=3)
        statuses = [r.status for r in results]
        self.assertEqual(statuses, ["updated"] * 3 + ["skipped_ceiling"] * 4)

    def test_a_skipped_object_produces_no_get_and_no_post(self):
        _, rest, _, _ = self._batch(size=7, max_objects=3)
        self.assertEqual(len(rest.gets()), 3)
        self.assertEqual(len(rest.posts()), 3)

    def test_the_skipped_object_counter_is_kept(self):
        proc, _, _, _ = self._batch(size=7, max_objects=3)
        self.assertEqual(proc.skipped_ceiling, 4)

    def test_every_skipped_object_carries_its_journal_line(self):
        _, _, journal, _ = self._batch(size=7, max_objects=3)
        self.assertEqual(len(journal.outcomes), 7)
        skipped = [o for o in journal.outcomes if o["status"] == "skipped_ceiling"]
        self.assertEqual(len(skipped), 4)

    def test_the_error_names_the_ceiling_that_was_reached(self):
        _, _, _, results = self._batch(size=7, max_objects=3)
        self.assertEqual(results[-1].error, "max_objects_reached:3")

    def test_a_batch_exactly_equal_to_the_ceiling_skips_nothing(self):
        proc, _, _, results = self._batch(size=2, max_objects=2)
        self.assertEqual(proc.counter, 2)
        self.assertEqual(proc.skipped_ceiling, 0)
        self.assertEqual([r.status for r in results], ["updated", "updated"])

    def test_the_statuses_without_a_post_do_not_count(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest, params=make_params(max_objects=1))
        for index in range(5):
            proc.process(make_event(title="object_%d" % index, write="w"))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_the_ceiling_never_triggers_in_simulation(self):
        """Section 4.3 (D-30) - simulation emits no POST, the counter stays at zero.

        It is this property that makes a default ceiling as low as ten workable: it puts
        the friction on the real write, never on the examination. A `dryrun` over a
        hundred objects that skipped ninety of them would be a defect.
        """
        proc, rest, _, results = self._batch(size=40, max_objects=10, dryrun=True)
        self.assertEqual(len(results), 40)
        self.assertEqual([r.status for r in results], ["dryrun"] * 40)
        self.assertEqual(proc.skipped_ceiling, 0)
        self.assertEqual(proc.counter, 0)
        self.assertEqual(rest.posts(), [])

    def test_resuming_after_the_ceiling_does_not_rewrite_the_first_ones(self):
        """Section 4.3 (D-30) - an interrupted batch is finished by relaunching the
        same search.

        The objects already written come out `noop` by idempotence; only the skipped
        ones get processed. What is simulated here bears on the fact that the second
        pass reads the **already converged** state of the first three.
        """
        already_written = {
            "/servicesNS/nobody/my_app/saved/searches/object_%02d" % i: RestResponse(
                200, acl_body(write=("new_role_admin",))
            )
            for i in range(3)
        }
        rest = FakeRest(
            get_responses=already_written,
            default_get=RestResponse(200, acl_body(write=("legacy_role",))),
        )
        proc = processor(rest, params=make_params(max_objects=10))
        results = [
            proc.process(make_event(title="object_%02d" % i, write="new_role_admin"))
            for i in range(7)
        ]
        statuses = [r.status for r in results]
        self.assertEqual(statuses, ["noop"] * 3 + ["updated"] * 4)
        self.assertEqual(len(rest.posts()), 4)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_the_message_states_the_ceiling_and_the_number_skipped(self):
        message = ceiling_message(10, 32)
        self.assertIn("10", message)
        self.assertIn("32", message)
        self.assertIn("skipped_ceiling", message)


class DeduplicationTest(unittest.TestCase):
    """Section 10.8: deduplication saves the GET and the POST, never an output event
    nor an `outcome` line."""

    def test_two_identical_events(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",))))
        proc = processor(rest, journal=journal)
        first = proc.process(make_event(write="new_role_admin"))
        second = proc.process(make_event(write="new_role_admin"))
        self.assertEqual(first.status, "updated")
        self.assertEqual(second.status, "noop")
        self.assertEqual(len(rest.gets()), 1)
        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(len(journal.outcomes), 2)

    def test_a_duplicate_asking_for_a_different_value_produces_a_second_write(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",))))
        proc = processor(rest)
        proc.process(make_event(write="new_role_admin"))
        second = proc.process(make_event(write="yet_another_role"))
        self.assertEqual(second.status, "updated")
        self.assertEqual(len(rest.posts()), 2)
        self.assertEqual(len(rest.gets()), 1)

    def test_an_object_whose_processing_failed_is_not_memorized(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest)
        proc.process(make_event(write="w"))
        proc.process(make_event(write="w"))
        self.assertEqual(len(rest.gets()), 2)


class RuntimeDiskDivergenceTest(unittest.TestCase):
    """A-2 - an `HTTP 500` on persistence does not mean "nothing has changed".

    It means "nothing has been **persisted**". The runtime view of splunkd may have been
    mutated - measured on the reference platform - and that view is the one that users,
    searches and access controls see until the next configuration reload. The object is
    moreover excluded from the restore set, `editacl_rollback` keeping only the
    `outcome` lines whose status is `updated`.

    The command cannot prevent the divergence: the platform produces it. It must make it
    visible.
    """

    def _result(self, code, body=b'{"messages":[{"type":"ERROR","text":"x"}]}'):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("legacy_role",))),
            default_post=RestResponse(code, body),
        )
        return processor(rest).process(make_event(write="new_role_admin"))

    def test_a_persistence_refusal_carries_the_warning(self):
        result = self._result(
            500,
            b'{"messages":[{"type":"ERROR","text":"Could not flush changes to '
            b'disk"}]}',
        )
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 500)
        self.assertIn(RUNTIME_DIVERGENCE_WARNING, result.warnings)

    def test_the_whole_5xx_class_carries_the_warning(self):
        """D-16: the warning bears on every `5xx`, not on `500` alone."""
        for code in (500, 501, 502, 503, 504, 507, 599):
            with self.subTest(code=code):
                result = self._result(code)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.http_code, code)
                self.assertIn(RUNTIME_DIVERGENCE_WARNING, result.warnings)

    def test_a_refusal_that_is_not_about_persistence_does_not_carry_it(self):
        for code in (400, 403, 404, 409):
            with self.subTest(code=code):
                result = self._result(code)
                self.assertEqual(result.status, "error")
                self.assertNotIn(RUNTIME_DIVERGENCE_WARNING, result.warnings)

    def test_a_successful_write_does_not_carry_it(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("legacy_role",))))
        result = processor(rest).process(make_event(write="new_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertNotIn(RUNTIME_DIVERGENCE_WARNING, result.warnings)

    def test_the_operator_message_names_both_facts(self):
        text = RUNTIME_DIVERGENCE_MESSAGE.lower()
        self.assertIn("runtime", text)
        self.assertIn("disk", text)
        self.assertIn("editacl_rollback", text)
        self.assertIn("configuration reload", text)

    def test_the_duplicate_of_a_diverged_object_keeps_the_warning(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("legacy_role",))),
            default_post=RestResponse(500, b'{"messages":[]}'),
        )
        proc = processor(rest)
        proc.process(make_event(write="new_role_admin"))
        second = proc.process(make_event(write="new_role_admin"))
        self.assertIn(RUNTIME_DIVERGENCE_WARNING, second.warnings)


def rest_post_refused():
    """Platform refusing the write, the state read staying the one from before the
    attempt."""
    return FakeRest(
        default_get=RestResponse(200, acl_body(write=("legacy_role",))),
        default_post=RestResponse(
            500,
            b'{"messages":[{"type":"ERROR","text":"Could not flush changes to '
            b'disk"}]}',
        ),
    )


class DeduplicationAfterRefusedPostTest(unittest.TestCase):
    """A-7 - the cache was populated only after a **successful** POST."""

    def _proc(self, rest, journal, max_objects=500):
        return processor(
            rest, journal=journal, params=make_params(max_objects=max_objects)
        )

    def test_a_single_intent_and_a_single_post_after_a_refusal(self):
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="new_role_admin"))
        proc.process(make_event(write="new_role_admin"))

        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(len(rest.gets()), 1)
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(proc.counter, 1)

    def test_the_sid_endpoint_phase_triple_stays_unambiguous(self):
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="new_role_admin"))
        proc.process(make_event(write="new_role_admin"))

        keys = [
            (record["sid"], record["endpoint"], record["phase"])
            for record in journal.intents
        ]
        self.assertEqual(len(set(keys)), len(keys))

    def test_the_duplicate_produces_one_event_and_one_outcome_line(self):
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal)
        first = proc.process(make_event(write="new_role_admin"))
        second = proc.process(make_event(write="new_role_admin"))

        self.assertEqual(len(journal.outcomes), 2)
        self.assertEqual(second.status, first.status)
        self.assertEqual(second.error, first.error)
        self.assertEqual(second.http_code, 500)
        self.assertIn("duplicate_post_suppressed", second.warnings)
        self.assertFalse(second.counted)

    def test_the_duplicate_never_comes_out_updated_or_noop(self):
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="new_role_admin"))
        second = proc.process(make_event(write="new_role_admin"))
        self.assertNotIn(second.status, ("updated", "noop"))

    def test_a_different_target_after_a_refusal_is_indeed_retried(self):
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="new_role_admin"))
        proc.process(make_event(write="new_role_read"))
        self.assertEqual(len(rest.posts()), 2)
        self.assertEqual(len(journal.intents), 2)

    def test_a_refusal_consumes_the_ceiling_only_once(self):
        """Three occurrences of a refused object do not exhaust `max_objects=2`."""
        rest, journal = rest_post_refused(), FakeJournal()
        proc = self._proc(rest, journal, max_objects=2)
        for _ in range(3):
            proc.process(make_event(write="new_role_admin"))
        self.assertEqual(proc.counter, 1)


class InternalErrorTest(unittest.TestCase):

    def test_an_unexpected_exception_becomes_a_per_event_error(self):
        class BrokenRest(FakeRest):
            def get_object_acl(self, object_path):
                raise RuntimeError("internal failure")

        journal = FakeJournal()
        proc = processor(BrokenRest(), journal=journal)
        result = proc.process(make_event())
        self.assertEqual(result.status, "error")
        self.assertTrue(result.error.startswith("internal:RuntimeError"))
        self.assertEqual(len(journal.outcomes), 1)


if __name__ == "__main__":
    unittest.main()
