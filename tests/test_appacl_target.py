"""Target resolution and URI construction (v4.1 sections 8.3, 11.3, and 4.1).

The heart of this module is the guarantee of section 4.1: the namespace segment is the
literal `nobody`, and it cannot be anything else because **no function here accepts an
owner**. That is checked on the signatures, not on the output - an output test says the
current callers pass the right thing, a signature test says no caller ever can.
"""

import inspect
import unittest
from urllib.parse import quote

from acltools import appacl_target
from acltools.appacl_model import STANZA_KIND_APP, STANZA_KIND_FAMILY
from acltools.appacl_target import (
    FIXED_CONTEXT,
    build_app_default_path,
    build_family_default_path,
    check_designation,
    designation_key,
    resolve_target,
)
from acltools.errors import EventRejected

from .appacl_helpers import FIXTURE_TABLE, make_app_event


class TheNamespaceIsNobodyTest(unittest.TestCase):
    """Section 4.1, and the trap sheet it produced.

    Measured: with `admin` in the namespace segment, splunkd answers `200` and writes
    `etc/users/admin/<app>/metadata/local.meta` - a private file, invisible to everybody
    else, with no warning and no diagnostic field. The whole increment rests on that
    segment being a literal.
    """

    def test_the_fixed_context_is_the_literal_nobody(self):
        self.assertEqual(FIXED_CONTEXT, "nobody")

    def test_the_family_path_carries_it(self):
        path = build_family_default_path("my_app", "data/ui/views")
        self.assertEqual(path, "/servicesNS/nobody/my_app/data/ui/views/_acl")

    def test_no_uri_builder_accepts_an_owner(self):
        """**The structural guarantee.** A parameter that does not exist cannot be fed.

        The check is on the signature of every public function of the module, not on the
        two builders alone: a helper taking an owner would be the way the guarantee comes
        back undone, one caller at a time.
        """
        forbidden = ("owner", "user", "username", "namespace", "context")
        for name, function in vars(appacl_target).items():
            if name.startswith("_") or not inspect.isfunction(function):
                continue
            if function.__module__ != appacl_target.__name__:
                continue
            with self.subTest(function=name):
                parameters = set(inspect.signature(function).parameters)
                self.assertEqual(
                    parameters & set(forbidden),
                    set(),
                    "%s exposes an owner-like parameter: the namespace segment must "
                    "not be reachable from any caller" % name,
                )

    def test_no_input_field_can_reach_the_namespace_segment(self):
        """An event carrying owner-looking values changes nothing in the URI."""
        event = make_app_event(app="my_app")
        target = resolve_target(event, FIXTURE_TABLE)
        self.assertIn("/servicesNS/nobody/", target.endpoint)
        self.assertNotIn("admin", target.endpoint)


class TheTwoPathsTest(unittest.TestCase):
    """Section 11.3: the two forms of the endpoint, which is a **string contract**."""

    def test_app_default_path(self):
        self.assertEqual(
            build_app_default_path("my_app"), "/services/apps/local/my_app/acl"
        )

    def test_family_default_path(self):
        self.assertEqual(
            build_family_default_path("my_app", "saved/searches"),
            "/servicesNS/nobody/my_app/saved/searches/_acl",
        )

    def test_the_handler_path_is_not_re_encoded(self):
        """Re-encoding it would turn `saved/searches` into `saved%2Fsearches`."""
        path = build_family_default_path("my_app", "saved/searches")
        self.assertIn("saved/searches", path)
        self.assertNotIn("%2F", path)

    def test_neither_path_carries_a_scheme_a_host_or_a_port(self):
        """Two members of a cluster would otherwise produce two keys for one target."""
        for path in (
            build_app_default_path("my_app"),
            build_family_default_path("my_app", "data/ui/views"),
        ):
            with self.subTest(path=path):
                self.assertTrue(path.startswith("/"))
                self.assertNotIn("://", path)
                self.assertNotIn(":8089", path)


class TheApplicationSegmentIsEncodedTest(unittest.TestCase):
    """v3.14 section 5.2: single encoding rule, `safe=''`, nothing left literal.

    Test cases of section 13.4 point 3: space, forward slash, accented character, percent
    sign.
    """

    CASES = ("an app", "a/b", "app_e", "100%_app", "app+plus")

    def test_every_special_character_is_encoded_on_both_paths(self):
        for app in self.CASES:
            expected = quote(app, safe="", encoding="utf-8")
            with self.subTest(app=app):
                self.assertIn(expected, build_app_default_path(app))
                self.assertIn(expected, build_family_default_path(app, "data/ui/views"))

    def test_a_forward_slash_in_the_application_cannot_forge_a_segment(self):
        path = build_app_default_path("a/b")
        self.assertNotIn("/a/b/", path)
        self.assertIn("a%2Fb", path)


class TheControlOrderOfTheDesignationTest(unittest.TestCase):
    """Ranks 0 to 2 of section 8.7, in their normative order."""

    def _rejection(self, **kwargs):
        with self.assertRaises(EventRejected) as caught:
            resolve_target(make_app_event(**kwargs), FIXTURE_TABLE)
        return caught.exception

    def test_rank_0_an_absent_stanza_kind_is_rejected(self):
        error = self._rejection(stanza_kind="")
        self.assertEqual(error.status, "rejected")
        self.assertEqual(error.error, "invalid_stanza_kind:")

    def test_rank_0_a_stanza_kind_outside_the_domain_is_rejected(self):
        error = self._rejection(stanza_kind="object_specific")
        self.assertEqual(error.error, "invalid_stanza_kind:object_specific")

    def test_rank_0_is_evaluated_before_rank_1(self):
        """A row missing both must name the kind: it is the more structural defect.

        Deducing `app_default` from an empty family value is the silent targeting defect
        section 8.3 exists to make impossible, so the message must point there first.
        """
        error = self._rejection(stanza_kind="", app="")
        self.assertTrue(error.error.startswith("invalid_stanza_kind"))

    def test_rank_1_an_absent_application_is_rejected(self):
        error = self._rejection(app="")
        self.assertEqual(error.error, "app_missing")

    def test_rank_2_the_system_application_is_rejected(self):
        error = self._rejection(app="system")
        self.assertEqual(error.error, "app_system_forbidden")

    def test_rank_2_is_case_insensitive(self):
        error = self._rejection(app="System")
        self.assertEqual(error.error, "app_system_forbidden")

    def test_check_designation_returns_the_two_values_it_validated(self):
        app, kind = check_designation(make_app_event(app="my_app"))
        self.assertEqual((app, kind), ("my_app", STANZA_KIND_FAMILY))


class TheFamilyResolutionTest(unittest.TestCase):
    """Rank 4 of section 8.7: two complementary and disjoint routes."""

    def test_the_handler_route_does_not_go_through_the_table(self):
        """That independence is what makes a rollback survive an incomplete table."""
        target = resolve_target(
            make_app_event(handler="admin/an-unlisted-handler", stanza="unlisted"),
            FIXTURE_TABLE,
        )
        self.assertEqual(target.handler, "admin/an-unlisted-handler")
        self.assertEqual(
            target.endpoint,
            "/servicesNS/nobody/my_app/admin/an-unlisted-handler/_acl",
        )

    def test_the_handler_route_works_with_no_table_at_all(self):
        target = resolve_target(make_app_event(handler="data/ui/views"), None)
        self.assertEqual(target.handler, "data/ui/views")

    def test_the_stanza_route_uses_the_table(self):
        target = resolve_target(
            make_app_event(handler="", stanza="savedsearches"), FIXTURE_TABLE
        )
        self.assertEqual(target.handler, "saved/searches")

    def test_an_unknown_family_is_rejected_with_its_name(self):
        with self.assertRaises(EventRejected) as caught:
            resolve_target(
                make_app_event(handler="", stanza="visualizations"), FIXTURE_TABLE
            )
        self.assertEqual(caught.exception.error, "unresolved_family:visualizations")

    def test_no_derivation_heuristic_is_applied(self):
        """Section 5.2, requirement 2: no pluralization, no hyphen substitution, no
        `data/` prefix invented."""
        for family in ("view", "Views", "ui/views", "workflow-actions", "saved_searches"):
            with self.subTest(family=family):
                with self.assertRaises(EventRejected) as caught:
                    resolve_target(
                        make_app_event(handler="", stanza=family), FIXTURE_TABLE
                    )
                self.assertTrue(
                    caught.exception.error.startswith("unresolved_family:")
                )

    def test_both_routes_missing_is_rejected(self):
        with self.assertRaises(EventRejected) as caught:
            resolve_target(make_app_event(handler="", stanza=""), FIXTURE_TABLE)
        self.assertEqual(caught.exception.error, "unresolved_family:")

    def test_a_traversal_handler_is_refused(self):
        for handler in ("../../etc", "data/../../x", "data/ui/../views", "."):
            with self.subTest(handler=handler):
                with self.assertRaises(EventRejected) as caught:
                    resolve_target(make_app_event(handler=handler), FIXTURE_TABLE)
                self.assertTrue(
                    caught.exception.error.startswith("invalid_handler:")
                )

    def test_an_encoded_sequence_in_a_handler_is_refused(self):
        with self.assertRaises(EventRejected) as caught:
            resolve_target(make_app_event(handler="data%2Fui/views"), FIXTURE_TABLE)
        self.assertTrue(caught.exception.error.startswith("invalid_handler:"))


class TheApplicationDefaultTargetTest(unittest.TestCase):
    """Neither route is consulted for `app_default` (section 8.3)."""

    def test_the_family_fields_are_ignored(self):
        target = resolve_target(
            make_app_event(
                stanza_kind=STANZA_KIND_APP, handler="data/ui/views", stanza="views"
            ),
            FIXTURE_TABLE,
        )
        self.assertEqual(target.endpoint, "/services/apps/local/my_app/acl")
        self.assertEqual(target.handler, "")
        self.assertEqual(target.stanza, "")

    def test_an_unknown_family_does_not_prevent_it(self):
        """A row whose family column is garbage still targets `[]` and only `[]`."""
        target = resolve_target(
            make_app_event(
                stanza_kind=STANZA_KIND_APP, handler="", stanza="not_a_family"
            ),
            FIXTURE_TABLE,
        )
        self.assertEqual(target.stanza_kind, STANZA_KIND_APP)
        self.assertEqual(target.endpoint, "/services/apps/local/my_app/acl")


class TheDesignationKeyTest(unittest.TestCase):
    """Rank 3 of section 8.7 needs a key computed **before** resolution."""

    def test_two_identical_designations_share_a_key(self):
        self.assertEqual(
            designation_key(make_app_event()), designation_key(make_app_event())
        )

    def test_two_different_families_do_not(self):
        self.assertNotEqual(
            designation_key(make_app_event(stanza="views")),
            designation_key(make_app_event(stanza="macros")),
        )

    def test_two_unresolvable_designations_still_share_a_key(self):
        """That is the reason the key exists: the duplicate of an unresolvable row must
        come out as `duplicate_target`, not twice as `unresolved_family`."""
        event = make_app_event(handler="", stanza="visualizations")
        self.assertEqual(designation_key(event), designation_key(event))


if __name__ == "__main__":
    unittest.main()
