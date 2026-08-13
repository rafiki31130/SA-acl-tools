"""Merge engine of the application-level command (v4.2 sections 8.4, 8.6).

Three things are held here and nowhere else:

- the **presence matrix**: column absent / present-and-empty / present-and-valued,
  crossed with the three attributes, and the discrimination happening on the presence of
  the key rather than on the type or the value of the cell;
- the **measured asymmetry of `owner`**: mandatory and inert on the `[]` path, refused
  with `400` on the `_acl` path;
- the **block replacement**: both permissions are always transmitted, because sending
  one of them deletes the other.
"""

import unittest

from acltools.appacl_merge import (
    INERT_OWNER,
    build_payload,
    is_noop,
    merge,
    parse_app_acl_state,
    validate_roles,
)
from acltools.appacl_model import (
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    TARGET_ATTRIBUTES,
    AppAclState,
)

from .appacl_helpers import ABSENT, app_state, make_app_event


class TheReadStateTest(unittest.TestCase):
    """`entry[0].acl`, same block shape on both read paths (Q0-1, Q0-2)."""

    def test_the_three_attributes_are_read(self):
        state = parse_app_acl_state(
            {"sharing": "app", "perms": {"read": ["power"], "write": ["admin"]}}
        )
        self.assertEqual(state.sharing, "app")
        self.assertEqual(state.perms_read, ("power",))
        self.assertEqual(state.perms_write, ("admin",))

    def test_the_owner_is_deliberately_not_read(self):
        """It is inert on one path and refused on the other: keeping it would give the
        idempotence comparison an attribute no write can settle."""
        state = parse_app_acl_state({"owner": "somebody", "sharing": "app"})
        self.assertFalse(hasattr(state, "owner"))

    def test_a_missing_perms_block_is_tolerated(self):
        state = parse_app_acl_state({"sharing": "app"})
        self.assertEqual(state.perms_read, ())

    def test_a_null_perms_block_is_tolerated(self):
        state = parse_app_acl_state({"sharing": "app", "perms": None})
        self.assertEqual(state.perms_write, ())

    def test_an_empty_permission_read_back_as_a_list_of_one_empty_string(self):
        """Measured (Q0-1 case E): after `perms.read=`, the read-back is `[""]` - not
        `[]`, not `null`. Without the convergence, idempotence would fail on every
        stanza carrying an empty permission."""
        state = parse_app_acl_state({"sharing": "app", "perms": {"read": [""]}})
        self.assertEqual(state.perms_read, ())

    def test_a_comma_separated_string_is_accepted(self):
        state = parse_app_acl_state({"perms": {"read": "b, a ,b"}})
        self.assertEqual(state.perms_read, ("a", "b"))


class ThePresenceMatrixTest(unittest.TestCase):
    """Section 8.4: the presence of the column decides, the cell only decides the value.

    The complete matrix, on the three attributes.
    """

    CURRENT = AppAclState(sharing="app", perms_read=("power",), perms_write=("admin",))

    def _after(self, **kwargs):
        return merge(self.CURRENT, make_app_event(**kwargs), STANZA_KIND_FAMILY).after

    def test_an_absent_column_preserves(self):
        after = self._after()
        self.assertEqual(after.perms_read, ("power",))
        self.assertEqual(after.perms_write, ("admin",))
        self.assertEqual(after.sharing, "app")

    def test_a_present_empty_column_empties(self):
        self.assertEqual(self._after(read="").perms_read, ())
        self.assertEqual(self._after(write="").perms_write, ())

    def test_a_present_valued_column_applies(self):
        self.assertEqual(self._after(read="user").perms_read, ("user",))
        self.assertEqual(self._after(sharing="global").sharing, "global")

    def test_the_other_attributes_are_untouched(self):
        after = self._after(read="user")
        self.assertEqual(after.perms_write, ("admin",))
        self.assertEqual(after.sharing, "app")

    def test_the_discrimination_is_on_the_key_not_on_the_value(self):
        """A `None` in a **present** column empties, exactly like an empty string: the
        extra caution `raw is not None` would turn an explicit clearing order into a
        preservation."""
        self.assertEqual(self._after(read=None).perms_read, ())

    def test_a_multivalue_is_normalized(self):
        after = self._after(read=["b", "a", "b", "", "  c "])
        self.assertEqual(after.perms_read, ("a", "b", "c"))

    def test_the_three_attributes_are_the_whole_domain(self):
        """**DV-5**: there is no fourth. An owner cannot be expressed here."""
        self.assertEqual(len(TARGET_ATTRIBUTES), 3)
        self.assertNotIn("owner", TARGET_ATTRIBUTES)


class TheSharingRulesTest(unittest.TestCase):
    """Ranks 6 and 7 of section 8.7, and **DV-4**."""

    CURRENT = AppAclState(sharing="app", perms_read=("power",))

    def _merge(self, **kwargs):
        return merge(self.CURRENT, make_app_event(**kwargs), STANZA_KIND_FAMILY)

    def test_an_empty_sharing_rejects(self):
        rejection = self._merge(sharing="").rejection
        self.assertEqual(rejection.status, "rejected")
        self.assertEqual(rejection.error, "sharing_empty_not_allowed")

    def test_the_user_scope_is_refused_per_event(self):
        """Measured `400` on both paths: `Apps cannot be unshared` and `Containers
        cannot be unshared`. Refusing it here spares the operator two messages for one
        fact - and spares a call that cannot succeed."""
        rejection = self._merge(sharing="user").rejection
        self.assertEqual(rejection.error, "invalid_sharing:user")

    def test_an_unknown_scope_is_refused(self):
        self.assertEqual(
            self._merge(sharing="whatever").rejection.error, "invalid_sharing:whatever"
        )

    def test_the_two_valid_scopes_pass(self):
        for scope in ("app", "global"):
            with self.subTest(scope=scope):
                result = self._merge(sharing=scope)
                self.assertIsNone(result.rejection)
                self.assertEqual(result.after.sharing, scope)

    def test_a_scope_change_is_warned(self):
        self.assertIn("sharing_change", self._merge(sharing="global").warnings)

    def test_an_unchanged_scope_is_not_warned(self):
        self.assertEqual(self._merge(sharing="app").warnings, ())

    def test_the_case_is_folded(self):
        self.assertEqual(self._merge(sharing="GLOBAL").after.sharing, "global")


class ThePayloadTest(unittest.TestCase):
    """Section 5.1: what goes into the body, and what must never go into it."""

    STATE = AppAclState(sharing="app", perms_read=("power",), perms_write=("admin",))

    def test_both_permissions_are_always_transmitted(self):
        """Measured (Q0-1 cases B and C, Q0-2): with one `perms.*` present, the `access`
        line is replaced whole and the absent one is DELETED from the file."""
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            with self.subTest(kind=kind):
                payload = build_payload(self.STATE, kind)
                self.assertIn("perms.read", payload)
                self.assertIn("perms.write", payload)

    def test_an_empty_permission_is_a_present_key_with_an_empty_value(self):
        payload = build_payload(AppAclState(sharing="app"), STANZA_KIND_FAMILY)
        self.assertEqual(payload["perms.read"], "")
        self.assertEqual(payload["perms.write"], "")

    def test_the_owner_is_present_on_the_application_path_and_inert(self):
        """Measured (Q0-1 cases D and G): mandatory, and its value is ignored - no
        `owner =` key is written and the read-back always returns `nobody`."""
        payload = build_payload(self.STATE, STANZA_KIND_APP)
        self.assertEqual(payload["owner"], INERT_OWNER)
        self.assertEqual(INERT_OWNER, "nobody")

    def test_the_owner_is_absent_from_the_family_path(self):
        """Measured (Q0-2): `data/ui/views/_acl` and `data/macros/_acl` answer
        `400 Argument "owner" is not supported by this handler.` `saved/searches`
        accepts it, which is precisely why it must not be sent."""
        self.assertNotIn("owner", build_payload(self.STATE, STANZA_KIND_FAMILY))

    def test_export_is_never_transmitted(self):
        """Both handlers answer `400 Argument "export" is not supported`. `sharing` is
        the only lever on it."""
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            with self.subTest(kind=kind):
                self.assertNotIn("export", build_payload(self.STATE, kind))

    def test_no_other_key_is_transmitted(self):
        """The handlers are strict: any other argument name answers `400`. A payload
        carrying one would fail the whole write on a typo."""
        self.assertEqual(
            sorted(build_payload(self.STATE, STANZA_KIND_FAMILY)),
            ["perms.read", "perms.write", "sharing"],
        )
        self.assertEqual(
            sorted(build_payload(self.STATE, STANZA_KIND_APP)),
            ["owner", "perms.read", "perms.write", "sharing"],
        )

    def test_the_roles_are_serialized_as_a_comma_separated_list(self):
        payload = build_payload(
            AppAclState(sharing="app", perms_read=("a", "b")), STANZA_KIND_FAMILY
        )
        self.assertEqual(payload["perms.read"], "a,b")

    def test_the_payload_of_a_merge_is_the_payload_of_its_target_state(self):
        result = merge(self.STATE, make_app_event(read="user"), STANZA_KIND_APP)
        self.assertEqual(result.payload, build_payload(result.after, STANZA_KIND_APP))


class TheIdempotenceTest(unittest.TestCase):
    """Section 8.6: strict equality after normalization, on three attributes."""

    def test_an_identical_state_is_a_noop(self):
        state = app_state(sharing="app", read=("a",), write=("b",))
        self.assertTrue(is_noop(state, state))

    def test_a_permutation_of_roles_is_a_noop(self):
        self.assertTrue(
            is_noop(
                app_state(read=("a", "b")),
                merge(
                    app_state(read=("a", "b")),
                    make_app_event(read="b,a"),
                    STANZA_KIND_FAMILY,
                ).after,
            )
        )

    def test_an_empty_permission_on_both_sides_is_a_noop(self):
        self.assertTrue(is_noop(app_state(read=()), app_state(read=())))

    def test_a_different_scope_is_not_a_noop(self):
        self.assertFalse(
            is_noop(app_state(sharing="app"), app_state(sharing="global"))
        )

    def test_a_different_permission_is_not_a_noop(self):
        self.assertFalse(is_noop(app_state(read=("a",)), app_state(read=("b",))))

    def test_the_comparison_ignores_no_attribute_it_should_compare(self):
        for attribute, other in (
            ("sharing", app_state(sharing="global")),
            ("perms_read", app_state(read=("x",))),
            ("perms_write", app_state(write=("x",))),
        ):
            with self.subTest(attribute=attribute):
                self.assertFalse(is_noop(app_state(), other))


class TheRoleValidationTest(unittest.TestCase):
    """Rank 11: restricted to the **added** roles (v3.14 D-4)."""

    def test_an_added_unknown_role_is_reported(self):
        unknown, stale = validate_roles(
            app_state(read=("power",)), app_state(read=("power", "ghost")), {"power"}
        )
        self.assertEqual(unknown, ("ghost",))
        self.assertEqual(stale, ())

    def test_a_preserved_unknown_role_does_not_block(self):
        """Blocking a write because a dead role lingers in a permission the operation
        does not touch prevents the very fix that would remove it."""
        unknown, stale = validate_roles(
            app_state(read=("ghost",), write=("power",)),
            app_state(read=("ghost",), write=("admin",)),
            {"power", "admin"},
        )
        self.assertEqual(unknown, ())
        self.assertEqual(stale, ("ghost",))

    def test_the_wildcard_role_is_a_role_like_any_other(self):
        unknown, _stale = validate_roles(
            app_state(), app_state(read=("*",)), {"*", "power"}
        )
        self.assertEqual(unknown, ())


class TheMergeRejectsNothingElseTest(unittest.TestCase):
    """The merge produces ranks 6 and 7 and no other status.

    Every other rank belongs to the pipeline, which alone holds the run's memory, the
    parameters, the provenance and the counters. Keeping the split explicit is what makes
    the order of section 8.7 testable in one place.
    """

    def test_a_nominal_merge_rejects_nothing(self):
        self.assertIsNone(
            merge(app_state(), make_app_event(read="a"), STANZA_KIND_FAMILY).rejection
        )

    def test_an_absent_sharing_column_never_rejects(self):
        self.assertIsNone(
            merge(app_state(sharing=""), make_app_event(sharing=ABSENT),
                  STANZA_KIND_FAMILY).rejection
        )


if __name__ == "__main__":
    unittest.main()
