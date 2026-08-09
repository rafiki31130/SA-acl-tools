"""Order of the controls of section 5.4, idempotence (section 5.5) and `validate_roles`
(D-4)."""

import unittest

from acltools.merge import is_noop, merge, validate_roles

from .helpers import make_event, state


class ControlOrderTest(unittest.TestCase):
    """The order is normative: it determines which status wins when several conditions
    are met at once (section 5.4)."""

    def test_rank_1_can_change_perms_wins_over_the_sharing_rejection(self):
        current = state(
            owner="nobody", sharing="app", read=(), write=(), can_change_perms=False
        )
        result = merge(current, make_event(sharing=""))
        self.assertEqual(result.rejection.status, "skipped_immutable")

    def test_rank_1_can_change_perms_wins_over_an_invalid_sharing(self):
        current = state(
            owner="nobody", sharing="app", read=(), write=(), can_change_perms=False
        )
        result = merge(current, make_event(sharing="galactic"))
        self.assertEqual(result.rejection.status, "skipped_immutable")

    def test_rank_1_can_change_perms_wins_over_the_owner_rejection(self):
        current = state(
            owner="an_owner", sharing="app", read=(), write=(),
            can_change_perms=False,
        )
        result = merge(current, make_event(owner=""))
        self.assertEqual(result.rejection.status, "skipped_immutable")

    def test_rank_1_names_the_acl_key_the_answer_came_from(self):
        """One status, two provenances - and the reason is what tells them apart.

        The outcome is identical: no POST, `skipped_immutable`. What differs is which
        statement of the platform was obeyed, and an operator filtering on that status
        is entitled to know it without going back to the GET.
        """
        for source, expected in (
            ("can_change_perms", "can_change_perms=0"),
            ("modifiable", "modifiable=0"),
        ):
            with self.subTest(source=source):
                current = state(
                    owner="nobody",
                    sharing="global",
                    can_change_perms=False,
                    perms_lock_source=source,
                )
                result = merge(current, make_event(read="*"))
                self.assertEqual(result.rejection.status, "skipped_immutable")
                self.assertEqual(result.rejection.error, expected)

    def test_rank_1_falls_back_on_the_expected_key_when_no_source_is_named(self):
        """A state built without a source - the case of a hand-written fixture - must
        not produce a reason reading `=0`."""
        current = state(can_change_perms=False, perms_lock_source="")
        result = merge(current, make_event(read="*"))
        self.assertEqual(result.rejection.error, "can_change_perms=0")

    def test_the_source_survives_the_merge(self):
        current = state(can_change_perms=False, perms_lock_source="modifiable")
        result = merge(current, make_event(read="*"))
        self.assertEqual(result.after.perms_lock_source, "modifiable")

    def test_rank_2_empty_sharing_wins_over_the_owner_rejection(self):
        current = state(owner="an_owner", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="", owner=""))
        self.assertEqual(result.rejection.error, "sharing_empty_not_allowed")

    def test_rank_3_invalid_sharing_wins_over_the_owner_rejection(self):
        current = state(owner="an_owner", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="galactic", owner=""))
        self.assertEqual(result.rejection.error, "invalid_sharing:galactic")

    def test_rank_4_empty_owner_wins_over_rank_5(self):
        """An empty `owner` is rejected before the `user`/`nobody` rule applies."""
        current = state(owner="nobody", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="user", owner=""))
        self.assertEqual(result.rejection.error, "owner_empty_not_allowed")

    def test_rank_5_sharing_user_on_owner_nobody(self):
        current = state(owner="nobody", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="user"))
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "sharing_user_requires_named_owner")

    def test_rank_5_does_not_trigger_on_a_named_owner(self):
        current = state(owner="an_owner", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="user"))
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.sharing, "user")

    def test_rank_5_bears_on_the_TARGET_owner_not_on_the_one_from_the_get(self):
        """Since D-22, `new_owner` can take the object out of `nobody` in the same POST.

        Rejecting on the value read rather than on the target value would forbid the
        only sequence that makes an object privatizable in one gesture: naming an owner
        and switching to `sharing=user`.
        """
        current = state(owner="nobody", sharing="app", read=(), write=())
        result = merge(
            current, make_event(sharing="user", owner="an_owner")
        )
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.owner, "an_owner")
        self.assertEqual(result.payload["owner"], "an_owner")

    def test_skipped_immutable_still_computes_the_target_state(self):
        """The journal must carry `before_*`/`after_*` for this status (section 8.2)."""
        current = state(
            owner="nobody",
            sharing="app",
            read=("role_a",),
            write=("legacy_role",),
            can_change_perms=False,
        )
        result = merge(current, make_event(write="new_role_admin"))
        self.assertEqual(result.rejection.status, "skipped_immutable")
        self.assertEqual(result.after.perms_write, ("new_role_admin",))


class IdempotenceTest(unittest.TestCase):

    def test_permuting_the_order_of_the_roles_is_a_noop(self):
        """The comparison bears on the sorted collections, not on the strings."""
        current = state(sharing="app", read=("role_a", "role_b"), write=("w",))
        result = merge(current, make_event(read="role_b,role_a", write="w"))
        self.assertTrue(is_noop(result.before, result.after))

    def test_a_present_empty_column_is_not_a_noop(self):
        current = state(sharing="app", read=("role_a",), write=("w",))
        result = merge(current, make_event(read="role_a", write=""))
        self.assertEqual(result.after.perms_write, ())
        self.assertFalse(is_noop(result.before, result.after))

    def test_a_column_absent_on_every_attribute_is_a_noop(self):
        """The nominal case of a second pass: nothing to change, no POST."""
        current = state(
            owner="an_owner", sharing="app", read=("role_a",), write=("w",)
        )
        result = merge(current, make_event())
        self.assertTrue(is_noop(result.before, result.after))

    def test_an_object_with_an_empty_permission_read_back_as_a_one_element_list(self):
        """The idempotence trap of measurement 4, frozen (D-8)."""
        from acltools.normalize import parse_acl_state

        current = parse_acl_state(
            {
                "owner": "nobody",
                "sharing": "global",
                "perms": {"read": [""], "write": ["admin"]},
            }
        )
        result = merge(current, make_event(read="", write="admin"))
        self.assertTrue(
            is_noop(result.before, result.after),
            "an object with an empty permission must come out as a noop on the second "
            "pass",
        )

    def test_owner_enters_the_comparison(self):
        """D-22: `owner` is now a target value.

        Excluding it from the comparison - which is what the v1 did, on the grounds that
        it was never modified - would make `new_owner` inoperative: a batch changing
        only the owner would come out entirely as `noop`, without a single POST.
        """
        left = state(owner="a", sharing="app", read=("r",), write=())
        right = state(owner="b", sharing="app", read=("r",), write=())
        self.assertFalse(is_noop(left, right))

    def test_the_same_owner_stays_a_noop(self):
        """Corollary: a pipeline built on the inventory macro carries the current owner
        on every line, which must produce a `noop`, not a write."""
        current = state(owner="an_owner", sharing="app", read=("r",), write=())
        result = merge(current, make_event(read="r", owner="an_owner"))
        self.assertTrue(is_noop(result.before, result.after))

    def test_a_change_of_sharing_is_not_a_noop(self):
        left = state(sharing="app")
        right = state(sharing="global")
        self.assertFalse(is_noop(left, right))


class ValidateRolesTest(unittest.TestCase):
    """D-4: the control bears only on the **added roles**."""

    CATALOG = frozenset({"role_a", "role_b", "new_role_admin", "*"})

    def test_a_dead_role_that_is_kept_does_not_block(self):
        before = state(read=("dead_role", "role_a"), write=("role_a",))
        after = state(read=("dead_role", "role_a"), write=("new_role_admin",))
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())
        self.assertEqual(stale, ("dead_role",))

    def test_a_dead_role_that_is_added_blocks(self):
        before = state(read=("role_a",), write=())
        after = state(read=("role_a", "nonexistent_role"), write=())
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("nonexistent_role",))
        self.assertEqual(stale, ())

    def test_a_dead_role_added_to_perms_write_blocks(self):
        before = state(read=(), write=("role_a",))
        after = state(read=(), write=("role_a", "nonexistent_role"))
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("nonexistent_role",))

    def test_a_dead_role_kept_in_read_while_write_is_modified(self):
        """The driving use case: `perms.write` is being fixed while a dead role is
        still lying around in `perms.read`. The write must not be blocked."""
        before = state(read=("dead_role",), write=("legacy_role",))
        after = state(read=("dead_role",), write=("new_role_admin",))
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())
        self.assertIn("dead_role", stale)

    def test_the_star_role_is_in_the_catalog(self):
        before = state(read=(), write=())
        after = state(read=("*",), write=())
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())

    def test_several_unknown_added_roles_are_all_reported(self):
        before = state(read=(), write=())
        after = state(read=("zz_unknown", "aa_unknown"), write=())
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("aa_unknown", "zz_unknown"))


if __name__ == "__main__":
    unittest.main()
