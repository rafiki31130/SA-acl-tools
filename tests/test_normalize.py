"""Normalization of role lists and of the sharing scope (sections 3.2, 5.5, D-8)."""

import unittest

from acltools.normalize import (
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    parse_acl_state,
    serialize_roles,
)

from .helpers import acl_body_raw


class NormalizeRolesTest(unittest.TestCase):

    def test_comma_separated_string(self):
        self.assertEqual(normalize_roles("role_b,role_a"), ("role_a", "role_b"))

    def test_multivalue(self):
        self.assertEqual(normalize_roles(["role_b", "role_a"]), ("role_a", "role_b"))

    def test_multivalue_one_element_of_which_is_itself_a_csv_list(self):
        self.assertEqual(
            normalize_roles(["role_c,role_a", "role_b"]),
            ("role_a", "role_b", "role_c"),
        )

    def test_duplicate_values_are_deduplicated(self):
        self.assertEqual(
            normalize_roles("role_a,role_a,role_b"), ("role_a", "role_b")
        )

    def test_stray_spaces_are_removed(self):
        self.assertEqual(
            normalize_roles("  role_b ,role_a  "), ("role_a", "role_b")
        )

    def test_empty_string(self):
        self.assertEqual(normalize_roles(""), ())

    def test_null_value(self):
        self.assertEqual(normalize_roles(None), ())

    def test_empty_list(self):
        self.assertEqual(normalize_roles([]), ())

    def test_list_holding_one_empty_string_D8(self):
        """`[""]` is the form read back after an empty `perms.read=` POST
        (measurement 4).

        Without this filtering, the state read and the merged state are never equal
        and idempotence detection fails on **every** object with an empty permission.
        """
        self.assertEqual(normalize_roles([""]), ())

    def test_list_of_several_empty_strings_D8(self):
        self.assertEqual(normalize_roles(["", "", "  "]), ())

    def test_interleaved_empty_elements_are_filtered(self):
        self.assertEqual(
            normalize_roles(["role_a", "", "role_b", "  "]), ("role_a", "role_b")
        )

    def test_commas_alone(self):
        self.assertEqual(normalize_roles(",,,"), ())

    def test_the_star_role_is_a_role_like_any_other(self):
        """The `*` role is never expanded into a list of roles (section 10.2)."""
        self.assertEqual(normalize_roles("*"), ("*",))
        self.assertEqual(normalize_roles(["*", "role_a"]), ("*", "role_a"))

    def test_deterministic_sort_by_code_points(self):
        self.assertEqual(
            normalize_roles("Zeta,alpha,Beta"), ("Beta", "Zeta", "alpha")
        )


class SerializeRolesTest(unittest.TestCase):

    def test_empty_tuple_yields_the_empty_string_never_a_star(self):
        self.assertEqual(serialize_roles(()), "")

    def test_comma_join(self):
        self.assertEqual(serialize_roles(("role_a", "role_b")), "role_a,role_b")


class IsFieldEmptyTest(unittest.TestCase):

    def test_empty_cases(self):
        for value in (None, "", [], [""], ["", "  "], "   ", ",", [None]):
            with self.subTest(value=value):
                self.assertTrue(is_field_empty(value))

    def test_non_empty_cases(self):
        for value in ("role_a", ["role_a"], ["", "role_a"], " x "):
            with self.subTest(value=value):
                self.assertFalse(is_field_empty(value))


class NormalizeSharingTest(unittest.TestCase):

    def test_lowercased_and_trimmed(self):
        self.assertEqual(normalize_sharing("  Global "), "global")

    def test_multivalue_takes_the_first_non_empty_token(self):
        self.assertEqual(normalize_sharing(["", "app"]), "app")

    def test_empty_yields_none(self):
        for value in (None, "", [], [""]):
            with self.subTest(value=value):
                self.assertIsNone(normalize_sharing(value))


class ParseAclStateTest(unittest.TestCase):

    def test_nominal_acl_block(self):
        state = parse_acl_state(
            {
                "owner": "nobody",
                "sharing": "global",
                "can_change_perms": True,
                "perms": {"read": ["role_b", "role_a"], "write": ["legacy_role"]},
            }
        )
        self.assertEqual(state.owner, "nobody")
        self.assertEqual(state.sharing, "global")
        self.assertEqual(state.perms_read, ("role_a", "role_b"))
        self.assertEqual(state.perms_write, ("legacy_role",))
        self.assertTrue(state.can_change_perms)

    def test_perms_absent_object_without_explicit_permission(self):
        state = parse_acl_state({"owner": "nobody", "sharing": "app"})
        self.assertEqual(state.perms_read, ())
        self.assertEqual(state.perms_write, ())

    def test_perms_read_back_as_a_list_of_one_empty_string(self):
        state = parse_acl_state(
            {"owner": "nobody", "sharing": "app", "perms": {"read": [""], "write": [""]}}
        )
        self.assertEqual(state.perms_read, ())
        self.assertEqual(state.perms_write, ())

    def test_can_change_perms_received_as_a_string(self):
        self.assertFalse(
            parse_acl_state({"can_change_perms": "0"}).can_change_perms
        )
        self.assertTrue(parse_acl_state({"can_change_perms": "1"}).can_change_perms)

    def test_can_change_perms_absent_means_true(self):
        self.assertTrue(parse_acl_state({}).can_change_perms)

    def test_full_response_body(self):
        import json

        document = json.loads(
            acl_body_raw(
                {"owner": "an_owner", "sharing": "user", "perms": {"read": "*"}}
            ).decode("utf-8")
        )
        state = parse_acl_state(document["entry"][0]["acl"])
        self.assertEqual(state.owner, "an_owner")
        self.assertEqual(state.sharing, "user")
        self.assertEqual(state.perms_read, ("*",))


if __name__ == "__main__":
    unittest.main()
