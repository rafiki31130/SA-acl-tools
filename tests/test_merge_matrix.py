"""Presence matrix of section 3.2 - **the twelve rows, one per named test**.

4 target attributes x 3 states of the column. No row is omitted, none is deferred to
another, and none is folded into a parameterized test: the name of the test designates
the row it covers.

    | Situation                             | Effect                  |
    |---------------------------------------|-------------------------|
    | column **absent** from the result set | attribute **preserved** |
    | column **present**, cell **empty**    | attribute **emptied**   |
    | column **present**, valued cell       | value applied           |

Two attributes depart from the second row, because their empty value does not exist on
the platform side: `sharing` and `owner` **reject** the event instead of emptying
themselves. Their rows 08 and 11 freeze that.

The v1 matrix - eighteen rows, 3 attributes x 2 states of the `fields` parameter x 3
states of the field - has no purpose any more: `fields` is gone, and it is the presence
of the column, not a parameter, that decides.
"""

import unittest

from acltools.merge import merge

from .helpers import make_event, state

#: State read by the GET, common to every row of the matrix.
CURRENT = state(
    owner="an_owner",
    sharing="app",
    read=("role_a", "role_b"),
    write=("legacy_role",),
)


class MergeMatrixTest(unittest.TestCase):

    def assertPayload(self, result, read=None, write=None, sharing=None, owner=None):
        for key, expected in (
            ("perms.read", read),
            ("perms.write", write),
            ("sharing", sharing),
            ("owner", owner),
        ):
            if expected is not None:
                self.assertEqual(result.payload[key], expected)
        self.assertEqual(
            sorted(result.payload),
            ["owner", "perms.read", "perms.write", "sharing"],
            "the four attributes are always transmitted (section 5.4)",
        )

    # ------------------------------------------------------------------ #
    # perms.read
    # ------------------------------------------------------------------ #

    def test_row_01_perms_read_column_absent_preserves_the_attribute(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_b")
        self.assertEqual(result.after.perms_read, ("role_a", "role_b"))

    def test_row_02_perms_read_column_present_empty_cell_empties_the_attribute(self):
        result = merge(CURRENT, make_event(read=""))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="")
        self.assertEqual(result.after.perms_read, ())

    def test_row_03_perms_read_column_present_valued_cell_is_applied(self):
        result = merge(CURRENT, make_event(read=["role_z", " role_a ", "role_z"]))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_z")

    # ------------------------------------------------------------------ #
    # perms.write
    # ------------------------------------------------------------------ #

    def test_row_04_perms_write_column_absent_preserves_the_attribute(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="legacy_role")
        self.assertEqual(result.after.perms_write, ("legacy_role",))

    def test_row_05_perms_write_column_present_empty_cell_empties_the_attribute(self):
        # This is the nominal decommissioning pipeline: an `mvmap` that removes the
        # last value leaves the column in place with an empty cell.
        result = merge(CURRENT, make_event(write=""))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="")
        self.assertEqual(result.after.perms_write, ())

    def test_row_06_perms_write_column_present_valued_cell_is_applied(self):
        result = merge(CURRENT, make_event(write="new_role_admin, role_b"))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="new_role_admin,role_b")

    # ------------------------------------------------------------------ #
    # sharing
    # ------------------------------------------------------------------ #

    def test_row_07_sharing_column_absent_preserves_the_attribute(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="app")
        self.assertNotIn("sharing_change", result.warnings)

    def test_row_08_sharing_column_present_empty_cell_rejects_the_event(self):
        # Departure: an empty sharing scope does not exist (section 3.3). The attribute
        # does not empty itself, the event is rejected.
        result = merge(CURRENT, make_event(sharing=""))
        self.assertIsNotNone(result.rejection)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "sharing_empty_not_allowed")

    def test_row_09_sharing_column_present_valued_cell_is_applied(self):
        result = merge(CURRENT, make_event(sharing=" Global "))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="global")
        self.assertIn("sharing_change", result.warnings)

    # ------------------------------------------------------------------ #
    # owner
    # ------------------------------------------------------------------ #

    def test_row_10_owner_column_absent_preserves_the_owner_from_the_get(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, owner="an_owner")
        self.assertEqual(result.after.owner, result.before.owner)
        self.assertNotIn("owner_change", result.warnings)

    def test_row_11_owner_column_present_empty_cell_rejects_the_event(self):
        # Departure: an empty owner does not exist, and the platform refuses a POST
        # whose body does not carry one (section 3.3). Exact counterpart of row 08.
        result = merge(CURRENT, make_event(owner=""))
        self.assertIsNotNone(result.rejection)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "owner_empty_not_allowed")

    def test_row_12_owner_column_present_valued_cell_is_applied(self):
        result = merge(CURRENT, make_event(owner="a_new_owner"))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, owner="a_new_owner")
        self.assertEqual(result.after.owner, "a_new_owner")
        self.assertIn("owner_change", result.warnings)


class PresenceIsNotTheTypeTest(unittest.TestCase):
    """The discriminant is the **presence of the key**, never the type nor the value.

    This is the point the v1 got wrong, and the only one a hurried reader is at risk of
    re-implementing the wrong way round.
    """

    def test_multivalue_reduced_to_one_value_arrives_as_a_string(self):
        """Measurement on 9.4.6: a multivalue field reduced to **a single** value does
        not arrive as a one-element list - it arrives as a **string**.

        An engine deciding by the type ("a list means the operator has spoken", "a
        string means this is only an inherited value") would treat this case as an
        absence and **preserve** the attribute, whereas the pipeline explicitly asks to
        reduce it to that single role. The present test freezes the correct reading.
        """
        result = merge(CURRENT, make_event(write="role_b"))
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.perms_write, ("role_b",))
        self.assertEqual(result.payload["perms.write"], "role_b")

    def test_the_same_value_as_a_one_element_list_gives_the_same_result(self):
        """Corollary: the type changes **nothing**. The list `["role_b"]` and the string
        `"role_b"` produce the same target state, since only the presence decided."""
        from_string = merge(CURRENT, make_event(write="role_b"))
        from_list = merge(CURRENT, make_event(write=["role_b"]))
        self.assertEqual(from_string.after, from_list.after)
        self.assertEqual(from_string.payload, from_list.payload)

    def test_column_present_holding_none_empties_and_does_not_preserve(self):
        """`None` is a **value** of a present column, not a signal of absence.

        A `raw is not None` added "out of caution" to the presence predicate would turn
        this explicit emptying into a silent preservation - exactly the defect the
        rework corrects.
        """
        result = merge(CURRENT, make_event(read=None))
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.perms_read, ())
        self.assertEqual(result.payload["perms.read"], "")

    def test_column_absent_and_column_present_empty_are_not_confused(self):
        """The two cases the v1 held to be indistinguishable, side by side."""
        absent = merge(CURRENT, make_event())
        present_empty = merge(CURRENT, make_event(read=""))
        self.assertEqual(absent.after.perms_read, ("role_a", "role_b"))
        self.assertEqual(present_empty.after.perms_read, ())
        self.assertNotEqual(absent.after, present_empty.after)

    def test_empty_list_on_a_present_column_empties_the_attribute(self):
        for value in ([], [""], ["", " "]):
            with self.subTest(value=value):
                result = merge(CURRENT, make_event(read=value))
                self.assertEqual(result.after.perms_read, ())


if __name__ == "__main__":
    unittest.main()
