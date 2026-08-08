"""Binding of an SPL record to `EventInput` (sections 3.1, 3.2, 3.3).

This is where the presence semantics is **realized**, out of the only datum the command
has at hand: the chunk record. The merge engine, for its part, only ever sees the
verdict (`EventInput.present`), which is precisely why the verdict itself is worth
exercising, on raw records.

Two failure modes are covered here and nowhere else:

1. **deciding by type**: a multivalue reduced to a single value arrives as a string,
   and an engine that read the type would conclude wrongly;
2. **deciding by value**: a `raw is not None` added "out of caution" to the presence
   predicate would turn an explicit clearing into a silent preservation.
"""

import unittest

from acltools.binding import build_event, field_present, field_value
from acltools.model import DEFAULT_FIELD_NAMES, TARGET_ATTRIBUTES, FieldNames


def record(**kwargs):
    """Chunk record. A key absent from the dict **is** an absent column."""
    return dict(kwargs)


NAMES = DEFAULT_FIELD_NAMES


class PresencePredicateTest(unittest.TestCase):
    """`field_present` is the single injection point of the rule of section 3.2.

    Its definition fits on one line, `name in record`, and that is deliberately all it
    does. Every additional clause would be a regression.
    """

    def test_key_present_with_a_value(self):
        self.assertTrue(field_present(record(a="x"), "a"))

    def test_key_present_holding_the_empty_string(self):
        self.assertTrue(field_present(record(a=""), "a"))

    def test_key_present_holding_none(self):
        """`None` is the value of a present column, not a signal of absence."""
        self.assertTrue(field_present(record(a=None), "a"))

    def test_key_present_holding_an_empty_list(self):
        self.assertTrue(field_present(record(a=[]), "a"))

    def test_key_absent(self):
        self.assertFalse(field_present(record(b="x"), "a"))

    def test_empty_record(self):
        self.assertFalse(field_present({}, "a"))

    def test_the_raw_value_is_not_coerced(self):
        """`field_value` carries, it does not interpret: `merge` is what decides."""
        for raw in ("", None, [], ["role_a"], "role_a,role_b"):
            with self.subTest(raw=raw):
                self.assertEqual(field_value(record(a=raw), "a"), raw)

    def test_an_absent_column_yields_the_requested_default(self):
        sentinel = object()
        self.assertIs(field_value({}, "a", default=sentinel), sentinel)


class TargetValuePresenceTest(unittest.TestCase):
    """The verdict bears on the four target attributes, one by one."""

    def test_no_target_column_no_attribute_present(self):
        event = build_event(record(title="My search", **{"eai:acl.app": "my_app"}),
                            NAMES)
        self.assertEqual(event.present, frozenset())
        for attribute in TARGET_ATTRIBUTES:
            self.assertFalse(event.has(attribute))

    def test_perms_read_present(self):
        event = build_event(record(**{"eai:acl.perms.read": "role_a"}), NAMES)
        self.assertTrue(event.has("perms.read"))
        self.assertFalse(event.has("perms.write"))

    def test_perms_write_present(self):
        event = build_event(record(**{"eai:acl.perms.write": ""}), NAMES)
        self.assertTrue(event.has("perms.write"))
        self.assertEqual(event.new_perms_write, "")

    def test_sharing_present(self):
        event = build_event(record(**{"eai:acl.sharing": "global"}), NAMES)
        self.assertTrue(event.has("sharing"))

    def test_owner_present(self):
        event = build_event(record(**{"eai:acl.owner": "an_owner"}), NAMES)
        self.assertTrue(event.has("owner"))
        self.assertEqual(event.new_owner, "an_owner")

    def test_the_four_columns_present(self):
        event = build_event(
            record(**{
                "eai:acl.perms.read": "role_a",
                "eai:acl.perms.write": "role_b",
                "eai:acl.sharing": "global",
                "eai:acl.owner": "an_owner",
            }),
            NAMES,
        )
        self.assertEqual(event.present, frozenset(TARGET_ATTRIBUTES))


class PresenceIsNotTypeTest(unittest.TestCase):
    """**The point on which v1 got it wrong.**

    Measured on 9.4.6: the command receives either a key absent from the record, or a
    key present holding the empty string. Never `None`, never an empty list. And a
    multivalue field **reduced to a single value arrives as a string**, not as a
    one-element list.
    """

    def test_multivalue_reduced_to_one_value_arrives_as_a_string_and_stays_present(self):
        """The nominal decommissioning case, once `mvmap` has run.

        An engine deciding by type - "a list means the operator spoke; a string is only
        an inherited value" - would treat this record as an absence and would
        **preserve** the attribute, whereas the pipeline explicitly asks for it to be
        reduced to that single role.
        """
        event = build_event(record(**{"eai:acl.perms.write": "remaining_role"}), NAMES)
        self.assertTrue(event.has("perms.write"))
        self.assertIsInstance(event.new_perms_write, str)
        self.assertNotIsInstance(event.new_perms_write, list)

    def test_multivalue_with_several_values_arrives_as_a_list_and_stays_present(self):
        event = build_event(
            record(**{"eai:acl.perms.write": ["role_a", "role_b"]}), NAMES
        )
        self.assertTrue(event.has("perms.write"))
        self.assertIsInstance(event.new_perms_write, list)

    def test_the_verdict_is_identical_whatever_the_type(self):
        """String, one-element list, two-element list, empty list, empty string,
        `None`: all these forms are **present columns**. The type enters nowhere."""
        for raw in ("role_a", ["role_a"], ["role_a", "role_b"], [], "", None, 0):
            with self.subTest(raw=raw):
                event = build_event(record(**{"eai:acl.perms.write": raw}), NAMES)
                self.assertTrue(
                    event.has("perms.write"),
                    "the presence of the key decides, not the type of its value",
                )

    def test_an_absent_column_and_an_empty_column_give_opposite_verdicts(self):
        """The two cases v1 held to be indistinguishable, side by side on raw
        records."""
        absent = build_event(record(title="x"), NAMES)
        empty = build_event(record(title="x", **{"eai:acl.perms.read": ""}), NAMES)
        self.assertFalse(absent.has("perms.read"))
        self.assertTrue(empty.has("perms.read"))

    def test_a_column_holding_none_is_present_and_not_absent(self):
        """The most tempting regression: adding `and raw is not None` to the predicate.

        It would turn an explicit clearing into a silent preservation, that is, exactly
        the v1 defect reintroduced through the back door.
        """
        event = build_event(record(**{"eai:acl.perms.read": None}), NAMES)
        self.assertTrue(event.has("perms.read"))
        self.assertIsNone(event.new_perms_read)


class FieldNamingParametersTest(unittest.TestCase):
    """Each parameter redirects the reading of one piece of information to another
    column name. That is what makes it possible to plug the command onto an upstream
    pipeline that renamed its fields."""

    def test_default_applied(self):
        event = build_event(
            record(title="My search", **{"eai:acl.app": "my_app",
                                         "eai:type": "savedsearch"}),
            NAMES,
        )
        self.assertEqual(event.title, "My search")
        self.assertEqual(event.app, "my_app")
        self.assertEqual(event.eai_type, "savedsearch")

    def test_renamed_field(self):
        names = FieldNames(type="object_type", new_perms_write="write")
        event = build_event(
            record(title="My search", **{"eai:acl.app": "my_app",
                                         "object_type": "savedsearch",
                                         "write": "new_role_admin"}),
            names,
        )
        self.assertEqual(event.eai_type, "savedsearch")
        self.assertTrue(event.has("perms.write"))
        self.assertEqual(event.new_perms_write, "new_role_admin")

    def test_the_original_field_is_no_longer_read_after_redirection(self):
        """Redirecting really means moving the reading, not widening it."""
        names = FieldNames(new_perms_write="write")
        event = build_event(
            record(**{"eai:acl.perms.write": "ignored_role"}), names
        )
        self.assertFalse(event.has("perms.write"))

    def test_designated_field_absent_from_the_result_set(self):
        names = FieldNames(new_perms_write="nonexistent_column")
        event = build_event(record(**{"eai:acl.perms.write": "role_a"}), names)
        self.assertFalse(event.has("perms.write"))
        self.assertIsNone(event.new_perms_write)

    def test_two_parameters_may_designate_the_same_column(self):
        """This is the default case: `sharing` and `new_sharing` both hold
        `eai:acl.sharing`. The current sharing scope serves to skip private objects,
        the target value to decide the write: two uses of one column."""
        event = build_event(record(**{"eai:acl.sharing": "global"}), NAMES)
        self.assertEqual(event.current_sharing, "global")
        self.assertTrue(event.has("sharing"))


class CurrentSharingScopeTest(unittest.TestCase):
    """Sections 3.1 and 3.5: the current sharing scope is optional, and its **absence**
    has an observable effect - the command can no longer skip private objects
    upstream."""

    def test_absent_column_yields_none(self):
        event = build_event(record(title="x"), NAMES)
        self.assertIsNone(event.current_sharing)

    def test_present_empty_column_yields_the_empty_string_not_none(self):
        """The distinction matters: `None` says "I do not know", `""` says "the
        platform did not fill it in". Neither one is `user`."""
        event = build_event(record(**{"eai:acl.sharing": ""}), NAMES)
        self.assertEqual(event.current_sharing, "")
        self.assertIsNotNone(event.current_sharing)

    def test_present_column_with_a_value(self):
        event = build_event(record(**{"eai:acl.sharing": "user"}), NAMES)
        self.assertEqual(event.current_sharing, "user")


class ReferenceFieldsTest(unittest.TestCase):

    def test_a_single_valued_multivalue_is_reduced_for_a_single_valued_field(self):
        event = build_event(record(title=["My search"]), NAMES)
        self.assertEqual(event.title, "My search")

    def test_surrounding_whitespace_is_stripped(self):
        event = build_event(record(title="  My search  "), NAMES)
        self.assertEqual(event.title, "My search")

    def test_an_empty_eai_type_counts_as_absent_for_resolution(self):
        """The resolution of section 5.2 has no use for an empty string: it falls back
        on `id`, or rejects. Normalizing it to `None` avoids a misleading
        `unresolved_endpoint:`."""
        event = build_event(record(**{"eai:type": "  "}), NAMES)
        self.assertIsNone(event.eai_type)

    def test_no_addressing_owner_field_is_read(self):
        """D-25: there is no reference `owner` parameter, only `new_owner`, which is a
        target value. A record carrying an owner therefore makes nothing of it other
        than a value to apply."""
        self.assertFalse(hasattr(NAMES, "owner"))
        event = build_event(record(**{"eai:acl.owner": "a_third_party"}), NAMES)
        self.assertTrue(event.has("owner"))
        self.assertFalse(hasattr(event, "owner"))


if __name__ == "__main__":
    unittest.main()
