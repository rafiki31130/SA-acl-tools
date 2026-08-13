"""Parameters of `editappacl` (v4.1 sections 8.5, 13.1, 13.3).

This is where the **contract defaults** are frozen: simulation on, creation refused, two
ceilings whose values are choices and not measurements. Three of the four are the friction
the contract deliberately places on the act rather than on the review, and a default that
drifts is a friction that disappears without anybody deciding it.
"""

import unittest

from acltools.appacl_model import DEFAULT_APP_FIELD_NAMES
from acltools.appacl_preflight import (
    ALLOW_CREATE_WARNING,
    APP_FIELD_NAME_PARAMS,
    DEFAULT_MAX_IMPACTED_OBJECTS,
    DEFAULT_MAX_STANZAS,
    DRYRUN_WARNING,
    REQUIRED_APP_CAPABILITY,
    parse_app_field_names,
    validate_app_params,
)
from acltools.errors import FatalConfigError


class TheContractualDefaultsTest(unittest.TestCase):

    def test_the_simulation_is_the_default(self):
        self.assertTrue(validate_app_params().dryrun)

    def test_the_creation_is_refused_by_default(self):
        """Section 9.3: the refusal IS the default, and `allow_create` is the deliberate
        act. An operation that nothing undoes deserves at least the friction a low write
        ceiling already carries."""
        self.assertFalse(validate_app_params().allow_create)

    def test_the_role_validation_and_the_journal_are_on_by_default(self):
        params = validate_app_params()
        self.assertTrue(params.validate_roles)
        self.assertTrue(params.journal)

    def test_the_two_ceilings_carry_their_contractual_values(self):
        """Five and two hundred, and both are **choices**: O-6 states that the real
        magnitude of a generic write has not been quantified."""
        self.assertEqual(DEFAULT_MAX_STANZAS, 5)
        self.assertEqual(DEFAULT_MAX_IMPACTED_OBJECTS, 200)
        params = validate_app_params()
        self.assertEqual(params.max_stanzas, 5)
        self.assertEqual(params.max_impacted_objects, 200)

    def test_the_two_ceilings_count_different_things(self):
        """Neither is enough alone: one write on the default of a large application is a
        single act with an immense reach, twenty writes on empty families move nothing."""
        params = validate_app_params(max_stanzas=1, max_impacted_objects=9999)
        self.assertEqual(params.max_stanzas, 1)
        self.assertEqual(params.max_impacted_objects, 9999)

    def test_the_capability_is_the_dedicated_one(self):
        self.assertEqual(REQUIRED_APP_CAPABILITY, "edit_app_acl_bulk")

    def test_the_capability_is_not_the_one_of_the_other_command(self):
        from acltools.preflight import REQUIRED_CAPABILITY

        self.assertNotEqual(REQUIRED_APP_CAPABILITY, REQUIRED_CAPABILITY)


class TheSimulationIsAnnouncedTest(unittest.TestCase):
    """Section 13.3: one warning per run, saying what will not happen and how to make it
    happen."""

    def test_a_simulation_carries_the_reminder(self):
        self.assertIn(DRYRUN_WARNING, validate_app_params(dryrun=True).warnings)

    def test_it_names_the_exact_gesture(self):
        self.assertIn("dryrun=false", DRYRUN_WARNING)

    def test_a_real_run_does_not_carry_it(self):
        self.assertNotIn(DRYRUN_WARNING, validate_app_params(dryrun=False).warnings)

    def test_a_real_run_authorizing_creations_says_so(self):
        warnings = validate_app_params(dryrun=False, allow_create=True).warnings
        self.assertIn(ALLOW_CREATE_WARNING, warnings)
        self.assertIn("cannot be undone", ALLOW_CREATE_WARNING)

    def test_a_real_run_with_an_implicit_ceiling_says_so(self):
        warnings = validate_app_params(dryrun=False, max_stanzas_explicit=False).warnings
        self.assertTrue(any("max_stanzas" in warning for warning in warnings))

    def test_the_warnings_are_carried_by_the_parameters_not_emitted_here(self):
        """They are emitted once per run by the adapter. A batch of several hundred rows
        would otherwise repeat them, and a repeated warning gets filtered out mentally."""
        self.assertIsInstance(validate_app_params().warnings, tuple)


class TheFieldNamingParametersTest(unittest.TestCase):
    """Sections 8.3 and 8.4: each parameter names ONE field, and defaults to what the
    inventory emits."""

    def test_the_seven_parameters_and_their_defaults(self):
        names = parse_app_field_names(None)
        self.assertEqual(names.app, "eai:acl.app")
        self.assertEqual(names.stanza_kind, "acl_stanza_kind")
        self.assertEqual(names.handler, "acl_handler")
        self.assertEqual(names.stanza, "acl_stanza")
        self.assertEqual(names.new_perms_read, "eai:acl.perms.read")
        self.assertEqual(names.new_perms_write, "eai:acl.perms.write")
        self.assertEqual(names.new_sharing, "eai:acl.sharing")

    def test_the_parameter_set_is_the_declared_one(self):
        self.assertEqual(len(APP_FIELD_NAME_PARAMS), 7)
        for parameter in APP_FIELD_NAME_PARAMS:
            with self.subTest(parameter=parameter):
                self.assertTrue(hasattr(DEFAULT_APP_FIELD_NAMES, parameter))

    def test_there_is_no_owner_parameter(self):
        """**DV-5**: no owner value is expressible, so exposing a parameter for one would
        be a false promise."""
        for parameter in APP_FIELD_NAME_PARAMS:
            with self.subTest(parameter=parameter):
                self.assertNotIn("owner", parameter)
        self.assertFalse(hasattr(DEFAULT_APP_FIELD_NAMES, "new_owner"))

    def test_a_redirected_field_is_taken(self):
        names = parse_app_field_names({"stanza": "my_family_column"})
        self.assertEqual(names.stanza, "my_family_column")
        self.assertEqual(names.app, "eai:acl.app")

    def test_an_empty_field_name_is_fatal(self):
        with self.assertRaises(FatalConfigError):
            parse_app_field_names({"app": "  "})

    def test_a_list_of_fields_is_fatal(self):
        """It catches the operator who writes a list where the contract expects one
        name - the value would otherwise be treated as an improbable field name."""
        for value in ("a,b", "a|b", "a\nb"):
            with self.subTest(value=value):
                with self.assertRaises(FatalConfigError):
                    parse_app_field_names({"new_perms_read": value})


class TheInvalidParametersAreFatalTest(unittest.TestCase):
    """Section 13.1: a parameter that is not what it claims interrupts the search."""

    def test_a_non_integer_ceiling_is_fatal(self):
        for parameter in ("max_stanzas", "max_impacted_objects"):
            for value in ("many", "", "1.5", "-"):
                with self.subTest(parameter=parameter, value=value):
                    with self.assertRaises(FatalConfigError):
                        validate_app_params(**{parameter: value})

    def test_a_non_positive_ceiling_is_fatal(self):
        for parameter in ("max_stanzas", "max_impacted_objects"):
            for value in (0, -1):
                with self.subTest(parameter=parameter, value=value):
                    with self.assertRaises(FatalConfigError):
                        validate_app_params(**{parameter: value})

    def test_a_non_boolean_is_fatal(self):
        for parameter in ("dryrun", "allow_create", "validate_roles", "journal"):
            with self.subTest(parameter=parameter):
                with self.assertRaises(FatalConfigError):
                    validate_app_params(**{parameter: "maybe"})

    def test_the_usual_boolean_spellings_are_accepted(self):
        for value in (True, "true", "t", "1", "yes", "on"):
            with self.subTest(value=value):
                self.assertTrue(validate_app_params(allow_create=value).allow_create)
        for value in (False, "false", "f", "0", "no", "off"):
            with self.subTest(value=value):
                self.assertFalse(validate_app_params(allow_create=value).allow_create)

    def test_an_unset_option_falls_back_on_the_default(self):
        """The SDK exposes an option that was not set as `None`, not as its default."""
        params = validate_app_params(
            dryrun=None, allow_create=None, max_stanzas=None, max_impacted_objects=None
        )
        self.assertTrue(params.dryrun)
        self.assertFalse(params.allow_create)
        self.assertEqual(params.max_stanzas, DEFAULT_MAX_STANZAS)


class TheCapabilityCheckIsSharedTest(unittest.TestCase):
    """The checking function is shared, the capability is not (section 8.1)."""

    def test_the_check_takes_the_capability_as_a_parameter(self):
        import inspect

        from acltools.preflight import check_capability

        parameters = inspect.signature(check_capability).parameters
        self.assertIn("capability", parameters)

    def test_its_default_is_still_the_one_of_the_previous_command(self):
        """`editacl` must keep checking exactly what it checked before."""
        import inspect

        from acltools.preflight import REQUIRED_CAPABILITY, check_capability

        default = inspect.signature(check_capability).parameters["capability"].default
        self.assertEqual(default, REQUIRED_CAPABILITY)


if __name__ == "__main__":
    unittest.main()
