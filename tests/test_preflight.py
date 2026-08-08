"""Preflight (sections 5.1, 4.2): parameters, capability, real time, roles catalog."""

import json
import unittest

from acltools.errors import FatalCapabilityError, FatalConfigError
from acltools.model import DEFAULT_FIELD_NAMES
from acltools.preflight import (
    DEFAULT_MAX_OBJECTS,
    DRYRUN_WARNING,
    AppStateCache,
    check_capability,
    check_realtime,
    load_roles_catalog,
    resolve_server_name,
    validate_params,
)
from acltools.rest import RestResponse

from .helpers import FakeRest


def body(content):
    return json.dumps({"entry": [{"name": "context", "content": content}]}).encode(
        "utf-8"
    )


class ValidateParamsTest(unittest.TestCase):

    def test_defaults_of_the_specification(self):
        params = validate_params()
        self.assertEqual(params.names, DEFAULT_FIELD_NAMES)
        self.assertTrue(params.dryrun)
        self.assertTrue(params.validate_roles)
        self.assertTrue(params.journal)
        self.assertEqual(params.max_objects, 10)

    def test_the_default_ceiling_is_ten(self):
        """D-30 - and not five hundred.

        A ceiling of five hundred let operations of several hundred objects through
        without a word. Ten lets the one-off fix through and makes raising the ceiling a
        conscious act.
        """
        self.assertEqual(DEFAULT_MAX_OBJECTS, 10)
        self.assertEqual(validate_params().max_objects, 10)

    def test_naming_defaults_conform_to_the_specification(self):
        """Sections 3.1 and 3.3: the defaults are the platform's native field names,
        which makes the nominal case implicit - the operator who uses them writes no
        parameter at all."""
        names = validate_params().names
        self.assertEqual(names.title, "title")
        self.assertEqual(names.app, "eai:acl.app")
        self.assertEqual(names.id, "id")
        self.assertEqual(names.type, "eai:type")
        self.assertEqual(names.sharing, "eai:acl.sharing")
        self.assertEqual(names.new_perms_read, "eai:acl.perms.read")
        self.assertEqual(names.new_perms_write, "eai:acl.perms.write")
        self.assertEqual(names.new_sharing, "eai:acl.sharing")
        self.assertEqual(names.new_owner, "eai:acl.owner")

    def test_a_renamed_field_name_is_taken_up(self):
        params = validate_params(
            names_raw={"type": "object_type", "new_perms_write": " write "}
        )
        self.assertEqual(params.names.type, "object_type")
        self.assertEqual(params.names.new_perms_write, "write")
        self.assertEqual(params.names.title, "title")

    def test_an_empty_field_name_is_a_fatal_error(self):
        with self.assertRaises(FatalConfigError):
            validate_params(names_raw={"title": "   "})

    def test_a_list_of_fields_is_a_fatal_error(self):
        """The v1 `fields` parameter no longer exists: each parameter names ONE field.
        Refusing the comma catches the operator who still reasons in v1 terms, and
        removes by construction the quoting trap of section 4.4."""
        with self.assertRaises(FatalConfigError) as raised:
            validate_params(names_raw={"new_perms_read": "perms.read,perms.write"})
        self.assertIn("fields", str(raised.exception))

    def test_the_fields_parameter_no_longer_exists(self):
        """`validate_params` no longer accepts it, even under its former call name."""
        with self.assertRaises(TypeError):
            validate_params(fields_raw="perms.read,perms.write")

    def test_a_non_integer_max_objects_is_a_fatal_error(self):
        with self.assertRaises(FatalConfigError):
            validate_params(max_objects="many")

    def test_a_zero_or_negative_max_objects_is_a_fatal_error(self):
        for value in (0, -1, "0", "-5"):
            with self.subTest(value=value):
                with self.assertRaises(FatalConfigError):
                    validate_params(max_objects=value)

    def test_an_invalid_boolean_is_a_fatal_error(self):
        with self.assertRaises(FatalConfigError):
            validate_params(dryrun="maybe")

    def test_warning_on_a_real_write_without_an_explicit_max_objects(self):
        params = validate_params(dryrun=False, max_objects_explicit=False)
        self.assertTrue(params.warnings)
        self.assertIn("max_objects", params.warnings[0])

    def test_no_warning_when_max_objects_is_explicit(self):
        params = validate_params(dryrun=False, max_objects=10, max_objects_explicit=True)
        self.assertEqual(params.warnings, ())

    def test_the_default_ceiling_is_not_signaled_in_simulation(self):
        """A simulation writes nothing: the ceiling reminder has no purpose there.

        This test used to say that a run in simulation emitted NO warning at all. That
        was accurate, and it was the defect: the most consequential parameter of the
        command was the only one whose default state was signaled nowhere. What remains
        true, and what this test keeps holding, is that the ceiling reminder does not
        fire where no write is planned.
        """
        params = validate_params(dryrun=True, max_objects_explicit=False)
        self.assertEqual(
            [w for w in params.warnings if "max_objects" in w], []
        )


class SimulationWarningTest(unittest.TestCase):
    """The simulation is the default state, and it was silent.

    A run in simulation returns a full result table, exactly like a run that wrote
    everything; only the `acl_status` column tells them apart. Without a reminder at the
    head of the run, the operator who believes his changes were applied has no signal to
    the contrary.

    The warning is carried by `Params.warnings`, and therefore emitted **once per run**
    by the adapter, never per event - see `tests/test_editacl_adapter.py`.
    """

    def test_the_simulation_is_signaled(self):
        params = validate_params(dryrun=True)
        self.assertIn(DRYRUN_WARNING, params.warnings)

    def test_the_default_simulation_is_signaled(self):
        """The real case: the operator did not write `dryrun` at all."""
        params = validate_params()
        self.assertIn(DRYRUN_WARNING, params.warnings)

    def test_the_message_says_that_no_write_will_take_place(self):
        self.assertIn("NO change", DRYRUN_WARNING)
        self.assertIn("will be written", DRYRUN_WARNING)

    def test_the_message_says_how_to_actually_push(self):
        self.assertIn("dryrun=false", DRYRUN_WARNING)

    def test_the_message_comes_first_among_the_warnings(self):
        """It precedes the others: it frames the reading of everything that follows."""
        params = validate_params(dryrun=True)
        self.assertEqual(params.warnings[0], DRYRUN_WARNING)

    def test_no_simulation_warning_on_a_real_write(self):
        for explicit in (True, False):
            with self.subTest(max_objects_explicit=explicit):
                params = validate_params(
                    dryrun=False, max_objects=10, max_objects_explicit=explicit
                )
                self.assertNotIn(DRYRUN_WARNING, params.warnings)

    def test_the_message_appears_only_once_in_the_set(self):
        params = validate_params(dryrun=True)
        self.assertEqual(list(params.warnings).count(DRYRUN_WARNING), 1)

    def test_an_unset_option_falls_back_on_the_default(self):
        """The SDK exposes an option absent from the command line as `None`, not as its
        default value: the fallback is carried here, not in the adapter."""
        params = validate_params(
            names_raw=None, dryrun=None, validate_roles=None, journal=None,
            max_objects=None,
        )
        self.assertEqual(params.names, DEFAULT_FIELD_NAMES)
        self.assertTrue(params.dryrun)
        self.assertTrue(params.validate_roles)
        self.assertTrue(params.journal)
        self.assertEqual(params.max_objects, 10)

    def test_booleans_accepted_in_string_form(self):
        params = validate_params(dryrun="f", journal="t", validate_roles="false")
        self.assertFalse(params.dryrun)
        self.assertTrue(params.journal)
        self.assertFalse(params.validate_roles)


class CapabilityTest(unittest.TestCase):
    """Measurement 6 reduces the control to a membership test: `capabilities` is the
    flattened effective set, `imported_roles` inheritance included."""

    PATH = "/services/authentication/current-context"

    def test_capability_present(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    200,
                    body(
                        {
                            "username": "operator",
                            "roles": ["a_role"],
                            "capabilities": ["search", "edit_acl_bulk"],
                        }
                    ),
                )
            }
        )
        check_capability(rest)

    def test_a_missing_capability_is_fatal(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    200,
                    body({"roles": ["a_role"], "capabilities": ["search"]}),
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        self.assertIn("edit_acl_bulk", str(raised.exception))
        self.assertIn("a_role", str(raised.exception))

    def test_an_unusable_response_is_fatal(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(500, b"boom")})
        with self.assertRaises(FatalCapabilityError):
            check_capability(rest)

    def test_an_unexpected_structure_is_fatal(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(200, b'{"entry":[]}')})
        with self.assertRaises(FatalCapabilityError):
            check_capability(rest)

    def test_a_tls_failure_designates_TLS_and_the_verify_ssl_parameter(self):
        """`verify_ssl=true` on a platform with a self-signed certificate fails
        **here**, on the first REST call of the run. The message must name the cause
        and the parameter: without that the operator reads "HTTP 0" on an
        authentication endpoint and goes looking at permissions."""
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    0,
                    b"",
                    "transport:SSLCertVerificationError: [SSL: "
                    "CERTIFICATE_VERIFY_FAILED] certificate verify failed: self "
                    "signed certificate in certificate chain (_ssl.c:1006)",
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        message = str(raised.exception)
        self.assertIn("TLS", message)
        self.assertIn("verify_ssl", message)
        self.assertIn("local/editacl.conf", message)

    def test_a_non_tls_transport_failure_does_not_mention_a_certificate(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    0, b"", "transport:ConnectionRefusedError: Connection refused"
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        message = str(raised.exception)
        self.assertNotIn("verify_ssl", message)
        self.assertIn("Connection refused", message)

    def test_no_walk_of_the_role_hierarchy(self):
        """A single REST call: `authorization/roles` is not solicited."""
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(200, body({"capabilities": ["edit_acl_bulk"]}))
            }
        )
        check_capability(rest)
        self.assertEqual(len(rest.calls), 1)


class RealtimeTest(unittest.TestCase):

    PATH = "/services/search/jobs/test_sid"

    def _rest(self, content):
        return FakeRest(json_responses={self.PATH: RestResponse(200, body(content))})

    def test_a_detected_real_time_search_is_fatal(self):
        with self.assertRaises(FatalCapabilityError):
            check_realtime(self._rest({"isRealTimeSearch": True}), "test_sid")

    def test_a_historical_search(self):
        self.assertEqual(
            check_realtime(self._rest({"isRealTimeSearch": False}), "test_sid"),
            "batch",
        )

    def test_fallback_on_the_time_bounds(self):
        with self.assertRaises(FatalCapabilityError):
            check_realtime(
                self._rest({"earliest_time": "rt-5m", "latest_time": "rt"}),
                "test_sid",
            )

    def test_historical_time_bounds(self):
        self.assertEqual(
            check_realtime(
                self._rest({"earliest_time": "-24h", "latest_time": "now"}),
                "test_sid",
            ),
            "batch",
        )

    def test_an_impossible_detection_does_not_raise(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(404, b"{}")})
        self.assertEqual(check_realtime(rest, "test_sid"), "unknown")

    def test_a_missing_sid(self):
        self.assertEqual(check_realtime(FakeRest(), ""), "unknown")


class RolesCatalogTest(unittest.TestCase):

    PATH = "/services/authorization/roles"

    def test_the_catalog_is_loaded_with_the_star(self):
        document = json.dumps(
            {"entry": [{"name": "role_a"}, {"name": "role_b"}]}
        ).encode("utf-8")
        rest = FakeRest(json_responses={self.PATH: RestResponse(200, document)})
        catalog = load_roles_catalog(rest)
        self.assertEqual(catalog, frozenset({"role_a", "role_b", "*"}))

    def test_the_star_is_present_even_if_the_call_fails(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(500, b"")})
        self.assertIn("*", load_roles_catalog(rest))


class ServerNameTest(unittest.TestCase):

    def test_the_server_name_is_read(self):
        document = json.dumps(
            {"entry": [{"name": "server-info", "content": {"serverName": "sh01"}}]}
        ).encode("utf-8")
        rest = FakeRest(
            json_responses={"/services/server/info": RestResponse(200, document)}
        )
        self.assertEqual(resolve_server_name(rest), "sh01")

    def test_unavailable_gives_an_empty_string(self):
        rest = FakeRest(
            json_responses={"/services/server/info": RestResponse(503, b"")}
        )
        self.assertEqual(resolve_server_name(rest), "")


class AppStateCacheTest(unittest.TestCase):
    """Section 10.5: one call per **distinct** app over the run."""

    def _rest(self, disabled):
        document = json.dumps(
            {"entry": [{"name": "my_app", "content": {"disabled": disabled}}]}
        ).encode("utf-8")
        return FakeRest(
            json_responses={"/services/apps/local/my_app": RestResponse(200, document)}
        )

    def test_a_disabled_app(self):
        cache = AppStateCache(self._rest(True))
        self.assertTrue(cache.is_app_disabled("my_app"))

    def test_an_enabled_app(self):
        cache = AppStateCache(self._rest(False))
        self.assertFalse(cache.is_app_disabled("my_app"))

    def test_memoization_per_app(self):
        rest = self._rest(True)
        cache = AppStateCache(rest)
        for _ in range(5):
            cache.is_app_disabled("my_app")
        self.assertEqual(len(rest.calls), 1)


if __name__ == "__main__":
    unittest.main()
