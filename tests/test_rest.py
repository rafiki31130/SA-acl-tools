"""REST client - retries and non-leakage of the session key.

No socket is opened: the transport method is substituted. This file checks the retry
**policy**, not the network stack, which belongs to the reference platform.
"""

import unittest

from acltools import rest as rest_module
from acltools.rest import (
    TLS_REMEDIATION,
    RestClient,
    RestResponse,
    build_ssl_context,
    is_tls_failure,
)

SESSION_KEY = "fake-session-key-0123456789"


class RecordingClient(RestClient):
    """Client whose transport is replaced by a queue of scripted responses."""

    def __init__(self, responses, **kwargs):
        super(RecordingClient, self).__init__(
            "https://base.invalid:0", SESSION_KEY, **kwargs
        )
        self.responses = list(responses)
        self.calls = []

    def _request(self, method, path, params=None, payload=None):
        self.calls.append((method, path, params, payload))
        if self.responses:
            return self.responses.pop(0)
        return RestResponse(200, b"{}")


class RetryPolicyTest(unittest.TestCase):

    def setUp(self):
        self._sleep = rest_module.time.sleep
        rest_module.time.sleep = lambda _seconds: None

    def tearDown(self):
        rest_module.time.sleep = self._sleep

    def test_a_single_retry_on_a_get_5xx(self):
        client = RecordingClient(
            [RestResponse(503, b"unavailable"), RestResponse(200, b"{}")]
        )
        response = client.get_object_acl("/servicesNS/nobody/my_app/saved/searches/o")
        self.assertEqual(response.status, 200)
        self.assertEqual(len(client.calls), 2)

    def test_no_third_attempt_on_a_get(self):
        client = RecordingClient(
            [RestResponse(503, b"x"), RestResponse(503, b"x"), RestResponse(200, b"{}")]
        )
        response = client.get_object_acl("/servicesNS/nobody/my_app/saved/searches/o")
        self.assertEqual(response.status, 503)
        self.assertEqual(len(client.calls), 2)

    def test_no_retry_on_a_get_4xx(self):
        client = RecordingClient([RestResponse(404, b"{}")])
        client.get_object_acl("/servicesNS/nobody/my_app/saved/searches/o")
        self.assertEqual(len(client.calls), 1)

    def test_no_retry_at_all_on_the_post(self):
        """A retry could not tell "the POST never left" from "the POST went through and
        the response was lost" - section 8.7 handles that case by cross-checking, which
        presupposes not multiplying the attempts."""
        client = RecordingClient([RestResponse(503, b"unavailable")])
        response = client.post_object_acl(
            "/servicesNS/nobody/my_app/saved/searches/o", {"owner": "nobody"}
        )
        self.assertEqual(response.status, 503)
        self.assertEqual(len(client.calls), 1)

    def test_the_post_targets_the_acl_suffix(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.post_object_acl("/servicesNS/nobody/my_app/saved/searches/o", {})
        method, path, _params, _payload = client.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/servicesNS/nobody/my_app/saved/searches/o/acl")

    def test_the_get_does_not_carry_the_acl_suffix(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.get_object_acl("/servicesNS/nobody/my_app/saved/searches/o")
        _method, path, params, _payload = client.calls[0]
        self.assertFalse(path.endswith("/acl"))
        self.assertEqual(params["f"], "eai:acl*")
        self.assertEqual(params["output_mode"], "json")


class SessionKeyTest(unittest.TestCase):
    """The session key appears neither in a log, nor in an error message, nor in a URL:
    it is carried by the `Authorization` header and nowhere else."""

    def test_the_key_does_not_appear_in_the_request_parameters(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.get_object_acl("/servicesNS/nobody/my_app/saved/searches/o")
        _method, path, params, payload = client.calls[0]
        self.assertNotIn(SESSION_KEY, path)
        self.assertNotIn(SESSION_KEY, repr(params))
        self.assertNotIn(SESSION_KEY, repr(payload))

    def test_the_key_does_not_appear_in_the_representation_of_a_response(self):
        response = RestResponse(0, b"", "transport:TimeoutError: expired")
        self.assertNotIn(SESSION_KEY, repr(response))
        self.assertNotIn(SESSION_KEY, response.text())

    def test_the_key_does_not_appear_in_the_representation_of_the_client(self):
        client = RecordingClient([])
        self.assertNotIn(SESSION_KEY, repr(client))


class ResponseTest(unittest.TestCase):

    def test_zero_sentinel_for_a_transport_failure(self):
        response = RestResponse(0, b"", "transport:URLError: unreachable")
        self.assertEqual(response.status, 0)
        self.assertFalse(response.ok)

    def test_body_truncated_at_512_characters(self):
        response = RestResponse(500, b"x" * 2000)
        self.assertEqual(len(response.text()), 512)


class SslContextTest(unittest.TestCase):

    def test_verification_enabled_by_default(self):
        import ssl

        context = build_ssl_context(verify_ssl=True)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_verification_can_be_disabled_for_a_self_signed_certificate(self):
        import ssl

        context = build_ssl_context(verify_ssl=False)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)


class TlsFailureTest(unittest.TestCase):
    """A TLS failure reaches the core like any other transport failure - an
    undifferentiated `status = 0`. This classification is what lets `preflight` turn it
    into a message that designates the cause and the parameter."""

    def test_the_message_actually_produced_by_the_transport_is_classified(self):
        # Message built exactly the way `RestClient._request` builds it when
        # `ssl.SSLCertVerificationError` is raised, the real exception of a platform
        # with a self-signed certificate.
        import ssl

        exc = ssl.SSLCertVerificationError(
            1,
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed "
            "certificate in certificate chain (_ssl.c:1006)",
        )
        response = RestResponse(
            0, b"", "transport:%s: %s" % (type(exc).__name__, exc)
        )
        self.assertTrue(is_tls_failure(response))

    def test_the_form_actually_observed_on_the_reference_platform_is_classified(self):
        # Measurement: `urlopen` did not let `SSLCertVerificationError` propagate but a
        # `URLError` wrapping it. It is that string, recorded on a platform with a
        # self-signed certificate, that the classification must recognize.
        response = RestResponse(
            0, b"",
            "transport:URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate verify failed: IP address mismatch, certificate is not "
            "valid for '203.0.113.1'. (_ssl.c:1161)>",
        )
        self.assertTrue(is_tls_failure(response))

    def test_a_non_tls_transport_failure_is_not_classified_as_tls(self):
        response = RestResponse(
            0, b"", "transport:ConnectionRefusedError: [Errno 111] Connection refused"
        )
        self.assertFalse(is_tls_failure(response))

    def test_an_http_response_is_never_a_tls_failure(self):
        # A 403 is not a transport failure: the tunnel was properly established.
        self.assertFalse(is_tls_failure(RestResponse(403, b"forbidden")))
        self.assertFalse(is_tls_failure(RestResponse(200, b"{}")))
        self.assertFalse(is_tls_failure(None))

    def test_the_remediation_designates_the_parameter_and_its_file(self):
        # This is the whole point of the fix: a message that names neither `verify_ssl`
        # nor `local/editacl.conf` leaves the operator looking at permissions, on an
        # authentication endpoint.
        self.assertIn("verify_ssl", TLS_REMEDIATION)
        self.assertIn("local/editacl.conf", TLS_REMEDIATION)
        self.assertIn("TLS", TLS_REMEDIATION)


if __name__ == "__main__":
    unittest.main()
