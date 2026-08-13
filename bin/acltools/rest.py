"""REST client towards splunkd. **Only module of the package allowed to open a socket.**

Standard library only: no dependency on `requests`, and none on the version of the
search-command SDK shipped by the platform.

No network exception escapes: a transport failure becomes a response with status `0`.
The core therefore has a single processing path.
"""

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

#: Module constants, **not** command parameters: section 4.1 freezes the parameter
#: surface of `editacl`.
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60

#: A single retry, after a delay, on `5xx` **for the GET** (section 5.3).
#: **No retry on the POST**: it could not tell "the first POST never left" from "the
#: first POST succeeded and the response was lost". Section 8.7 handles that case by
#: cross-checking with the splunkd access log, which presupposes not multiplying the
#: attempts.
RETRY_DELAY_SECONDS = 2

#: Markers of a transport failure attributable to TLS, searched for in lower case in
#: the normalized message of `RestResponse.error`.
#:
#: The classification lives here, next to the code that **produces** that message:
#: separating the two would guarantee they diverge at the first format change.
TLS_FAILURE_MARKERS = (
    "sslcertverificationerror",
    "sslerror",
    "certificate_verify_failed",
    "certificate verify failed",
    "self signed certificate",
    "self-signed certificate",
    "unable to get local issuer certificate",
    "certificate has expired",
    "hostname mismatch",
    "doesn't match either of",
)

#: Remediation message for a TLS failure. It **names the setting**: without it the
#: operator only sees an `HTTP 0` on a preflight call and has no reason to suspect the
#: certificate. The nominal case is a platform with a self-signed certificate, on which
#: `verify_ssl` defaults to `true` (section 2.2).
TLS_REMEDIATION = (
    "TLS verification of the splunkd certificate failed. On a platform with a "
    "self-signed certificate: create the file local/editacl.conf of the SA-acl-tools "
    "app with [editacl] then verify_ssl = false, or install the platform CA in "
    "$SPLUNK_HOME/etc/auth/cacert.pem."
)


def is_tls_failure(response):
    """True if `response` is a **transport** failure attributable to TLS.

    A TLS failure reaches the core like any other transport failure - `status = 0` -
    hence as an undifferentiated `HTTP 0`. This function is what lifts that ambiguity.
    """
    if response is None or getattr(response, "status", None) != 0:
        return False
    marker = str(getattr(response, "error", "") or "").lower()
    return any(pattern in marker for pattern in TLS_FAILURE_MARKERS)


class RestResponse(object):
    """`(status, body, error)`. `status = 0` signals a transport failure."""

    __slots__ = ("status", "body", "error")

    def __init__(self, status, body=b"", error=None):
        self.status = int(status)
        self.body = body or b""
        self.error = error

    @property
    def ok(self):
        return 200 <= self.status < 300

    def text(self, limit=512):
        try:
            decoded = self.body.decode("utf-8", "replace")
        except Exception:                                    # pragma: no cover
            decoded = repr(self.body)
        return decoded[:limit]

    def __repr__(self):                                      # pragma: no cover
        return "RestResponse(status=%d, error=%r)" % (self.status, self.error)


def build_ssl_context(verify_ssl=True, ca_file=None):
    """TLS context. Verification on by default, with the platform CA bundle."""
    if not verify_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


class RestClient(object):
    """Minimal HTTP client towards `splunkd_uri`.

    The session key appears in no log, in no error message and in no URL: it is only
    carried by the `Authorization` header.
    """

    def __init__(self, base_uri, session_key, verify_ssl=True, ca_file=None):
        self._base = str(base_uri).rstrip("/")
        self._session_key = session_key
        self._context = build_ssl_context(verify_ssl, ca_file)

    # -- transport --------------------------------------------------------- #

    def _request(self, method, path, params=None, payload=None):
        url = self._base + path
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        data = None
        headers = {"Authorization": "Splunk %s" % self._session_key}
        if payload is not None:
            data = urllib.parse.urlencode(payload).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(
                request, context=self._context, timeout=READ_TIMEOUT
            ) as response:
                return RestResponse(response.status, response.read())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:                                # pragma: no cover
                body = b""
            return RestResponse(exc.code, body)
        except Exception as exc:
            # Transport failure: never an exception towards the core. The message is
            # normalized and cannot contain the session key, which only appears in a
            # header.
            return RestResponse(0, b"", "transport:%s: %s" % (type(exc).__name__, exc))

    # -- REST port --------------------------------------------------------- #

    def get_object_acl(self, object_path):
        """`GET <object_path>?output_mode=json&f=eai:acl*` - one retry on `5xx`."""
        params = {"output_mode": "json", "f": "eai:acl*"}
        response = self._request("GET", object_path, params=params)
        if 500 <= response.status < 600:
            time.sleep(RETRY_DELAY_SECONDS)
            response = self._request("GET", object_path, params=params)
        return response

    def post_object_acl(self, object_path, payload):
        """`POST <object_path>/acl`, body `application/x-www-form-urlencoded`.

        No retry, deliberately.
        """
        body = dict(payload)
        body["output_mode"] = "json"
        return self._request("POST", object_path + "/acl", payload=body)

    def get_app_acl(self, path):
        """`GET <path>?output_mode=json` - one retry on `5xx` (v4.1 section 8.7).

        The application-level paths are **not** object paths: the `[]` path already
        carries its `/acl` suffix and the family path its `/_acl` action, so the read and
        the write bear on the **same** string. That is why this method takes the path as
        it stands instead of suffixing it, and why the field filter `f=eai:acl*` of
        `get_object_acl` is not applied: on `/services/apps/local/<app>/acl` it would
        filter a `content` block the caller does not read anyway, and adding a parameter
        no measurement covered to a measured call buys nothing.
        """
        params = {"output_mode": "json"}
        response = self._request("GET", path, params=params)
        if 500 <= response.status < 600:
            time.sleep(RETRY_DELAY_SECONDS)
            response = self._request("GET", path, params=params)
        return response

    def post_app_acl(self, path, payload):
        """`POST <path>`, body `application/x-www-form-urlencoded`. **No retry.**

        No retry, and for the reason that already forbids it on the object path: it could
        not tell "the first POST never left" from "the first POST succeeded and the
        answer was lost". Here the reason is sharper still - a write may have happened
        despite a non-2xx answer (measured), so a retry would risk a second write on a
        target whose state is already undetermined.
        """
        body = dict(payload)
        body["output_mode"] = "json"
        return self._request("POST", path, payload=body)

    def get_json(self, path, params=None):
        """Preflight call (context, roles, apps, search job)."""
        merged = {"output_mode": "json"}
        if params:
            merged.update(params)
        return self._request("GET", path, params=merged)
