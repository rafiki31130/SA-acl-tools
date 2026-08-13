"""Test doubles of the application-level command (v4.3).

Same discipline as `tests/helpers.py`: no HTTP simulation library, no socket, no local
server, and JSON fixtures **written by hand** from the shape observed on the reference
platform, using generic identifiers only.

The provenance double is not a mock: it is the **real** `AppProvenance`, fed with the
text of a `.meta` file. Reading a `.meta` is pure text handling once the file is open, so
substituting the reader would replace the thing under test by a description of it.
"""

import json

from acltools.appacl_family import FamilyTable
from acltools.appacl_model import (
    STANZA_KIND_FAMILY,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    AppAclState,
    AppEventInput,
    AppFieldNames,
    AppParams,
    AppRunContext,
)
from acltools.appacl_provenance import AppProvenance, MetaFile, parse_meta
from acltools.rest import RestResponse

#: The three shapes a `[<family>/<object>]` stanza really takes on the platform, and what
#: each one freezes. **Measured** on the lab during the remediation of 2026-08-13, by
#: writing the generic header and re-reading the effective ACL of a witness of each shape:
#:
#:     shape        keys                        perms      scope
#:     TOUCHED      owner / version / modtime   inherits   inherits
#:     SCOPED       export (+ bookkeeping)      inherits   frozen
#:     FROZEN       access + export             frozen     frozen
#:
#: They exist as **named constants** because the fixtures that used to stand in for a
#: frozen object carried an invented key (`a = 1`), which freezes nothing. That is what
#: let anomaly A-2 through a suite of 1 288 tests: the code was wrong and the fixtures
#: were wrong in the same direction, so they agreed. A fixture that does not reproduce
#: what the platform writes tests the developer's belief, not the platform.
def frozen_stanza(name):
    """A stanza that really freezes: it carries the permissions."""
    return ("[%s]\naccess = read : [ power ], write : [ admin ]\nexport = none\n"
            "owner = nobody\nversion = 9.4.6\nmodtime = 1786518192.167816000\n" % name)


def touched_stanza(name):
    """What splunkd writes for **every object it creates or edits**. Freezes nothing."""
    return ("[%s]\nowner = admin\nversion = 9.4.6\n"
            "modtime = 1786518192.167816000\n" % name)


def scoped_stanza(name):
    """A stanza carrying `export` and no `access`: the scope is frozen, the permissions
    are not. Produced by a POST that sets the sharing without sending permissions."""
    return ("[%s]\nexport = system\nowner = nobody\nversion = 9.4.6\n"
            "modtime = 1786518192.167816000\n" % name)


#: Sentinel for an **absent column** in `make_app_event`. `None` cannot play that role:
#: it is a possible value of a *present* column, and confusing the two is the very error
#: the presence semantics exists to avoid.
ABSENT = object()

#: Table used by the tests: a strict subset of the shipped one, with the three families
#: the phase 1b measurement covered plus one whose stanza name differs from its URI.
FIXTURE_TABLE = FamilyTable(
    {
        "views": "data/ui/views",
        "savedsearches": "saved/searches",
        "macros": "data/macros",
        "workflow_actions": "data/ui/workflow-actions",
    }
)


def app_acl_body(sharing="app", read=("power",), write=("admin",), name="views"):
    """Body of a `GET` on either read path.

    The two paths return the same block shape (Q0-1, Q0-2); what differs is
    `entry[0].name`, which carries the family name on the `_acl` path. `owner` is present
    because the platform emits it, and **deliberately unused**: it is inert on one path
    and refused on the other.
    """
    document = {
        "entry": [
            {
                "name": name,
                "content": {},
                "acl": {
                    "app": "my_app",
                    "owner": "nobody",
                    "sharing": sharing,
                    "perms": {"read": list(read), "write": list(write)},
                },
            }
        ]
    }
    return json.dumps(document).encode("utf-8")


def object_listing_body(names_and_apps, sharing="app"):
    """Body of a listing `GET /servicesNS/nobody/<app>/<handler>`.

    `names_and_apps` is a sequence of `(name, app)`: the application of each entry
    matters, since an object shared globally by **another** app is visible in this
    namespace and is not governed by this app's stanzas.
    """
    return json.dumps(
        {
            "entry": [
                {
                    "name": name,
                    "acl": {"app": app, "sharing": sharing},
                }
                for name, app in names_and_apps
            ]
        }
    ).encode("utf-8")


class FakeAppRest(object):
    """In-memory implementation of the REST port used by the application-level core.

    Three methods, scripted by path; every call is recorded, in order.
    """

    def __init__(
        self,
        get_responses=None,
        post_responses=None,
        json_responses=None,
        default_get=None,
        default_post=None,
        default_json=None,
    ):
        self.get_responses = dict(get_responses or {})
        self.post_responses = dict(post_responses or {})
        self.json_responses = dict(json_responses or {})
        self.default_get = default_get or RestResponse(200, app_acl_body())
        self.default_post = default_post or RestResponse(200, b"{}")
        self.default_json = default_json or RestResponse(200, b'{"entry":[]}')
        self.calls = []

    def get_app_acl(self, path):
        self.calls.append(("GET", path, None))
        return self.get_responses.get(path, self.default_get)

    def post_app_acl(self, path, payload):
        self.calls.append(("POST", path, dict(payload)))
        return self.post_responses.get(path, self.default_post)

    def get_json(self, path, params=None):
        self.calls.append(("JSON", path, params))
        return self.json_responses.get(path, self.default_json)

    # -- convenience accessors ---------------------------------------------- #

    def count(self, method):
        return len([call for call in self.calls if call[0] == method])

    def posts(self):
        return [call for call in self.calls if call[0] == "POST"]

    def gets(self):
        return [call for call in self.calls if call[0] == "GET"]


class FakeProvenanceReader(object):
    """Reader returning a prepared `AppProvenance`, whatever the application."""

    def __init__(self, provenance=None, per_app=None):
        self._provenance = provenance
        self._per_app = dict(per_app or {})
        self.reads = []

    def provenance_of_app(self, app):
        self.reads.append(app)
        if app in self._per_app:
            return self._per_app[app]
        return self._provenance

    def refresh(self, app):
        pass


def provenance(local=None, default=None, local_error="", default_error="", app="my_app"):
    """Build a real `AppProvenance` from the **text** of the two files.

    `None` means the file does not exist - the measured shape of an application that was
    never given per-application permissions, and a valid answer rather than a failure.
    An `error` means it could not be read, which is the only thing that makes the
    provenance unavailable.
    """
    def _file(text, error):
        if error:
            return MetaFile(path="fake", present=False, error=error)
        if text is None:
            return MetaFile(path="fake", present=False, error="")
        stanzas, skipped = parse_meta(text)
        return MetaFile(path="fake", present=True, stanzas=stanzas, skipped=skipped)

    return AppProvenance(app, _file(local, local_error), _file(default, default_error))


class FakeImpact(object):
    """Impact estimator returning a fixed figure, or one per endpoint."""

    def __init__(self, value=0, per_endpoint=None):
        self.value = value
        self.per_endpoint = dict(per_endpoint or {})
        self.calls = []

    def estimate(self, target):
        self.calls.append(target.endpoint)
        return self.per_endpoint.get(target.endpoint, self.value)


def make_app_params(
    names=None,
    dryrun=False,
    allow_create=True,
    validate_roles=False,
    journal=True,
    max_stanzas=50,
    max_impacted_objects=10000,
):
    """Parameters of a test run.

    The defaults are **deliberately not** those of the contract: a unit test that wants
    to exercise a rank of the control table should not have to defeat a ceiling or an
    irreversibility refusal it is not testing. The contract defaults are exercised where
    they belong - in `tests/test_appacl_preflight.py`, which is what freezes them.
    """
    return AppParams(
        names=names or AppFieldNames(),
        dryrun=dryrun,
        allow_create=allow_create,
        validate_roles=validate_roles,
        journal=journal,
        max_stanzas=max_stanzas,
        max_impacted_objects=max_impacted_objects,
    )


def make_app_ctx(sid="test_sid", user="an_operator", dryrun=False):
    return AppRunContext(sid=sid, user=user, dryrun=dryrun)


def make_app_event(
    app="my_app",
    stanza_kind=STANZA_KIND_FAMILY,
    handler="data/ui/views",
    stanza="views",
    read=ABSENT,
    write=ABSENT,
    sharing=ABSENT,
):
    """Build an `AppEventInput`, with **columns absent by default**.

    Each of the three target attributes stays `ABSENT` until it is given: a test that
    says nothing about an attribute describes an absent column, which is the nominal
    preservation case. Passing `read=""` describes the opposite - a present column with
    an empty cell, that is, the order to clear the attribute.
    """
    present = set()
    values = {}
    for attribute, raw in (
        (TARGET_PERMS_READ, read),
        (TARGET_PERMS_WRITE, write),
        (TARGET_SHARING, sharing),
    ):
        if raw is ABSENT:
            values[attribute] = None
            continue
        present.add(attribute)
        values[attribute] = raw

    return AppEventInput(
        app=app,
        stanza_kind=stanza_kind,
        handler=handler,
        stanza=stanza,
        new_perms_read=values[TARGET_PERMS_READ],
        new_perms_write=values[TARGET_PERMS_WRITE],
        new_sharing=values[TARGET_SHARING],
        present=frozenset(present),
    )


def app_state(sharing="app", read=(), write=()):
    return AppAclState(
        sharing=sharing, perms_read=tuple(read), perms_write=tuple(write)
    )
