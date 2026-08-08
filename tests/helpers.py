"""Test doubles: REST port, journal port and clock.

No HTTP simulation library, no socket, no local server. The `RestPort` contract is
narrow (three methods), and an explicit port reads better than a low-level patch on
the network stack.

The JSON fixtures are **written by hand** from the shape observed on the reference
platform, never from raw captures, and they only use generic identifiers (section 14).
"""

import json

from acltools.mapping import Mapping
from acltools.model import (
    DEFAULT_FIELD_NAMES,
    TARGET_ATTRIBUTES,
    AclState,
    EventInput,
    FieldNames,
    Params,
    RunContext,
)
from acltools.rest import RestResponse

#: Sentinel for an **absent column** in `make_event`.
#:
#: It exists because `None` cannot play that role: since section 3.2, `None` is a
#: possible value of a *present* column, and confusing the two is precisely the error
#: the redesign fixes. A test that wants an absent column writes `ABSENT`; everything
#: else is present.
ABSENT = object()

#: Minimal mapping table used by the tests. A strict subset of the shipped table; the
#: endpoint resolution tests do not need all 28 entries.
FIXTURE_MAPPING = Mapping(
    {
        "savedsearch": "saved/searches",
        "views": "data/ui/views",
        "eventtypes": "saved/eventtypes",
        "macros": "data/macros",
        "lookup-table-file": "data/lookup-table-files",
        "fvtags": "saved/fvtags",
    }
)


def acl_body(
    owner="nobody",
    app="my_app",
    sharing="global",
    read=("role_a",),
    write=("legacy_role",),
    can_change_perms=True,
    name="witness_object",
):
    """Response body of a `GET <object>?output_mode=json&f=eai:acl*`.

    Only the `entry[0].acl` block is authoritative (section 5.3); `content` is
    deliberately reduced, and the `f` parameter filters it out anyway.

    `name` is the canonical identity returned by splunkd. It is distinct from the
    `title` of the input event, and it is what feeds rank 0 of section 5.4
    (section 3.4, D-18).
    """
    document = {
        "entry": [
            {
                "name": name,
                "content": {},
                "acl": {
                    "app": app,
                    "owner": owner,
                    "sharing": sharing,
                    "can_change_perms": can_change_perms,
                    "perms": {"read": list(read), "write": list(write)},
                },
            }
        ]
    }
    return json.dumps(document).encode("utf-8")


def acl_body_raw(acl_block):
    """Response body built from a raw `acl` block (parsing edge cases)."""
    return json.dumps(
        {"entry": [{"name": "witness_object", "content": {}, "acl": acl_block}]}
    ).encode("utf-8")


class FakeRest(object):
    """In-memory implementation of `RestPort`.

    Responses are scripted by `(method, path)`; failing that, a default response is
    served. Every call is recorded, in order.
    """

    def __init__(self, get_responses=None, post_responses=None, json_responses=None,
                 default_get=None, default_post=None, default_json=None):
        self.get_responses = dict(get_responses or {})
        self.post_responses = dict(post_responses or {})
        self.json_responses = dict(json_responses or {})
        self.default_get = default_get or RestResponse(200, acl_body())
        self.default_post = default_post or RestResponse(200, b"{}")
        self.default_json = default_json or RestResponse(200, b'{"entry":[]}')
        self.calls = []

    def get_object_acl(self, object_path):
        self.calls.append(("GET", object_path, None))
        return self.get_responses.get(object_path, self.default_get)

    def post_object_acl(self, object_path, payload):
        self.calls.append(("POST", object_path, dict(payload)))
        return self.post_responses.get(object_path, self.default_post)

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


class FakeJournal(object):
    """In-memory implementation of `JournalPort`.

    `fail_intent` / `fail_outcome` simulate a failure of the write + flush + fsync
    sequence, which must cancel the POST (section 8.4).
    """

    def __init__(self, fail_intent=False, fail_outcome=False):
        self.intents = []
        self.outcomes = []
        self.fail_intent = fail_intent
        self.fail_outcome = fail_outcome
        self.closed = False

    def write_intent(self, record):
        if self.fail_intent:
            return False
        self.intents.append(record)
        return True

    def write_outcome(self, record):
        if self.fail_outcome:
            return False
        self.outcomes.append(record)
        return True

    def close(self):
        self.closed = True


class FakeClock(object):
    """Deterministic timestamps, in the format of section 8.2 (milliseconds
    are mandatory)."""

    def __init__(self, start=0):
        self.tick = start

    def __call__(self):
        self.tick += 1
        return "2026-01-01T00:00:%02d.%03d+01:00" % (
            self.tick % 60,
            self.tick % 1000,
        )


def make_params(
    names=None,
    dryrun=False,
    validate_roles=False,
    journal=True,
    max_objects=500,
):
    return Params(
        names=names or FieldNames(),
        dryrun=dryrun,
        validate_roles=validate_roles,
        journal=journal,
        max_objects=max_objects,
    )


def make_ctx(sid="test_sid", user="an_operator", host="sh01", dryrun=False):
    return RunContext(sid=sid, user=user, host=host, dryrun=dryrun)


def make_event(
    title="My search",
    app="my_app",
    id_value=None,
    eai_type="savedsearch",
    current_sharing=None,
    read=ABSENT,
    write=ABSENT,
    sharing=ABSENT,
    owner=ABSENT,
):
    """Build an `EventInput`, with **columns absent by default**.

    Each of the four target attributes stays `ABSENT` until it is given: a test that
    says nothing about an attribute therefore describes an absent column, which is the
    nominal preservation case (section 3.2). Passing `read=""` describes the opposite,
    a present column with an empty cell, that is, the order to clear the attribute.
    """
    present = set()
    values = {}
    for attribute, raw in (
        ("perms.read", read),
        ("perms.write", write),
        ("sharing", sharing),
        ("owner", owner),
    ):
        if raw is ABSENT:
            values[attribute] = None
            continue
        present.add(attribute)
        values[attribute] = raw

    return EventInput(
        title=title,
        app=app,
        id_value=id_value,
        eai_type=eai_type,
        current_sharing=current_sharing,
        new_perms_read=values["perms.read"],
        new_perms_write=values["perms.write"],
        new_sharing=values["sharing"],
        new_owner=values["owner"],
        present=frozenset(present),
    )


def state(owner="nobody", sharing="global", read=(), write=(), can_change_perms=True):
    return AclState(
        owner=owner,
        sharing=sharing,
        perms_read=tuple(read),
        perms_write=tuple(write),
        can_change_perms=can_change_perms,
    )
