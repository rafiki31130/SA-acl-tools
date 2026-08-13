"""Legitimacy of the run, established once and for all before any event (section 5.1).

`validate_params` is **pure** and tests on its own. The rest consumes a `RestPort` and
is tested by substitution - no HTTP mock, no socket.
"""

import json

from .endpoint import encode_namespace_segment
from .errors import FatalCapabilityError, FatalConfigError
from .model import DEFAULT_FIELD_NAMES, FieldNames, Params
# Relative import of a **pure predicate**: `preflight` still consumes nothing but a
# `RestPort` port and stays substitutable without a socket. See `rest.is_tls_failure`.
from .rest import TLS_REMEDIATION, is_tls_failure

#: Dedicated capability, declared by `default/authorize.conf` (section 7). Splunk
#: offers no native gating of search commands by capability: the check is implemented
#: in the code and constitutes a fatal error.
REQUIRED_CAPABILITY = "edit_acl_bulk"

#: The `*` role is a legitimate value of the catalog and is **never** expanded into a
#: list of roles (section 10.2).
WILDCARD_ROLE = "*"

#: Default write ceiling (section 4.1, D-30). **Ten, and not five hundred.**
#:
#: A one-off fix - a few identified objects, checked in simulation - goes through
#: without the operator having to bother with the ceiling. Beyond that, they have to
#: write it, hence to state the volume they are about to mutate. A ceiling of five
#: hundred let operations of several hundred objects through without a word, which
#: amounted to keeping nothing of the safeguard in most real cases.
#:
#: This default is only tenable because **the ceiling never fires in simulation**: the
#: counter is only incremented by a POST actually sent, and a simulation sends none.
#: The friction bears on the real write, never on the review.
DEFAULT_MAX_OBJECTS = 10

#: Reminder emitted at the head of the run when the simulation is active (section 4.1).
#:
#: `dryrun` is `true` by default: without this reminder, a run that writes nothing is
#: indistinguishable from a run that wrote everything - both return a full result
#: table, and only the `acl_status` column tells them apart. It is the most
#: consequential parameter of the command, and its default state was the only one
#: reported nowhere.
#:
#: The message carries the two things the operator needs: what will not happen, and the
#: exact gesture that would make it happen.
#:
#: It is carried by `Params.warnings`, hence emitted **once per run** by the adapter
#: (section 5.1) - never per event. A batch of several hundred objects would repeat it
#: as many times, and a repeated warning gets filtered out mentally: it would stop
#: being read exactly where it matters.
#:
#: It is a warning (`MSG[WARN]`), never an error: it changes neither the status of the
#: job, nor the number of results, nor the exit code of the command.
DRYRUN_WARNING = (
    "simulation active (dryrun=true, the default value): NO change will be written. "
    "The objects come out with acl_status=dryrun. To actually apply the changes, run "
    "the same search again with dryrun=false."
)


def _decode(response):
    """Decode a JSON response body. Returns `None` if it cannot be decoded."""
    if response is None or response.status != 200 or not response.body:
        return None
    try:
        return json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return None


def _as_bool(raw, name, default=None):
    """Coerce a boolean. `None` means "not supplied" and falls back on the section 4.1
    default: the SDK exposes an option that was not set as `None`, not as its default
    value."""
    if raw is None and default is not None:
        return default
    if isinstance(raw, bool):
        return raw
    token = str(raw).strip().lower()
    if token in ("1", "true", "t", "yes", "y", "on"):
        return True
    if token in ("0", "false", "f", "no", "n", "off"):
        return False
    raise FatalConfigError("invalid parameter: '%s' is not a boolean (%r)" % (name, raw))


#: Stable order of the nine field-naming parameters (sections 3.1, 3.3), for the
#: validation and the error messages.
FIELD_NAME_PARAMS = (
    "title",
    "app",
    "id",
    "type",
    "sharing",
    "new_perms_read",
    "new_perms_write",
    "new_sharing",
    "new_owner",
)

#: Characters that cannot appear in an SPL field name passed as a parameter.
#:
#: The comma is the most useful of the three: it catches the operator who still thinks
#: in terms of the v1 `fields` and writes `new_perms_read="perms.read,perms.write"`.
#: Each parameter now carries a **single field name** - that is what makes the v1.3
#: quoting trap (section 4.4) disappear by construction, where SPL silently truncated
#: an unquoted list to its first value. Refusing it explicitly is better than treating
#: "perms.read,perms.write" as an improbable field name.
_FORBIDDEN_NAME_CHARS = (",", "|", "\n")


def parse_field_names(raw_names):
    """Validate the field-naming parameters and return a `FieldNames` (3.1, 3.3, 5.1-2).

    `raw_names` is a mapping `<parameter> -> <raw value>`. A `None` or missing value
    falls back on the default of the specification - the platform's native field
    names - which makes the nominal case implicit: an operator who uses them writes no
    parameter at all.

    Errors: `FatalConfigError` if a parameter designates an empty or syntactically
    invalid field identifier (section 9).
    """
    raw_names = raw_names or {}
    resolved = {}
    for param in FIELD_NAME_PARAMS:
        raw = raw_names.get(param)
        if raw is None:
            resolved[param] = getattr(DEFAULT_FIELD_NAMES, param)
            continue
        value = str(raw).strip()
        if not value:
            raise FatalConfigError(
                "invalid parameter: '%s' designates an empty field name. Omit the "
                "parameter to take the default (%s)."
                % (param, getattr(DEFAULT_FIELD_NAMES, param))
            )
        for char in _FORBIDDEN_NAME_CHARS:
            if char in value:
                raise FatalConfigError(
                    "invalid parameter: '%s=%s' is not a field name. Each naming "
                    "parameter designates ONE field, never a list - the v1 'fields' "
                    "parameter no longer exists." % (param, value)
                )
        resolved[param] = value
    return FieldNames(**resolved)


def validate_params(
    names_raw=None,
    dryrun=True,
    validate_roles=True,
    journal=True,
    max_objects=DEFAULT_MAX_OBJECTS,
    max_objects_explicit=True,
):
    """Validate the parameters of section 4.1. Pure function.

    Errors: `FatalConfigError` if a field-naming parameter is invalid, or if
    `max_objects` is not a strictly positive integer (section 9).
    """
    names = parse_field_names(names_raw)
    dryrun = _as_bool(dryrun, "dryrun", default=True)
    validate_roles = _as_bool(validate_roles, "validate_roles", default=True)
    journal = _as_bool(journal, "journal", default=True)

    if max_objects is None:
        max_objects = DEFAULT_MAX_OBJECTS
    try:
        max_objects_int = int(str(max_objects).strip())
    except (TypeError, ValueError):
        raise FatalConfigError(
            "invalid parameter: 'max_objects' must be a strictly positive integer "
            "(%r)" % (max_objects,)
        )
    if max_objects_int <= 0:
        raise FatalConfigError(
            "invalid parameter: 'max_objects' must be a strictly positive integer "
            "(%r)" % (max_objects,)
        )

    warnings = []
    if dryrun:
        warnings.append(DRYRUN_WARNING)
    if not dryrun and not max_objects_explicit:
        warnings.append(
            "dryrun=false with no explicit max_objects: the default ceiling applies "
            "(%d)" % max_objects_int
        )

    return Params(
        names=names,
        dryrun=dryrun,
        validate_roles=validate_roles,
        journal=journal,
        max_objects=max_objects_int,
        warnings=tuple(warnings),
    )


def check_capability(rest, capability=REQUIRED_CAPABILITY):
    """Capability check (section 5.1, step 3).

    `content.capabilities` of `current-context` is the **effective flattened** set of
    the user's capabilities, `imported_roles` inheritance included (measurement 6). The
    check therefore reduces to a membership test; no walk of the role hierarchy is
    needed.

    The capability is a **parameter with a default**, and the default is the one of
    `editacl`: the second command of the app checks `edit_app_acl_bulk`, which is
    neither implied by `edit_acl_bulk` nor implies it (v4.1 section 8.1). The two
    capabilities differ by orders of magnitude in blast radius - one rewrites the ACL of
    objects the pipeline **enumerates**, the other moves the rights of objects the
    pipeline does not enumerate - and `admin_all_objects` does not tell them apart. One
    checking function for both is right; one capability for both would not be.
    """
    response = rest.get_json("/services/authentication/current-context", None)
    document = _decode(response)
    if document is None:
        # The first REST call of the run is also the one a platform with a self-signed
        # certificate fails on. With no explicit naming, the operator only reads an
        # "HTTP 0" on an authentication endpoint and looks at permissions, not at the
        # certificate.
        if is_tls_failure(response):
            raise FatalCapabilityError(
                "%s (detail: %s)" % (TLS_REMEDIATION, response.error)
            )
        raise FatalCapabilityError(
            "capability check impossible: unusable response from "
            "/services/authentication/current-context (HTTP %s%s)"
            % (
                getattr(response, "status", "?"),
                ", %s" % response.error if getattr(response, "error", None) else "",
            )
        )
    try:
        content = document["entry"][0]["content"]
    except (KeyError, IndexError, TypeError):
        raise FatalCapabilityError(
            "capability check impossible: unexpected response structure"
        )

    capabilities = content.get("capabilities") or []
    if capability not in capabilities:
        roles = content.get("roles") or []
        raise FatalCapabilityError(
            "capability '%s' missing. Roles of the user: %s"
            % (capability, ", ".join(str(role) for role in roles) or "(none)")
        )


def check_realtime(rest, sid):
    """Real-time mode check (section 4.2, D-2).

    Returns `"realtime"` (never actually reached: an exception is raised), `"batch"` if
    the search is confirmed not to be real-time, or `"unknown"` if the detection did
    not succeed. The safeguard does not turn into a false positive: a detection that
    does not succeed is reported by the adapter, not turned into a refusal.

    Errors: `FatalCapabilityError` if real-time mode is detected.
    """
    if not sid:
        return "unknown"

    response = rest.get_json(
        "/services/search/jobs/%s" % encode_namespace_segment(sid), None
    )
    document = _decode(response)
    if document is None:
        return "unknown"
    try:
        content = document["entry"][0]["content"]
    except (KeyError, IndexError, TypeError):
        return "unknown"

    flag = content.get("isRealTimeSearch")
    if flag is not None:
        if _truthy(flag):
            raise FatalCapabilityError(
                "running inside a real-time search is refused (section 4.2)."
            )
        return "batch"

    # Fallback: inspection of the time bounds.
    earliest = str(content.get("earliest_time") or "")
    latest = str(content.get("latest_time") or "")
    if earliest.startswith("rt") or latest.startswith("rt"):
        raise FatalCapabilityError(
            "running inside a real-time search is refused (section 4.2)."
        )
    if earliest or latest:
        return "batch"
    return "unknown"


def _truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y", "on")


def load_roles_catalog(rest):
    """Catalog of the existing roles (section 5.1, step 5).

    This call serves **only** `validate_roles`: it is useless to the capability check,
    which measurement 6 reduces to a membership test.
    """
    response = rest.get_json(
        "/services/authorization/roles", {"count": "0", "f": "title"}
    )
    document = _decode(response)
    roles = {WILDCARD_ROLE}
    if document is None:
        return frozenset(roles)
    for entry in document.get("entry") or []:
        name = entry.get("name")
        if name:
            roles.add(str(name))
    return frozenset(roles)


def resolve_server_name(rest):
    """`serverName` of the member, for the **diagnostic** startup line. `""` if
    unavailable.

    It no longer feeds the journal: that key was removed as a duplicate of the `host`
    metadata Splunk stamps on every event. The diagnostic file is free text and carries
    no such metadata of its own, so this is where the datum still has to be written.
    """
    response = rest.get_json("/services/server/info", None)
    document = _decode(response)
    if document is None:
        return ""
    try:
        return str(document["entry"][0]["content"].get("serverName") or "")
    except (KeyError, IndexError, TypeError):
        return ""


class AppStateCache(object):
    """Enablement state of the apps, **memoized per app** (section 10.5).

    The information is carried neither by the event nor by the `/acl` response: it
    requires a dedicated call. Cost: one call per distinct app over the run.
    """

    def __init__(self, rest):
        self._rest = rest
        self._cache = {}

    def is_app_disabled(self, app):
        if app in self._cache:
            return self._cache[app]
        disabled = False
        response = self._rest.get_json(
            "/services/apps/local/%s" % encode_namespace_segment(app), None
        )
        document = _decode(response)
        if document is not None:
            try:
                content = document["entry"][0]["content"]
                disabled = _truthy(content.get("disabled"))
            except (KeyError, IndexError, TypeError):
                disabled = False
        self._cache[app] = disabled
        return disabled
