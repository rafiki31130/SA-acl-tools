"""Parameters and legitimacy of an `editappacl` run (v4.2 sections 8.5, 13.1).

`validate_app_params` is **pure** and tests on its own. The checks that need the
platform - capability, real-time search, role catalog, application state - are the ones
of `preflight.py`, reused as they stand: `check_capability` takes the capability as a
parameter, and the three others are indifferent to which command calls them. One more
copy of them would be one more thing to keep in step.
"""

from .appacl_inventory import parse_app_filter, parse_family_list
from .appacl_model import (
    DEFAULT_APP_FIELD_NAMES,
    AppFieldNames,
    AppInventoryParams,
    AppParams,
)
from .errors import FatalConfigError

#: Dedicated capability of the write command (section 8.1), declared **and granted to
#: `admin`** by `default/authorize.conf`. It is neither implied by `edit_acl_bulk` nor
#: does it imply it: `edit_acl_bulk` authorizes rewriting the ACL of objects the pipeline
#: **enumerates**, `edit_app_acl_bulk` authorizes moving the rights of objects the
#: pipeline does not enumerate and whose number is only known by estimation. This is the
#: only place the app can express that difference - `admin_all_objects` does not.
REQUIRED_APP_CAPABILITY = "edit_app_acl_bulk"

#: Dedicated capability of the **inventory** command (section 7.6), declared **and
#: granted to `admin`** by `default/authorize.conf`.
#:
#: Its motive is proper to this command, and it is the counterpart of the file-reading
#: exception: **reading the file short-circuits the capability filtering REST applies**.
#: The frozen-stanza counters of an application carry information the API would not serve
#: a caller without `admin_all_objects`. Bound 3 of section 6.2 - counts, never names -
#: reduces the exposure; this capability governs it.
#:
#: Splunk offers no native gating of search commands by capability: the check lives in
#: the code, at the head of the run, and a failed check is a fatal error (v3.14
#: section 7).
REQUIRED_INVENTORY_CAPABILITY = "list_app_acl"

#: Default stanza ceiling (section 8.5). **A choice, not a measurement**, and it is named
#: as such wherever it appears: O-6 of the phase 0 measurement states that the real
#: magnitude of a generic write has not been quantified. The reasoning: five covers the
#: governance of one application - its `[]` stanza and a few families - with no friction.
DEFAULT_MAX_STANZAS = 5

#: Default blast-radius ceiling (section 8.5). **A choice, not a measurement**, same
#: reservation: two hundred is the order of magnitude of a medium-sized application,
#: beyond which the operator states what they are moving.
DEFAULT_MAX_IMPACTED_OBJECTS = 200

#: Reminder emitted at the head of the run when the simulation is active (section 13.3).
#:
#: `dryrun` is `true` by default: without this reminder, a run that writes nothing is
#: indistinguishable from a run that wrote everything - both return a full result table.
#: It is emitted **once per run**, never per event: a repeated warning gets filtered out
#: mentally, and it would stop being read exactly where it matters.
DRYRUN_WARNING = (
    "simulation active (dryrun=true, the default value): NO change will be written. The "
    "targets come out with acl_status=dryrun. To actually apply the changes, run the "
    "same search again with dryrun=false."
)

#: Reminder emitted when a real run is asked for while creations are authorized. It is
#: not a refusal: `allow_create=true` is the deliberate act section 9.3 asks for, and
#: this only says out loud what that act allows.
ALLOW_CREATE_WARNING = (
    "allow_create=true: a target with no stanza in local.meta will be CREATED, and a "
    "creation cannot be undone - no measured REST path removes a generic stanza. The "
    "created stanzas are excluded from app_acl_rollback and listed by "
    "app_acl_irreversible."
)

#: Stable order of the seven field-naming parameters (sections 8.3, 8.4).
APP_FIELD_NAME_PARAMS = (
    "app",
    "stanza_kind",
    "handler",
    "stanza",
    "new_perms_read",
    "new_perms_write",
    "new_sharing",
)

#: Characters that cannot appear in an SPL field name passed as a parameter. Same three
#: as `preflight._FORBIDDEN_NAME_CHARS`, and the comma is still the useful one: it
#: catches the operator who writes a list where the contract expects a single name.
_FORBIDDEN_NAME_CHARS = (",", "|", "\n")


def _as_bool(raw, name, default=None):
    """Coerce a boolean. `None` means "not supplied" and falls back on the default: the
    SDK exposes an option that was not set as `None`, not as its default value."""
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


def _as_positive_int(raw, name, default):
    if raw is None:
        return int(default)
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise FatalConfigError(
            "invalid parameter: '%s' must be a strictly positive integer (%r)"
            % (name, raw)
        )
    if value <= 0:
        raise FatalConfigError(
            "invalid parameter: '%s' must be a strictly positive integer (%r)"
            % (name, raw)
        )
    return value


def parse_app_field_names(raw_names):
    """Validate the field-naming parameters and return an `AppFieldNames`.

    A `None` or missing value falls back on the default of the contract - the field
    names `appaclinventory` emits - which makes the nominal case implicit: an operator
    who builds their pipeline on the inventory writes no parameter at all.

    Errors: `FatalConfigError` if a parameter designates an empty or syntactically
    invalid field identifier (section 13.1).
    """
    raw_names = raw_names or {}
    resolved = {}
    for param in APP_FIELD_NAME_PARAMS:
        raw = raw_names.get(param)
        if raw is None:
            resolved[param] = getattr(DEFAULT_APP_FIELD_NAMES, param)
            continue
        value = str(raw).strip()
        if not value:
            raise FatalConfigError(
                "invalid parameter: '%s' designates an empty field name. Omit the "
                "parameter to take the default (%s)."
                % (param, getattr(DEFAULT_APP_FIELD_NAMES, param))
            )
        for char in _FORBIDDEN_NAME_CHARS:
            if char in value:
                raise FatalConfigError(
                    "invalid parameter: '%s=%s' is not a field name. Each naming "
                    "parameter designates ONE field, never a list." % (param, value)
                )
        resolved[param] = value
    return AppFieldNames(**resolved)


def validate_app_params(
    names_raw=None,
    dryrun=True,
    allow_create=False,
    validate_roles=True,
    journal=True,
    max_stanzas=DEFAULT_MAX_STANZAS,
    max_impacted_objects=DEFAULT_MAX_IMPACTED_OBJECTS,
    max_stanzas_explicit=True,
):
    """Validate the parameters of section 8.5. Pure function.

    Errors: `FatalConfigError` if a field-naming parameter is invalid, or if
    `max_stanzas` or `max_impacted_objects` is not a strictly positive integer
    (section 13.1).
    """
    names = parse_app_field_names(names_raw)
    dryrun = _as_bool(dryrun, "dryrun", default=True)
    allow_create = _as_bool(allow_create, "allow_create", default=False)
    validate_roles = _as_bool(validate_roles, "validate_roles", default=True)
    journal = _as_bool(journal, "journal", default=True)
    max_stanzas_int = _as_positive_int(
        max_stanzas, "max_stanzas", DEFAULT_MAX_STANZAS
    )
    max_impacted_int = _as_positive_int(
        max_impacted_objects, "max_impacted_objects", DEFAULT_MAX_IMPACTED_OBJECTS
    )

    warnings = []
    if dryrun:
        warnings.append(DRYRUN_WARNING)
    else:
        if allow_create:
            warnings.append(ALLOW_CREATE_WARNING)
        if not max_stanzas_explicit:
            warnings.append(
                "dryrun=false with no explicit max_stanzas: the default ceiling applies "
                "(%d), and it is a choice rather than a measurement" % max_stanzas_int
            )

    return AppParams(
        names=names,
        dryrun=dryrun,
        allow_create=allow_create,
        validate_roles=validate_roles,
        journal=journal,
        max_stanzas=max_stanzas_int,
        max_impacted_objects=max_impacted_int,
        warnings=tuple(warnings),
    )


def validate_inventory_params(apps=None, families=None, count_objects=False):
    """Validate the three parameters of section 7.3. Pure function.

    **No parameter of this command can be fatally invalid**, and that is a decision
    rather than an omission: the two filters are passed through the allow list of
    section 7.3, so a character the contract does not admit is dropped instead of
    rejecting the run. Section 13.1 lists the fatal errors limitatively and names only
    "invalid parameter: syntactically incorrect field name, `max_stanzas` or
    `max_impacted_objects` not a strictly positive integer" - none of which this command
    has. `count_objects` is the exception that proves it: a value that is not a boolean
    **is** an invalid parameter, and it is refused as one.
    """
    return AppInventoryParams(
        apps=parse_app_filter(apps),
        families=parse_family_list(families),
        count_objects=_as_bool(count_objects, "count_objects", default=False),
    )
