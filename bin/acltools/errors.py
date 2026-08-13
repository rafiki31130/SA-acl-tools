"""Error taxonomy - spec section 9.

The boundary between the two error classes is **structural**: it rests on the type of
the exception, not on a naming convention.

- **Fatal** error -> the search is interrupted. Exhaustive list in section 9.
- **Per-event** error -> `EventRejected`, the pipeline carries on.

No other exception may cross the pipeline: any unexpected `Exception` is caught there
and converted into `EventRejected("error", "internal:...")`.
"""


class AclToolsError(Exception):
    """Root of the package hierarchy."""


# --------------------------------------------------------------------------- #
# Fatal errors (section 9) - the search is interrupted
# --------------------------------------------------------------------------- #

class FatalError(AclToolsError):
    """Base class of fatal errors. Interrupts the search."""


class FatalConfigError(FatalError):
    """Invalid `fields`, `max_objects` not a positive integer, `splunkd_uri` or
    `session_key` unavailable."""


class FatalCapabilityError(FatalError):
    """Capability `edit_acl_bulk` missing, or execution inside a real-time search."""


class FatalMappingError(FatalError):
    """Mapping table unreadable or malformed."""


class FatalJournalError(FatalError):
    """Journal not openable for writing while `journal=true` AND `dryrun=false`."""


class FatalFamilyTableError(FatalError):
    """Family table unreadable or malformed (v4.3 section 13.1, `editappacl` only).

    Distinct from `FatalMappingError`, which bears on the `eai:type` table of
    `editacl`: the two tables have different keys, different sources and different
    consumers, and a single class would make a message about one of them plausible
    while the other is at fault.
    """


class FatalProvenanceRootError(FatalError):
    """Read root neither resolved nor unambiguous (v4.3 section 13.1).

    Two independent routes lead to `etc/apps` (section 6.2, bound 4). The error covers
    the two cases the bound names, and they are not the same failure: **neither** route
    yields an existing `etc/apps`, or **both** yield one and they diverge. A divergence
    is fatal rather than arbitrated, because an ambiguous root would make the command
    read a tree other than the one the platform serves, with no symptom whatsoever.
    """


# **The `max_objects` ceiling is no longer a fatal error** (D-28). It was one in v1:
# reaching the ceiling interrupted the search, the whole output was lost, and the
# operator was left with a partial mutation **and** no visibility on what had just
# happened. The safeguard produced the worst of both worlds at the exact moment it
# fired.
#
# Its real value - bounding the blast radius of a write launched without a simulation
# first - is fully preserved by stopping the writes. What disappears is the blindness:
# the ceiling now surfaces as `acl_status = "skipped_ceiling"`, a per-event status, and
# the output of the search stays complete. A safeguard must inform, not blind.
#
# There is therefore no exception class for the ceiling any more: looking for one here
# is the mistake a reader of v1 would make.


# --------------------------------------------------------------------------- #
# Per-event error - the pipeline carries on
# --------------------------------------------------------------------------- #

class EventRejected(AclToolsError):
    """Rejection bearing on one given object.

    `status` is one of the `acl_status` values of section 5.7; `error` feeds
    `acl_error`.
    """

    MAX_ERROR_LEN = 512

    def __init__(self, status, error):
        error = "" if error is None else str(error)
        if len(error) > self.MAX_ERROR_LEN:
            error = error[: self.MAX_ERROR_LEN]
        super().__init__("%s: %s" % (status, error))
        self.status = status
        self.error = error
