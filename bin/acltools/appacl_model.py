"""Immutable data structures of the application-level commands (v4.1).

Same discipline as `model.py`, whose vocabulary this module extends rather than
replaces: `dataclass(frozen=True)` carriers with no business method, plus the
**single sources** the rest of the package and the test suite derive from - the status
enumeration, the declared output field set, the closed warning domain.

**Why a module of its own rather than more entries in `model.py`.** The two commands do
not share a status enumeration: `editacl` counts objects and knows nothing of
`created`, `noop_inherited` or `skipped_impact_ceiling`; `editappacl` counts stanzas and
knows nothing of `skipped_private`, `skipped_derived` or `skipped_immutable`. Merging
the two lists would put every consumer of either in front of statuses the command it
watches can never produce, and would make the syntax-tree control of
`tests/test_statuses.py` - which requires each declared status to be **observed on a
real case** - unsatisfiable for both at once. The separation is what keeps that control
exact on each side (v4.1 section 14.2, "Statuts").
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple

#: The two target kinds of v4.1 section 1.1, and the **only** two. They are the domain
#: of the required `stanza_kind` input field: a value outside it is rejected without any
#: call (section 8.7, rank 0).
STANZA_KIND_APP = "app_default"
STANZA_KIND_FAMILY = "family_default"

#: Third classification produced by the `.meta` reader, and by it alone
#: (section 6.4). It is **never** a target: `[<family>/<object>]` stanzas are counted,
#: never listed, never written by this command - `editacl` is the tool for those.
STANZA_KIND_OBJECT = "object_specific"

STANZA_KINDS = (STANZA_KIND_APP, STANZA_KIND_FAMILY)

#: Logical names of the three target values (section 8.4). These are the keys used by
#: `AppEventInput.present` and by the merge engine - never SPL field names, which the
#: operator may rename.
#:
#: **There is no owner among them, and that is DV-5.** Measured: `owner` is mandatory
#: and inert on the `[]` path (Q0-1 case G), and refused with `400` by `data/ui/views`
#: and `data/macros` on the `_acl` path (Q0-2). No owner value is expressible, so
#: exposing a parameter for one would be a false promise.
TARGET_PERMS_READ = "perms.read"
TARGET_PERMS_WRITE = "perms.write"
TARGET_SHARING = "sharing"

TARGET_ATTRIBUTES = (TARGET_PERMS_READ, TARGET_PERMS_WRITE, TARGET_SHARING)

#: Sharing scopes accepted by both write paths (**DV-4**). `user` is measured `400` on
#: both - `Apps cannot be unshared` on the `[]` path (Q0-1 case J), `Containers cannot
#: be unshared` on the `_acl` path (Q0-2) - and is therefore refused per event rather
#: than sent to be refused by the platform.
VALID_APP_SHARING = frozenset({"app", "global"})

#: **Normative enumeration of the `acl_status` values of section 8.8 - single source.**
#:
#: It lives here, in the core, and neither in the test suite nor in the contract, for
#: the reason `model.ACL_STATUSES` states at length: a copied enumeration drifts. Two
#: tests tie it to the code, the same pair that holds the enumeration of the previous
#: command:
#:
#: - `tests/test_appacl_statuses.py` extracts from the syntax tree of the
#:   application-level modules **every** literal status actually produced and requires
#:   equality with this tuple;
#: - `tests/test_appacl_pipeline.py` requires observing **each** of these values on a
#:   real case, so a status declared here with no test case fails the suite as well.
#:
#: The order is that of the table in section 8.8.
APP_ACL_STATUSES = (
    "updated",
    "created",
    "noop",
    "noop_inherited",
    "dryrun",
    "rejected",
    "not_found",
    "forbidden",
    "invalid_role",
    "skipped_ceiling",
    "skipped_impact_ceiling",
    "error",
)

#: Closed domain of `acl_warning` (section 8.8). A warning emitted outside this tuple is
#: a defect: the field is concatenated into a single string, so an undeclared token is
#: indistinguishable from a typo for whoever filters on it.
#:
#: `stale_role_preserved` carries a list appended after a colon; it is declared here as
#: its **prefix**, which is what the checker compares against.
APP_ACL_WARNINGS = (
    "irreversible_creation",
    "provenance_unavailable",
    "not_materialized",
    "no_inheriting_object",
    "sharing_change",
    "stale_role_preserved",
    "write_may_have_occurred",
    "runtime_divergence_possible",
    "journal_outcome_failed",
    "self_app_target",
    "app_disabled",
)

#: Three values of `acl_reversible` (section 9.3), and of the `reversible` journal key
#: (section 11.2). They are not a boolean: "the stanza pre-existed", "the stanza did not
#: exist" and "the provenance could not be read" are three distinct answers, and the
#: third one must not be collapsed into either of the other two - the rollback set is
#: built on this very field.
REVERSIBLE_TRUE = "true"
REVERSIBLE_FALSE = "false"
REVERSIBLE_UNKNOWN = "unknown"

#: Three values of the `write_asserted` journal key (section 11.2). It translates
#: section 4.3: a non-2xx answer after a POST was sent does **not** prove that nothing
#: was written - measured, a `403` came with an effective write.
WRITE_ASSERTED_YES = "yes"
WRITE_ASSERTED_UNKNOWN = "unknown"
WRITE_ASSERTED_NO = "no"

#: **Declared output field set** (section 8.8, and v3.14 section 5.7, D-33).
#:
#: The SDK writer freezes the stream header on the keys of the **first** record emitted,
#: then projects every later record onto it: a field absent from that first record
#: disappears from the whole output, with no error and no warning. Several statuses of
#: this command carry no state field at all - a `rejected` upstream of the GET, a
#: `skipped_ceiling` - and a batch whose first row is one of those would deprive the
#: operator of everything the simulation exists to show.
APP_ACL_OUTPUT_FIELDS = (
    "acl_status",
    "acl_endpoint",
    "acl_stanza_kind",
    "acl_stanza",
    "acl_handler",
    "acl_reversible",
    "acl_impacted_estimate",
    "acl_http_code",
    "acl_error",
    "acl_warning",
    "acl_before_perms_read",
    "acl_before_perms_write",
    "acl_before_sharing",
    "acl_after_perms_read",
    "acl_after_perms_write",
    "acl_after_sharing",
    "acl_journaled",
)


@dataclass(frozen=True)
class AppFieldNames:
    """Name of the SPL field to read each piece of information from (sections 8.3, 8.4).

    Every logical input is a **parameter naming a field**, with a default that is the
    field name `app_acl_inventory` emits. An operator who builds their pipeline on the
    inventory therefore writes no parameter at all.

    There is **no** owner entry, in either direction: none is read, none is written
    (**DV-5**).
    """

    app: str = "eai:acl.app"
    stanza_kind: str = "acl_stanza_kind"
    handler: str = "acl_handler"
    stanza: str = "acl_stanza"
    new_perms_read: str = "eai:acl.perms.read"
    new_perms_write: str = "eai:acl.perms.write"
    new_sharing: str = "eai:acl.sharing"


#: Defaults of sections 8.3 and 8.4, exposed for the documentation and the tests.
DEFAULT_APP_FIELD_NAMES = AppFieldNames()


@dataclass(frozen=True)
class AppEventInput:
    """Projection of one input event (sections 8.3, 8.4).

    **`present` is the heart of the contract**, exactly as in `model.EventInput`: it
    carries the subset of `TARGET_ATTRIBUTES` whose **column exists in the result set**,
    and it is the only discriminant between "preserve" and "modify".

    `stanza_kind`, `handler` and `stanza` are read for their **value**: they designate
    the target, they are not target values. `stanza` legitimately holds the empty string
    for the `[]` stanza, which is why `stanza_kind` is required and never deduced
    (section 8.3).
    """

    app: str = ""
    stanza_kind: str = ""
    handler: str = ""
    stanza: str = ""
    new_perms_read: object = None
    new_perms_write: object = None
    new_sharing: object = None
    present: frozenset = frozenset()

    def has(self, attribute):
        """True if the column of `attribute` exists in the result set.

        Single presence predicate of the application-level core: no other module reads
        `present` directly, which makes it structurally impossible to substitute a type
        or value test for it.
        """
        return attribute in self.present


@dataclass(frozen=True)
class AppAclState:
    """Normalized ACL state of a generic stanza (section 8.6).

    Three attributes, and three only. There is no `owner`: it is inert on one path and
    refused on the other, so it is neither compared, nor journaled as a target value,
    nor published (section 4.2).
    """

    sharing: str = ""
    perms_read: Tuple[str, ...] = ()
    perms_write: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AppTarget:
    """Resolved target: what the URI, the body and the journal need (section 8.3)."""

    app: str = ""
    stanza_kind: str = ""
    #: Literal stanza name. **The empty string is a legitimate value**: it is the name
    #: of the `[]` stanza (section 11.2). Discrimination goes through `stanza_kind`,
    #: never through this field alone.
    stanza: str = ""
    #: Handler path, empty for `app_default`, whose URI is entirely determined by `app`.
    handler: str = ""
    #: Write path, without scheme, host or port - the string contract of section 11.3.
    endpoint: str = ""


@dataclass(frozen=True)
class AppMergeResult:
    """Result of the merge (section 8.4)."""

    before: AppAclState
    after: AppAclState
    payload: dict = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()
    rejection: object = None  # EventRejected | None


@dataclass(frozen=True)
class AppParams:
    """Validated parameters of the command (section 8.5)."""

    names: AppFieldNames
    dryrun: bool
    allow_create: bool
    validate_roles: bool
    journal: bool
    max_stanzas: int
    max_impacted_objects: int
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AppRunContext:
    """Run constants, identical on every journal line (section 11.2).

    No `host`, no `member`: v3.14 section 8.2 (D-46) removed both as duplicates of the
    `host` metadata Splunk stamps at collection, and nothing in v4.1 reopens that. The
    `acl_member` field of v4.1 section 6.3 belongs to the **inventory output**, which is
    a search result and carries no such metadata; it is not a journal key.
    """

    sid: str
    user: str
    dryrun: bool


@dataclass(frozen=True)
class AppEventResult:
    """Result of processing one event (sections 8.8 and 11.2)."""

    status: str
    app: str = ""
    stanza_kind: str = ""
    stanza: str = ""
    handler: str = ""
    endpoint: str = ""
    reversible: str = ""
    #: Estimated number of objects whose effective rights the write moves
    #: (section 10.3). Empty - not zero - when it was not computed: zero is a
    #: **measured** answer that carries `no_inheriting_object`, and confusing the two
    #: would let a target nobody counted pass for a target that moves nothing.
    impacted_estimate: Optional[int] = None
    http_code: int = 0
    error: Optional[str] = None
    warnings: Tuple[str, ...] = ()
    before: Optional[AppAclState] = None
    after: Optional[AppAclState] = None
    #: Effective state read when it is **not** a restorable prior state: an inherited
    #: value, or a value whose provenance could not be established. It is journaled
    #: under `inherited_*` keys, which the rollback macro does not read (section 11.2).
    inherited: Optional[AppAclState] = None
    journaled: bool = False
    post_attempted: bool = False
