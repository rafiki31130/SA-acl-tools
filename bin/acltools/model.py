"""Immutable data structures shared by the core.

All of them are `dataclass(frozen=True)`, with no business method: they carry, they do
not decide.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple

#: Logical names of the four target values (section 3.3). These are the keys used by
#: `EventInput.present` and by the merge engine - never SPL field names, which the
#: operator may rename.
TARGET_PERMS_READ = "perms.read"
TARGET_PERMS_WRITE = "perms.write"
TARGET_SHARING = "sharing"
TARGET_OWNER = "owner"

#: Stable order, used by the matrix tests and by the error messages.
TARGET_ATTRIBUTES = (
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    TARGET_OWNER,
)

#: **Normative enumeration of the `acl_status` values of section 5.7 - single source.**
#:
#: It lives here, in the core, and neither in the test suite nor in the specification:
#: a copied enumeration drifts. Three drafts of the contract, then one of the test
#: suite, had this list wrong - twice by omission, once by excess. D-35 removed the
#: enumeration from section 8.2 to entrust it to the test suite; the test suite in turn
#: wrote it out by hand, and it drifted the same way.
#:
#: Two tests tie it to the code and close that error class:
#:
#: - `tests/test_statuses.py` extracts from the syntax tree of the core **every**
#:   literal status actually produced - first argument of an `EventRejected(...)`,
#:   assignment of a `status` attribute - and requires equality with this tuple. A
#:   status added to the code without being declared here fails the suite;
#: - invariant 1 of section 8.2 (`tests/test_pipeline.py`) requires observing **each**
#:   of these values on a real case. A status declared here with no test case therefore
#:   fails the suite as well.
#:
#: The order is that of the table in section 5.7.
ACL_STATUSES = (
    "updated",
    "noop",
    "dryrun",
    "rejected",
    "not_found",
    "forbidden",
    "invalid_role",
    "skipped_immutable",
    "skipped_derived",
    "skipped_private",
    "skipped_ceiling",
    "error",
)

#: Output fields carried by **every** record, whatever the `acl_status`
#: (section 5.7). They enter the stream header through the first record emitted.
ACL_UNCONDITIONAL_FIELDS = (
    "acl_status",
    "acl_endpoint",
    "acl_http_code",
    "acl_error",
    "acl_warning",
    "acl_journaled",
)

#: The eight state fields of section 5.7. They are only carried by the records whose
#: merge was computed: a `skipped_private`, a `skipped_derived`, a `skipped_ceiling`, a
#: `not_found`, a `forbidden` or a rejection **upstream** of the merge carries none of
#: them.
ACL_STATE_FIELDS = (
    "acl_before_owner",
    "acl_after_owner",
    "acl_before_perms_read",
    "acl_before_perms_write",
    "acl_before_sharing",
    "acl_after_perms_read",
    "acl_after_perms_write",
    "acl_after_sharing",
)

#: **Declared output field set** (section 5.7, D-33), in the order of the normative
#: table.
#:
#: The SDK writer freezes the stream header on the keys of the **first** record
#: emitted, then projects every later record onto it: a field absent from that first
#: record disappears from the entire output, with no error and no warning. Since the
#: eight fields of `ACL_STATE_FIELDS` are not carried by every status, a batch starting
#: with a `skipped_private` - which the inventory macro routinely produces - would
#: deprive the operator of everything the simulation exists to show.
#:
#: The declaration is therefore **explicit** and lives here, outside the adapter, so
#: that the declared list and the projected list are the same datum and cannot diverge.
#: The vendored SDK is not modified: it exposes `RecordWriter.custom_fields` for
#: exactly this purpose.
ACL_OUTPUT_FIELDS = (
    "acl_status",
    "acl_endpoint",
    "acl_http_code",
    "acl_error",
    "acl_warning",
    "acl_before_owner",
    "acl_after_owner",
    "acl_before_perms_read",
    "acl_before_perms_write",
    "acl_before_sharing",
    "acl_after_perms_read",
    "acl_after_perms_write",
    "acl_after_sharing",
    "acl_journaled",
)


@dataclass(frozen=True)
class FieldNames:
    """Name of the SPL field to read each piece of information from (3.1, 3.3, 4.1).

    Every logical input of the command is a **parameter naming a field**, with a
    default that is the platform's native field name. An operator who uses the native
    names therefore writes no parameter at all.

    There is **no** addressing property field: addressing uses a fixed context
    (section 5.2, D-25). `new_owner` exists, but it is a **target value**, not an
    address.
    """

    title: str = "title"
    app: str = "eai:acl.app"
    id: str = "id"
    type: str = "eai:type"
    sharing: str = "eai:acl.sharing"
    new_perms_read: str = "eai:acl.perms.read"
    new_perms_write: str = "eai:acl.perms.write"
    new_sharing: str = "eai:acl.sharing"
    new_owner: str = "eai:acl.owner"


#: Defaults of sections 3.1 and 3.3, exposed for the documentation and the tests.
DEFAULT_FIELD_NAMES = FieldNames()


@dataclass(frozen=True)
class EventInput:
    """Projection of one input event (sections 3.1, 3.2, 3.3).

    **`present` is the heart of the contract.** It carries the subset of
    `TARGET_ATTRIBUTES` whose **column exists in the result set**. It is the only
    discriminant between "preserve" and "modify": neither the type of the value nor the
    value itself enters into it (section 3.2).

    `current_sharing` is the **current** sharing scope (section 3.1), used to skip
    private objects (section 3.5). `None` means the column is absent from the result
    set - the case where the command cannot skip them upstream.
    """

    title: str
    app: str
    id_value: Optional[str] = None
    eai_type: Optional[str] = None
    current_sharing: Optional[str] = None
    new_perms_read: object = None
    new_perms_write: object = None
    new_sharing: object = None
    new_owner: object = None
    present: frozenset = frozenset()

    def has(self, attribute):
        """True if the column of `attribute` exists in the result set.

        This is the core's only presence predicate: no other module queries `present`
        directly, which guarantees that none can substitute a type or value test for
        it.
        """
        return attribute in self.present


@dataclass(frozen=True)
class AclState:
    """Normalized ACL state of an object (section 5.5)."""

    owner: str = ""
    sharing: str = ""
    perms_read: Tuple[str, ...] = ()
    perms_write: Tuple[str, ...] = ()
    can_change_perms: bool = True


@dataclass(frozen=True)
class MergeResult:
    """Result of the merge (section 5.4)."""

    before: AclState
    after: AclState
    payload: dict = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()
    rejection: object = None  # EventRejected | None


@dataclass(frozen=True)
class Params:
    """Validated parameters of the command (section 4.1)."""

    names: FieldNames
    dryrun: bool
    validate_roles: bool
    journal: bool
    max_objects: int
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RunContext:
    """Run constants, identical for every journal line.

    **The search head member is not among them.** It used to be, under the key `host`
    and then, after D-46, under the key `member`. Both were a duplicate: the `host`
    **metadata** Splunk stamps on every event at collection carries the same value, and
    the diagnostic file logs the member on its own line at startup. The rename fixed the
    multivalued field the collision produced; removing the key removes the duplication
    the rename had preserved. Whoever needs the member reads the metadata, which no
    version of this command has to keep in step.
    """

    sid: str
    user: str
    dryrun: bool


@dataclass(frozen=True)
class EventResult:
    """Result of processing one event (section 5.7 plus the journal needs of 8.2)."""

    status: str
    title: str = ""
    app: str = ""
    eai_type: str = ""
    #: Handler path the command **actually resolved** for this object, for example
    #: `saved/searches` (section 5.2). Empty when resolution did not take place.
    #:
    #: It is the datum `eai_type` was expected to stand for and does not always carry:
    #: an event coming from a native endpoint has no `eai:type` at all, and the object
    #: is nevertheless resolved and written. The command knows the handler at that
    #: moment and used to discard it.
    #:
    #: **It is not an inverted type, and it must not be read as one.** The mapping
    #: table of section 6 is not injective: two keys, `times` and `conf-times`, share
    #: the handler `data/ui/times`, and the `id` route resolves handler paths that
    #: belong to no key at all. Going back from a handler to a type is therefore
    #: undefined in the general case; the handler itself is not.
    handler: str = ""
    endpoint: str = ""
    http_code: int = 0
    error: Optional[str] = None
    warnings: Tuple[str, ...] = ()
    before: Optional[AclState] = None
    after: Optional[AclState] = None
    journaled: bool = False
    post_attempted: bool = False
    counted: bool = False
    source: str = ""
