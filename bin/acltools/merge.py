"""Merge engine (sections 3.2, 3.3, 5.4) - the heart of the input contract.

**The presence of the column alone decides whether to modify or to preserve; the cell
only decides the value.**

    column absent                     -> attribute preserved, as read by the GET
    column present, cell empty        -> attribute emptied
    column present, cell valued       -> value applied

The presence predicate is not evaluated here: it is frozen at binding time
(`binding.field_present`) and carried by `EventInput.present`. This module only
consults `event.has(<attribute>)`, which makes it structurally impossible to
substitute a type or value test for it.

Two attributes depart from the "empty cell -> empty attribute" line, and for the same
reason: the empty value **does not exist** on the platform side.

- `sharing`: `sharing=` is not a valid scope.
- `owner`  : an empty owner makes the POST fail.

In both cases the event is **rejected**, with no POST, and without incrementing the
counter of section 4.3.
"""

from .errors import EventRejected
from .model import (
    TARGET_OWNER,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    AclState,
    MergeResult,
)
from .normalize import (
    VALID_SHARING,
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    serialize_roles,
)

#: Technical owner: an object shared at `user` scope cannot belong to it.
NOBODY = "nobody"


def _merged_roles(current_value, event, attribute, raw):
    """Apply the presence semantics to a role list (section 3.2).

    `is_field_empty` is consulted **only after** presence has decided: it settles the
    value, never the intent.
    """
    if not event.has(attribute):
        return current_value
    return () if is_field_empty(raw) else normalize_roles(raw)


def merge(current, event):
    """Compute the target state and the rejections of ranks 1 to 4 of section 5.4.

    Ranks 5 (`validate_roles`), 6 (`noop`) and 7 (`dryrun`) are applied by the
    pipeline, which alone holds the role catalog and the parameters. Ranks -1
    (`skipped_private`) and 0 (`skipped_derived`) are too: they precede the merge and
    have no target state.
    """
    perms_read = _merged_roles(
        current.perms_read, event, TARGET_PERMS_READ, event.new_perms_read
    )
    perms_write = _merged_roles(
        current.perms_write, event, TARGET_PERMS_WRITE, event.new_perms_write
    )

    sharing = current.sharing
    sharing_rejection = None
    if event.has(TARGET_SHARING):
        if is_field_empty(event.new_sharing):
            # An empty scope does not exist. Sending it would expose the operation
            # either to an opaque HTTP rejection or to a silent substitution - on an
            # endpoint that operates by full replacement (section 3.3, D-1).
            sharing_rejection = EventRejected("rejected", "sharing_empty_not_allowed")
        else:
            candidate = normalize_sharing(event.new_sharing)
            if candidate not in VALID_SHARING:
                sharing_rejection = EventRejected(
                    "rejected", "invalid_sharing:%s" % candidate
                )
            else:
                sharing = candidate

    # The owner is sent **in every case** - omitting it from the body makes the
    # platform refuse - but it comes from the GET as long as the `new_owner` column is
    # absent (section 5.4).
    owner = current.owner
    owner_rejection = None
    if event.has(TARGET_OWNER):
        if is_field_empty(event.new_owner):
            # Exact counterpart of the `sharing` exception (section 3.3). The case
            # arises on a heterogeneous batch where some rows do not carry the owner.
            owner_rejection = EventRejected("rejected", "owner_empty_not_allowed")
        else:
            owner = _first_token(event.new_owner)

    after = AclState(
        owner=owner,
        sharing=sharing,
        perms_read=perms_read,
        perms_write=perms_write,
        can_change_perms=current.can_change_perms,
        perms_lock_source=current.perms_lock_source,
    )

    # Normative order of section 5.4: it determines which status wins when several
    # conditions hold at once.
    rejection = None
    if not current.can_change_perms:                                     # rank 1
        # The reason names the ACL key the answer was read from. The status alone
        # cannot: splunkd states the same fact under two names depending on the
        # handler (`normalize.PERMS_LOCK_KEYS`), and an operator who filters on
        # `skipped_immutable` is entitled to know which statement was obeyed - a full
        # ACL block saying the permissions are frozen, or a reduced one that carries no
        # permissions at all. That is a difference of provenance, not of outcome, so it
        # belongs in the reason and not in a status of its own.
        rejection = EventRejected(
            "skipped_immutable",
            "%s=0" % (current.perms_lock_source or "can_change_perms"),
        )
    elif sharing_rejection is not None:                                  # ranks 2 and 3
        rejection = sharing_rejection
    elif owner_rejection is not None:                                    # rank 3bis
        rejection = owner_rejection
    elif after.sharing == "user" and (after.owner or "").lower() == NOBODY:
        rejection = EventRejected(                                       # rank 4
            "rejected", "sharing_user_requires_named_owner"
        )

    warnings = []
    if after.sharing != current.sharing:
        # The visibility of the object changes for every consumer.
        warnings.append("sharing_change")
    if after.owner != current.owner:
        # Taking over ownership changes who holds the object and, on a private object,
        # who can still reach it.
        warnings.append("owner_change")

    # The four attributes are **always** sent: the `/acl` endpoint operates by full
    # replacement, so any omission amounts to an erasure (section 5.4). An empty value
    # is serialized as `perms.read=` - key present, value empty, never an omission.
    payload = {
        "owner": after.owner,
        "sharing": after.sharing,
        "perms.read": serialize_roles(after.perms_read),
        "perms.write": serialize_roles(after.perms_write),
    }

    return MergeResult(
        before=current,
        after=after,
        payload=payload,
        warnings=tuple(warnings),
        rejection=rejection,
    )


def _first_token(raw):
    """First non-empty value of a single-valued field, as a string.

    An `owner` is single-valued. A pipeline may nevertheless present it as a
    multivalue - that happens after certain `stats` - and the first value is then the
    only one.
    """
    if isinstance(raw, (list, tuple, set, frozenset)):
        for item in raw:
            token = _first_token(item)
            if token:
                return token
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw if raw is not None else "").strip()


def is_noop(current, target):
    """Strict equality of the merged state and the read state, after normalization.

    Section 5.5. Bears on `owner`, `sharing`, `perms_read` and `perms_write`.

    **`owner` entered it with D-22.** v1 excluded it on the grounds that it was never
    modified; that ground falls with `new_owner`. Excluding it would make ownership
    takeover inoperative: a batch changing only the owner would come out entirely as
    `noop`, without a single POST, and section 11.2-17bis - the `new_owner` round
    trip - would be untenable.

    The comparison bears on the sorted collections, not on the strings: a permutation
    of the role order is a `noop`.
    """
    return (
        current.owner == target.owner
        and current.sharing == target.sharing
        and current.perms_read == target.perms_read
        and current.perms_write == target.perms_write
    )


def validate_roles(before, after, catalog):
    """Control of section 5.4 rank 5, restricted to the **added roles** (D-4).

    Returns `(unknown_added, stale_preserved)`, two sorted tuples.

    An unknown role already present on the object and left untouched by the operation
    does not block the write: it is only reported. The opposite reading would make the
    tool unusable on exactly the platform it targets - blocking a write on the grounds
    that a dead role lingers in `perms.read` while `perms.write` is what is being
    modified prevents the fix without making the dead reference go away.
    """
    before_read, before_write = set(before.perms_read), set(before.perms_write)
    after_read, after_write = set(after.perms_read), set(after.perms_write)

    added = (after_read - before_read) | (after_write - before_write)
    preserved = (after_read & before_read) | (after_write & before_write)

    unknown_added = tuple(sorted(added - set(catalog)))
    stale_preserved = tuple(sorted(preserved - set(catalog)))
    return unknown_added, stale_preserved
