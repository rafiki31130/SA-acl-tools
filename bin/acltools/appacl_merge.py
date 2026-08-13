"""Merge engine of the application-level command (v4.3 sections 8.4, 8.6).

**The presence of the column alone decides whether to modify or to preserve; the cell
only decides the value** - the semantics of v3.14 section 3.2, reconducted without
modification::

    column absent                     -> attribute preserved, as read by the GET
    column present, cell empty        -> attribute emptied
    column present, cell valued       -> value applied

Two things are specific to this command, and both are measured.

**The two permissions are always transmitted.** The merge semantics of the two write
paths is a **block replacement conditioned on the presence of at least one
permission**: with one `perms.*` in the body, the `access` line is replaced whole and
the absent one is **deleted** from the file; with none, `access` is preserved entirely
(Q0-1 cases B, C and L, and Q0-2 on the omission of `perms.write`). A command that only
means to touch `read` therefore has to re-read and send **both**.

**`sharing` is the only lever, and `user` is refused.** `export` is never transmitted:
both handlers answer `400 Argument "export" is not supported by this handler.`
`sharing` drives it - `app` writes `export = none`, `global` writes `export = system` -
it is mandatory on both paths, and `user` is refused per event (**DV-4**).

There is no owner in this module, in either direction (**DV-5**).
"""

from .appacl_model import (
    STANZA_KIND_APP,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    VALID_APP_SHARING,
    AppAclState,
    AppMergeResult,
)
from .errors import EventRejected
from .normalize import (
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    serialize_roles,
)

#: Owner value transmitted on the `[]` path, where it is **mandatory and inert**
#: (measured, Q0-1 cases D and G): no `owner =` key is written into the stanza, and the
#: read-back always returns `nobody` whatever was sent.
#:
#: It is a **literal**, never derived from an input field, and the command draws no
#: conclusion from it: it is not exposed as a parameter, not journaled as a target value,
#: and not compared for idempotence (section 4.2).
INERT_OWNER = "nobody"


def parse_app_acl_state(entry_acl):
    """Build an `AppAclState` from the `entry[0].acl` block of a GET response.

    Same block shape on both read paths (Q0-1, Q0-2). `owner` is deliberately **not**
    read: it is inert on one path and refused on the other, so keeping it would give the
    idempotence comparison an attribute no write can ever settle.

    Tolerant of a missing `perms`, and of `perms.read` / `perms.write` arriving either as
    a list or as a string - `normalize_roles` converges `null`, `[]`, `[""]` and
    `["", ""]` on the empty tuple, which is what makes idempotence detectable on a stanza
    with an empty permission (measured: after `perms.read=`, the read-back is `[""]`).
    """
    entry_acl = entry_acl or {}
    perms = entry_acl.get("perms") or {}
    if not isinstance(perms, dict):
        perms = {}
    return AppAclState(
        sharing=str(entry_acl.get("sharing") or ""),
        perms_read=normalize_roles(perms.get("read")),
        perms_write=normalize_roles(perms.get("write")),
    )


def _merged_roles(current_value, event, attribute, raw):
    """Apply the presence semantics to a role list (section 8.4).

    `is_field_empty` is consulted **only after** presence has decided: it settles the
    value, never the intent.
    """
    if not event.has(attribute):
        return current_value
    return () if is_field_empty(raw) else normalize_roles(raw)


def merge(current, event, stanza_kind):
    """Compute the target state, the payload and the rejections of ranks 6 and 7.

    Ranks 6 and 7 of section 8.7 - an empty `sharing`, a `sharing` outside
    `{app, global}` - are the only rejections this function produces. Every other rank
    belongs to the pipeline, which alone holds the run's memory, the parameters, the
    provenance and the counters.
    """
    perms_read = _merged_roles(
        current.perms_read, event, TARGET_PERMS_READ, event.new_perms_read
    )
    perms_write = _merged_roles(
        current.perms_write, event, TARGET_PERMS_WRITE, event.new_perms_write
    )

    sharing = current.sharing
    rejection = None
    if event.has(TARGET_SHARING):
        if is_field_empty(event.new_sharing):
            # An empty scope does not exist, and `sharing` is mandatory on both paths:
            # sending nothing would be refused, sending an empty value would be refused
            # too. The event is rejected before any call (rank 6).
            rejection = EventRejected("rejected", "sharing_empty_not_allowed")
        else:
            candidate = normalize_sharing(event.new_sharing)
            if candidate not in VALID_APP_SHARING:
                # `user` lands here like any other invalid value, and that is
                # deliberate: the platform refuses it with two different messages
                # depending on the path (`Apps cannot be unshared`, `Containers cannot be
                # unshared`), and an operator does not have to learn two of them to
                # discover that the scope does not exist at this level (**DV-4**).
                rejection = EventRejected(
                    "rejected", "invalid_sharing:%s" % (candidate or "")
                )
            else:
                sharing = candidate

    after = AppAclState(
        sharing=sharing, perms_read=perms_read, perms_write=perms_write
    )

    warnings = []
    if after.sharing != current.sharing:
        # The visibility of every object governed by this stanza changes.
        warnings.append("sharing_change")

    return AppMergeResult(
        before=current,
        after=after,
        payload=build_payload(after, stanza_kind),
        warnings=tuple(warnings),
        rejection=rejection,
    )


def build_payload(state, stanza_kind):
    """POST body of the target state (section 5.1).

    **The two permissions are always present**, empty value included, serialized as
    `perms.read=` - key present, value empty, never an omission: an omission would delete
    the permission from the file.

    **`owner` is present on the `[]` path and absent on the `_acl` path**, and that
    asymmetry is measured on both sides rather than smoothed: it is mandatory on the
    first (`400 The following required arguments are missing: owner, sharing.`) and
    refused on the second (`400 Argument "owner" is not supported by this handler.`) by
    `data/ui/views` and `data/macros`. `saved/searches` accepts it, and that is precisely
    why it must not be sent: the only shape every measured handler accepts is the one
    without it (section 4.2).

    **`export` is never transmitted**, on either path. `sharing` drives it.
    """
    payload = {
        "sharing": state.sharing,
        "perms.read": serialize_roles(state.perms_read),
        "perms.write": serialize_roles(state.perms_write),
    }
    if stanza_kind == STANZA_KIND_APP:
        payload["owner"] = INERT_OWNER
    return payload


def is_noop(current, target):
    """Strict equality of the merged state and the effective read state (section 8.6).

    Bears on `perms.read`, `perms.write` and `sharing`, and **never on the owner**,
    which is not expressible here.

    The comparison bears on the sorted collections, not on the strings: a permutation of
    the role order is a `noop`.
    """
    return (
        current.sharing == target.sharing
        and current.perms_read == target.perms_read
        and current.perms_write == target.perms_write
    )


def validate_roles(before, after, catalog):
    """Control of rank 11, restricted to the **added roles** (v3.14 section 5.4, D-4).

    Returns `(unknown_added, stale_preserved)`, two sorted tuples. An unknown role
    already carried by the stanza and left untouched does not block the write: it is only
    reported, because blocking it would prevent the very fix that would remove it.
    """
    before_read, before_write = set(before.perms_read), set(before.perms_write)
    after_read, after_write = set(after.perms_read), set(after.perms_write)

    added = (after_read - before_read) | (after_write - before_write)
    preserved = (after_read & before_read) | (after_write & before_write)

    unknown_added = tuple(sorted(added - set(catalog)))
    stale_preserved = tuple(sorted(preserved - set(catalog)))
    return unknown_added, stale_preserved
