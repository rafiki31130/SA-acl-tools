"""Normalization of role lists and of the sharing scope (sections 3.2, 5.5).

Total functions: they never raise.

Filtering out empty items is not cosmetic (D-8). After a POST carrying an empty
`perms.read=`, the following GET returns neither `[]` nor `null` but `[""]` - a list
holding one empty string. Without that filtering, the state read and the merged state
are never equal and the idempotence detection of section 5.5 fails on **every** object
with an empty permission.
"""

from .model import AclState

VALID_SHARING = frozenset({"user", "app", "global"})


def _flatten(raw):
    """Flatten a raw field into a list of text tokens, without filtering."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set, frozenset)):
        out = []
        for item in raw:
            out.extend(_flatten(item))
        return out
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return [part for part in str(raw).split(",")]


def normalize_roles(raw):
    """Normalize a permission field into a sorted, deduplicated tuple, no empties.

    Accepts a multivalue, a comma-separated string, `None`, and any combination.
    `null`, `[]`, `[""]` and `["", ""]` all converge on the empty tuple.
    """
    tokens = set()
    for part in _flatten(raw):
        token = part.strip()
        if token:
            tokens.add(token)
    return tuple(sorted(tokens))


def serialize_roles(roles):
    """Serialize a tuple of roles for the POST body.

    An empty tuple yields the empty string, never `*` (section 3.3).
    """
    return ",".join(roles)


def normalize_sharing(raw):
    """Normalize a sharing scope. Returns `None` when the field is empty."""
    for part in _flatten(raw):
        token = part.strip()
        if token:
            return token.lower()
    return None


def is_field_empty(raw):
    """True for `None`, `""`, `[]`, and any value whose tokens are all empty.

    On the permissions side, "field absent", "field null" and "field empty" are the
    same case (section 3.3): this function is the point where that equivalence is
    realized.
    """
    for part in _flatten(raw):
        if part.strip():
            return False
    return True


def _as_bool(raw, default=True):
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    token = str(raw).strip().lower()
    if token in ("1", "true", "t", "yes", "y", "on"):
        return True
    if token in ("0", "false", "f", "no", "n", "off"):
        return False
    return default


#: Names of the ACL keys that state whether an object's permissions may be changed,
#: **in order of authority**. The first one present in the block settles the question;
#: the following ones are only consulted in its absence.
#:
#: There are two of them because splunkd publishes the same fact under two names,
#: depending on the handler.
#:
#: - `can_change_perms` is the exact question - may the *permissions* be changed - and
#:   is what every handler with a full ACL block answers.
#: - `modifiable` is the nearest question a reduced ACL block answers. Handlers that
#:   publish no `can_change_perms` publish it instead, together with `perms: null` and
#:   without any of the `can_share_*` keys: the whole permission side of the block is
#:   missing, and `modifiable` is the only statement left about it.
#:
#: **The order matters and the fallback is not a synonym.** `modifiable` speaks of the
#: object, `can_change_perms` of its ACL; a handler that publishes both answers the
#: exact question, and its answer must win. Reading `modifiable` first would let an
#: object that is merely read-only in content be reported as having a frozen ACL.
#: Reading it only when `can_change_perms` is absent adds an answer where there was
#: none and changes none of those that existed.
#:
#: Measured on 9.4.6 over the 1 502 objects of the 27 native handler paths: `modifiable`
#: is published by 1 502, `can_change_perms` by 1 501. The single object missing it is
#: an `admin/ntags` one, which is also the single object carrying `modifiable = false`.
#: No object anywhere carries the two keys with contradictory values.
PERMS_LOCK_KEYS = ("can_change_perms", "modifiable")


def read_perms_lock(entry_acl):
    """Return `(can_change_perms, key)` read from the `acl` block.

    `key` is the name of the ACL key the answer came from, so that the rejection of
    rank 1 (section 5.4) can say **which** statement of the platform it obeyed. When
    no key of `PERMS_LOCK_KEYS` is present, the answer is the permissive default and
    the key is the empty string: nothing was read.
    """
    entry_acl = entry_acl or {}
    for key in PERMS_LOCK_KEYS:
        if key in entry_acl:
            return _as_bool(entry_acl.get(key), default=True), key
    return True, ""


def parse_acl_state(entry_acl):
    """Build an `AclState` from the `entry[0].acl` block of the GET response.

    The `f=eai:acl*` parameter of section 5.3 filters `content` and leaves `acl`
    untouched; `acl` is the authority (section 5.3). The parsing tolerates a missing
    `perms` (object with no explicit permission, case of section 10.1) and accepts
    `perms.read` / `perms.write` received either as a list or as a string.

    Whether the permissions may be changed is read through `read_perms_lock`, which
    knows the two names splunkd publishes that fact under.
    """
    entry_acl = entry_acl or {}
    perms = entry_acl.get("perms") or {}
    if not isinstance(perms, dict):
        perms = {}
    can_change_perms, source = read_perms_lock(entry_acl)
    return AclState(
        owner=str(entry_acl.get("owner") or ""),
        sharing=str(entry_acl.get("sharing") or ""),
        perms_read=normalize_roles(perms.get("read")),
        perms_write=normalize_roles(perms.get("write")),
        can_change_perms=can_change_perms,
        perms_lock_source=source,
    )
