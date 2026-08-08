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


def parse_acl_state(entry_acl):
    """Build an `AclState` from the `entry[0].acl` block of the GET response.

    The `f=eai:acl*` parameter of section 5.3 filters `content` and leaves `acl`
    untouched; `acl` is the authority (section 5.3). The parsing tolerates a missing
    `perms` (object with no explicit permission, case of section 10.1) and accepts
    `perms.read` / `perms.write` received either as a list or as a string.
    """
    entry_acl = entry_acl or {}
    perms = entry_acl.get("perms") or {}
    if not isinstance(perms, dict):
        perms = {}
    return AclState(
        owner=str(entry_acl.get("owner") or ""),
        sharing=str(entry_acl.get("sharing") or ""),
        perms_read=normalize_roles(perms.get("read")),
        perms_write=normalize_roles(perms.get("write")),
        can_change_perms=_as_bool(entry_acl.get("can_change_perms"), default=True),
    )
