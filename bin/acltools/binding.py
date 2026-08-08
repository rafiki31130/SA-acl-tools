"""Binding of an SPL record to an `EventInput` (spec sections 3.1, 3.2, 3.3).

This is **the** module where the presence semantics of section 3.2 is decided, and it
does nothing else: read, in a record, the fields designated by the field-naming
parameters, and record **which columns exist**.

    | Situation                            | Effect                       |
    |--------------------------------------|------------------------------|
    | column **absent** from the result set  | attribute **preserved**    |
    | column **present**, cell **empty**     | attribute **emptied**      |
    | column **present**, cell valued        | value applied              |

**The discriminant is the presence of the key in the record - never the type, never
the value.** Measured on 9.4.6: the command receives either a key absent from the
record, or a key present holding the empty string. Never `None`, never an empty list.
And a multivalue field **reduced to a single value arrives as a string**, not as a
list: a type test would conclude "single value" where there is nothing to conclude,
and above all would say nothing about presence.

The extra caution - `raw is not None` on top of `key in record` - would be a mistake,
not a precaution: it would reintroduce through the back door the value-based
discrimination that section 3.2 forbids, and would turn an explicit "empty this
attribute" into "preserve it". The predicate is therefore **exactly** `key in record`,
with no further clause.
"""

from .model import (
    TARGET_OWNER,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    EventInput,
)


def field_present(record, name):
    """Column presence predicate. Single injection point of the section 3.2 rule.

    No other caller in the package tests for the presence of a field: the rule lives
    here, on one line, and cannot drift elsewhere.
    """
    if record is None or not name:
        return False
    try:
        return name in record
    except TypeError:                                                # pragma: no cover
        return False


def field_value(record, name, default=None):
    """Raw value of a column, with no interpretation and no coercion."""
    if not field_present(record, name):
        return default
    return record.get(name)


def _text(raw):
    """Reduce a raw value to a string, without deciding whether it is empty.

    A multivalue is reduced to its first non-empty value: this covers `title`, `app`,
    `id`, `type` and the current sharing scope, which are single-valued by nature.
    """
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        for item in raw:
            token = _text(item)
            if token:
                return token
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).strip()


def build_event(record, names):
    """Build the `EventInput` of a record, following the field-naming parameters.

    The **reference** fields (section 3.1) are read for their value; their presence as
    a column only matters for the current sharing scope, whose absence deprives the
    command of the section 3.5 filter.

    The four **target values** (section 3.3) are read for their value **and** for their
    presence, the latter being recorded in `present`.
    """
    record = record if record is not None else {}

    sharing_column = names.sharing
    current_sharing = (
        _text(field_value(record, sharing_column))
        if field_present(record, sharing_column)
        else None
    )

    present = set()
    for attribute, column in (
        (TARGET_PERMS_READ, names.new_perms_read),
        (TARGET_PERMS_WRITE, names.new_perms_write),
        (TARGET_SHARING, names.new_sharing),
        (TARGET_OWNER, names.new_owner),
    ):
        if field_present(record, column):
            present.add(attribute)

    return EventInput(
        title=_text(field_value(record, names.title)),
        app=_text(field_value(record, names.app)),
        id_value=field_value(record, names.id),
        eai_type=_text(field_value(record, names.type)) or None,
        current_sharing=current_sharing,
        new_perms_read=field_value(record, names.new_perms_read),
        new_perms_write=field_value(record, names.new_perms_write),
        new_sharing=field_value(record, names.new_sharing),
        new_owner=field_value(record, names.new_owner),
        present=frozenset(present),
    )
