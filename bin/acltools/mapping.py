"""Mapping table `eai:type` -> handler path (section 6).

Two sources, in this order: `bin/acl_endpoint_map.json` (shipped), then
`lookups/acl_endpoint_map_override.csv` (created by the operator, never shipped -
D-5), which overrides the first.

No derivation heuristic is allowed (section 6.2): `resolve` returns `None` on an
unknown type, never a guessed value. The lab measurement justifies this empirically -
`commands` resolves to `admin/commandsconf`, `conf-times` to `data/ui/times`.

The table is read in **both** directions. Forward, `resolve` turns the type an operator
wrote into the handler path the URI needs. Backwards, `type_of_handler` turns a handler
path the `id` route produced back into the type - which is what lets the journal record
one single designation of the object type, in the vocabulary the operator writes, on
every line whatever route resolved the object. The backwards direction is a **partial**
function and says so: see `Mapping.type_of_handler`.
"""

import csv
import json
import os
import re

from .errors import FatalMappingError

#: A handler path is a URL-safe literal. Since the override file is editable by the
#: operator, it is untrusted input: a forged path could aim at an arbitrary endpoint.
HANDLER_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)*$")

#: Path traversal segment - `.`, `..`, and any run of dots. The pattern above requires
#: an alphanumeric first character, which rules out a leading `../`, but it admits a
#: `..` in a later position: the dot belongs to the character class of the following
#: segments.
_DOT_SEGMENT_RE = re.compile(r"^\.+$")


def is_valid_handler_path(path):
    """True if `path` is an admissible handler path.

    Refusing the `.` and `..` segments is **the tool's own defense**, not a duplicate
    of the platform's. Splunk 9.4.6 does not normalize `..` - it treats it as a handler
    action and answers 404 - but resting namespace confinement on a third party's
    behavior is not defending against it: a platform that did normalize the path, or a
    behavior change upstream, would make the URI reconstruction exploitable.
    `handler_path` is the only one of the four segments deliberately left un-`%`-encoded
    (section 5.2), and it comes either from the shipped table, or from the override
    file edited by the operator, or from the `id` field of the event.
    """
    if not path or not HANDLER_PATH_RE.match(path):
        return False
    return not any(_DOT_SEGMENT_RE.match(segment) for segment in path.split("/"))


class Mapping(object):
    """Table `eai:type` -> `handler_path`, immutable once built.

    The table is also read **backwards**, and that direction is a partial function
    rather than a bijection: the shipped table carries 28 keys for 27 distinct handler
    paths. `data/ui/times` is the image of **two** keys, `times` and `conf-times`, and
    a handler path resolved through the `id` route of section 5.2 may belong to no key
    at all. `type_of_handler` therefore answers `None` on both of those cases instead
    of picking one, and `ambiguous_handlers` publishes the collisions so that a test
    can fail the day the table stops being invertible somewhere else.
    """

    def __init__(self, entries, from_json=(), from_override=(), rejected=()):
        self._entries = dict(entries)
        self._from_json = tuple(sorted(from_json))
        self._from_override = tuple(sorted(from_override))
        self._rejected = tuple(rejected)
        inverse = {}
        for eai_type, handler_path in self._entries.items():
            inverse.setdefault(handler_path, []).append(eai_type)
        self._inverse = {
            handler_path: tuple(sorted(keys))
            for handler_path, keys in inverse.items()
        }

    def resolve(self, eai_type):
        """Return the `handler_path` of an `eai:type`, or `None` if it is unknown."""
        if not eai_type:
            return None
        return self._entries.get(str(eai_type).strip())

    def type_of_handler(self, handler_path):
        """Return the `eai:type` of a handler path, or `None` when it is undefined.

        Undefined covers **two** distinct situations, and neither of them may be
        guessed:

        - the handler path is the image of **several** keys - `data/ui/times`, image of
          `times` and of `conf-times` on the shipped table. There is no ground on which
          to prefer one, and the SPL counterpart of this table would answer with aplomb
          because it drops one of the two keys (see `lookups/acl_object_families.csv`);
        - the handler path is the image of **no** key. The `id` route of section 5.2
          accepts any pattern-valid path, including endpoints this table never named.

        The caller reads the empty type as "the type could not be established", which
        is the truth, rather than as a type that happens to be wrong.
        """
        if not handler_path:
            return None
        keys = self._inverse.get(str(handler_path).strip())
        if keys is None or len(keys) != 1:
            return None
        return keys[0]

    def ambiguous_handlers(self):
        """Handler paths that are the image of more than one key, with their keys."""
        return {
            handler_path: keys
            for handler_path, keys in sorted(self._inverse.items())
            if len(keys) > 1
        }

    def types(self):
        return tuple(sorted(self._entries))

    def coverage(self):
        """State of the table, for README section 6.4 and re-validation section 6.5."""
        return {
            "total": len(self._entries),
            "from_json": len(self._from_json),
            "from_override": len(self._from_override),
            "overridden": tuple(
                t for t in self._from_override if t in self._from_json
            ),
            "rejected": self._rejected,
            "types": self.types(),
            "handlers": len(self._inverse),
            "ambiguous_handlers": self.ambiguous_handlers(),
        }

    def __len__(self):
        return len(self._entries)

    def __contains__(self, eai_type):
        return self.resolve(eai_type) is not None


def load_mapping(json_path, override_csv_path=None, diag=None):
    """Load the shipped table, then the override if there is one.

    `diag` is an optional callable `(level, message)` for the diagnostic log; the
    package does not know the platform's `logging`.

    Errors: `FatalMappingError` if the JSON is missing, unreadable or malformed
    (section 9). A **missing override CSV is normal**; an unreadable CSV produces a
    diagnostic warning, not a fatal error - the absence of an override must not prevent
    running with the shipped table.
    """
    def _diag(level, message):
        if diag is not None:
            diag(level, message)

    try:
        with open(json_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (IOError, OSError) as exc:
        raise FatalMappingError(
            "mapping table unreadable (%s): %s" % (json_path, exc)
        )
    except ValueError as exc:
        raise FatalMappingError(
            "mapping table malformed (%s): %s" % (json_path, exc)
        )

    if not isinstance(raw, dict):
        raise FatalMappingError(
            "mapping table malformed (%s): a JSON object was expected" % json_path
        )

    entries = {}
    rejected = []
    from_json = []
    for eai_type, handler_path in raw.items():
        key = str(eai_type).strip()
        value = str(handler_path).strip()
        if not key or not is_valid_handler_path(value):
            rejected.append((key, value, "acl_endpoint_map.json"))
            _diag("WARNING", "table entry discarded: %r -> %r" % (key, value))
            continue
        entries[key] = value
        from_json.append(key)

    from_override = []
    if override_csv_path and os.path.exists(override_csv_path):
        try:
            with open(override_csv_path, "r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = [
                    (name or "").strip() for name in (reader.fieldnames or [])
                ]
                if "eai_type" not in fieldnames or "handler_path" not in fieldnames:
                    raise ValueError(
                        "columns 'eai_type' and 'handler_path' expected, saw %r"
                        % (fieldnames,)
                    )
                for row in reader:
                    key = (row.get("eai_type") or "").strip()
                    value = (row.get("handler_path") or "").strip()
                    if not key or key.startswith("#"):
                        # Comment line: the file is hand-edited by the operator, so it
                        # necessarily contains some.
                        continue
                    if not is_valid_handler_path(value):
                        rejected.append((key, value, "override"))
                        _diag(
                            "WARNING",
                            "override entry discarded: %r -> %r" % (key, value),
                        )
                        continue
                    entries[key] = value
                    from_override.append(key)
        except (IOError, OSError, ValueError, csv.Error) as exc:
            _diag(
                "WARNING",
                "override unreadable, shipped table kept (%s): %s"
                % (override_csv_path, exc),
            )

    return Mapping(entries, from_json, from_override, rejected)
