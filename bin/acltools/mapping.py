"""Mapping table `eai:type` -> handler path (section 6).

Two sources, in this order: `bin/acl_endpoint_map.json` (shipped), then
`lookups/acl_endpoint_map_override.csv` (created by the operator, never shipped -
D-5), which overrides the first.

No derivation heuristic is allowed (section 6.2): `resolve` returns `None` on an
unknown type, never a guessed value. The lab measurement justifies this empirically -
`commands` resolves to `admin/commandsconf`, `conf-times` to `data/ui/times`.
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
    """Table `eai:type` -> `handler_path`, immutable once built."""

    def __init__(self, entries, from_json=(), from_override=(), rejected=()):
        self._entries = dict(entries)
        self._from_json = tuple(sorted(from_json))
        self._from_override = tuple(sorted(from_override))
        self._rejected = tuple(rejected)

    def resolve(self, eai_type):
        """Return the `handler_path` of an `eai:type`, or `None` if it is unknown."""
        if not eai_type:
            return None
        return self._entries.get(str(eai_type).strip())

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
