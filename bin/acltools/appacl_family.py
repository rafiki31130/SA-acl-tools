"""Family table `stanza name` -> handler path (v4.1 section 5.2).

Two sources, in this order: `bin/app_acl_family_map.json` (shipped), then
`lookups/app_acl_family_map_override.csv` (created by the operator, never shipped),
which overrides the first. That is the arrangement of `mapping.py`, and the validation
of a handler path is **the same function** - a second pattern would be a second
opportunity to diverge.

Two things set this table apart from the one of `mapping.py`, and both come from the
measurement:

- it is keyed by **stanza name**, not by object type. The measurement produced
  handler -> stanza; the command needs the inverse, and **the inversion is a choice,
  not a measurement**: seven handlers write `[props]`, two write `[savedsearches]`, and
  one has to be designated as canonical (Q0-2, "Alias mesurés");
- the stanza name follows the **underlying configuration file**, never the URI:
  `data/ui/workflow-actions` writes `[workflow_actions]`, with an underscore and not a
  hyphen (measured, Q0-2). No derivation heuristic - pluralization, hyphen
  substitution, insertion of a `data/` prefix - is admitted (section 5.2,
  requirement 2).

**Three families known to be negative are deliberately absent** rather than named in the
code (section 5.3, and the arbitration of v3.14 section 10.10): naming them would carve
a property of the platform into the tool, one that nothing lets us re-check and that the
next version may contradict. Absent, they are treated as any uncovered family - rejected
before any call, with their name in `acl_error` - which is the correct behavior.
"""

import csv
import json
import os

from .errors import FatalFamilyTableError
from .mapping import is_valid_handler_path


class FamilyTable(object):
    """Table `stanza` -> `handler_path`, immutable once built.

    Unlike `Mapping`, it is **not** read backwards. The command never needs to go from a
    handler path to a family name: when the input carries a handler, that handler is the
    address, and the stanza name it writes is a fact of the platform this table cannot
    establish. Inventing the reverse direction would produce exactly the false aplomb
    `Mapping.type_of_handler` refuses on its ambiguous entries.
    """

    def __init__(self, entries, from_json=(), from_override=(), rejected=()):
        self._entries = dict(entries)
        self._from_json = tuple(sorted(from_json))
        self._from_override = tuple(sorted(from_override))
        self._rejected = tuple(rejected)

    def resolve(self, family):
        """Return the handler path of a family, or `None` if it is not covered."""
        if not family:
            return None
        return self._entries.get(str(family).strip())

    def families(self):
        return tuple(sorted(self._entries))

    def coverage(self):
        """State of the table, for the diagnostic and the re-validation procedure."""
        return {
            "total": len(self._entries),
            "from_json": len(self._from_json),
            "from_override": len(self._from_override),
            "overridden": tuple(f for f in self._from_override if f in self._from_json),
            "rejected": self._rejected,
            "families": self.families(),
        }

    def __len__(self):
        return len(self._entries)

    def __contains__(self, family):
        return self.resolve(family) is not None


def load_family_table(json_path, override_csv_path=None, diag=None):
    """Load the shipped table, then the override if there is one.

    `diag` is an optional callable `(level, message)` for the diagnostic log; the
    package does not know the platform's `logging`.

    Errors: `FatalFamilyTableError` if the JSON is missing, unreadable or malformed
    (section 13.1). A **missing override CSV is normal**; an unreadable CSV produces a
    diagnostic warning and nothing more - the absence of an override must not prevent
    running with the shipped table.
    """
    def _diag(level, message):
        if diag is not None:
            diag(level, message)

    try:
        with open(json_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (IOError, OSError) as exc:
        raise FatalFamilyTableError(
            "family table unreadable (%s): %s" % (json_path, exc)
        )
    except ValueError as exc:
        raise FatalFamilyTableError(
            "family table malformed (%s): %s" % (json_path, exc)
        )

    if not isinstance(raw, dict):
        raise FatalFamilyTableError(
            "family table malformed (%s): a JSON object was expected" % json_path
        )

    entries = {}
    rejected = []
    from_json = []
    for family, handler_path in raw.items():
        key = str(family).strip()
        value = str(handler_path).strip()
        if not key or not is_valid_handler_path(value):
            rejected.append((key, value, "app_acl_family_map.json"))
            _diag("WARNING", "family entry discarded: %r -> %r" % (key, value))
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
                if "family" not in fieldnames or "handler_path" not in fieldnames:
                    raise ValueError(
                        "columns 'family' and 'handler_path' expected, saw %r"
                        % (fieldnames,)
                    )
                for row in reader:
                    key = (row.get("family") or "").strip()
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

    return FamilyTable(entries, from_json, from_override, rejected)
