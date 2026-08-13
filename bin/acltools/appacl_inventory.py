"""Inventory of the application-level ACL stanzas (v4.1 section 7).

**What this command exists to answer**, and nothing else has its place in the output
(section 7.1): *is this application still governable through its generic stanzas, or is
it already frozen object by object?*

That question has **no REST answer**. Measured (Q0-4): an object that inherits and an
object carrying its own stanza of the same value return a **strictly identical** ACL
block, and six alternative REST sources were probed, six negative. The provenance comes
from the file, and only from the file - which is why `app_acl_inventory` is a
**command** and not a macro, an SPL macro being unable to read one (section 6.1).

The division of labour inside this module follows the bounds of section 6.2 exactly:

    effective values      REST          eai:acl.perms.*, eai:acl.sharing
    provenance            the file      acl_present_*, acl_file_*, acl_provenance
    counts, never names   the file      acl_frozen_stanzas, acl_family_headers
    object population     REST          acl_objects_total, acl_objects_inheriting
    governability         derived       acl_governable, a mechanical function of the two
                                        counters and of nothing else

`acl_governable` is **a derivation, not an appreciation** (section 7.4): every one of
its values recomputes from the other columns of the same row, so an operator who
distrusts it can redo the arithmetic in SPL. That is the same discipline as the
`acl_status` enumeration - a figure whose provenance cannot be retraced is a figure
nobody can contest.
"""

import json

from .appacl_family import FamilyTable
from .appacl_merge import parse_app_acl_state
from .appacl_model import (
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    AppAclState,
)
from .appacl_provenance import classify_stanza, family_of
from .appacl_target import build_app_default_path, build_family_default_path
from .normalize import serialize_roles

#: Values of `acl_write_path` (section 7.4): does the family have a **known write
#: path**? It is the column that tells a family this tool could govern from one it can
#: only report on. `unmapped` is not a defect - it is a family present on the platform
#: and absent from the table of section 5.2, which the operator treats through the
#: override CSV.
WRITE_PATH_MAPPED = "mapped"
WRITE_PATH_UNMAPPED = "unmapped"

#: Closed domain of `acl_governable` (section 7.4).
GOVERNABLE_YES = "yes"
GOVERNABLE_PARTIAL = "partial"
GOVERNABLE_UNKNOWN = "unknown"

#: Path of the cheap REST call that names the execution member (section 6.3).
#:
#: **HY-4, and the branch that was left open by the phase 1b measurement.** The
#: `searchinfo` branch is measured **negative**: the full dump of its fourteen fields
#: carries neither a member name, nor a `serverName`, nor a host name, and `splunkd_uri`
#: is `https://127.0.0.1:8089`. The remaining branch was the cheap REST call, and it is
#: measured **positive** on the reference platform: `entry[0].content.serverName` carries
#: the instance name. `/services/shcluster/member/info` answers `503` on a standalone
#: instance and is therefore **not** the route.
#:
#: Reservation, stated rather than smoothed over: the measurement is on a standalone
#: instance. That `serverName` is the right discriminant **between members of a search
#: head cluster** is an inference; the README says to fall back on `splunk_server` if the
#: column comes out empty or ambiguous.
SERVER_INFO_PATH = "/services/server/info"

#: Key of the member name inside the `content` block of that call.
SERVER_NAME_KEY = "serverName"

#: REST path listing the applications (section 6.2, bound 4: the perimeter of read files
#: is limited to the applications **this call returns**).
APPS_PATH = "/services/apps/local"

#: Literal keys of a `.meta` stanza this module reads (section 6.4). `access` carries
#: both permissions on one line, which is why the two output columns are obtained by
#: splitting it rather than by looking up two keys that do not exist.
META_ACCESS_KEY = "access"
META_EXPORT_KEY = "export"

#: **Declared output field set** (section 7.4, and v3.14 section 5.7, D-33). The SDK
#: writer freezes the stream header on the keys of the **first** record emitted; a field
#: absent from that record disappears from the whole output with no error and no warning.
#: The constraint bites here exactly as it does on a streaming command - more so, in
#: fact, since the first row of an inventory is an `app_default` row, which is the one
#: row that never carries `acl_objects_*` when `count_objects` is off.
#:
#: The order is that of the table of section 7.4, and the first eight fields are
#: **exactly** the input contract of `editappacl`: a pipeline built on this command needs
#: no parameter at all.
INVENTORY_OUTPUT_FIELDS = (
    "eai:acl.app",
    "acl_stanza_kind",
    "acl_stanza",
    "acl_handler",
    "acl_write_path",
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    "acl_present_local",
    "acl_present_default",
    "acl_file_perms_read",
    "acl_file_perms_write",
    "acl_file_export",
    "acl_frozen_stanzas",
    "acl_family_headers",
    "acl_objects_total",
    "acl_objects_inheriting",
    "acl_governable",
    "acl_provenance",
    "acl_provenance_error",
    "acl_member",
)

#: Characters kept when a user argument is injected into a pattern. Same allow list as
#: the SPL convention of the repository - `replace(..., "[^A-Za-z0-9_,*-]", "")` - so
#: that the Python side and the SPL side of the same idea cannot diverge (section 7.3).
_ALLOWED_FILTER_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_,*-"
)


# --------------------------------------------------------------------------- #
# Parameters: filters, and the allow list that guards them
# --------------------------------------------------------------------------- #

def sanitize_filter(raw):
    """Drop every character outside the allow list of section 7.3.

    Dropping rather than rejecting is the convention of the repository, and it is the
    conservative choice here: the filter selects what is **shown**, so a mangled pattern
    shows too little, never too much.
    """
    return "".join(char for char in str(raw or "") if char in _ALLOWED_FILTER_CHARS)


def parse_app_filter(raw):
    """`apps` parameter -> tuple of patterns. Empty or absent means `*` (section 7.3)."""
    tokens = tuple(
        token for token in (
            part.strip() for part in sanitize_filter(raw).split(",")
        ) if token
    )
    return tokens or ("*",)


def parse_family_list(raw):
    """`families` parameter -> tuple of family names, possibly empty (section 7.3)."""
    return tuple(
        token for token in (
            part.strip() for part in sanitize_filter(raw).split(",")
        ) if token
    )


def _pattern_matches(name, pattern):
    """`*` is the only metacharacter, and it matches any run of characters.

    Written by hand rather than through `fnmatch`, for one reason that is not stylistic:
    `fnmatch` also honours `?` and `[...]`, which the allow list of section 7.3 does not
    let through - an operator would type a bracket, see it silently deleted, and get a
    filter that does something else than what is on screen.
    """
    if pattern == "*":
        return True
    parts = pattern.split("*")
    if len(parts) == 1:
        return name == pattern
    if not name.startswith(parts[0]):
        return False
    if not name.endswith(parts[-1]):
        return False
    position = len(parts[0])
    for middle in parts[1:-1]:
        if not middle:
            continue
        found = name.find(middle, position)
        if found < 0:
            return False
        position = found + len(middle)
    return position <= len(name) - len(parts[-1])


def app_matches(name, patterns):
    """True if the application name matches at least one pattern of the filter."""
    return any(_pattern_matches(str(name or ""), pattern) for pattern in patterns)


# --------------------------------------------------------------------------- #
# Platform reads
# --------------------------------------------------------------------------- #

def _entries(response):
    """`entry` list of a JSON REST answer, `[]` on any failure.

    A failed read is never an exception towards the caller: the inventory is an aid to
    decision, and losing one column of one row must not cost the whole table. What the
    operator sees instead is an empty cell, which is exactly what an empty cell means
    everywhere else in this output.
    """
    if response is None or not getattr(response, "ok", False):
        return []
    try:
        document = json.loads(response.body.decode("utf-8", "replace"))
    except (ValueError, AttributeError, TypeError):
        return []
    entries = document.get("entry")
    return entries if isinstance(entries, list) else []


def list_applications(rest):
    """Names of the applications, from `GET /services/apps/local` (section 7.3).

    **This list is also the read perimeter** (section 6.2, bound 4): the `.meta` files
    read are those of the applications this call returns, and of no others.
    """
    response = rest.get_json(APPS_PATH, {"count": "0", "f": "title"})
    names = []
    for entry in _entries(response):
        name = str(entry.get("name") or "").strip()
        if name:
            names.append(name)
    return names


def resolve_member(rest):
    """Name of the execution member (section 6.3), or the empty string.

    Never from `SPLUNK_SERVER_NAME` of the environment: **named trap** of HY-4, that
    variable carries the name of the systemd service, not the `serverName` of the
    instance. A value that is plausible and false is worse here than no value at all,
    because the whole point of the column is to compare two members.
    """
    for entry in _entries(rest.get_json(SERVER_INFO_PATH)):
        content = entry.get("content")
        if isinstance(content, dict):
            name = str(content.get(SERVER_NAME_KEY) or "").strip()
            if name:
                return name
    return ""


def read_effective_state(rest, endpoint):
    """Effective ACL of one target, read through REST (section 7.4).

    `None` when the read failed, which the row turns into three empty cells. The
    provenance columns stay meaningful in that case, and they are the ones that carry the
    decision.
    """
    if not endpoint:
        return None
    for entry in _entries(rest.get_app_acl(endpoint)):
        return parse_app_acl_state(entry.get("acl"))
    return None


# --------------------------------------------------------------------------- #
# Literal values of a stanza (section 6.4)
# --------------------------------------------------------------------------- #

def split_access(literal):
    """`access = read : [ a, b ], write : [ c ]` -> `("a, b", "c")`, literally.

    The two values are returned **as the file spells them**, whitespace normalized and
    nothing else: they are the provenance columns, not the effective ones, and
    reformatting them would blur the very comparison they exist to allow - what the file
    says next to what splunkd serves.

    Total, like every reader of section 6.4: an absent key, a missing bracket, an
    unexpected order all yield empty strings rather than an exception.
    """
    text = str((literal or {}).get(META_ACCESS_KEY) or "")
    found = {}
    for chunk in _split_top_level(text):
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        key = key.strip().lower()
        if key in ("read", "write"):
            found[key] = _strip_brackets(value)
    return found.get("read", ""), found.get("write", "")


def _split_top_level(text):
    """Split on the commas that are **outside** the brackets.

    The role lists are themselves comma-separated, so a naive split would cut
    `read : [ a, b ], write : [ c ]` into four fragments of which none is a clause.
    """
    chunks = []
    current = []
    depth = 0
    for char in text:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            chunks.append("".join(current))
            current = []
            continue
        current.append(char)
    chunks.append("".join(current))
    return chunks


def _strip_brackets(value):
    text = str(value).strip()
    if text.startswith("["):
        text = text[1:]
    if text.endswith("]"):
        text = text[:-1]
    return " ".join(text.split())


def export_of(literal):
    """Literal `export` key of the stanza, empty when absent."""
    return str((literal or {}).get(META_EXPORT_KEY) or "").strip()


# --------------------------------------------------------------------------- #
# Governability - a derivation, never an appreciation
# --------------------------------------------------------------------------- #

def governable_of(stanza_kind, provenance_available, frozen_stanzas, family_headers):
    """`acl_governable` (section 7.4), recomputable from the other columns.

    Its definition is closed, and deliberately blunt:

        family_default   yes if no object of the family carries its own stanza
        app_default      yes if the application carries neither a family header nor a
                         single object stanza - that is, if nothing yet stands between
                         `[]` and the objects
        both             unknown as soon as the provenance could not be read: a file
                         nobody could open supports no conclusion, and `partial` would
                         be one

    `partial` is the honest word: it says some objects escape the generic stanza, and it
    does not pretend to say how many matter.
    """
    if not provenance_available:
        return GOVERNABLE_UNKNOWN
    if stanza_kind == STANZA_KIND_APP:
        if int(frozen_stanzas or 0) == 0 and int(family_headers or 0) == 0:
            return GOVERNABLE_YES
        return GOVERNABLE_PARTIAL
    return GOVERNABLE_YES if int(frozen_stanzas or 0) == 0 else GOVERNABLE_PARTIAL


# --------------------------------------------------------------------------- #
# Row production
# --------------------------------------------------------------------------- #

def families_to_emit(provenance, requested):
    """Which `family_default` rows an application produces (section 7.5).

    A family is emitted when **at least one** of the three conditions is met:

    1. its header exists in `local.meta` or in `default.meta`;
    2. at least one `[<family>/<object>]` stanza of that family exists in either;
    3. it is named in the `families` parameter.

    Condition 3 is what makes exhaustiveness available **on demand** - *what would happen
    if I governed `[savedsearches]` on this app?* - without emitting nineteen mostly empty
    rows per application, whose proportion of blank cells would hide the information.

    Conditions 1 and 2 come from the **file**, so a family the shipped table does not know
    still shows up: it is reported with an empty `acl_handler` and
    `acl_write_path = "unmapped"` (section 6.4), which is a fact about the tool rather
    than about the platform.
    """
    names = set(str(name) for name in requested if str(name))
    for meta in (provenance.local, provenance.default):
        for stanza in meta.stanzas:
            kind = classify_stanza(stanza)
            if kind == STANZA_KIND_APP:
                continue
            family = family_of(stanza)
            if family:
                names.add(family)
    return tuple(sorted(names))


class InventoryBuilder(object):
    """Builds the inventory rows. Knows the SDK not at all, and the network only
    through the REST port.

    Everything that costs a REST call is behind a flag or memoized: the columns carrying
    the decision - presence of a stanza, number of frozen ones - are read from **one
    file**, and the object enumeration costs one call per (application, family), which is
    why `count_objects` defaults to false (section 7.3).
    """

    def __init__(self, rest, provenance_reader, table=None, impact=None, member=""):
        self._rest = rest
        self._provenance = provenance_reader
        self._table = table if table is not None else FamilyTable({})
        self._impact = impact
        self._member = str(member or "")

    # -- one row ------------------------------------------------------------ #

    def _base_row(self, app, stanza_kind, stanza, handler):
        endpoint = ""
        if stanza_kind == STANZA_KIND_APP:
            endpoint = build_app_default_path(app)
        elif handler:
            endpoint = build_family_default_path(app, handler)

        effective = read_effective_state(self._rest, endpoint) if endpoint else None
        state = effective if effective is not None else AppAclState()
        return {
            "eai:acl.app": app,
            "acl_stanza_kind": stanza_kind,
            "acl_stanza": stanza,
            "acl_handler": handler,
            "acl_write_path": (
                WRITE_PATH_MAPPED
                if (stanza_kind == STANZA_KIND_APP or handler)
                else WRITE_PATH_UNMAPPED
            ),
            "eai:acl.perms.read": serialize_roles(state.perms_read),
            "eai:acl.perms.write": serialize_roles(state.perms_write),
            "eai:acl.sharing": state.sharing,
            "acl_member": self._member,
        }

    def _object_counts(self, app, stanza_kind, family, handler, count_objects):
        """`(total, inheriting)` as strings, both empty when they were not computed.

        Empty and **not zero**: zero is an answer - the family is empty in this
        application - and confusing the two would let a column nobody computed pass for a
        family nobody uses.
        """
        if not count_objects or self._impact is None:
            return "", ""
        if stanza_kind == STANZA_KIND_APP:
            total, inheriting = self._impact.app_default_counts(app)
            return total, inheriting
        if not handler:
            return "", ""
        return (
            self._impact.shared_object_count(app, handler),
            self._impact.inheriting_count(app, family, handler),
        )

    def app_default_row(self, app, provenance, count_objects=False):
        """The `app_default` row, emitted **unconditionally** for every application
        retained by the filter (section 7.5).

        `acl_frozen_stanzas` counts the object stanzas of the **whole application** here,
        not those of a family: that is what makes the `app_default` line of the
        `acl_governable` table recomputable from the columns of its own row.
        """
        row = self._base_row(app, STANZA_KIND_APP, "", "")
        literal = provenance.literal("")
        read_literal, write_literal = split_access(literal)
        frozen = provenance.frozen_count()
        headers = provenance.family_header_count()
        total, inheriting = self._object_counts(
            app, STANZA_KIND_APP, "", "", count_objects
        )
        row.update({
            "acl_present_local": _boolean(provenance.present_local("")),
            "acl_present_default": _boolean(provenance.present_default("")),
            "acl_file_perms_read": read_literal,
            "acl_file_perms_write": write_literal,
            "acl_file_export": export_of(literal),
            "acl_frozen_stanzas": frozen,
            "acl_family_headers": headers,
            "acl_objects_total": total,
            "acl_objects_inheriting": inheriting,
            "acl_governable": governable_of(
                STANZA_KIND_APP, provenance.available, frozen, headers
            ),
            "acl_provenance": provenance.provenance_of(""),
            "acl_provenance_error": provenance.error,
        })
        return row

    def family_row(self, app, family, provenance, count_objects=False):
        """One `family_default` row.

        `acl_family_headers` stays **empty** here: section 7.4 confines it to the
        `app_default` line, and repeating an application-wide figure on every family row
        would invite a `stats sum()` that counts it once per family.
        """
        handler = self._table.resolve(family) or ""
        row = self._base_row(app, STANZA_KIND_FAMILY, family, handler)
        literal = provenance.literal(family)
        read_literal, write_literal = split_access(literal)
        frozen = provenance.frozen_count(family)
        total, inheriting = self._object_counts(
            app, STANZA_KIND_FAMILY, family, handler, count_objects
        )
        row.update({
            "acl_present_local": _boolean(provenance.present_local(family)),
            "acl_present_default": _boolean(provenance.present_default(family)),
            "acl_file_perms_read": read_literal,
            "acl_file_perms_write": write_literal,
            "acl_file_export": export_of(literal),
            "acl_frozen_stanzas": frozen,
            "acl_family_headers": "",
            "acl_objects_total": total,
            "acl_objects_inheriting": inheriting,
            "acl_governable": governable_of(
                STANZA_KIND_FAMILY, provenance.available, frozen, 0
            ),
            "acl_provenance": provenance.provenance_of(family),
            "acl_provenance_error": provenance.error,
        })
        return row

    # -- the run ------------------------------------------------------------ #

    def rows(self, params, applications=None):
        """Every row of the run, application by application, in a stable order.

        The order is not decorative: an inventory is read as a table and compared with
        the one from another member (section 6.3), and two runs that ordered their rows
        by whatever the platform returned would diverge for no reason at all.
        """
        names = applications
        if names is None:
            names = list_applications(self._rest)
        for app in sorted(str(name) for name in names):
            if not app_matches(app, params.apps):
                continue
            provenance = self._provenance.provenance_of_app(app)
            yield self.app_default_row(app, provenance, params.count_objects)
            for family in families_to_emit(provenance, params.families):
                yield self.family_row(app, family, provenance, params.count_objects)


def _boolean(value):
    """`true` / `false`, as a string.

    The output of a search command is text: a Python `True` would reach SPL as the string
    `True`, capital included, and every comparison an operator writes uses the lower-case
    form the platform itself emits.
    """
    return "true" if value else "false"
