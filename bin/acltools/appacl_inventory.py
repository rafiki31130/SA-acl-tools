"""Inventory of the application-level ACL stanzas (v4.5 section 7).

**What this command exists to answer** (section 7.1): *is this application still governed
by its generic stanzas, or already frozen object by object?*

That question has **no REST answer**. Measured (Q0-4): an object that inherits and an
object carrying its own stanza of the same value return a **strictly identical** ACL
block, and six alternative REST sources were probed, six negative. The answer comes from
the file, and only from the file - which is why `appaclinventory` is a **command** and not
a macro, an SPL macro being unable to read one (section 6.1).

**The output is organised in four named levels, and no column mixes two of them.** That is
the correction of the v4.5 revision, made after the command was first opened in the
interface: the columns had been side by side with nothing separating them, and that is
where the two most serious findings came from.

    identification   which stanza this row describes, and why it is here
    platform         what splunkd applies right now          eai:acl.*
    file             what the .meta carries, literally       acl_file_*
    decision         what stands between this stanza and the objects

**One rule governs the whole table, and v4.7 completes it: no column is ever empty without
another saying why - nor without something saying whether that emptiness is an absence or
an empty set.** `acl_effective_status` explains the three platform columns; the three
`acl_file_*` columns say their own absence with the `(absent)` token, so an empty cell
there means one thing only, *the key is written and carries no value*; `acl_file_read` says
when the file-level values are suspect; and an empty `acl_handler` has **one definition and
only one** - the family is not in the table shipped with the tool. Writing there remains
possible through an explicit handler (section 8.3).

`acl_reach` is **a derivation, not an appreciation** (section 7.4): each of its values
recomputes from the columns beside it, so an operator who distrusts the verdict can redo
the arithmetic in SPL. A figure whose provenance cannot be retraced is a figure nobody can
contest.
"""

import json

from .appacl_family import FamilyTable
from .appacl_merge import parse_app_acl_state
from .appacl_model import (
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    AppAclState,
)
from .appacl_provenance import (
    FILE_READ_OK,
    LAYER_LOCAL,
    LAYER_NOWHERE,
    META_ACCESS_KEY,
    META_EXPORT_KEY,
    classify_stanza,
    family_of,
)
from .appacl_target import build_app_default_path, build_family_default_path
from .normalize import serialize_roles

#: How a stanza is written **in the output**: as it is written in the file, **brackets
#: included, everywhere**. The v4.5 output quoted the file for `[]` and dropped the
#: brackets for `commands`, which the reading trial flagged as an inconsistency - the same
#: column citing the file in two different registers.
#:
#: `editappacl` strips the brackets before resolving a family (section 8.3), so chaining
#: without parameters keeps working.
APP_STANZA_LABEL = "[]"


def stanza_label(name):
    """The stanza as the file writes it: `[]`, `[views]`, `[commands]`."""
    return "[%s]" % (name or "")


#: Closed domain of `acl_write_effect` (v4.6 section 7.4) - **what a write would do to this
#: target, and whether it could be undone.**
#:
#: The most important correction of v4.6. The inventory exists to decide **before** writing,
#: and it did not say whether the write would be reversible. The independent reader deduced
#: it - **without certainty** - from the fact that all eight stanzas of the inventoried
#: application live in the `default` layer, which makes every write there a creation.
#:
#: **The predicate is exactly the one of section 9.2** - the `access` key in `local.meta` -
#: applied to reading instead of writing. It is not reimplemented here: it comes from
#: `AppProvenance.perms_source`, which calls the same `materializes_permissions` the write
#: command calls through `materialized_local`.
#:
#: **Two values, and the domain is exhaustive** (v4.7): every target falls into one or the
#: other, on **every** row. The v4.6 third value `no_route` is withdrawn, and it was a
#: design defect rather than a wording one. It monopolized the column: on a family outside
#: the shipped table, this column spoke of the **route** and said nothing of
#: reversibility - while the route is not closed at all (section 8.3, deliberate since
#: v4.3: an explicit `acl_handler` addresses any handler). An operator taking that door on
#: an out-of-table family **created an irreversible stanza with no warning from the
#: table** - exactly the hole this column exists to close, reopened by the column itself on
#: the rows where the tool guides least.
#:
#: Reachability and reversibility are two questions, and one column carries one. The route
#: is said by `acl_handler` - empty or not, with a single definition - and its consequence
#: for reading by `acl_effective_status`.
WRITE_EFFECT_OVERWRITE = "overwrite_reversible"
WRITE_EFFECT_CREATE = "create_irreversible"

#: The token the three `acl_file_*` columns publish when **the key is not written** (v4.7
#: section 7.4).
#:
#: The v4.6 arrangement made `acl_perms_source` carry the *absence / empty set* distinction
#: for the permissions. It worked there and **left the scope unanswered**: an empty
#: `acl_file_export` stayed undecidable, which the second reading trial raised. Rather than
#: adding a second source column for `export`, the three file columns **say the absence
#: themselves**. A column that answers alone beats a pair that has to be interpreted, and
#: this removes a rule instead of adding one.
#:
#: The token cannot be confused with a real value: neither a role name nor a platform
#: `export` value is written between parentheses. An empty cell in those three columns
#: therefore means **one thing only** - the key is written and carries no value.
FILE_VALUE_ABSENT = "(absent)"

#: Closed domain of `acl_row_reason` (section 7.4) - *why is this row here?*
#:
#: A row emitted because of an object stanza used to describe an **absent** header on three
#: columns and name nowhere the stanza that had triggered it. That was the puzzle which
#: opened the revision of the output contract.
ROW_REASON_APP = "app_row"
ROW_REASON_STANZA = "stanza_exists"
ROW_REASON_OBJECTS = "objects_exist"
ROW_REASON_REQUESTED = "requested"

#: Closed domain of `acl_effective_status` (section 7.4): were the three platform columns
#: read, **and if not why**.
#:
#: They used to come out empty for **three indistinguishable causes** - family outside the
#: table, failed call, disabled application - on 26 rows out of 124, that is 21 %. The
#: previous contract forbade adding an error column; that prohibition was withdrawn once a
#: fifth of the rows were mute.
#: **One nature only, since v4.6.** `no_handler` used to live here and said a fact about
#: the **tool** in a column that answers *could the platform be read*. The reading trial
#: classified the column as `guessed` for that single reason. A family the tool cannot
#: reach by name reads as `unreadable`, and `acl_handler` - empty - says which of the two
#: causes it is: **empty** means no route by name, **filled** means the call failed.
EFFECTIVE_OK = "ok"
EFFECTIVE_APP_DISABLED = "app_disabled"
EFFECTIVE_UNREADABLE = "unreadable"

#: Closed domain of `acl_reach` (section 7.4) - **the verdict**.
#:
#: It replaces `acl_governable`, which promised something wider than its definition: a
#: family absent from the output may be perfectly governable, and a family reported `all`
#: may be out of the tool's reach when `acl_handler` is empty. `reach` says what is
#: measured - does this stanza reach every object of its scope.
REACH_ALL = "all"
REACH_PARTIAL = "partial"
REACH_UNKNOWN = "unknown"

#: Value of `acl_member` when the platform would not give its own name (v4.6 section 6.3).
#: The v4.5 fallback was an empty cell plus a README pointing at `splunk_server` - a field
#: **absent from this output**, so the advice could not be followed from the table. A named
#: value can at least be filtered on.
MEMBER_UNKNOWN = "unknown"

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

#: **Declared output field set** (section 7.4, and v3.14 section 5.7, D-33). The SDK
#: writer freezes the stream header on the keys of the **first** record emitted; a field
#: absent from that record disappears from the whole output with no error and no warning.
#: The constraint bites here exactly as it does on a streaming command - more so, in
#: fact, since the first row of an inventory is an `app_default` row, which is the one
#: row whose object count spans the whole application rather than one family.
#:
#: The order is that of the table of section 7.4, and the first seven fields are
#: **exactly** the input contract of `editappacl`: a pipeline built on this command needs
#: no parameter at all.
INVENTORY_OUTPUT_FIELDS = (
    # -- the input contract of `editappacl`, in order (section 7.4) ------------ #
    "eai:acl.app",
    "acl_stanza_kind",
    "acl_stanza",
    "acl_handler",
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    # -- why the columns above may be empty, and why this row exists ----------- #
    "acl_effective_status",
    "acl_row_reason",
    # -- what a write would do to this target, and whether it could be undone -- #
    "acl_write_effect",
    # -- what the file carries, and from which layer --------------------------- #
    "acl_perms_source",
    "acl_file_perms_read",
    "acl_file_perms_write",
    "acl_file_export",
    "acl_file_read",
    # -- what stands between this stanza and the objects, and the verdict ------ #
    "acl_objects_with_own_perms",
    "acl_families_with_own_perms",
    "acl_reach",
    # -- context --------------------------------------------------------------- #
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

    **What is not written comes back as `(absent)`** (v4.7): no `access` key at all, or an
    `access` key with no clause for that side. What is written and carries no role comes
    back **empty**. The two states are opposite everywhere else in this contract - an empty
    permission leaves the object unreachable, an absent stanza makes it inherit - and they
    are the two states that decide `updated` against `created` on a write. A table that
    renders them identically hides the one thing it exists to let an operator decide.

    Total, like every reader of section 6.4: a missing bracket or an unexpected order
    yields the absent token rather than an exception.
    """
    keys = literal or {}
    if META_ACCESS_KEY not in keys:
        return FILE_VALUE_ABSENT, FILE_VALUE_ABSENT
    text = str(keys.get(META_ACCESS_KEY) or "")
    found = {}
    for chunk in _split_top_level(text):
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        key = key.strip().lower()
        if key in ("read", "write"):
            found[key] = _strip_brackets(value)
    return (found.get("read", FILE_VALUE_ABSENT),
            found.get("write", FILE_VALUE_ABSENT))


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
    """Literal `export` key of the stanza, `(absent)` when the key is not written.

    Same rule as `split_access`, and for the same reason: an empty cell here means the key
    is written and carries nothing. The distinction matters on `export` as much as on the
    permissions - the second reading trial could not tell an unexported stanza from a
    stanza with no `export` key at all, and only the first is a decision.
    """
    keys = literal or {}
    if META_EXPORT_KEY not in keys:
        return FILE_VALUE_ABSENT
    return str(keys.get(META_EXPORT_KEY) or "").strip()


# --------------------------------------------------------------------------- #
# Governability - a derivation, never an appreciation
# --------------------------------------------------------------------------- #

def write_effect_of(perms_source):
    """`acl_write_effect` (v4.7 section 7.4) - **what a write would do to this target.**

        overwrite_reversible   the target already carries its permissions in `local.meta`:
                               a write replaces them, and `app_acl_rollback` can undo it
        create_irreversible    a write would MATERIALIZE permissions in `local.meta` where
                               there are none - nothing removes them afterwards, and
                               `editappacl` refuses without `allow_create=true`

    **The predicate is exactly the one of section 9.2**, applied to reading instead of
    writing: `perms_source` comes from `AppProvenance.perms_source`, which calls the same
    `materializes_permissions` the write command calls through `materialized_local`. The
    two commands answer the same question with the same rule, and the inventory stops
    obliging the operator to reconstitute it.

    **The domain is exhaustive and the column answers on every row**, out-of-table families
    included - it takes no argument about the route, and that is the v4.7 correction: the
    row where the tool guides least is the row that most needs to be told a write there
    cannot be undone.
    """
    if perms_source == LAYER_LOCAL:
        return WRITE_EFFECT_OVERWRITE
    return WRITE_EFFECT_CREATE


def reach_of(stanza_kind, file_read, objects_with_own_perms, families_with_own_perms):
    """`acl_reach` (section 7.4) - **the verdict of scope**, recomputable from its
    neighbours.

        family_default   all   no object of the family carries its own permissions
        app_default      all   no object AND no family carries its own permissions
        both             unknown as soon as the metadata could not be read in full

    **The v4.6 rule "no route, therefore `unknown`" is withdrawn** (v4.7): it rested on a
    false premise. It held a family outside the shipped table to be unreachable, while
    section 8.3 has posed since v4.3 that the table bounds **resolution by name**, never
    the write perimeter. Nothing stands between `[searchbnf]` and its objects: `all` is the
    **right** answer, and correcting it made the verdict lie to compensate for another
    column. What v4.6 sought to avoid - an operator sorting on `acl_reach` picking up a
    target he misreads - is handled where it belongs: `acl_write_effect` now says on
    **every** row what a write would do, out-of-table families included.

    The one cause of `unknown` is named by a neighbouring column, `acl_file_read`, as the
    rule of the empty cell requires.
    """
    if str(file_read or "") != FILE_READ_OK:
        return REACH_UNKNOWN
    if int(objects_with_own_perms or 0) > 0:
        return REACH_PARTIAL
    if stanza_kind == STANZA_KIND_APP and int(families_with_own_perms or 0) > 0:
        return REACH_PARTIAL
    return REACH_ALL


def families_to_emit(provenance, requested):
    """Which `family_default` rows an application produces, **and why** (section 7.5).

    Returns `((family, reason), ...)`, sorted. The reason travels with the family rather
    than being recomputed later: two answers to the same question drift, and this one ends
    up in a column an operator reads.

    A family is emitted when **at least one** of three conditions is met, and the reason
    names the first one that is:

    1. `stanza_exists`  - its header exists in `local.meta` or in `default.meta`;
    2. `objects_exist`  - at least one `[<family>/<object>]` stanza of that family
       **exists** in either. **Presence, not freezing**: a family whose objects were merely
       edited stays emitted, with `acl_objects_with_own_perms = 0` and `acl_reach = all`.
       Restricting this to the freeze predicate would hide from the operator families that
       do exist - the condition of **emission** and the verdict of **governance** answer two
       different questions;
    3. `requested`      - it is named in the `families` parameter.

    Condition 3 makes exhaustiveness available on demand - *what would happen if I governed
    `[savedsearches]` on this app?* - without emitting nineteen mostly empty rows per
    application, whose proportion of blank cells would hide the information.

    Conditions 1 and 2 come from the **file**, so a family the shipped table does not know
    still shows up: its `acl_handler` is empty, which is a fact about the tool and not
    about the platform, and `acl_write_effect` still says what a write there would do.

    **The measured edge case is instructive**: two `[macros/...]` stanzas written by splunkd
    and carrying only `version` and `modtime` are enough to emit the `macros` family, with
    `acl_objects_with_own_perms = 0` and `acl_reach = all`. The row then says exactly what
    is: this family is here because it carries object stanzas, none of which freezes
    anything.
    """
    asked = set(str(name) for name in requested if str(name))
    headers, objects = set(), set()
    for meta in (provenance.local, provenance.default):
        for stanza in meta.stanzas:
            kind = classify_stanza(stanza)
            if kind == STANZA_KIND_APP:
                continue
            if kind == STANZA_KIND_FAMILY:
                headers.add(stanza)
                continue
            family = family_of(stanza)
            if family:
                objects.add(family)

    reasons = {}
    for family in sorted(headers | objects | asked):
        if family in headers:
            reasons[family] = ROW_REASON_STANZA
        elif family in objects:
            reasons[family] = ROW_REASON_OBJECTS
        else:
            reasons[family] = ROW_REASON_REQUESTED
    return tuple((family, reasons[family]) for family in sorted(reasons))


class InventoryBuilder(object):
    """Builds the inventory rows. Knows the SDK not at all, and the network only through
    the REST port.

    **Nothing here costs a REST call per object.** The columns that carry the decision -
    which stanzas exist, how many objects and families carry their own permissions - are
    read from **two files per application**. The object enumeration that used to feed two
    optional columns was withdrawn in v4.5: measured at **+790 REST calls** and a factor
    **6,4 to 7,3** on 41 applications, for a lower bound with three reservations that came
    out empty by default. The blast-radius question is answered where it engages - the
    simulation of `editappacl`, per target.
    """

    def __init__(self, rest, provenance_reader, table=None, member="",
                 app_disabled_fn=None):
        self._rest = rest
        self._provenance = provenance_reader
        self._table = table if table is not None else FamilyTable({})
        self._member = str(member or "") or MEMBER_UNKNOWN
        #: Consulted **only** when a platform read has already failed, so that the row can
        #: say `app_disabled` instead of the undifferentiated `unreadable`. Memoized by the
        #: caller, and never called on the nominal path.
        self._app_disabled_fn = app_disabled_fn

    # -- one row ------------------------------------------------------------ #

    def _platform_state(self, app, stanza_kind, handler):
        """`(state, acl_effective_status)`.

        **One nature only since v4.6**: this answers *could the platform be read*. With no
        route by name there is nothing to read, so the answer is `unreadable`, and the pair
        with `acl_handler` tells the two causes apart - empty handler, no route; filled
        handler, the call failed.
        """
        if stanza_kind == STANZA_KIND_APP:
            endpoint = build_app_default_path(app)
        elif handler:
            endpoint = build_family_default_path(app, handler)
        else:
            return AppAclState(), EFFECTIVE_UNREADABLE

        state = read_effective_state(self._rest, endpoint)
        if state is not None:
            return state, EFFECTIVE_OK
        if self._app_disabled_fn is not None and self._app_disabled_fn(app):
            return AppAclState(), EFFECTIVE_APP_DISABLED
        return AppAclState(), EFFECTIVE_UNREADABLE

    def _row(self, app, stanza_kind, stanza, handler, reason, provenance, scope):
        """One row, built **in the declared order**.

        The order is not cosmetic and a test freezes it: the SDK writer fixes the stream
        header on the keys of the first record, so the order emitted is the order of this
        dictionary.

        `scope` is the stanza name whose object stanzas count for this row - the family on
        a family row, `None` for an application row, where the count spans the whole
        application.
        """
        state, effective_status = self._platform_state(app, stanza_kind, handler)
        perms_source = provenance.perms_source(stanza)
        read_literal, write_literal = split_access(provenance.access_literal(stanza))
        file_read = provenance.read_status()
        objects = provenance.frozen_count(scope)
        families = provenance.family_header_count()
        write_effect = write_effect_of(perms_source)

        return {
            "eai:acl.app": app,
            "acl_stanza_kind": stanza_kind,
            "acl_stanza": stanza_label("" if stanza_kind == STANZA_KIND_APP else stanza),
            "acl_handler": handler,
            "eai:acl.perms.read": serialize_roles(state.perms_read),
            "eai:acl.perms.write": serialize_roles(state.perms_write),
            "eai:acl.sharing": state.sharing,
            "acl_effective_status": effective_status,
            "acl_row_reason": reason,
            "acl_write_effect": write_effect,
            "acl_perms_source": perms_source,
            "acl_file_perms_read": read_literal,
            "acl_file_perms_write": write_literal,
            "acl_file_export": export_of(provenance.literal_any(stanza)),
            "acl_file_read": file_read,
            "acl_objects_with_own_perms": objects,
            "acl_families_with_own_perms": families,
            "acl_reach": reach_of(stanza_kind, file_read, objects, families),
            "acl_member": self._member,
        }

    def app_default_row(self, app, provenance):
        """The `[]` row, emitted **unconditionally** for every application the filter keeps
        (section 7.5).

        `acl_objects_with_own_perms` counts over the **whole application** here, which is
        what makes the `app_default` line of the `acl_reach` table recomputable from the
        columns of its own row.
        """
        return self._row(app, STANZA_KIND_APP, "", "", ROW_REASON_APP, provenance, None)

    def family_row(self, app, family, provenance, reason=ROW_REASON_STANZA):
        """One family row.

        `acl_families_with_own_perms` is **emitted here too**, and that is a change: it
        carries an **application** fact, so blanking it on family rows created one more
        semantics of emptiness for nothing.
        """
        handler = self._table.resolve(family) or ""
        return self._row(app, STANZA_KIND_FAMILY, family, handler, reason, provenance,
                         family)

    # -- the run ------------------------------------------------------------ #

    def rows(self, params, applications=None):
        """Every row of the run, application by application, in a stable order.

        The order is not decorative: an inventory is read as a table and compared with the
        one from another member (section 6.3), and two runs ordering their rows by whatever
        the platform returned would diverge for no reason at all.
        """
        names = applications
        if names is None:
            names = list_applications(self._rest)
        for app in sorted(str(name) for name in names):
            if not app_matches(app, params.apps):
                continue
            provenance = self._provenance.provenance_of_app(app)
            yield self.app_default_row(app, provenance)
            for family, reason in families_to_emit(provenance, params.families):
                yield self.family_row(app, family, provenance, reason)
