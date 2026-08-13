"""Provenance: reading the `.meta` files (v4.2 section 6).

**This module is the exception to the "API only" rule of the project, and it carries its
own bounds.** The rule aims at writes, because a write is what creates a replication
divergence in a search head cluster; reading creates none. What reading buys, and
nothing else buys, is the **provenance**: measured (Q0-4), an object that inherits and
an object carrying its own stanza of the same value return a **strictly identical** ACL
block, and six alternative REST sources were probed, six negative. Without the file,
`editappacl` cannot tell a modification (reversible) from a creation (irreversible), and
the whole dispositif of section 9 rests on that distinction.

The four bounds of section 6.2, and how each of them is held here:

1. **Read only, and located through the two named routes.** This module exposes no
   write, create, rename or delete function, and it never uses one. The guarantee is
   **mechanical, not declarative**: `tests/test_appacl_provenance.py` reads the syntax
   tree of this file and fails on any of the two forbidden families - the write
   expressions, and the three **misleading localization** expressions of HY-6.
2. **Provenance only.** The file answers two questions, and two only: *does this stanza
   exist in this file?* and *what does it literally hold?* **The effective values come
   from REST, never from here.** This module reimplements neither the layer merge, nor
   inheritance resolution, nor the platform's normalization. That is the bound that
   keeps the exception from becoming a reimplementation of splunkd.
3. **No object enumeration leaves this module.** `[<family>/<object>]` stanzas are
   **counted**, never listed and never emitted: reading the file short-circuits the
   capability filtering REST applies, and a caller without `admin_all_objects` would
   otherwise see object names the API refuses them. No public function of this module
   returns an object name - a test freezes that, and it is the reason the impact
   estimate of `appacl_impact.py` is computed from **counts** rather than from a set
   difference over names.
4. **Limitative file perimeter, root resolved through two named routes.** Only
   `<root>/<app>/metadata/local.meta` and `<root>/<app>/metadata/default.meta` are ever
   opened. Neither `etc/system`, nor `etc/users` - not even the private file the
   namespace trap of section 4.1 produces - nor `etc/slave-apps`, nor
   `etc/deployment-apps`, nor any path built from an input datum.

**The reader is total: it never raises, whatever the input.** A missing file is a valid
and informative result, not an error (measured: a freshly installed app has no
`local.meta`); an unreadable file yields `unavailable` with its error class; a malformed
line is skipped and **counted**.
"""

import os
import re

from .appacl_model import (
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    STANZA_KIND_OBJECT,
)
from .errors import FatalProvenanceRootError

#: Name of the two files read, in the order the layers are consulted. `local` first
#: because it is the layer the command writes; `default` second because a stanza it
#: carries makes the family governed by the application's own packaging.
LOCAL_META = "local.meta"
DEFAULT_META = "default.meta"

#: Directory holding them inside an application.
METADATA_DIR = "metadata"

#: The two path segments the read root must end with, after normalization (bound 4,
#: control 1). Any candidate root that does not is refused, whatever produced it.
APPS_ROOT_SEGMENTS = ("etc", "apps")

#: Environment variable of the **main route** (HY-6, route A). Measured present in the
#: three probed executions - generating command and streaming command, dispatch from the
#: carrying app and from `search` - with an absolute value, independent of the working
#: directory and of the dispatching app. It is already the route `bin/editacl.py` uses to
#: locate its journal.
SPLUNK_HOME_VARIABLE = "SPLUNK_HOME"

#: Number of `dirname` applications that take the **fallback route** (HY-6, route G)
#: from the absolute path of the command module to `etc/apps`:
#: `<...>/etc/apps/<app>/bin/<command>.py` -> `bin` -> `<app>` -> `apps`.
#:
#: It yields `etc/apps` **directly**, without presupposing that `etc` sits under
#: `SPLUNK_HOME` - which is exactly what makes it independent of the main route rather
#: than a derivative of it, and what makes its failure **detectable** (`isdir` false)
#: instead of silent.
FALLBACK_DIRNAME_LEVELS = 3

#: Keys of a `.meta` stanza that **interrupt inheritance**, and the dimension each one
#: interrupts. *Measured* on the lab (remediation of 2026-08-13), at **both** stanza
#: levels - object stanza and family header - by writing the generic and re-reading the
#: effective ACL of witnesses carrying different key sets:
#:
#:     stanza keys                    perms.read  perms.write  sharing
#:     (no stanza at all)             moved       moved        moved
#:     owner / version / modtime      moved       moved        moved
#:     export (no access)             moved       moved        FROZEN
#:     access + export                FROZEN      FROZEN       FROZEN
#:
#: **`access` is the key that freezes the permissions; `export` freezes the scope; the
#: bookkeeping keys freeze nothing.** That is the whole correction of anomaly A-2: splunkd
#: writes a stanza for **every object it creates or edits**, carrying only
#: `owner`/`version`/`modtime`, and treating those as frozen made the impact estimate zero
#: in the nominal case - wrong by 100 %, in the direction that reassures.
META_ACCESS_KEY = "access"
META_EXPORT_KEY = "export"

#: Provenance values (section 7.4), closed domain.
PROVENANCE_LOCAL = "local"
PROVENANCE_DEFAULT = "default"
PROVENANCE_INHERITED = "inherited"
PROVENANCE_UNAVAILABLE = "unavailable"

#: Both path separators, so that the segment control of bound 4 reads a path the same way
#: on either platform. A string substitution would do as well and is deliberately not
#: used: the read-only control of bound 1 refuses every write-looking method name in this
#: module, `replace` among them, and weakening that control to spell a path split would
#: be a bad trade.
_PATH_SEPARATORS = re.compile(r"[\\/]+")


# --------------------------------------------------------------------------- #
# Root resolution - bound 4 of section 6.2
# --------------------------------------------------------------------------- #

def _normalized(path):
    """Comparable form of a path: absolute, normalized, case-folded where it matters."""
    return os.path.normcase(os.path.normpath(os.path.abspath(str(path))))


def _looks_like_apps_root(path):
    """Control 1: the resolved path ends on an `etc/apps` segment sequence.

    The check is on the **segments**, not on a substring: a directory named
    `my_etc_apps` is not an `etc/apps`, and a substring test would accept it.
    """
    if not path:
        return False
    segments = [
        segment for segment in _PATH_SEPARATORS.split(_normalized(path)) if segment
    ]
    tail = tuple(segment.lower() for segment in segments[-len(APPS_ROOT_SEGMENTS):])
    return tail == APPS_ROOT_SEGMENTS


def root_from_environment(environ):
    """Main route: `SPLUNK_HOME` then `etc/apps`. `None` when the variable is absent."""
    home = (environ or {}).get(SPLUNK_HOME_VARIABLE)
    if not str(home or "").strip():
        return None
    return os.path.join(str(home).strip(), *APPS_ROOT_SEGMENTS)


def root_from_command_file(command_file):
    """Fallback route: `dirname` applied three times to the command module's path.

    The argument is the `__file__` of the **command module** - the adapter passes its
    own - and never a path this module goes looking for. That is what keeps the three
    misleading routes of HY-6 out of reach here: the working directory is the `bin/` of
    the carrying app, the SDK's `splunk_home` silently falls back on that same working
    directory when the variable is missing, and `searchinfo.app` names the
    **dispatching** app rather than the carrying one.
    """
    if not str(command_file or "").strip():
        return None
    path = os.path.abspath(str(command_file))
    for _ in range(FALLBACK_DIRNAME_LEVELS):
        path = os.path.dirname(path)
    return path or None


def resolve_apps_root(environ=None, command_file=None, isdir=None):
    """Resolve the read root, or raise `FatalProvenanceRootError` (section 13.1).

    The three controls of bound 4, **in this order**:

    1. a candidate whose normalized path does not end on `etc/apps` is refused, and
       therefore does not take part in the comparison;
    2. the two routes are computed and **compared**. A divergence is fatal: an ambiguous
       root would make the command read a tree other than the one the platform serves,
       and nothing would signal it;
    3. if neither route yields an **existing** `etc/apps`, it is fatal.

    `isdir` is injectable so the resolution can be exercised without a Splunk tree; it
    defaults to `os.path.isdir`.
    """
    exists = isdir or os.path.isdir

    candidates = []
    for label, raw in (
        ("SPLUNK_HOME", root_from_environment(environ)),
        ("command file", root_from_command_file(command_file)),
    ):
        if raw and _looks_like_apps_root(raw):                            # control 1
            candidates.append((label, os.path.normpath(raw)))

    if len(candidates) == 2:                                              # control 2
        first, second = candidates
        if _normalized(first[1]) != _normalized(second[1]):
            raise FatalProvenanceRootError(
                "ambiguous read root: %s yields %s while %s yields %s. Refusing rather "
                "than reading a tree other than the one splunkd serves."
                % (first[0], first[1], second[0], second[1])
            )

    for _label, candidate in candidates:                                  # control 3
        if exists(candidate):
            return candidate

    raise FatalProvenanceRootError(
        "read root not resolved: neither SPLUNK_HOME nor the command module's own path "
        "yields an existing etc/apps directory (candidates: %s)."
        % (", ".join(c for _l, c in candidates) or "none")
    )


def is_safe_app_segment(app):
    """True if `app` may be used as a single directory segment of the read path.

    Bound 4 forbids any path built from an input datum. The application name **is** an
    input datum, so it is validated rather than trusted: no separator, no `.` or `..`,
    no null byte, nothing empty.
    """
    name = str(app or "").strip()
    if not name or name in (os.curdir, os.pardir):
        return False
    if "\x00" in name:
        return False
    return not any(sep and sep in name for sep in (os.sep, os.altsep, "/", "\\"))


def meta_path(root, app, basename):
    """Path of one `.meta` file, or `None` when it would leave the perimeter.

    Two guards rather than one: the segment is validated on its own, and the resulting
    path is then checked to still start with the root after normalization. The second
    catches whatever the first would not have foreseen.
    """
    if not root or not is_safe_app_segment(app) or basename not in (
        LOCAL_META, DEFAULT_META
    ):
        return None
    candidate = os.path.join(str(root), str(app).strip(), METADATA_DIR, basename)
    normalized_root = _normalized(root)
    if not _normalized(candidate).startswith(normalized_root + os.sep):
        return None
    return candidate


# --------------------------------------------------------------------------- #
# Reading one file - section 6.4
# --------------------------------------------------------------------------- #

def classify_stanza(name):
    """Classify a stanza name (section 6.4), the only interpretation the reader allows.

        ""                  -> app_default      the `[]` stanza
        "views"             -> family_default   a family header
        "views/my_view"     -> object_specific  counted, never listed

    The empty name is a **legitimate** value and not a defect: `[]` has no name.
    """
    text = "" if name is None else str(name).strip()
    if not text:
        return STANZA_KIND_APP
    if "/" in text:
        return STANZA_KIND_OBJECT
    return STANZA_KIND_FAMILY


def materializes_permissions(keys):
    """True if this stanza's keys **carry the permissions**, rather than inherit them.

    The single predicate of the whole package for the question *does this stanza take its
    object, or its family, out of the reach of the generic one above it?* It is used at
    both levels - `[<family>/<object>]` and `[<family>]` - because the measurement gave
    the same answer at both, which is what makes one function enough.

    **Presence of the stanza is not the question, and that was the defect.** A stanza
    carrying only `owner`, `version` and `modtime` is what splunkd writes for every object
    it creates or edits; such an object keeps inheriting its permissions in full. Counting
    it as frozen made the impact estimate collapse to zero on any application whose objects
    had ever been touched - that is, on any real application.

    `export` is deliberately **not** part of the predicate. It freezes the **scope**, not
    the permissions: an object whose stanza carries `export` without `access` still has its
    permissions moved by a generic write, so it must stay **inside** the count. The
    consequence is stated where it belongs - the estimate may overstate what the scope
    dimension of a write reaches - and overstating is the safe direction for a volume
    guard rail.

    `keys` is any iterable of key names, so a stanza mapping can be passed as it stands.
    """
    return META_ACCESS_KEY in set(keys or ())


def family_of(name):
    """Family a stanza belongs to: itself for a header, its prefix for an object.

    `""` for the `[]` stanza, which belongs to no family. A name with several slashes -
    which the platform does not produce, and which the reader still has to survive -
    keeps its **first** segment: it is the only one that could be a family.
    """
    text = "" if name is None else str(name).strip()
    if not text:
        return ""
    return text.split("/", 1)[0]


class MetaFile(object):
    """One parsed `.meta` file. Never raises, whatever the file holds.

    `present` says the file was read. `error` is empty when it was, and carries an error
    **class** - never a system message, which could disclose a path - when it was not.
    """

    __slots__ = ("path", "present", "stanzas", "error", "skipped")

    def __init__(self, path="", present=False, stanzas=None, error="", skipped=0):
        self.path = path
        self.present = present
        self.stanzas = stanzas or {}
        self.error = error
        self.skipped = int(skipped)

    def has(self, name):
        return str(name or "") in self.stanzas

    def get(self, name):
        return dict(self.stanzas.get(str(name or ""), {}))


def parse_meta(text):
    """Parse the content of a `.meta` file. Returns `(stanzas, skipped)`.

    The shape is the one measured in Q0-1, Q0-2 and Q0-3::

        []
        access = read : [ power ], write : [ admin ]
        export = none

        [views]
        access = read : [ power ], write : [ power ]
        export = none
        version = 9.4.6

    Robustness clauses of section 6.4, all of them applied here: a malformed line or an
    unknown key is **skipped and counted**, and parsing carries on; a stanza whose name
    matches no expected shape is reported as it stands, which
    `classify_stanza` handles on its own; a duplicated stanza has its keys merged, the
    last one winning, which is what splunkd does with a repeated stanza.

    A line before any stanza header is skipped and counted: it belongs to no stanza, and
    attaching it to `[]` would invent a value the file does not carry.
    """
    stanzas = {}
    skipped = 0
    current = None
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            stanzas.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            skipped += 1
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            skipped += 1
            continue
        stanzas[current][key] = value.strip()
    return stanzas, skipped


def read_meta_file(path, opener=None):
    """Read and parse one `.meta` file. **Never raises.**

    Encoding: UTF-8 with substitution of invalid bytes (HY-5 - the platform is assumed
    to write these files in UTF-8, and the fallback **is** the nominal behavior, so an
    invalidated hypothesis costs nothing here).

    `opener` is injectable for the tests, which exercise the failure classes - permission
    denied, I/O error - without having to produce them on a real file system.
    """
    if not path:
        return MetaFile(path="", present=False, error="no_path")
    read = opener or _default_opener
    try:
        text = read(path)
    except FileNotFoundError:
        # Not an error: an application that was never given per-application permissions
        # has no `local.meta` at all (measured, Q0-1). The caller reads
        # `present = False`, which is a fact and not a failure.
        return MetaFile(path=path, present=False, error="")
    except (IOError, OSError, ValueError) as exc:
        return MetaFile(path=path, present=False, error=type(exc).__name__)
    stanzas, skipped = parse_meta(text)
    return MetaFile(path=path, present=True, stanzas=stanzas, skipped=skipped)


def _default_opener(path):
    """Open in **read** mode and return the whole text. The only file access here.

    Concentrating it in one function is what makes bound 1 checkable by reading the
    syntax tree: there is exactly one `open()` in this module, its mode is a literal
    `"r"`, and no other file primitive appears anywhere.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


# --------------------------------------------------------------------------- #
# Per-application provenance
# --------------------------------------------------------------------------- #

class AppProvenance(object):
    """Provenance of the generic stanzas of one application.

    It answers the two questions of bound 2, and **only** counts about the third:

        present_local(stanza)    does the stanza exist in `local.meta`?
        provenance_of(stanza)    local | default | inherited | unavailable
        literal(stanza)          what the `local.meta` stanza literally holds
        frozen_count(family)     how many `[<family>/<object>]` stanzas exist
        family_header_count()    how many family headers the application carries

    **No method returns an object name.** That is bound 3, and it is what the impact
    estimate of `appacl_impact.py` is built around.
    """

    def __init__(self, app, local, default):
        self.app = str(app or "")
        self.local = local or MetaFile()
        self.default = default or MetaFile()

    # -- availability ------------------------------------------------------- #

    @property
    def available(self):
        """False only when **neither** file could be read.

        A missing file is not an unavailability: it is the measured shape of an
        application that carries no local metadata. What makes provenance unavailable is
        an I/O failure, a permission denial, a lock - something that leaves the question
        unanswered rather than answering it negatively.
        """
        return not (self.local.error or self.default.error)

    @property
    def error(self):
        """Reason of `unavailable`, or the `parse_skipped:<n>` report (section 6.4)."""
        for meta in (self.local, self.default):
            if meta.error:
                return meta.error
        skipped = self.local.skipped + self.default.skipped
        return "parse_skipped:%d" % skipped if skipped else ""

    # -- presence and provenance -------------------------------------------- #

    def present_local(self, stanza):
        """Does the stanza **exist** in `local.meta`? (section 7.4, `acl_present_local`)

        Presence, and presence only. It is **not** the predicate that decides whether the
        stanza governs anything - `materialized_local` is - and the two were conflated
        before the remediation of 2026-08-13.
        """
        return self.local.has(stanza)

    def present_default(self, stanza):
        return self.default.has(stanza)

    def materialized_local(self, stanza):
        """Does the stanza carry the **permissions** in `local.meta`?

        The question `editappacl` has to answer before writing, and the one that decides
        whether the write is reversible. A stanza that exists without an `access` line does
        not carry the permissions: writing them **materializes** them, which masks the
        inherited value and cannot be undone - no measured REST path removes a key from a
        stanza any more than it removes the stanza itself.

        Reporting such a write as a reversible modification would promise a restore that
        `app_acl_rollback` cannot deliver: replaying the prior effective values would write
        an `access` line where there was none, freezing the family instead of restoring it.
        That is the failure class of the 515 objects, one level down.
        """
        return materializes_permissions(self.local.get(stanza))

    def provenance_of(self, stanza):
        """Where the effective value comes from (section 7.4), closed domain.

        `unavailable` emits **no** provenance conclusion: the files could not be read, so
        neither `inherited` nor anything else may be asserted.
        """
        if not self.available:
            return PROVENANCE_UNAVAILABLE
        if self.present_local(stanza):
            return PROVENANCE_LOCAL
        if self.present_default(stanza):
            return PROVENANCE_DEFAULT
        return PROVENANCE_INHERITED

    def literal(self, stanza):
        """Literal keys of the stanza in `local.meta`, empty dict when absent."""
        return self.local.get(stanza)

    # -- counts, and counts only (bound 3) ---------------------------------- #

    def _object_stanza_names(self, family=None):
        """Set of the `[<family>/<object>]` stanzas that **freeze** their object,
        **private to this class**.

        Two filters, and the second one is the correction of A-2:

        1. the name must be an object name - `classify_stanza`;
        2. the stanza must **materialize the permissions** - carry an `access` key. A
           stanza carrying only `owner`, `version` and `modtime` is what splunkd writes
           for every object it touches, and such an object still inherits.

        The union of the two files is taken rather than their sum: HY-2 establishes that
        specificity wins between layers, so an object frozen in either file is one frozen
        object and not two. **A stanza that freezes in `default.meta` counts even when its
        `local.meta` twin carries only bookkeeping keys** - the freezing layer wins.

        The set never leaves the instance, and no public method returns it: that is
        bound 3 of section 6.2, held by a test.
        """
        names = set()
        for meta in (self.local, self.default):
            for name, keys in meta.stanzas.items():
                if classify_stanza(name) != STANZA_KIND_OBJECT:
                    continue
                if family is not None and family_of(name) != str(family or ""):
                    continue
                if not materializes_permissions(keys):
                    continue
                names.add(name)
        return names

    def frozen_count(self, family=None):
        """Number of distinct objects whose stanza **carries the permissions**.

        With no argument, over the whole application. This is the figure the impact
        estimate subtracts and the one `acl_frozen_stanzas` publishes; before the
        remediation it counted every object stanza, frozen or not, and collapsed the
        estimate to zero on any application whose objects had been edited.
        """
        return len(self._object_stanza_names(family))

    def has_family_header(self, family):
        """True if `[<family>]` **governs** the family in either file.

        Same predicate one level up, and the measurement gave the same answer there: a
        `[savedsearches]` header carrying only `export`, `version` and `modtime` does
        **not** interrupt the inheritance of the permissions from `[]` - the witness
        object followed `[]` across a change. So a header that does not materialize the
        permissions leaves its family inside the blast radius of the application default.
        """
        name = str(family or "")
        if not name:
            return False
        return any(
            materializes_permissions(meta.get(name))
            for meta in (self.local, self.default)
            if meta.has(name)
        )

    def family_header_count(self):
        """Number of distinct family headers that **govern** their family.

        It feeds the `app_default` line of `acl_governable`, whose `yes` asks that nothing
        stand between `[]` and the objects. A header that materializes nothing stands in
        the way of nothing.
        """
        names = set()
        for meta in (self.local, self.default):
            for name, keys in meta.stanzas.items():
                if classify_stanza(name) != STANZA_KIND_FAMILY:
                    continue
                if not materializes_permissions(keys):
                    continue
                names.add(name)
        return len(names)


class ProvenanceReader(object):
    """Reads and **memoizes** the provenance of each application of the run.

    Memoization is per application and lasts **until `refresh()` is called**, which is the
    whole of the contract this class offers.

    **Who calls it, and who does not, is a decision of the caller and not of this class.**
    `editappacl` refreshes before every target: it writes between rows, and section 13.4
    point 7 allows carrying only the object enumeration from one row to the next.
    `app_acl_inventory` does not refresh: it writes nothing, so no row can invalidate the
    read of another, and re-reading the same two files once per emitted row would buy
    nothing at all.

    Before the remediation of 2026-08-13 nobody called `refresh()` and two comments in the
    package asserted that the provenance was re-read for every target. The behaviour was
    corrected rather than the comments, because the clause is normative.
    """

    def __init__(self, root, opener=None):
        self.root = root
        self._opener = opener
        self._cache = {}

    def refresh(self, app):
        """Drop the memoized provenance of one application."""
        self._cache.pop(str(app or ""), None)

    def provenance_of_app(self, app):
        key = str(app or "")
        if key not in self._cache:
            self._cache[key] = AppProvenance(
                key,
                read_meta_file(meta_path(self.root, key, LOCAL_META), self._opener),
                read_meta_file(meta_path(self.root, key, DEFAULT_META), self._opener),
            )
        return self._cache[key]
