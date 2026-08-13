"""The `acl_status` enumeration is **derived from the code**, never copied out
(section 5.7, section 8.2).

Four successive writings of this list were wrong: three in the specification, then one
in the test suite to which D-35 had entrusted it - `DOUZE_STATUTS` announced twelve
values and carried eleven, `skipped_derived` missing. The flaw is not forgetfulness: it
is that a hand-written enumeration has **no mechanical link** with what the code
produces, and therefore drifts at every evolution.

This module establishes that link. It extracts from the syntax tree of the core every
literal status actually produced, and requires equality with
`acltools.model.ACL_STATUSES`. Combined with invariant 1 of section 8.2 - which requires
observing each of those values on a real case - it attacks the error class from both
ends:

- a status added to the code and absent from `ACL_STATUSES` -> this module fails;
- a status added to `ACL_STATUSES` with no test case -> invariant 1 fails.

**What the first version of this module missed, and why the fix lands somewhere other
than expected.** The extractor recognized two written forms and **ignored everything
else**. A status passed as a keyword argument (`EventRejected(status=...)`) or by
indirection (`work.status = _CONSTANT`) entered the core unseen, and the suite stayed
green - measured at the closing audit, two stealth statuses, `501 passed`. Adding those
two forms to the extractor would have reproduced the flaw one notch further out: the
next form, unforeseen, would have escaped in its turn, silently.

The fix is therefore a **reversal of the default**. The extractor no longer classifies
"what it recognizes" against "the rest": it classifies **every** construct that touches
a status into three exhaustive categories -

1. **canonical**: the status is a literal, it gets collected
   (`EventRejected("<status>", ...)`, `<obj>.status = "<status>"`);
2. **recognized propagation**: the value is a status born elsewhere, already collected
   at its birth - a **parameter** named `status` of the enclosing function, or an
   expression `<...>.status` (`self.status = status`, `work.status = exc.status`);
3. **opaque**: everything else. **Opaque fails the suite**, naming the module, the line,
   the scope and the offending source fragment.

A noisy blind spot is infinitely better than a silent one. Whoever introduces an opaque
form has two ways out, both explicit: write the canonical form, or extend the extractor
- therefore knowingly, never by inadvertence.

**What this control does not guarantee.** It is **static**, and its reach stops where
the reading of a syntax tree stops:

- it covers the modules of `SOURCES` - the business package and the command adapter. A
  status born in a module added outside that list, or in `bin/lib/` (vendored SDK), is
  not seen; `tests/test_layering.py` bounds the dependencies of the core, it does not
  bound the place where a status may be born;
- it follows no value at run time: a status built by `exec`, by `importlib`, by a
  metaclass or by a decorator that rewrites an attribute escapes any reading of source;
- categories 1 and 2 rest on **names** (`status`, `acl_status`, `EventRejected`). A
  status written into an attribute carrying another name, then copied over to `status`
  by a non-textual path, is not seen;
- a propagation `<expr>.status` is accepted **without tracing back to the origin** of
  the value. If that origin is not itself a canonical site of the core - an object built
  elsewhere, a module constant carrying a `status` attribute - the status it carries is
  not collected. Propagation from a **name** is narrower: only a parameter of the
  enclosing function is admitted, a local variable named `status` is refused;
- the **declared exemptions** (`EXEMPTIONS`) are holes opened by hand. Each one carries
  its justification, none is implicit, and an exemption that no longer matches anything
  fails the suite - but as long as it holds, it holds.

These limits are the reason for the `test_the_extraction_is_not_empty` guard rail and
for the self-tests of the extractor: a dead instrument produces reassuring zeros.
"""

import ast
import os
import re
import unittest

from acltools.model import ACL_STATUSES

from . import BIN_DIR, REPO_ROOT

#: Modules scanned: the business package and the command adapter. `bin/lib/` - vendored
#: SDK, left unmodified - is out of scope. This is a **declared boundary**, not a
#: proof: see the limits at the top of the module.
_PACKAGE = os.path.join(BIN_DIR, "acltools")

#: Prefix of the modules of the **application-level** command. They are excluded from
#: `SOURCES` and scanned by `tests/test_appacl_statuses.py`, against the enumeration of
#: `appacl_model.APP_ACL_STATUSES`.
#:
#: **The partition is the point, not a convenience.** The two commands do not share a
#: status enumeration - one counts objects and knows nothing of `created` or
#: `noop_inherited`, the other counts stanzas and knows nothing of `skipped_private` -
#: so a single scan would make both directions of the control unsatisfiable: every status
#: of one command would be "produced by the code and undeclared" for the other, and every
#: status of the other would be "declared and dead". Partitioning keeps the control exact
#: on each side. The **shared** modules - `journal.py`, `binding.py`, `normalize.py`,
#: `mapping.py` - stay in `SOURCES` and carry no literal status either way.
APP_MODULE_PREFIX = "appacl_"

#: The adapters of the application-level side. `appaclinventory.py` produces no status
#: at all - it writes nothing, so it has nothing to report the outcome of - and it is
#: scanned all the same: a file left out of both sets is a place where a status could be
#: born unseen, which is precisely the blind spot this device exists to close.
APP_ADAPTERS = ("editappacl.py", "appaclinventory.py")


def _package_modules(app_level):
    return tuple(
        sorted(
            os.path.join(_PACKAGE, name)
            for name in os.listdir(_PACKAGE)
            if name.endswith(".py")
            and name.startswith(APP_MODULE_PREFIX) is app_level
        )
    )


SOURCES = _package_modules(False) + (os.path.join(BIN_DIR, "editacl.py"),)

#: Counterpart set, consumed by `tests/test_appacl_statuses.py`. It lives here, next to
#: the extractor, so that a module added to the package lands in exactly one of the two
#: sets - neither in both, nor in neither.
APP_SOURCES = _package_modules(True) + tuple(
    os.path.join(BIN_DIR, name) for name in APP_ADAPTERS
)

#: Attribute names that carry an `acl_status`. A write to one of them is a **status
#: site**: it is canonical, propagated, or opaque - never ignored.
STATUS_ATTRIBUTES = ("status",)

#: Same names, on the dictionary-key side (`output["acl_status"] = ...`, the sink of
#: section 5.7).
STATUS_KEYS = ("status", "acl_status")

#: Same names, on the keyword-argument side (`EventResult(status=...)`).
STATUS_ARGUMENTS = ("status", "acl_status")

#: Per-event exception: its first positional argument **is** the status.
REJECTION_CONSTRUCTORS = ("EventRejected",)

#: Wrappers that cannot change the value of an already established status. They are
#: **unwrapped** before classification, never accepted wholesale: `str(<expr>)` sends
#: the classification back to `<expr>`, which stays canonical, propagated, or opaque.
TRANSPARENT_WRAPPERS = ("str",)


# --------------------------------------------------------------------------- #
# Declared exemptions
# --------------------------------------------------------------------------- #

#: Sites that carry the name `status` **without** carrying an `acl_status`. Each entry
#: is a hole opened by hand in the control: it is named, justified, and checked alive
#: (`test_every_declared_exemption_matches_a_construct`).
#: Key: `(module, scope, normalized source)` - moving or rewriting the site drops the
#: exemption, therefore fails the suite, therefore forces a fresh decision.
EXEMPTIONS = (
    (
        "rest.py",
        "RestResponse.__init__",
        "self.status = int(status)",
        "HTTP code of the transport response, not an `acl_status`: `RestResponse` "
        "carries `status = 0` for a transport failure and `2xx`/`4xx`/`5xx` otherwise "
        "(section 10.4). The homonymy is in the domain, not in the control.",
    ),
)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

class OpaqueSite(object):
    """Construct touching a status that the extractor cannot interpret."""

    __slots__ = ("module", "line", "scope", "source", "reason")

    def __init__(self, module, line, scope, source, reason):
        self.module = module
        self.line = line
        self.scope = scope
        self.source = source
        self.reason = reason

    def key(self):
        """Stable identity of a site, insensitive to the line number."""
        return (self.module, self.scope, self.source)

    def __repr__(self):
        return "%s:%d in %s -- %s\n        source: %s" % (
            self.module, self.line, self.scope, self.reason, self.source,
        )


class _Scanner(ast.NodeVisitor):
    """Classifies every status site of a module as canonical / propagated / opaque."""

    def __init__(self, module, text):
        self.module = module
        self._lines = text.splitlines()
        self._stack = []
        self._parameters = []
        self.statuses = set()
        self.opaque_sites = []

    # -- tooling ------------------------------------------------------------ #

    def _scope(self):
        return ".".join(self._stack) or "<module>"

    def _source(self, node):
        start = max(node.lineno - 1, 0)
        end = getattr(node, "end_lineno", None) or node.lineno
        raw = " ".join(line.strip() for line in self._lines[start:end])
        return re.sub(r"\s+", " ", raw).strip()

    def _opaque(self, node, reason):
        self.opaque_sites.append(
            OpaqueSite(
                self.module, node.lineno, self._scope(), self._source(node), reason
            )
        )

    # -- scope stack -------------------------------------------------------- #

    @staticmethod
    def _parameter_names(node):
        args = getattr(node, "args", None)
        if args is None or not isinstance(args, ast.arguments):
            return frozenset()                     # ClassDef: no parameters
        names = set()
        for group in (
            getattr(args, "posonlyargs", []), args.args, args.kwonlyargs,
        ):
            names.update(arg.arg for arg in group)
        for lone in (args.vararg, args.kwarg):
            if lone is not None:
                names.add(lone.arg)
        return frozenset(names)

    def _descend(self, node):
        self._stack.append(getattr(node, "name", "<lambda>"))
        self._parameters.append(self._parameter_names(node))
        self.generic_visit(node)
        self._parameters.pop()
        self._stack.pop()

    visit_ClassDef = _descend
    visit_FunctionDef = _descend
    visit_AsyncFunctionDef = _descend
    visit_Lambda = _descend

    def _is_a_parameter(self, name):
        """A **local** variable named `status` is not a propagation: it is an
        indirection, and indirection is precisely what C-1 refuses."""
        return bool(self._parameters) and name in self._parameters[-1]

    # -- classification of a value assigned to a status --------------------- #

    @classmethod
    def _unwrap(cls, value):
        """Strips the **transparent** wrappers: `str(<value>)`.

        This is not one more recognized form, it is a rewrite: what sits inside falls
        back through the same three categories. `str(_TABLE["key"])` therefore stays
        opaque, `str(result.status)` stays a propagation.
        """
        if (
            isinstance(value, ast.Call)
            and getattr(value.func, "id", None) in TRANSPARENT_WRAPPERS
            and len(value.args) == 1
            and not value.keywords
            and not isinstance(value.args[0], ast.Starred)
        ):
            return cls._unwrap(value.args[0])
        return value

    def _classify_value(self, stmt, value, reason):
        value = self._unwrap(value)
        if isinstance(value, ast.Constant):
            if isinstance(value.value, str):
                self.statuses.add(value.value)     # (1) canonical
            return                                 # non-text constant: off topic
        if (
            isinstance(value, ast.Name)
            and value.id in STATUS_ATTRIBUTES
            and self._is_a_parameter(value.id)
        ):
            return                                 # (2) self.status = status
        if isinstance(value, ast.Attribute) and value.attr in STATUS_ATTRIBUTES:
            return                                 # (2) work.status = exc.status
        self._opaque(stmt, reason)                 # (3) opaque

    # -- target recognition ------------------------------------------------- #

    @staticmethod
    def _subscript_key(target):
        key = target.slice
        if key.__class__.__name__ == "Index":      # Python < 3.9
            key = key.value                        # pragma: no cover
        return key

    @classmethod
    def _designates_a_status(cls, target):
        if isinstance(target, ast.Starred):
            target = target.value
        if isinstance(target, ast.Attribute):
            return target.attr in STATUS_ATTRIBUTES
        if isinstance(target, ast.Subscript):
            key = cls._subscript_key(target)
            return (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value in STATUS_KEYS
            )
        if isinstance(target, (ast.Tuple, ast.List)):
            return any(cls._designates_a_status(sub) for sub in target.elts)
        return False

    def _assigned_target(self, stmt, target, value):
        if isinstance(target, (ast.Tuple, ast.List, ast.Starred)):
            if self._designates_a_status(target):
                self._opaque(
                    stmt,
                    "unpacking assignment: the value that lands in the status cannot "
                    "be isolated. Expected canonical form: a plain assignment.",
                )
            return
        if not self._designates_a_status(target):
            return
        self._classify_value(
            stmt,
            value,
            "a status written by an expression that is neither a literal nor a "
            "recognized propagation. Canonical forms: `<obj>.status = \"<status>\"`, "
            "or propagation from `status` / `<expr>.status`.",
        )

    # -- visits ------------------------------------------------------------- #

    def visit_Assign(self, node):
        for target in node.targets:
            self._assigned_target(node, target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._assigned_target(node, node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self._designates_a_status(node.target):
            self._opaque(
                node,
                "augmented assignment on a status: the resulting value cannot be read "
                "in the source.",
            )
        self.generic_visit(node)

    def visit_For(self, node):
        if self._designates_a_status(node.target):
            self._opaque(
                node,
                "status assigned by a loop: the value cannot be read in the source.",
            )
        self.generic_visit(node)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None and self._designates_a_status(
                item.optional_vars
            ):
                self._opaque(
                    node,
                    "status assigned by a context manager: the value cannot be read "
                    "in the source.",
                )
        self.generic_visit(node)

    def visit_Call(self, node):
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name in REJECTION_CONSTRUCTORS:
            self._classify_rejection(node)
        else:
            if name == "setattr":
                self._classify_setattr(node)
            for kw in node.keywords:
                if kw.arg in STATUS_ARGUMENTS:
                    self._classify_value(
                        node,
                        kw.value,
                        "a status passed as a keyword argument by an expression that "
                        "is neither a literal nor a recognized propagation.",
                    )
        self.generic_visit(node)

    # -- special forms ------------------------------------------------------ #

    def _classify_rejection(self, node):
        """`EventRejected(...)`: the status is the **first positional argument**.

        Any other shape is refused - including the keyword argument, which would
        however be readable. This is deliberate: a single canonical form leaves a
        single path to watch, where two tolerated forms call for a third.
        """
        for kw in node.keywords:
            if kw.arg is None:
                self._opaque(
                    node,
                    "`**` expansion: the arguments of EventRejected cannot be read in "
                    "the source.",
                )
                return
            if kw.arg in STATUS_ARGUMENTS:
                self._opaque(
                    node,
                    "status carried as a keyword argument. Expected canonical form: "
                    "EventRejected(\"<status>\", <error>).",
                )
                return
        if not node.args:
            self._opaque(
                node,
                "EventRejected with no positional argument: the status cannot be "
                "located.",
            )
            return
        first = node.args[0]
        if isinstance(first, ast.Starred):
            self._opaque(
                node,
                "`*` expansion as first argument: the status cannot be read in the "
                "source.",
            )
            return
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            self.statuses.add(first.value)
            return
        self._opaque(
            node,
            "first argument of EventRejected is not a literal (indirection). Expected "
            "canonical form: EventRejected(\"<status>\", <error>).",
        )

    def _classify_setattr(self, node):
        """`setattr` is an attribute write that the name alone does not betray."""
        if node.keywords or len(node.args) != 3:
            self._opaque(
                node,
                "`setattr` of unexpected shape: impossible to establish whether it "
                "targets a status.",
            )
            return
        name = node.args[1]
        if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
            self._opaque(
                node,
                "`setattr` whose attribute name is not a literal: it may target "
                "`status`.",
            )
            return
        if name.value in STATUS_ATTRIBUTES:
            self._classify_value(
                node,
                node.args[2],
                "a status written by `setattr` with a non-literal value.",
            )


def scan_source(text, module="<fragment>"):
    """Scans one source fragment. Returns `(statuses, opaque sites)`."""
    scanner = _Scanner(module, text)
    scanner.visit(ast.parse(text))
    return scanner.statuses, scanner.opaque_sites


def scan_the_core():
    """Scans `SOURCES`. Returns `(statuses, opaque sites)`."""
    return scan_paths(SOURCES)


def scan_paths(paths):
    """Scans an explicit set of files. Returns `(statuses, opaque sites)`.

    Extracted from `scan_the_core` so that the application-level suite scans its own
    partition **with this very extractor**: a second copy of it would be a second thing
    to keep in step, and the whole point of this module is that a hand-maintained
    duplicate drifts.
    """
    statuses = set()
    opaque_sites = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        seen, silent = scan_source(text, os.path.basename(path))
        statuses |= seen
        opaque_sites.extend(silent)
    return statuses, opaque_sites


def statuses_produced_by_the_code():
    """Union of the literal statuses of every core module."""
    return scan_the_core()[0]


def _apply_exemptions(opaque_sites):
    """Returns `(non-exempted sites, index of exemptions actually used)`."""
    index = {(mod, scope, src): rank
             for rank, (mod, scope, src, _) in enumerate(EXEMPTIONS)}
    remaining = []
    used = set()
    for site in opaque_sites:
        rank = index.get(site.key())
        if rank is None:
            remaining.append(site)
        else:
            used.add(rank)
    return remaining, used


# --------------------------------------------------------------------------- #
# The enumeration of the code
# --------------------------------------------------------------------------- #

class EnumerationDerivedFromTheCodeTest(unittest.TestCase):
    """`ACL_STATUSES` is the exact projection of what the core produces."""

    def test_the_code_produces_no_undeclared_status(self):
        """The strong direction: a status added to the code fails the suite right here."""
        unknown = statuses_produced_by_the_code() - set(ACL_STATUSES)
        self.assertEqual(
            set(), unknown,
            "status(es) produced by the core and absent from ACL_STATUSES: %s. A "
            "status is not added without being declared, nor without its test case in "
            "invariant 1 of section 8.2." % sorted(unknown),
        )

    def test_no_declared_status_is_dead(self):
        """The reverse direction: a declared value that the code no longer produces is
        a residue, and a residue in an enumeration is where drift starts."""
        dead = set(ACL_STATUSES) - statuses_produced_by_the_code()
        self.assertEqual(
            set(), dead,
            "status(es) declared in ACL_STATUSES that the core no longer produces: %s"
            % sorted(dead),
        )

    def test_the_extraction_is_not_empty(self):
        """Guard rail against the "zero produced by a dead instrument": an extraction
        that found nothing would make the two tests above true by vacuity."""
        self.assertGreaterEqual(len(statuses_produced_by_the_code()), 12)

    def test_the_enumeration_has_no_duplicate(self):
        self.assertEqual(len(ACL_STATUSES), len(set(ACL_STATUSES)))


# --------------------------------------------------------------------------- #
# The unknown fails
# --------------------------------------------------------------------------- #

class NoSilentBlindSpotTest(unittest.TestCase):
    """The central control: what the extractor cannot read, it refuses."""

    def test_no_status_construct_escapes_the_extractor(self):
        _, opaque_sites = scan_the_core()
        remaining, _ = _apply_exemptions(opaque_sites)
        self.assertEqual(
            [], remaining,
            "construct(s) touching an `acl_status` that the extractor cannot "
            "interpret with certainty. Each one must be rewritten in canonical form, "
            "or covered by a justified entry of EXEMPTIONS, or the extractor must be "
            "extended - never ignored:\n    - %s"
            % "\n    - ".join(repr(site) for site in remaining),
        )

    def test_every_declared_exemption_matches_a_construct(self):
        """A dead exemption is a hole that outlived its motive."""
        _, opaque_sites = scan_the_core()
        _, used = _apply_exemptions(opaque_sites)
        dead = [EXEMPTIONS[rank][:3]
                for rank in range(len(EXEMPTIONS)) if rank not in used]
        self.assertEqual(
            [], dead,
            "declared exemption(s) no longer matching any construct of the core: %s. "
            "An exemption rarely survives the code that motivated it; remove it, or "
            "readjust it knowingly." % (dead,),
        )


class ExtractorIsProvenTest(unittest.TestCase):
    """The extractor itself is put to the test, on constructed fragments.

    Without this, the tests above would measure an instrument that nothing shows still
    sees anything at all.
    """

    #: The two canonical forms, under their four spellings.
    CANONICAL_FORMS = (
        ('raise EventRejected("by_exception", "reason")', "by_exception"),
        ('errors.EventRejected("by_qualified_exception", "r")',
         "by_qualified_exception"),
        ('work.status = "by_assignment"', "by_assignment"),
        ('self.status = "by_self_assignment"', "by_self_assignment"),
        ('output["acl_status"] = "by_subscript"', "by_subscript"),
        ('EventResult(status="by_keyword_argument")', "by_keyword_argument"),
    )

    #: The propagations: a status born elsewhere, already collected at its birth. They
    #: are given inside their enclosing function - propagation from a name requires
    #: that name to be a **parameter**.
    PROPAGATED_FORMS = (
        "def f(work, exc):\n    work.status = exc.status\n",
        "def __init__(self, status, error):\n    self.status = status\n",
        "def result(self):\n    return EventResult(status=self.status)\n",
        'def write(record, result):\n    record["status"] = str(result.status)\n',
    )

    #: The forms the extractor cannot interpret. Each one **must** fail. The first two
    #: are exactly the ones the closing audit injected into the core, and which left
    #: the whole suite green.
    REFUSED_FORMS = (
        'raise EventRejected(status="stealth_status_kw", error="probe")',
        'work.status = _STEALTH_STATUS_INDIRECT',
        'raise EventRejected(_STATUS, "probe")',
        'raise EventRejected(*args)',
        'raise EventRejected(**payload)',
        'raise EventRejected()',
        'work.status = pick_the_status()',
        'work.status = "a" if condition else "b"',
        'work.status = _TABLE["key"]',
        # the transparent wrapper does not whitewash what it wraps
        'work.status = str(_TABLE["key"])',
        'work.status = str(a, b)',
        'work.status, work.error = _pair()',
        'work.status += "_suffix"',
        'setattr(work, "status", _STEALTH_STATUS_INDIRECT)',
        'setattr(work, computed_name, "stealth_status")',
        'output["acl_status"] = _STEALTH_STATUS_INDIRECT',
        'EventResult(status=compute())',
        'for work.status in _STATUSES: pass',
        # a **local** variable named `status`: this is not a propagation, it is
        # indirection by constant, disguised as propagation.
        'def f(work):\n    status = "stealth_status_local"\n    work.status = status\n',
    )

    def test_the_canonical_forms_are_recognized_and_collected(self):
        for source, expected in self.CANONICAL_FORMS:
            with self.subTest(source=source):
                statuses, opaque_sites = scan_source(source)
                self.assertEqual([], opaque_sites, "canonical form judged opaque")
                self.assertEqual({expected}, statuses)

    def test_the_propagations_are_recognized_and_collect_nothing(self):
        for source in self.PROPAGATED_FORMS:
            with self.subTest(source=source):
                statuses, opaque_sites = scan_source(source)
                self.assertEqual([], opaque_sites, "propagation judged opaque")
                self.assertEqual(set(), statuses)

    def test_every_unrecognized_form_is_refused(self):
        """The heart of C-1: the unknown fails, and it names itself."""
        for source in self.REFUSED_FORMS:
            with self.subTest(source=source):
                _, opaque_sites = scan_source(source, "fragment.py")
                self.assertEqual(
                    1, len(opaque_sites),
                    "unrecognized form passed over in silence: %s" % source,
                )
                site = opaque_sites[0]
                self.assertEqual("fragment.py", site.module)
                self.assertTrue(site.reason, "a refusal without a reason helps nobody")
                self.assertGreaterEqual(site.line, 1)
                self.assertIn(site.source, re.sub(r"[ \t]+", " ", source))

    def test_the_real_core_triggers_no_refusal(self):
        """The third case: on the shipped code, the control stays silent."""
        statuses, opaque_sites = scan_the_core()
        remaining, _ = _apply_exemptions(opaque_sites)
        self.assertEqual([], remaining)
        self.assertEqual(set(ACL_STATUSES), statuses)


# --------------------------------------------------------------------------- #
# The enumeration of the shipped documentation
# --------------------------------------------------------------------------- #

#: Path of the two documents, relative to the repository root. The split gave each of
#: them one copy of the enumeration and no more, and the class below anchors each copy
#: to `ACL_STATUSES`.
#:
#: `DEVNOTES.md` replaced `docs/DESIGN.md` when the README was reduced to an operator
#: document: one file at the root, absorbing the design notes and everything the README
#: no longer carries, and excluded from the deployable archive by `.gitattributes`.
README = "README.md"
DESIGN = "DEVNOTES.md"

#: The one turn of phrase in the README that spells the size of the enumeration out in
#: words. A number written in letters is an enumeration in disguise, and it drifts the
#: same way.
_COUNT_RE = re.compile(r"\bthe\s+([a-z]+)\s+`acl_status`\s+values", re.IGNORECASE)

#: Enough cardinals to frame an evolution; **a word absent from this table fails**,
#: rather than letting an unverified count through.
_CARDINALS = {
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
}


def _read_document(relative_path):
    with open(os.path.join(REPO_ROOT, relative_path), encoding="utf-8") as handle:
        return handle.read()


class ShippedDocumentationAnchoredToTheSingleSourceTest(unittest.TestCase):
    """C-2 - the enumeration of the shipped documentation is derived from the code.

    The README used to copy the twelve values by hand: exact on the day of the audit,
    and with no link whatsoever to the source. That is the error class of D-35, on the
    shipped-documentation side. These tests establish the missing link.

    **Where each copy lives, and why the reduction of the README did not move it.** The
    README is the operator document: it carries the enumeration itself, in the output
    field table, because the set of values an operator may read in `acl_status` is part
    of the output contract. Two arguments could have been argued either way once the
    README shrank to an operator document; a third settles it. `README.md` is the **only
    one of the two documents shipped in the deployable archive** - `DEVNOTES.md` carries
    `export-ignore` - so an enumeration living there would be unreachable from an app
    installed on a search head, which is exactly where the question gets asked.

    `DEVNOTES.md` carries the state machine instead, because that diagram shows the
    normative ranks and the internal transitions, which nobody reads to interpret a
    result table. One copy each, one anchoring test each - a value duplicated in both
    documents would be one more thing to keep in step, for nothing.

    Reach: they anchor the **enumeration**, the **count**, the **explanation of each
    value** in the README, and the **state machine** of `DEVNOTES.md`. They say nothing
    about the correctness of the wording that describes each status, nor about the
    specification, which no test of this repository can reach.
    """

    @classmethod
    def setUpClass(cls):
        cls.readme = _read_document(README)
        cls.design = _read_document(DESIGN)

    def _table_row(self):
        rows = [
            row for row in self.readme.splitlines()
            if row.startswith("| `acl_status` |")
        ]
        self.assertEqual(
            1, len(rows),
            "the README must carry exactly one table row enumerating the "
            "`acl_status` values; %d found." % len(rows),
        )
        return rows[0]

    def test_the_readme_enumeration_equals_ACL_STATUSES(self):
        """A status added without a README update fails the suite here."""
        cell = self._table_row().split("|")[2]
        enumerated = re.findall(r"`([^`]+)`", cell)
        self.assertEqual(
            list(ACL_STATUSES), enumerated,
            "the output-field table of the README diverges from ACL_STATUSES (order "
            "included). Missing: %s ; extra: %s."
            % (sorted(set(ACL_STATUSES) - set(enumerated)),
               sorted(set(enumerated) - set(ACL_STATUSES))),
        )

    def test_the_count_announced_by_the_readme_is_right(self):
        """The README spells the size of the enumeration out in words, which is an
        enumeration disguised as a number."""
        words = _COUNT_RE.findall(self.readme)
        self.assertTrue(
            words, "the README no longer announces the number of `acl_status` values "
                   "in words; if the wording changed, this control must be readjusted, "
                   "not removed.",
        )
        for word in words:
            with self.subTest(word=word):
                self.assertIn(
                    word.lower(), _CARDINALS,
                    "cardinal \"%s\" absent from the table: count unverifiable, "
                    "therefore refused." % word,
                )
                self.assertEqual(
                    len(ACL_STATUSES), _CARDINALS[word.lower()],
                    "the README announces \"%s\" `acl_status` values, ACL_STATUSES "
                    "carries %d." % (word, len(ACL_STATUSES)),
                )

    def test_every_status_is_mentioned_in_the_readme(self):
        """The enumeration is one row; the operator also needs each value explained.

        A status added to the table row and nowhere else would leave the operator with
        a name and no meaning. This is the broad net under the exact check above: every
        value must appear at least once **outside** the enumeration row.

        **That exclusion is what the reduction of the README bought.** The check used to
        search the whole document, which the enumeration row satisfied on its own - so
        the docstring claimed a reach the code did not have, and a status added to the
        row and explained nowhere passed. The operator README now carries a one-line
        meaning for each value, so the row can be taken out of the haystack and the
        question asked is the one that matters: is this value explained anywhere?
        """
        body = self.readme.replace(self._table_row(), "")
        missing = sorted(
            status for status in ACL_STATUSES
            if not re.search(r"(?<![\w.])%s(?![\w.])" % re.escape(status), body)
        )
        self.assertEqual(
            [], missing,
            "status(es) declared in ACL_STATUSES that the README never mentions "
            "outside its enumeration row: %s. Add the case, or say why it cannot "
            "occur." % missing,
        )

    def test_the_design_state_machine_covers_every_status(self):
        """The state machine of `DEVNOTES.md` is the second copy, and the last one."""
        blocks = [
            block for block in re.findall(r"```mermaid\n(.*?)```", self.design, re.S)
            if "stateDiagram" in block
        ]
        self.assertEqual(
            1, len(blocks),
            "exactly one state diagram expected in %s; %d found." % (DESIGN, len(blocks)),
        )
        targets = set(re.findall(r"-->\s*([A-Za-z_][A-Za-z0-9_]*)", blocks[0]))
        missing = sorted(set(ACL_STATUSES) - targets)
        self.assertEqual(
            [], missing,
            "status(es) declared in ACL_STATUSES and absent from the state machine of "
            "%s: %s." % (DESIGN, missing),
        )

    def test_the_readme_carries_no_state_machine(self):
        """The state machine lives in one document, and the split says which one.

        Without this, a well-meaning contributor puts the diagram back into the README
        "for convenience", the anchoring test above keeps watching the other file, and
        the copy nobody checks is the one everybody reads.
        """
        blocks = [
            block for block in re.findall(r"```mermaid\n(.*?)```", self.readme, re.S)
            if "stateDiagram" in block
        ]
        self.assertEqual(
            [], blocks,
            "the README carries a state diagram again. The enumeration of the states "
            "belongs to %s, which is where the anchoring test looks; either move it "
            "back or extend that test to cover both." % DESIGN,
        )

    def test_the_readme_still_carries_a_conceptual_diagram(self):
        """The operator document keeps at least one diagram, and it is not the state
        machine.

        The specification requires a conceptual schema in the README. Reducing a document
        is exactly the moment a diagram gets dropped as "design material", so the floor is
        held mechanically rather than by intention: at least one mermaid block, none of
        them a state diagram (the test above).
        """
        blocks = re.findall(r"```mermaid\n(.*?)```", self.readme, re.S)
        self.assertTrue(
            blocks,
            "the README no longer carries any mermaid diagram; the specification "
            "requires at least one conceptual schema in the operator document.",
        )


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
