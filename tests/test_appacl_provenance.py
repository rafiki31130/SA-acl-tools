"""Reading the `.meta` files, and the bounds of that exception (v4.2 section 6).

Two of the four bounds are held **mechanically** here, by reading the syntax tree of
`bin/acltools/appacl_provenance.py` rather than by trusting a comment:

- bound 1, **read only**: no write, delete, rename or temporary-file expression;
- bound 1 again, **misleading localization**: none of the three expressions HY-6 measured
  as plausible-and-false may appear.

The rest of the module exercises the robustness clauses of section 6.4 - *the reader
never raises, whatever the input* - and the two-route resolution of bound 4.
"""

import ast
import os
import unittest

from acltools.appacl_model import (
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    STANZA_KIND_OBJECT,
)
from acltools.appacl_provenance import (
    PROVENANCE_DEFAULT,
    PROVENANCE_INHERITED,
    PROVENANCE_LOCAL,
    PROVENANCE_UNAVAILABLE,
    AppProvenance,
    ProvenanceReader,
    classify_stanza,
    family_of,
    is_safe_app_segment,
    materializes_permissions,
    meta_path,
    parse_meta,
    read_meta_file,
    resolve_apps_root,
    root_from_command_file,
    root_from_environment,
)
from acltools.errors import FatalProvenanceRootError

from . import BIN_DIR
from .appacl_helpers import (
    frozen_stanza,
    provenance,
    scoped_stanza,
    touched_stanza,
)

MODULE_PATH = os.path.join(BIN_DIR, "acltools", "appacl_provenance.py")

#: Shape measured in Q0-1, Q0-2 and Q0-3, reproduced literally.
SAMPLE_META = """[]
access = read : [ power ], write : [ admin ]
export = none

[views]
access = read : [ power ], write : [ power ]
export = none
version = 9.4.6
modtime = 1786518192.167816000

[views/probe_view_shared]
access = read : [ power ], write : [ admin ]
export = none
owner = nobody
"""


def _module_tree():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return ast.parse(handle.read(), filename=MODULE_PATH)


class TheModuleIsReadOnlyTest(unittest.TestCase):
    """Bound 1 of section 6.2, **mechanical and not declarative**.

    The exception granted to this module bears on reading. Nothing must be able to make
    it drift - and "nothing" means a test that fails, not a comment that asks.
    """

    #: Call expressions that write, delete, move or create a file.
    FORBIDDEN_CALLS = (
        "os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir", "os.mkdir",
        "os.makedirs", "os.truncate", "os.chmod", "os.chown", "os.symlink", "os.link",
        "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
        "shutil.move", "shutil.rmtree",
        "tempfile.NamedTemporaryFile", "tempfile.mkstemp", "tempfile.mkdtemp",
        "tempfile.TemporaryFile", "tempfile.TemporaryDirectory",
    )

    #: Modules whose mere import would give the module a write surface.
    FORBIDDEN_IMPORTS = ("shutil", "tempfile", "pathlib")

    #: Attribute names of a write API, whatever the object they are called on.
    FORBIDDEN_ATTRIBUTES = (
        "write", "writelines", "write_text", "write_bytes", "truncate", "unlink",
        "rename", "replace", "mkdir", "touch", "rmdir",
    )

    #: The only file-opening modes admitted. Anything else - `w`, `a`, `x`, `+` - is a
    #: write mode, whatever it is combined with.
    ALLOWED_OPEN_MODES = ("r", "rb", "rt")

    def setUp(self):
        self.tree = _module_tree()

    def test_no_forbidden_module_is_imported(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                with self.subTest(imported=name):
                    self.assertNotIn(name.split(".")[0], self.FORBIDDEN_IMPORTS)

    def test_no_write_call_appears(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            rendered = ast.unparse(node.func)
            with self.subTest(call=rendered):
                self.assertNotIn(rendered, self.FORBIDDEN_CALLS)

    def test_no_write_method_is_called_on_anything(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            with self.subTest(method=node.func.attr):
                self.assertNotIn(node.func.attr, self.FORBIDDEN_ATTRIBUTES)

    def test_every_open_call_is_in_a_read_mode(self):
        """The mode must also be a **literal**: a computed mode is opaque, and an opaque
        mode is exactly the way a write comes back in."""
        opens = 0
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
                continue
            opens += 1
            mode = None
            if len(node.args) > 1:
                mode = node.args[1]
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = keyword.value
            self.assertIsInstance(
                mode, ast.Constant, "the opening mode must be a literal"
            )
            self.assertIn(mode.value, self.ALLOWED_OPEN_MODES)
        self.assertEqual(
            opens, 1, "there must be exactly one open() in this module, and it reads"
        )

    def test_no_public_function_is_named_like_a_write(self):
        """A second line, on the surface rather than on the body: a module that exposes
        `write_meta` would be one refactor away from doing it."""
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                with self.subTest(function=node.name):
                    for marker in ("write", "delete", "remove", "create", "rename"):
                        self.assertNotIn(marker, node.name.lower())


class TheMisleadingLocalizationsAreForbiddenTest(unittest.TestCase):
    """Bound 1, second family - **measured** by HY-6.

    The three expressions below return a plausible and false path. They are of the same
    order as the hardcoded `nobody` of section 4.1: what is forbidden is forbidden
    because the platform accepts the mistake in silence.

    - the SDK's `environment.splunk_home` falls back on the **working directory** when
      the variable is missing: `abspath(join(getcwd(), environ.get("SPLUNK_HOME", "")))`.
      Measured outside splunkd: it then yields the app's `bin/`, under which `etc/apps`
      does not exist. A command resting on it would fail **later and worse**;
    - `os.getcwd()` is that same `bin/` directory, in all three measured executions;
    - `searchinfo.app` names the **dispatching** app, not the carrying one: it is
      `search` as soon as the search is launched from anywhere else.
    """

    FORBIDDEN_TEXT = (
        "environment.splunk_home",
        "os.getcwd",
        "getcwd",
        "searchinfo.app",
        "searchinfo",
    )

    def test_none_of_the_three_appears_in_the_source(self):
        with open(MODULE_PATH, encoding="utf-8") as handle:
            source = handle.read()
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        # The docstring names them, which is the point of naming them; the code must not.
        tree = ast.parse(code)
        stripped = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue
            if isinstance(node, ast.Call):
                stripped.append(ast.unparse(node))
            if isinstance(node, ast.Attribute):
                stripped.append(ast.unparse(node))
        rendered = "\n".join(stripped)
        for expression in self.FORBIDDEN_TEXT:
            with self.subTest(expression=expression):
                self.assertNotIn(expression, rendered)


def _same_path(first, second):
    """Compare two paths the way the resolution does: absolute, normalized, case-folded.

    The test suite runs on the developer's platform as well as on the target one, and a
    path literal that is absolute on one is relative on the other.
    """
    return os.path.normcase(os.path.normpath(os.path.abspath(first))) == os.path.normcase(
        os.path.normpath(os.path.abspath(second))
    )


class TheRootResolutionTest(unittest.TestCase):
    """Bound 4: two independent routes, three controls, in this order."""

    HOME = os.path.join(os.sep + "opt", "splunk")
    APPS = os.path.join(HOME, "etc", "apps")
    COMMAND = os.path.join(APPS, "SA-acl-tools", "bin", "editappacl.py")

    def test_the_main_route_is_the_environment_variable(self):
        self.assertTrue(
            _same_path(root_from_environment({"SPLUNK_HOME": self.HOME}), self.APPS)
        )

    def test_the_main_route_answers_none_without_the_variable(self):
        self.assertIsNone(root_from_environment({}))
        self.assertIsNone(root_from_environment({"SPLUNK_HOME": "   "}))

    def test_the_fallback_route_climbs_three_levels_from_the_command(self):
        """It yields `etc/apps` **directly**, without presupposing where `etc` sits."""
        self.assertTrue(_same_path(root_from_command_file(self.COMMAND), self.APPS))

    def test_the_fallback_route_does_not_derive_from_the_variable(self):
        """Independence is what makes its failure detectable instead of silent."""
        self.assertEqual(
            root_from_command_file(self.COMMAND),
            root_from_command_file(self.COMMAND),
        )
        self.assertIsNone(root_from_command_file(""))

    def test_the_two_routes_agreeing_resolves(self):
        root = resolve_apps_root(
            {"SPLUNK_HOME": self.HOME}, self.COMMAND, isdir=lambda p: True
        )
        self.assertTrue(_same_path(root, self.APPS))

    def test_control_1_a_candidate_not_under_etc_apps_is_refused(self):
        """A root that is not an `etc/apps` takes no part in the comparison."""
        with self.assertRaises(FatalProvenanceRootError):
            resolve_apps_root(
                {"SPLUNK_HOME": self.HOME},
                os.path.join(os.sep + "somewhere", "else", "bin", "cmd.py"),
                isdir=lambda p: False,
            )

    def test_control_2_a_divergence_is_fatal(self):
        """An ambiguous root would make the command read another tree than splunkd's,
        with no symptom at all. The refusal is the whole point."""
        other = os.path.join(os.sep + "srv", "splunk", "etc", "apps", "app", "bin", "c.py")
        with self.assertRaises(FatalProvenanceRootError) as caught:
            resolve_apps_root(
                {"SPLUNK_HOME": self.HOME}, other, isdir=lambda p: True
            )
        self.assertIn("ambiguous", str(caught.exception).lower())

    def test_control_2_fires_even_when_only_one_of_the_two_exists(self):
        """The comparison precedes the existence check (bound 4, controls 2 then 3).

        Preferring the existing one would silently pick a root the other route
        contradicts - which is the case the divergence rule exists to refuse.
        """
        other = os.path.join(os.sep + "srv", "splunk", "etc", "apps", "app", "bin", "c.py")
        with self.assertRaises(FatalProvenanceRootError):
            resolve_apps_root(
                {"SPLUNK_HOME": self.HOME},
                other,
                isdir=lambda p: p.startswith(self.HOME),
            )

    def test_control_3_no_existing_etc_apps_is_fatal(self):
        with self.assertRaises(FatalProvenanceRootError):
            resolve_apps_root(
                {"SPLUNK_HOME": self.HOME}, self.COMMAND, isdir=lambda p: False
            )

    def test_a_single_available_route_is_enough(self):
        root = resolve_apps_root({}, self.COMMAND, isdir=lambda p: True)
        self.assertTrue(_same_path(root, self.APPS))

    def test_a_root_named_like_etc_apps_without_being_it_is_refused(self):
        """Control 1 is on **segments**: `my_etc_apps` is not an `etc/apps`.

        A substring test would accept it, and the command would then read a directory
        that merely looks like the right one - which is the exact failure mode bound 4
        turns into a refusal.
        """
        candidate = os.path.join(os.sep + "opt", "my_etc_apps", "a", "bin", "c.py")
        with self.assertRaises(FatalProvenanceRootError):
            resolve_apps_root({}, candidate, isdir=lambda p: True)


class ThePerimeterOfFilesTest(unittest.TestCase):
    """Bound 4: two files per application, and no path built from an input datum."""

    ROOT = os.path.join(os.sep + "opt", "splunk", "etc", "apps")

    def test_only_the_two_metadata_files_are_reachable(self):
        for basename in ("local.meta", "default.meta"):
            with self.subTest(basename=basename):
                path = meta_path(self.ROOT, "my_app", basename)
                self.assertTrue(path.endswith(os.path.join("metadata", basename)))

    def test_no_other_basename_is_reachable(self):
        for basename in ("app.conf", "../../passwd", "local.meta.bak", ""):
            with self.subTest(basename=basename):
                self.assertIsNone(meta_path(self.ROOT, "my_app", basename))

    def test_an_application_segment_cannot_escape(self):
        for app in ("..", ".", "a/b", "a\\b", "", "   ", None):
            with self.subTest(app=app):
                self.assertFalse(is_safe_app_segment(app))
                self.assertIsNone(meta_path(self.ROOT, app, "local.meta"))

    def test_a_normal_application_name_is_accepted(self):
        self.assertTrue(is_safe_app_segment("SA-acl-tools"))
        self.assertTrue(is_safe_app_segment("TA_probe 01"))

    def test_the_resolved_path_stays_under_the_root(self):
        path = meta_path(self.ROOT, "my_app", "local.meta")
        self.assertTrue(os.path.normpath(path).startswith(os.path.normpath(self.ROOT)))

    def test_no_user_tree_is_ever_addressed(self):
        """Section 1.2 and section 13.4 point 6: private metadata is neither read nor
        written - including the file the namespace trap of section 4.1 produces."""
        path = meta_path(self.ROOT, "my_app", "local.meta")
        self.assertNotIn("etc%susers" % os.sep, path)


class TheStanzaClassificationTest(unittest.TestCase):
    """Section 6.4, the only interpretation the reader allows, edge cases included."""

    def test_the_three_classes(self):
        self.assertEqual(classify_stanza(""), STANZA_KIND_APP)
        self.assertEqual(classify_stanza("views"), STANZA_KIND_FAMILY)
        self.assertEqual(classify_stanza("views/my_view"), STANZA_KIND_OBJECT)

    def test_the_frontier_cases(self):
        for name, expected in (
            (None, STANZA_KIND_APP),
            ("   ", STANZA_KIND_APP),
            ("views/", STANZA_KIND_OBJECT),
            ("/views", STANZA_KIND_OBJECT),
            ("a/b/c", STANZA_KIND_OBJECT),
            ("global-banner", STANZA_KIND_FAMILY),
        ):
            with self.subTest(name=name):
                self.assertEqual(classify_stanza(name), expected)

    def test_the_family_of_a_stanza(self):
        self.assertEqual(family_of("views/my_view"), "views")
        self.assertEqual(family_of("views"), "views")
        self.assertEqual(family_of("a/b/c"), "a")
        self.assertEqual(family_of(""), "")


class TheReaderNeverRaisesTest(unittest.TestCase):
    """Section 6.4: the reader is **total**, whatever the input."""

    def test_a_missing_file_is_a_valid_result(self):
        def opener(path):
            raise FileNotFoundError(path)

        meta = read_meta_file("whatever", opener)
        self.assertFalse(meta.present)
        self.assertEqual(meta.error, "")

    def test_an_unreadable_file_yields_an_error_class(self):
        def opener(path):
            raise PermissionError(path)

        meta = read_meta_file("whatever", opener)
        self.assertFalse(meta.present)
        self.assertEqual(meta.error, "PermissionError")

    def test_an_io_error_yields_an_error_class(self):
        def opener(path):
            raise OSError("disk")

        self.assertEqual(read_meta_file("whatever", opener).error, "OSError")

    def test_no_path_is_not_an_exception(self):
        self.assertEqual(read_meta_file(None).error, "no_path")

    def test_an_empty_file_parses_to_nothing(self):
        meta = read_meta_file("whatever", lambda path: "")
        self.assertTrue(meta.present)
        self.assertEqual(meta.stanzas, {})

    def test_malformed_lines_are_skipped_and_counted(self):
        text = "[views]\nnot a key value line\naccess = read : [ * ]\n= no key\n"
        meta = read_meta_file("whatever", lambda path: text)
        self.assertEqual(meta.skipped, 2)
        self.assertIn("views", meta.stanzas)

    def test_a_line_before_any_stanza_is_skipped(self):
        meta = read_meta_file("whatever", lambda path: "orphan = 1\n[views]\na = b\n")
        self.assertEqual(meta.skipped, 1)
        self.assertEqual(meta.stanzas["views"], {"a": "b"})

    def test_an_unknown_key_is_kept_without_interpretation(self):
        meta = read_meta_file("whatever", lambda path: "[views]\nunknown_key = 1\n")
        self.assertEqual(meta.stanzas["views"], {"unknown_key": "1"})

    def test_a_stanza_with_no_name_is_the_application_default(self):
        meta = read_meta_file("whatever", lambda path: "[]\nexport = none\n")
        self.assertIn("", meta.stanzas)

    def test_a_stanza_with_several_slashes_survives(self):
        meta = read_meta_file("whatever", lambda path: "[a/b/c]\nx = 1\n")
        self.assertIn("a/b/c", meta.stanzas)

    def test_a_repeated_stanza_merges_its_keys(self):
        meta = read_meta_file("whatever", lambda path: "[views]\na = 1\n[views]\nb = 2\n")
        self.assertEqual(meta.stanzas["views"], {"a": "1", "b": "2"})

    def test_comments_and_blank_lines_are_not_counted_as_malformed(self):
        meta = read_meta_file("whatever", lambda path: "# a comment\n\n[views]\na = 1\n")
        self.assertEqual(meta.skipped, 0)

    def test_the_measured_shape_parses_as_measured(self):
        stanzas, skipped = parse_meta(SAMPLE_META)
        self.assertEqual(skipped, 0)
        self.assertEqual(
            sorted(stanzas), ["", "views", "views/probe_view_shared"]
        )
        self.assertEqual(stanzas["views"]["export"], "none")

    def test_invalid_bytes_do_not_raise(self):
        """HY-5: files are assumed UTF-8, and the fallback IS the nominal behavior."""
        text = "[views]\naccess = read : [ powe� ]\n"
        meta = read_meta_file("whatever", lambda path: text)
        self.assertTrue(meta.present)


class TheProvenanceAnswersTest(unittest.TestCase):
    """Section 7.4: closed domain, and no conclusion when the files are unreadable."""

    def test_local_wins(self):
        prov = provenance(local="[views]\na = 1\n", default="[views]\na = 2\n")
        self.assertEqual(prov.provenance_of("views"), PROVENANCE_LOCAL)

    def test_default_when_local_has_nothing(self):
        prov = provenance(local="[macros]\na = 1\n", default="[views]\na = 2\n")
        self.assertEqual(prov.provenance_of("views"), PROVENANCE_DEFAULT)

    def test_inherited_when_neither_carries_it(self):
        prov = provenance(local="[macros]\na = 1\n", default=None)
        self.assertEqual(prov.provenance_of("views"), PROVENANCE_INHERITED)

    def test_unavailable_emits_no_conclusion(self):
        prov = provenance(local_error="PermissionError")
        self.assertEqual(prov.provenance_of("views"), PROVENANCE_UNAVAILABLE)
        self.assertFalse(prov.available)

    def test_a_missing_file_does_not_make_the_provenance_unavailable(self):
        """Measured: a freshly installed application has no `local.meta` at all. That is
        an answer - the stanza does not exist - not a failure to answer."""
        prov = provenance(local=None, default=None)
        self.assertTrue(prov.available)
        self.assertEqual(prov.provenance_of("views"), PROVENANCE_INHERITED)

    def test_the_application_default_is_addressed_by_the_empty_name(self):
        prov = provenance(local="[]\naccess = read : [ power ]\n")
        self.assertTrue(prov.present_local(""))
        self.assertEqual(prov.provenance_of(""), PROVENANCE_LOCAL)

    def test_the_literal_values_come_back_unparsed(self):
        prov = provenance(local=SAMPLE_META)
        self.assertEqual(
            prov.literal("views")["access"], "read : [ power ], write : [ power ]"
        )
        self.assertEqual(prov.literal("nothing"), {})

    def test_the_parse_skipped_count_is_reported(self):
        prov = provenance(local="[views]\ngarbage line\n")
        self.assertEqual(prov.error, "parse_skipped:1")


class TheCountsNeverListNamesTest(unittest.TestCase):
    """Bound 3 of section 6.2: object stanzas are **counted**, never listed nor emitted.

    Reading the file short-circuits the capability filtering REST applies; a caller
    without `admin_all_objects` would otherwise see object names the API refuses them.
    """

    #: **Faithful fixtures.** Every stanza that stands for a frozen object or a governing
    #: header carries an `access` line, because that is the key the platform writes when it
    #: freezes and the only one that interrupts inheritance. The previous fixtures used an
    #: invented key (`a = 1`), which freezes nothing - so the counts agreed with a
    #: predicate that was wrong, and anomaly A-2 crossed 1 288 tests untouched.
    LOCAL = (
        frozen_stanza("")
        + frozen_stanza("views")
        + frozen_stanza("views/one")
        + frozen_stanza("views/two")
    )
    DEFAULT = frozen_stanza("views/two") + frozen_stanza("macros/m")

    def setUp(self):
        self.prov = provenance(local=self.LOCAL, default=self.DEFAULT)

    def test_no_public_method_returns_an_object_name(self):
        forbidden_results = ("one", "two", "views/one", "views/two", "macros/m")
        for name in dir(self.prov):
            if name.startswith("_"):
                continue
            attribute = getattr(self.prov, name)
            if not callable(attribute):
                continue
            for arguments in ((), ("views",)):
                try:
                    result = attribute(*arguments)
                except TypeError:
                    continue
                with self.subTest(method=name, arguments=arguments):
                    rendered = repr(result)
                    for leak in forbidden_results:
                        self.assertNotIn(
                            "'%s'" % leak,
                            rendered,
                            "%s returns an object stanza name" % name,
                        )

    def test_the_frozen_count_is_a_union_of_the_two_files(self):
        """HY-2: specificity wins between layers, so a stanza present in both files is
        ONE frozen object, not two."""
        self.assertEqual(self.prov.frozen_count("views"), 2)

    def test_the_frozen_count_over_the_whole_application(self):
        self.assertEqual(self.prov.frozen_count(), 3)

    def test_the_family_header_count_ignores_object_stanzas(self):
        self.assertEqual(self.prov.family_header_count(), 1)

    def test_a_family_header_is_seen_in_either_file(self):
        self.assertTrue(self.prov.has_family_header("views"))
        self.assertFalse(self.prov.has_family_header("macros"))
        self.assertFalse(self.prov.has_family_header(""))


class TheFreezePredicateTest(unittest.TestCase):
    """**Anomaly A-2 of the pre-delivery audit, and the measurement that closes it.**

    The premise the contract carried - *an object stanza freezes its object* - is false.
    splunkd writes a `[<family>/<object>]` stanza for **every object it creates or edits**,
    carrying `owner`, `version` and `modtime` and no `access` line, and such an object goes
    on inheriting its permissions. Counting those as frozen made the impact estimate zero
    on any application whose objects had ever been touched, while the output announced
    `no_inheriting_object` and the write moved the whole family: wrong by 100 %, in the
    direction that reassures.

    **Measured on the lab**, at both stanza levels, by writing the generic and re-reading
    the effective ACL of a witness of each shape:

        stanza keys                    perms.read  perms.write  sharing
        (no stanza at all)             moved       moved        moved
        owner / version / modtime      moved       moved        moved
        export, no access              moved       moved        FROZEN
        access + export                FROZEN      FROZEN       FROZEN

    And one level up, on a `[savedsearches]` header carrying `export`, `version` and
    `modtime`: the witness object followed a change of `[]` on its permissions, so a header
    that materializes nothing governs nothing either.

    A fourth shape - `access` without `export` - is **not producible** through the
    platform's own write paths: `sharing` is a required argument of the object ACL handler,
    measured `400 The following required arguments are missing: owner, sharing`. So the
    single predicate below covers every shape splunkd writes.

    Every test in this class **fails on the previous behaviour**, which counted presence.
    """

    def test_a_stanza_that_carries_the_permissions_freezes(self):
        prov = provenance(local=frozen_stanza("views/frozen_one"))
        self.assertEqual(prov.frozen_count("views"), 1)

    def test_a_stanza_written_by_splunkd_on_an_edit_freezes_nothing(self):
        """THE case of A-2, and the one that dominates any real application."""
        prov = provenance(local=touched_stanza("views/edited_one"))
        self.assertEqual(prov.frozen_count("views"), 0)

    def test_a_stanza_carrying_only_the_scope_freezes_nothing_here(self):
        """`export` freezes the SCOPE, not the permissions. Such an object still has its
        permissions moved by a generic write, so it stays inside the count - and the
        estimate then overstates what the scope dimension of that write reaches, which is
        the safe direction for a volume guard rail."""
        prov = provenance(local=scoped_stanza("views/scoped_one"))
        self.assertEqual(prov.frozen_count("views"), 0)

    def test_the_mixture_counts_only_what_freezes(self):
        prov = provenance(
            local=(frozen_stanza("views/a") + touched_stanza("views/b")
                   + scoped_stanza("views/c") + frozen_stanza("views/d")),
        )
        self.assertEqual(prov.frozen_count("views"), 2)

    def test_the_freezing_layer_wins_over_the_touched_one(self):
        """HY-2: specificity wins between layers, and at equal specificity the two files
        are a union. An object frozen in `default.meta` is frozen, whatever its
        `local.meta` twin carries."""
        prov = provenance(
            local=touched_stanza("views/one"), default=frozen_stanza("views/one")
        )
        self.assertEqual(prov.frozen_count("views"), 1)

    def test_a_family_header_that_materializes_nothing_governs_nothing(self):
        """Same predicate one level up, and it is measured there too: the objects of such
        a family stay inside the blast radius of the application default."""
        prov = provenance(local=scoped_stanza("views"))
        self.assertFalse(prov.has_family_header("views"))
        self.assertEqual(prov.family_header_count(), 0)

    def test_a_family_header_that_carries_the_permissions_governs(self):
        prov = provenance(local=frozen_stanza("views"))
        self.assertTrue(prov.has_family_header("views"))
        self.assertEqual(prov.family_header_count(), 1)

    def test_the_predicate_reads_the_keys_and_nothing_else(self):
        self.assertTrue(materializes_permissions(["access"]))
        self.assertTrue(materializes_permissions({"access": "", "export": ""}))
        self.assertFalse(materializes_permissions([]))
        self.assertFalse(materializes_permissions(None))
        self.assertFalse(materializes_permissions(["owner", "version", "modtime"]))
        self.assertFalse(materializes_permissions(["export"]))

    def test_presence_and_materialization_are_two_different_questions(self):
        """`acl_present_local` answers presence, which is what section 7.4 asks of it.
        The freeze predicate answers governance. Conflating them is the defect."""
        prov = provenance(local=touched_stanza("views"))
        self.assertTrue(prov.present_local("views"))
        self.assertFalse(prov.materialized_local("views"))

    def test_a_stanza_carrying_the_permissions_is_materialized(self):
        prov = provenance(local=frozen_stanza("views"))
        self.assertTrue(prov.present_local("views"))
        self.assertTrue(prov.materialized_local("views"))

    def test_an_absent_stanza_is_neither(self):
        prov = provenance(local=None)
        self.assertFalse(prov.present_local("views"))
        self.assertFalse(prov.materialized_local("views"))


class TheReaderMemoizesPerApplicationTest(unittest.TestCase):

    def test_one_read_per_application(self):
        reads = []

        def opener(path):
            reads.append(path)
            return "[views]\na = 1\n"

        reader = ProvenanceReader(os.path.join(os.sep + "root"), opener)
        reader.provenance_of_app("my_app")
        reader.provenance_of_app("my_app")
        # Two files on the first call, nothing on the second.
        self.assertEqual(len(reads), 2)

    def test_refresh_drops_the_memory(self):
        reads = []

        def opener(path):
            reads.append(path)
            return ""

        reader = ProvenanceReader(os.path.join(os.sep + "root"), opener)
        reader.provenance_of_app("my_app")
        reader.refresh("my_app")
        reader.provenance_of_app("my_app")
        self.assertEqual(len(reads), 4)

    def test_an_unusable_application_name_yields_an_unavailable_provenance(self):
        reader = ProvenanceReader(os.path.join(os.sep + "root"), lambda path: "")
        prov = reader.provenance_of_app("../escape")
        self.assertFalse(prov.available)


class TheProvenanceObjectIsInert(unittest.TestCase):
    """A last structural check: the class exposes nothing that could write."""

    def test_no_setter_no_writer(self):
        prov = AppProvenance("my_app", None, None)
        for name in dir(prov):
            if name.startswith("_"):
                continue
            with self.subTest(attribute=name):
                for marker in ("write", "save", "delete", "remove", "create"):
                    self.assertNotIn(marker, name.lower())


if __name__ == "__main__":
    unittest.main()
