"""Run monitoring view: structure, searches, declarations (specification section 15).

A Simple XML dashboard is a **normative deliverable** exactly like a `.conf` file, and
it fails in the same way: silently. A panel whose token is never set never appears; a
search that lost its time range runs over all time; a status literal renamed in the
code and left in the view keeps counting zero, forever, without a single message. None
of that shows up anywhere but in a browser, on an instance, at the moment somebody
happens to look.

What this module freezes is therefore everything about the view that can be decided
**without** Splunk: the XML structure, the token wiring, the SPL constructs the
measurement campaign proved to be traps, and the consistency between the view, the
macros, the role and the metadata. What remains is the lab acceptance list of
specification section 8.2 - the part no parser can reach.

The readers are the ones already written for the other artifacts:
`tests/test_spl_artifacts.read_splunk_conf` for `.conf` files with line continuations,
`tests/test_app_layout.MetadataTest.read_meta` for `.meta` files, whose `[]` stanza
`configparser` rejects. Reimplementing them here would create a second reader that
drifts from the first.
"""

import os
import re
import unittest
import xml.etree.ElementTree as ElementTree

from . import REPO_ROOT
from .test_app_layout import LayoutTest, MetadataTest
from .test_spl_artifacts import read_splunk_conf

#: Path of the view, repository-relative. Everything else derives from it.
VIEW_PARTS = ("default", "data", "ui", "views", "editacl_runs.xml")

#: Name of the view as Splunk knows it: the file name, without its extension. The
#: `.meta` stanza and the `nav` entry must both use exactly this.
VIEW_NAME = "editacl_runs"

#: Name of the read role. It appears in three files and must be the same in all three.
ROLE_NAME = "editacl_auditor"

#: The two source macros (D-51). No search of the view names an index by hand.
SOURCE_MACROS = ("acl_journal_source", "acl_diag_source")

#: Titles of the twelve panels, verbatim. Eleven carry a search; `What this view cannot
#: show` is a static panel. The prompt panel carries no title and is checked separately.
EXPECTED_PANEL_TITLES = (
    "Entitlement check",
    "Legacy-format lines excluded",
    "Runs started with no journal line",
    "Runs",
    "Selected run",
    "Status breakdown - observed vs declared",
    "HTTP code breakdown",
    "Breakdown by application and object type",
    "Objects whose endpoint was resolved",
    "Events refused before endpoint resolution",
    "Errors",
    "What this view cannot show",
)

#: The one panel allowed to write `index=` in its query, named by its title.
#:
#: It is the entitlement guard, and its subsearch `| eventcount summarize=false
#: index=* index=_*` enumerates the indexes the running role may search. That is not a
#: source designation - there is nothing for a macro to carry - and no other
#: construction answers the question D-48 asks. The exception is therefore named here
#: rather than left to a reader's judgement.
INDEX_LITERAL_EXEMPT_PANEL = "Entitlement check"


def view_path():
    return os.path.join(REPO_ROOT, *VIEW_PARTS)


def view_tree():
    return ElementTree.parse(view_path())


def view_source():
    with open(view_path(), encoding="utf-8") as handle:
        return handle.read()


def panels(root):
    """Every `<panel>` of the view, in document order."""
    return root.findall(".//panel")


def panel_title(panel):
    node = panel.find("title")
    return None if node is None else (node.text or "").strip()


def queries(root):
    """`[(panel title, query text)]` for every `<query>` of the view."""
    found = []
    for panel in panels(root):
        for query in panel.findall(".//query"):
            found.append((panel_title(panel), (query.text or "").strip()))
    return found


class TheViewIsWellFormedTest(unittest.TestCase):
    """T1, T2: a broken XML or an accented label is only seen by opening the page."""

    def setUp(self):
        self.root = view_tree().getroot()

    def test_the_file_exists_and_parses(self):
        self.assertTrue(os.path.exists(view_path()), view_path())
        self.assertGreater(os.path.getsize(view_path()), 0)

    def test_the_root_element_is_a_form(self):
        # A `<form>` and not a `<dashboard>`: the view carries two inputs, the time
        # range and the sid. D-43 also rules out Dashboard Studio, whose root would be
        # a JSON document and not this element at all.
        self.assertEqual(self.root.tag, "form")

    def test_the_version_attribute_is_declared(self):
        self.assertEqual(self.root.get("version"), "1.1")

    def test_the_label_is_present_and_pure_ascii(self):
        label = self.root.find("label")
        self.assertIsNotNone(label)
        text = (label.text or "").strip()
        self.assertTrue(text)
        text.encode("ascii")

    def test_the_whole_file_is_pure_ascii(self):
        # `tests/test_language.py` catches French words and French typography; it does
        # not catch an accented character in an otherwise English sentence. Here the
        # rule is absolute and costs nothing: this file has no legitimate use for a
        # non-ASCII character.
        view_source().encode("ascii")


class ThePanelsAreAllThereTest(unittest.TestCase):
    """T3: a panel deleted by accident during a rework."""

    def setUp(self):
        self.root = view_tree().getroot()

    def test_the_expected_panels_are_present_and_no_other(self):
        titles = tuple(
            title for title in (panel_title(p) for p in panels(self.root)) if title
        )
        self.assertEqual(sorted(titles), sorted(EXPECTED_PANEL_TITLES))

    def test_eleven_panels_carry_a_search(self):
        with_query = {
            title for title, _query in queries(self.root)
        }
        self.assertEqual(len(with_query), 11)
        self.assertNotIn("What this view cannot show", with_query)

    def test_the_static_panel_carries_html_and_no_search(self):
        for panel in panels(self.root):
            if panel_title(panel) == "What this view cannot show":
                self.assertIsNotNone(panel.find("html"))
                self.assertEqual(panel.findall(".//query"), [])
                return
        self.fail("static panel not found")


class TheTokenWiringTest(unittest.TestCase):
    """T4 to T8: seven searches launched empty, or a panel that never appears."""

    #: Panels that must not run before a run has been selected.
    DETAIL_PANELS = (
        "Selected run",
        "Status breakdown - observed vs declared",
        "HTTP code breakdown",
        "Breakdown by application and object type",
        "Objects whose endpoint was resolved",
        "Events refused before endpoint resolution",
        "Errors",
    )

    def setUp(self):
        self.root = view_tree().getroot()

    def test_every_detail_panel_depends_on_the_sid_token(self):
        for panel in panels(self.root):
            title = panel_title(panel)
            if title in self.DETAIL_PANELS:
                with self.subTest(panel=title):
                    self.assertEqual(panel.get("depends"), "$sid$")

    def test_no_overview_panel_depends_on_the_sid_token(self):
        for panel in panels(self.root):
            title = panel_title(panel)
            if title and title not in self.DETAIL_PANELS:
                with self.subTest(panel=title):
                    self.assertIsNone(panel.get("depends"))

    def test_exactly_one_panel_rejects_the_sid_token(self):
        rejecting = [p for p in panels(self.root) if p.get("rejects") == "$sid$"]
        self.assertEqual(len(rejecting), 1)
        # It is the prompt, so it holds text and no search.
        self.assertIsNotNone(rejecting[0].find("html"))
        self.assertEqual(rejecting[0].findall(".//query"), [])

    def test_every_token_used_in_depends_or_rejects_is_set_somewhere(self):
        used = set()
        for panel in panels(self.root):
            for attribute in ("depends", "rejects"):
                value = panel.get(attribute)
                if value:
                    used.update(re.findall(r"\$([A-Za-z0-9_.]+)\$", value))
        set_tokens = {
            node.get("token")
            for node in self.root.findall(".//set")
            if node.get("token")
        }
        self.assertTrue(used)
        self.assertEqual(used - set_tokens, set())

    def test_the_run_list_drilldown_sets_both_tokens(self):
        # `sid` drives the panels, `sid_in` makes the text input reflect the selection.
        # Setting `sid_in` alone would not do: nothing guarantees that setting a token
        # programmatically fires the `<change>` handler of the input that owns it.
        for panel in panels(self.root):
            if panel_title(panel) != "Runs":
                continue
            drilldown = panel.find(".//drilldown")
            self.assertIsNotNone(drilldown)
            tokens = {
                node.get("token"): (node.text or "").strip()
                for node in drilldown.findall("set")
            }
            self.assertEqual(sorted(tokens), ["sid", "sid_in"])
            for value in tokens.values():
                self.assertEqual(value, "$row.sid$")
            return
        self.fail("run list panel not found")

    def test_the_text_input_carries_no_default(self):
        # A `<default>` - even empty - **defines** the token to the empty string, and a
        # token defined to the empty string satisfies `depends`. The seven detail
        # panels would then run at first load, filtered on `sid=""`: seven useless
        # searches over the whole window.
        for node in self.root.findall(".//input"):
            if node.get("token") == "sid_in":
                self.assertEqual(node.get("type"), "text")
                self.assertIsNone(node.find("default"))
                return
        self.fail("sid_in input not found")

    def test_emptying_the_text_input_unsets_the_sid_token(self):
        for node in self.root.findall(".//input"):
            if node.get("token") != "sid_in":
                continue
            change = node.find("change")
            self.assertIsNotNone(change)
            unset = [n.get("token") for n in change.findall(".//unset")]
            self.assertIn("sid", unset)
            return
        self.fail("sid_in input not found")

    def test_the_fieldset_runs_at_load(self):
        fieldset = self.root.find("fieldset")
        self.assertIsNotNone(fieldset)
        self.assertEqual(fieldset.get("autoRun"), "true")
        self.assertEqual(fieldset.get("submitButton"), "false")

    def test_every_search_carries_its_own_time_range(self):
        # A `<search>` with no `<earliest>` runs over all time. On an index holding the
        # journal of every run ever made, that is not a detail of comfort.
        searches = self.root.findall(".//search")
        self.assertTrue(searches)
        for index, search in enumerate(searches):
            with self.subTest(search=index):
                self.assertIsNotNone(search.find("earliest"))
                self.assertIsNotNone(search.find("latest"))
                self.assertEqual(
                    (search.find("earliest").text or "").strip(), "$tr.earliest$"
                )
                self.assertEqual(
                    (search.find("latest").text or "").strip(), "$tr.latest$"
                )

    def test_the_time_input_declares_the_default_window(self):
        for node in self.root.findall(".//input"):
            if node.get("token") == "tr":
                default = node.find("default")
                self.assertIsNotNone(default)
                self.assertEqual((default.find("earliest").text or "").strip(), "-7d@d")
                self.assertEqual((default.find("latest").text or "").strip(), "now")
                return
        self.fail("time input not found")


class TheSearchesAvoidTheMeasuredTrapsTest(unittest.TestCase):
    """T9 to T17. Every rule below froze a chart that was measured wrong."""

    def setUp(self):
        self.root = view_tree().getroot()
        self.queries = queries(self.root)

    def test_no_query_uses_a_sourcetype_wildcard(self):
        # D-49. The diagnostic file auto-extracts seventeen business fields with no
        # props.conf, among them `app`, `title`, `id`, `type` and `user` - homonyms of
        # the journal fields, with the inverted meaning. A wildcard mixes both sets
        # without raising anything.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotIn("editacl:*", query)
                self.assertNotRegex(query, r"sourcetype\s*=\s*[\"']?editacl[^\"'\s)]*\*")

    def test_the_journal_and_the_diagnostic_are_reached_through_a_macro(self):
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertRegex(
                    query,
                    r"`(%s)`" % "|".join(SOURCE_MACROS),
                    "the source must be named by a macro, never written out",
                )

    def test_only_the_entitlement_guard_writes_an_index_literal(self):
        for title, query in self.queries:
            with self.subTest(panel=title):
                if title == INDEX_LITERAL_EXEMPT_PANEL:
                    continue
                self.assertNotRegex(query, r"(?<![\w])index\s*=")

    def test_the_exempt_query_only_uses_the_index_literal_to_enumerate_indexes(self):
        # The exemption is narrow on purpose: it covers `| eventcount ... index=* ...`
        # and nothing else. Should the guard ever be rewritten into a plain search on a
        # written-out index, this test fails.
        query = dict((t, q) for t, q in self.queries)[INDEX_LITERAL_EXEMPT_PANEL]
        for occurrence in re.findall(r"[^|]*index\s*=[^|]*", query):
            self.assertIn("eventcount", occurrence)

    def test_every_macro_invoked_is_declared(self):
        declared = set(read_splunk_conf("default", "macros.conf"))
        for title, query in self.queries:
            for name in re.findall(r"`([A-Za-z0-9_]+)`", query):
                with self.subTest(panel=title, macro=name):
                    self.assertIn(name, declared)

    def test_no_query_uses_the_obvious_and_wrong_error_predicate(self):
        # Measured (M1c): the `error` field is present on **every** `outcome` line of
        # the current format, empty value included. `isnotnull(error)` is therefore
        # true on the whole batch - eight objects reported in error out of eight, where
        # there were two. Error selection is done by the statuses.
        #
        # `error!=""` inside a `values(eval(...))` is a different construct: it filters
        # what is aggregated, not what is searched, and it is legitimate. The check
        # therefore targets the predicate position only.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotIn("isnotnull(error)", query)
                self.assertNotRegex(
                    query, r"\|\s*(?:where|search)\b[^|]*\berror\s*!=\s*\"\""
                )

    def test_no_query_counts_objects_through_a_reconstructed_identity(self):
        # Section 15.6: counting is done by counting `outcome` lines. `endpoint` is
        # empty on nearly a quarter of the lines of a heterogeneous batch and
        # `eai_type` on more than three quarters, so a distinct count over either of
        # them is a number that looks right and is not.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotIn("dc(endpoint)", query)
                self.assertNotIn("dc(eai_type)", query)

    def test_no_query_carries_a_field_of_the_previous_journal_format(self):
        # D-46 renamed `host` to `member` and replaced the JSON `null` of `error` by
        # the empty string. A search copied from the measurement report without being
        # adapted would silently read a field that no longer exists.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"(?<![\w.])host(?![\w.])")
                self.assertNotIn('error=="null"', query)
                self.assertNotIn('error="null"', query)

    def test_no_query_builds_an_object_key_by_concatenation(self):
        # Measured collisions (M4a): six on a single batch, two objects of different
        # endpoints merged. Pairing is done `BY endpoint`, like the rollback macro, so
        # that the view and the safety net pair the same way.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"app\s*\.\s*\"[^\"]*\"\s*\.\s*eai_type")
                self.assertNotRegex(query, r"eai_type\s*\.\s*\"[^\"]*\"\s*\.\s*title")

    def test_every_sid_token_is_quoted(self):
        # The error class of D-12: an unquoted parameter truncated by SPL, silently.
        # It cost a rollback that restored one attribute out of three and reported a
        # success.
        for title, query in self.queries:
            for match in re.finditer(r"\$sid\$", query):
                start, end = match.span()
                with self.subTest(panel=title, position=start):
                    self.assertEqual(query[start - 1:start], '"')
                    self.assertEqual(query[end:end + 1], '"')

    def test_the_status_literals_all_exist_in_the_code(self):
        from acltools import model

        declared = set(model.ACL_STATUSES)
        source = view_source()
        literals = set(re.findall(r'status\s*=\s*"([a-z_]+)"', source))
        for group in re.findall(r"status\s+IN\s*\(([^)]*)\)", source):
            literals.update(
                token.strip().strip('"').strip("'")
                for token in group.split(",")
                if token.strip()
            )
        self.assertTrue(literals, "no status literal found: the extractor is broken")
        self.assertEqual(literals - declared, set())

    def test_the_skipped_prefix_matches_at_least_one_declared_status(self):
        from acltools import model

        prefixes = re.findall(r'like\(\s*status\s*,\s*"([a-z_]+)%"\s*\)', view_source())
        self.assertTrue(prefixes, "no status prefix found: the extractor is broken")
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    [s for s in model.ACL_STATUSES if s.startswith(prefix)],
                    "no declared status starts with %r" % prefix,
                )

    def test_the_empty_object_type_is_labelled_wherever_it_is_grouped_on(self):
        # Measured, and named nowhere in the specification before this view: `eai_type`
        # can be empty on a line whose endpoint is resolved and whose status is
        # `updated`. A breakdown by object type that does not label those lines
        # undercounts without a word.
        for title, query in self.queries:
            if "BY" not in query:
                continue
            if not re.search(r"BY[^|]*\beai_type\b|object_type", query):
                continue
            with self.subTest(panel=title):
                self.assertIn('"(not journaled)"', query)

    def test_the_comparison_columns_are_guarded_against_null_equals_null(self):
        # Measured: `null == null` is false in SPL, so an object with no prior state
        # compared to itself comes out CHANGED. Without these guards the most-read
        # column of the view lies on every line that has no prior state.
        query = dict(self.queries)["Objects whose endpoint was resolved"]
        for column in ("read_change", "write_change", "owner_change", "sharing_change"):
            with self.subTest(column=column):
                self.assertRegex(
                    query, r"%s\s*=\s*case\(isnull\(" % column
                )
        self.assertEqual(query.count('"n/a"'), 4)

    def test_the_state_columns_are_aggregated_by_earliest_and_not_by_values(self):
        # MEASURED, on a batch carrying one deliberate duplicate. Section 8.5: an
        # object presented twice produces two `outcome` lines. `values()` merges the
        # prior state of the first pass with the state read back on the second, turns
        # the column multivalued, and reports "=" on an object that did change.
        # `earliest(... ) BY endpoint` is also exactly how the rollback macro pairs, so
        # the view and the safety net now agree on what "before" means.
        query = dict(self.queries)["Objects whose endpoint was resolved"]
        for field in ("before_owner", "after_owner", "before_perms_read",
                      "after_perms_read", "before_perms_write", "after_perms_write",
                      "before_sharing", "after_sharing"):
            with self.subTest(field=field):
                self.assertIn("earliest(%s)" % field, query)
                self.assertNotIn("values(%s)" % field, query)

    def test_the_declared_counters_are_filtered_to_the_counter_fields(self):
        # MEASURED, and it is the trap of this panel: `| fields count_*` does NOT drop
        # the internal fields. `transpose` then emits `_raw`, `_time`, `_indextime`,
        # `_subsecond` and `_sourcetype` as if they were statuses, and the panel
        # reports three MISMATCH rows - "lines are missing from the journal", the most
        # alarming message it can produce - on a perfectly healthy run.
        query = dict(self.queries)["Status breakdown - observed vs declared"]
        self.assertIn('substr(counter, 1, 6) = "count_"', query)

    def test_the_legacy_format_is_excluded_from_every_panel_but_the_two_that_report_it(
        self,
    ):
        # Section 2.3 of the design: legacy lines are excluded, and what is excluded is
        # counted and displayed. The two exceptions are the panel that counts them and
        # the header of a selected run, which must be able to explain an old sid rather
        # than render blank.
        exceptions = {"Legacy-format lines excluded", "Selected run",
                      "Entitlement check", "Runs started with no journal line"}
        for title, query in self.queries:
            if title in exceptions:
                continue
            with self.subTest(panel=title):
                self.assertIn("isnotnull(member)", query)

    def test_the_diagnostic_fields_are_qualified_by_their_sourcetype(self):
        # The one query that reads both sourcetypes. It does not break D-49 - each one
        # is named - but it reintroduces the homonym risk D-49 exists to close. Every
        # field read from the diagnostic side is therefore qualified.
        query = dict(self.queries)["Runs started with no journal line"]
        for field in ("user", "journal", "max_objects"):
            with self.subTest(field=field):
                self.assertRegex(
                    query,
                    r'if\(sourcetype="editacl:diag",\s*%s\s*,' % field,
                )


class TheDeclarationsAgreeWithEachOtherTest(unittest.TestCase):
    """T18 to T26: the renaming done on one side only."""

    def setUp(self):
        self.meta = MetadataTest.read_meta()
        self.authorize = read_splunk_conf("default", "authorize.conf")
        self.macros = read_splunk_conf("default", "macros.conf")

    def test_the_view_is_exported_to_the_system(self):
        stanza = "views/%s" % VIEW_NAME
        self.assertIn(stanza, self.meta)
        self.assertEqual(self.meta[stanza].get("export"), "system")

    def test_the_view_is_readable_by_the_single_declared_role(self):
        stanza = self.meta["views/%s" % VIEW_NAME]["access"]
        read = re.search(r"read\s*:\s*\[([^\]]*)\]", stanza).group(1)
        write = re.search(r"write\s*:\s*\[([^\]]*)\]", stanza).group(1)
        self.assertEqual([r.strip() for r in read.split(",")], [ROLE_NAME])
        self.assertEqual([r.strip() for r in write.split(",")], ["admin"])

    def test_no_class_wide_views_stanza_is_added(self):
        # A `[views]` stanza would export every future view of this app without anyone
        # deciding it.
        self.assertNotIn("views", self.meta)

    def test_the_metadata_stanza_names_the_file_that_exists(self):
        # A stanza pointing at a view that does not exist loads without the slightest
        # error and does exactly nothing.
        self.assertEqual(VIEW_PARTS[-1], "%s.xml" % VIEW_NAME)
        self.assertTrue(os.path.exists(view_path()))

    def test_the_role_is_declared_with_the_capabilities_of_the_decision(self):
        stanza = self.authorize["role_%s" % ROLE_NAME]
        self.assertEqual(stanza.get("search"), "enabled")
        for capability in ("run_collect", "run_mcollect", "schedule_rtsearch"):
            with self.subTest(capability=capability):
                self.assertEqual(stanza.get(capability), "disabled")

    def test_the_role_declares_no_index_entitlement(self):
        # D-44: the absence is normative, so it is tested. Index entitlement belongs to
        # the role management chain, outside this app.
        stanza = self.authorize["role_%s" % ROLE_NAME]
        for key in ("srchIndexesAllowed", "srchIndexesDefault", "srchFilter"):
            with self.subTest(key=key):
                self.assertNotIn(key, stanza)

    def test_the_role_is_not_a_writer(self):
        stanza = self.authorize["role_%s" % ROLE_NAME]
        self.assertNotIn("edit_acl_bulk", stanza)
        self.assertNotIn("importRoles", stanza)

    def test_the_role_is_granted_to_nobody(self):
        # D-44: the app declares it and grants it to no role. A `[role_*]` stanza that
        # imported it would grant it by the back door.
        for name, stanza in self.authorize.items():
            if not name.startswith("role_") or name == "role_%s" % ROLE_NAME:
                continue
            with self.subTest(stanza=name):
                self.assertNotIn(ROLE_NAME, (stanza.get("importRoles") or ""))

    def test_the_role_of_the_metadata_is_the_role_of_authorize_conf(self):
        declared = {
            name[len("role_"):]
            for name in self.authorize
            if name.startswith("role_") and name != "role_admin"
        }
        stanza = self.meta["views/%s" % VIEW_NAME]["access"]
        read = re.search(r"read\s*:\s*\[([^\]]*)\]", stanza).group(1)
        self.assertEqual({r.strip() for r in read.split(",")}, declared)

    def test_the_nav_declares_the_view(self):
        nav = ElementTree.parse(
            os.path.join(REPO_ROOT, "default", "data", "ui", "nav", "default.xml")
        ).getroot()
        names = [node.get("name") for node in nav.findall(".//view")]
        self.assertIn(VIEW_NAME, names)

    def test_the_default_view_of_the_app_is_not_the_dashboard(self):
        # Making the dashboard the default view would land every account without the
        # role on a 404 when opening the root of the app, turning a restricted access
        # into the appearance of a breakage.
        nav = ElementTree.parse(
            os.path.join(REPO_ROOT, "default", "data", "ui", "nav", "default.xml")
        ).getroot()
        defaults = [n.get("name") for n in nav.findall(".//view") if n.get("default")]
        self.assertEqual(defaults, ["search"])

    def test_both_source_macros_are_declared_and_name_their_sourcetype(self):
        expected = {
            "acl_journal_source": "sourcetype=editacl:journal",
            "acl_diag_source": "sourcetype=editacl:diag",
        }
        for name, sourcetype in expected.items():
            with self.subTest(macro=name):
                self.assertIn(name, self.macros)
                definition = self.macros[name]["definition"]
                self.assertIn(sourcetype, definition)
                self.assertNotIn("*", definition)
                self.assertEqual(self.macros[name].get("iseval"), "0")
                self.assertTrue(self.macros[name].get("description", "").strip())

    def test_the_view_is_part_of_the_shipped_archive(self):
        self.assertIn(VIEW_PARTS, LayoutTest.EXPECTED)


class NoShippedSearchWritesItsSourceOutTest(unittest.TestCase):
    """D-51, section 8.3.bis: **every** shipped search names its source by a macro.

    The reserve R-9 of the design named the change-journal saved search; the rollback
    macro had the same flaw and it is the one where it would cost the most. Redirecting
    the journal index would have left the only safety net of an irreversible operation
    returning an EMPTY rollback set, reported as a success.
    """

    #: The definitions of the source macros themselves, which necessarily carry the
    #: index: they are the single place where it is written.
    SOURCE_STANZAS = frozenset(SOURCE_MACROS)

    def test_no_macro_definition_other_than_the_sources_writes_an_index(self):
        macros = read_splunk_conf("default", "macros.conf")
        for name, stanza in macros.items():
            if name in self.SOURCE_STANZAS:
                continue
            with self.subTest(macro=name):
                self.assertNotRegex(stanza.get("definition", ""), r"(?<![\w])index\s*=")

    def test_no_shipped_search_writes_an_index(self):
        searches = read_splunk_conf("default", "savedsearches.conf")
        for name, stanza in searches.items():
            with self.subTest(search=name):
                self.assertNotRegex(stanza.get("search", ""), r"(?<![\w])index\s*=")

    def test_the_search_that_reads_the_journal_names_it_by_the_macro(self):
        searches = read_splunk_conf("default", "savedsearches.conf")
        self.assertIn("`acl_journal_source`", searches["ACL - change journal"]["search"])

    def test_the_rollback_macro_names_the_journal_by_the_macro(self):
        macros = read_splunk_conf("default", "macros.conf")
        self.assertIn(
            "`acl_journal_source`", macros["editacl_rollback(1)"]["definition"]
        )

    def test_the_source_macros_are_exported_to_the_system(self):
        # Same reason as `acl_inventory`: a macro confined to its own app is not
        # resolvable from a view opened in the context of another app.
        meta = read_splunk_conf("metadata", "default.meta")
        self.assertEqual(meta["macros"]["export"], "system")

    def test_the_ingestion_file_no_longer_claims_to_be_the_only_point(self):
        # Section 8.3 said `local/inputs.conf` was "the only configuration point to
        # change". It governs ingestion, not reading. A redirection applied there and
        # not in `local/macros.conf` empties every shipped search without a message.
        with open(
            os.path.join(REPO_ROOT, "default", "inputs.conf"), encoding="utf-8"
        ) as handle:
            text = handle.read()
        self.assertIn("macros.conf", text)
        self.assertNotIn("That is the only configuration point", text)


if __name__ == "__main__":                                           # pragma: no cover
    unittest.main()
