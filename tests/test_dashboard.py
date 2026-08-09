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
#: It is the entitlement guard, and its two subsearches enumerate what no macro can
#: carry: `| eventcount summarize=false index=* index=_*` lists the indexes the running
#: role may search, and `| tstats ... WHERE (index=* OR index=_*)
#: sourcetype=editacl:journal BY index` locates the journal across them. Neither is a
#: source designation - there is nothing for a macro to name - and no other construction
#: answers the questions D-48 asks. The exception is therefore named here rather than
#: left to a reader's judgement.
INDEX_LITERAL_EXEMPT_PANEL = "Entitlement check"

#: Title of the one panel that reads the diagnostic sourcetype.
DIAGNOSTIC_PANEL = "Runs started with no journal line"

#: The commands the view is allowed to use, exhaustively.
#:
#: A **positive** list, and the difference matters: a forbidden-command list only stops
#: what it already knows about. The audit of 2026-08-09 established the cost of the
#: negative form - a mutation adding `| collect index=summary` was caught, but nothing
#: would have caught the next side-effecting command nobody had thought of. Any command
#: outside this set has to be added here deliberately, which is exactly the review the
#: rule exists to force.
VIEW_ALLOWED_COMMANDS = frozenset(
    (
        "addinfo", "append", "appendcols", "convert", "eval", "eventcount",
        "eventstats", "fields", "rename", "rex", "search", "sort", "stats",
        "table", "transpose", "tstats", "where",
    )
)

#: Commands that write, send, or run something. Applied to **every** shipped SPL, macros
#: and saved searches included, where a positive list is impractical.
SIDE_EFFECTING_COMMANDS = frozenset(
    (
        "collect", "mcollect", "meventcollect", "tscollect", "summaryindex",
        "outputlookup", "outputcsv", "outputtext", "sendemail", "sendalert",
        "script", "runshell", "run", "delete", "crawl", "dump", "external",
    )
)

#: Attributes the view is allowed to carry, per element, exhaustively.
#:
#: Simple XML loads client-side code through `script` and `stylesheet` on the root, and
#: through any `on*` handler. None of them is used, so the list is closed rather than
#: the vectors enumerated: an attribute that appears without being declared here fails,
#: whatever it is called.
VIEW_ALLOWED_ATTRIBUTES = {
    "form": frozenset(("version",)),
    "fieldset": frozenset(("autoRun", "submitButton")),
    "input": frozenset(("searchWhenChanged", "token", "type")),
    "condition": frozenset(("match",)),
    "set": frozenset(("token",)),
    "unset": frozenset(("token",)),
    "option": frozenset(("name",)),
    "panel": frozenset(("depends", "rejects")),
}


def spl_commands(query):
    """Command name opening each pipeline segment of `query`.

    Deliberately crude - it is a control, not a parser. A leading `[` is stripped so
    that subsearches are read too.
    """
    names = set()
    for segment in query.split("|"):
        token = segment.strip().lstrip("[").strip()
        match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)", token)
        if match:
            names.add(match.group(1))
    return names


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
        # The exemption is narrow on purpose: it covers the two commands that enumerate
        # - `eventcount`, which lists the searchable indexes, and `tstats`, which locates
        # the journal across them - and nothing else. Should the guard ever be rewritten
        # into a plain search on a written-out index, this test fails.
        query = dict((t, q) for t, q in self.queries)[INDEX_LITERAL_EXEMPT_PANEL]
        for occurrence in re.findall(r"[^|]*index\s*=[^|]*", query):
            with self.subTest(occurrence=occurrence.strip()[:60]):
                self.assertTrue(
                    "eventcount" in occurrence or "tstats" in occurrence,
                    "an index literal outside the two enumerating commands",
                )

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


class TheDiagnosticIsReadAsFreeTextTest(unittest.TestCase):
    """A-1 of the audit of 2026-08-09. The class of error is worth stating in full.

    The diagnostic file is FREE TEXT (section 8.1). Qualifying its fields by their
    sourcetype - what the first version of this panel did - closes the homonym risk of
    D-49 and nothing else: it says which sourcetype a field is read FROM, never whether
    the value is the one the line meant to carry.

    MEASURED on a lab, 2 201 diagnostic lines: the automatic key/value extractor
    swallows the whole message into `sid` on a fatal line - 11 polluted values out of
    259 distinct, up to 144 characters - and into `max_objects` on 5 lines out of 241.
    The panel rendered TWO rows for ONE run, and the row carrying the usable sid carried
    the WRONG cause.

    The fix has two layers, and this class checks both are present and agree:

      - `default/props.conf` turns the automatic extractor off for the sourcetype and
        declares what it gives back. That fixes it at the source, for every consumer;
      - the panel rebuilds its own fields from `_raw` with the same anchored
        expressions, so it holds even where the props stanza does not apply.
    """

    #: Fields the panel reads from the diagnostic, and the name it rebuilds them under.
    DIAGNOSTIC_FIELDS = ("sid", "user", "journal", "max_objects")

    def setUp(self):
        self.root = view_tree().getroot()
        self.query = dict(queries(self.root))[DIAGNOSTIC_PANEL]
        self.props = read_splunk_conf("default", "props.conf")

    def test_the_diagnostic_sourcetype_has_automatic_extraction_turned_off(self):
        # The single line that removes the class rather than one instance of it.
        self.assertEqual(self.props["editacl:diag"].get("KV_MODE"), "none")

    def test_every_field_the_panel_needs_has_a_declared_extraction(self):
        declared = " ".join(
            value
            for key, value in self.props["editacl:diag"].items()
            if key.startswith("EXTRACT-")
        )
        self.assertTrue(declared, "no declared extraction on the diagnostic sourcetype")
        for field in self.DIAGNOSTIC_FIELDS:
            with self.subTest(field=field):
                self.assertIn("(?<%s>" % field, declared)

    def test_the_declared_sid_extraction_cannot_absorb_a_message(self):
        # `\S+` is the whole guarantee: a sid carries no space, so a sentence cannot end
        # up inside it. A `.*` or a `[^=]+` here would reopen the defect.
        expression = self.props["editacl:diag"]["EXTRACT-editacl_diag_run"]
        self.assertTrue(expression.startswith("^"), expression)
        self.assertIn("sid=(?<sid>\\S+)", expression)

    def test_the_panel_restricts_the_raw_line_to_the_diagnostic_sourcetype(self):
        self.assertIn(
            'eval diag_raw = if(sourcetype="editacl:diag", _raw, null())', self.query
        )

    def test_the_panel_rebuilds_the_aggregation_key_before_aggregating(self):
        rebuild = self.query.find("eval sid = coalesce(diag_sid, sid)")
        aggregate = self.query.find("BY sid")
        self.assertNotEqual(rebuild, -1, "the panel does not rebuild sid")
        self.assertNotEqual(aggregate, -1)
        self.assertLess(rebuild, aggregate, "sid is rebuilt after it is aggregated on")

    def test_the_panel_and_the_declared_extraction_use_the_same_expression(self):
        # Two expressions that drift apart would make the panel and every other consumer
        # disagree on what a sid is, without a message.
        declared = self.props["editacl:diag"]["EXTRACT-editacl_diag_run"]
        self.assertIn(declared.replace("(?<sid>", "(?<diag_sid>"), self.query)

    def test_no_diagnostic_field_is_read_from_an_extracted_field(self):
        for field in self.DIAGNOSTIC_FIELDS:
            with self.subTest(field=field):
                self.assertIn("rex field=diag_raw", self.query)
                self.assertNotRegex(
                    self.query,
                    r'if\(sourcetype="editacl:diag",\s*%s\s*,' % field,
                    "%s is read from an extracted field, not from the raw line" % field,
                )

    def test_the_rebuilt_fields_are_the_ones_the_panel_aggregates(self):
        for field in ("user", "journal", "max_objects"):
            with self.subTest(field=field):
                self.assertIn("values(diag_%s)" % field, self.query)


class TheSearchesAvoidTheMeasuredTrapsAgainTest(unittest.TestCase):
    """Continuation of `TheSearchesAvoidTheMeasuredTrapsTest`."""

    def setUp(self):
        self.root = view_tree().getroot()
        self.queries = queries(self.root)

    def test_the_guard_names_the_sourcetype_its_source_macro_names(self):
        # The guard locates the journal by naming its sourcetype without naming an
        # index - the only way to answer "where do the lines actually land". The literal
        # is therefore tied to the macro definition, so the two cannot drift apart.
        macros = read_splunk_conf("default", "macros.conf")
        definition = macros["acl_journal_source"]["definition"]
        sourcetype = re.search(r"sourcetype=(\S+)", definition).group(1)
        query = dict(self.queries)[INDEX_LITERAL_EXEMPT_PANEL]
        self.assertIn("sourcetype=%s" % sourcetype, query)


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

    #: `default/authorize.conf` in full, key by key. Anything else is a defect.
    #:
    #: The audit of 2026-08-09 (A-7) passed a mutation adding `admin_all_objects =
    #: enabled` to the read role through 658 tests: every control checked that the
    #: EXPECTED keys carried the expected value, none checked that the stanza carried
    #: NOTHING ELSE. On a role whose contractual statement is closed - section 15.4:
    #: `search`, and three refusals - the exhaustive form is the natural one.
    EXPECTED_AUTHORIZE = {
        "capability::edit_acl_bulk": {},
        "role_admin": {"edit_acl_bulk": "enabled"},
        "role_editacl_auditor": {
            "search": "enabled",
            "run_collect": "disabled",
            "run_mcollect": "disabled",
            "schedule_rtsearch": "disabled",
        },
    }

    def test_the_role_is_declared_with_the_capabilities_of_the_decision(self):
        stanza = self.authorize["role_%s" % ROLE_NAME]
        self.assertEqual(stanza.get("search"), "enabled")
        for capability in ("run_collect", "run_mcollect", "schedule_rtsearch"):
            with self.subTest(capability=capability):
                self.assertEqual(stanza.get(capability), "disabled")

    def test_authorize_conf_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(
            {name: dict(stanza) for name, stanza in self.authorize.items()},
            self.EXPECTED_AUTHORIZE,
        )

    def test_no_stanza_of_authorize_conf_grants_an_administrative_capability(self):
        # Second line, and independent of the enumeration above: it names the class
        # rather than the list, so a role stanza added in a future increment is caught
        # by this one even before anybody thinks to extend `EXPECTED_AUTHORIZE`.
        forbidden = (
            "admin_all_objects", "edit_roles", "edit_roles_grantable", "edit_user",
            "edit_indexer_cluster", "edit_search_server", "edit_server", "edit_tcp",
            "edit_udp", "edit_scripted", "edit_deployment_server", "rest_apps_management",
            "run_debug_commands", "dispatch_rest_to_indexers", "edit_forwarders",
        )
        for name, stanza in self.authorize.items():
            if not name.startswith("role_"):
                continue
            for capability in forbidden:
                with self.subTest(stanza=name, capability=capability):
                    self.assertNotIn(capability, stanza)

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


class TheGuardRailSeesMoreThanAnEmptyWindowTest(unittest.TestCase):
    """A-2 of the audit of 2026-08-09.

    The guard of section 15.5 only fired on `journal_events = 0`. MEASURED on a lab:
    redirect the journal in `local/inputs.conf` without overriding `local/macros.conf`,
    and the panel answered `OK - the journal is readable and carries events in this
    window` - because lines older than the redirection were still in reach - while the
    run list below stopped at the date of the redirection without a word. A view that
    lists runs reassures where an empty one at least asks a question.

    What is frozen here is that the panel now carries **two signals besides the empty
    window**, and that each is worded for what it proves. The tests cannot exercise
    Splunk; what they can do is prevent the two signals from being quietly removed, and
    prevent the wording from hardening into a diagnosis the construction does not
    support.
    """

    def setUp(self):
        self.root = view_tree().getroot()
        self.query = dict(queries(self.root))[INDEX_LITERAL_EXEMPT_PANEL]

    def test_the_panel_reports_the_date_of_the_most_recent_journal_line(self):
        self.assertIn("max(_time) AS last_journal_event", self.query)
        self.assertIn("last_journal_event", self.query.split("| table", 1)[1])

    def test_the_panel_locates_the_journal_across_the_searchable_indexes(self):
        self.assertIn("tstats", self.query)
        self.assertIn("values(index) AS journal_found_in", self.query)
        self.assertIn("values(index) AS journal_read_from", self.query)

    def test_both_index_sets_are_shown_side_by_side(self):
        columns = self.query.split("| table", 1)[1]
        self.assertIn("journal_read_from", columns)
        self.assertIn("journal_found_in", columns)

    def test_a_line_outside_what_the_view_reads_changes_the_state(self):
        self.assertRegex(
            self.query,
            r"unread_events\s*>\s*0\s*OR\s*found_index_count\s*>\s*read_index_count",
        )

    def test_a_silent_end_of_window_changes_the_state(self):
        self.assertIn("silent_tail_pct", self.query)
        self.assertRegex(self.query, r"silent_tail_pct\s*>\s*\d+")

    def test_the_window_bounds_come_from_the_search_and_not_from_a_constant(self):
        # `addinfo` is what makes the silence relative to the window the operator asked
        # for. A hard-coded duration would be right for one time range and wrong for the
        # rest, silently.
        self.assertIn("| addinfo", self.query)
        self.assertIn("info_max_time", self.query)
        self.assertIn("info_min_time", self.query)

    def test_the_silence_is_reported_and_not_diagnosed(self):
        # The wording is normative. This panel exists because a confident and wrong
        # message is worse than an empty page; replacing the disclaimer by a verdict
        # would recreate the defect one level up.
        self.assertIn("CANNOT TELL THOSE TWO APART", self.query)

    def test_the_ok_state_no_longer_rests_on_a_non_empty_count_alone(self):
        # The defect in one line: `journal_events > 0` was the FIRST branch of the case,
        # so it won over everything else. Whatever the ordering becomes, the count alone
        # must no longer be able to produce the OK state.
        branches = re.findall(r'([^,()]*),\s*"OK[^"]*"', self.query)
        self.assertTrue(branches, "no OK branch found: the extractor is broken")
        for branch in branches:
            with self.subTest(branch=branch.strip()):
                self.assertNotRegex(branch, r"journal_events\s*>\s*0")


class TheViewLoadsNoCodeAndNoExternalResourceTest(unittest.TestCase):
    """A-7 of the audit of 2026-08-09, second half.

    A mutation adding `script="evil.js"` to the `<form>` passed the 658 tests of the
    increment: the structural controls checked the root element, the version, the label
    and the ASCII, none checked what the root element was allowed to CARRY.

    Simple XML loads client-side code through `script` and `stylesheet` on the root, and
    a `<html>` panel can carry markup. The controls below are exhaustive by
    construction - a closed list of attributes per element - rather than a list of known
    vectors, because the point of A-7 is precisely that a list of known vectors is only
    as good as the imagination of whoever wrote it.
    """

    def setUp(self):
        self.root = view_tree().getroot()

    def test_no_element_carries_an_attribute_that_is_not_declared(self):
        for element in self.root.iter():
            allowed = VIEW_ALLOWED_ATTRIBUTES.get(element.tag, frozenset())
            for attribute in element.keys():
                with self.subTest(element=element.tag, attribute=attribute):
                    self.assertIn(attribute, allowed)

    def test_the_view_carries_no_element_that_can_load_anything(self):
        for tag in ("script", "style", "link", "iframe", "object", "embed", "applet"):
            with self.subTest(tag=tag):
                self.assertEqual(self.root.findall(".//%s" % tag), [])

    def test_the_view_references_no_external_resource(self):
        source = view_source()
        for pattern in ("http://", "https://", "ftp://", "data:", "javascript:", "//cdn"):
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, source)

    def test_the_view_carries_no_event_handler(self):
        # `on*` attributes are the third way into client-side code, and they are not
        # caught by naming `script` and `stylesheet`.
        for element in self.root.iter():
            for attribute in element.keys():
                with self.subTest(element=element.tag, attribute=attribute):
                    self.assertFalse(attribute.lower().startswith("on"))


class NoShippedSearchHasASideEffectTest(unittest.TestCase):
    """A-7 of the audit of 2026-08-09, third half - the one nobody asked for.

    The increment detected the mutation that added `| collect index=summary` to a panel.
    It detected that command, and only that command. A read-only role that runs a view
    carrying a writing command is an elevation, whichever command it is.

    Two forms of control, because the two bodies of SPL do not admit the same one:

      - the **view** is checked against a closed list of allowed commands. Its eleven
        queries are read-only by design and their vocabulary is small;
      - the **macros and saved searches** cannot be: `acl_inventory_base` legitimately
        drives `| map` over `| rest`, and `editacl_rollback_apply` legitimately ends on
        `| editacl dryrun=f`, which is the one shipped artifact whose job is to write.
        Those are checked against the class of side-effecting commands instead, and the
        `| rest` invocation is checked to be a read.
    """

    def all_shipped_spl(self):
        found = []
        for title, query in queries(view_tree().getroot()):
            found.append(("view panel %s" % title, query))
        for name, stanza in read_splunk_conf("default", "macros.conf").items():
            found.append(("macro %s" % name, stanza.get("definition", "")))
        for name, stanza in read_splunk_conf("default", "savedsearches.conf").items():
            found.append(("saved search %s" % name, stanza.get("search", "")))
        return found

    def test_the_view_uses_no_command_outside_the_declared_set(self):
        for title, query in queries(view_tree().getroot()):
            for command in spl_commands(query):
                with self.subTest(panel=title, command=command):
                    self.assertIn(command, VIEW_ALLOWED_COMMANDS)

    def test_no_shipped_search_invokes_a_side_effecting_command(self):
        for label, spl in self.all_shipped_spl():
            for command in spl_commands(spl):
                with self.subTest(spl=label, command=command):
                    self.assertNotIn(command, SIDE_EFFECTING_COMMANDS)

    def test_no_shipped_search_drives_the_rest_endpoint_in_write(self):
        # `| rest` is a read by default and stays one. A `method=POST` there would turn
        # a search into a mutation of the platform, from a role that may only search.
        for label, spl in self.all_shipped_spl():
            if "rest " not in spl:
                continue
            with self.subTest(spl=label):
                self.assertNotRegex(spl, r"method\s*=\s*(?i:post|put|delete)")

    def test_the_one_writing_macro_is_the_one_that_says_so(self):
        macros = read_splunk_conf("default", "macros.conf")
        writers = [
            name
            for name, stanza in macros.items()
            if re.search(r"\|\s*editacl\b", stanza.get("definition", ""))
        ]
        self.assertEqual(writers, ["editacl_rollback_apply(1)"])


if __name__ == "__main__":                                           # pragma: no cover
    unittest.main()
