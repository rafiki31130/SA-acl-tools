"""The application-level audit view: structure, tokens, searches, declarations.

A Simple XML dashboard is a normative deliverable exactly like a `.conf` file, and it
fails the same way: **silently**. A panel whose token is never set never appears; a search
that lost its time range runs over all time; a status literal renamed in the code and left
in the view counts zero for ever without one message. None of it shows anywhere but in a
browser, on an instance, at the moment somebody happens to look.

**What this view has that its neighbour does not**, and what most of the controls below
exist for: the question *what will never be undone*. The panel that answers it is
permanent, it comes **before** the run list, and it **invokes the shipped macro** instead
of restating its predicate - two definitions of one notion always drift, and this project
paid for that on 2026-08-10.

The readers are the ones already written: `test_spl_artifacts.read_splunk_conf` for
`.conf` files with their line continuations, `test_app_layout.MetadataTest.read_meta` for
`.meta` files, whose `[]` stanza `configparser` rejects. A second reader would drift from
the first.
"""

import os
import re
import unittest
import xml.etree.ElementTree as ElementTree

from acltools.appacl_model import APP_ACL_STATUSES

from . import REPO_ROOT
from .test_app_layout import MetadataTest
from .test_spl_artifacts import read_splunk_conf

#: Path of the view, repository-relative. Everything else derives from it.
VIEW_PARTS = ("default", "data", "ui", "views", "appacl_runs.xml")

#: The view as Splunk knows it: the file name without its extension. The `.meta` stanza
#: and the `nav` entry must both use exactly this.
VIEW_NAME = "appacl_runs"

#: Read role. Reused from the neighbouring view rather than duplicated (spec section 7).
ROLE_NAME = "editacl_auditor"

#: The two application-level source macros. **DV-3**: they are not the ones of `editacl`,
#: and no search of this view may read the neighbouring sourcetypes.
SOURCE_MACROS = ("app_acl_journal_source", "app_acl_diag_source")

#: The sourcetype the entitlement probe must name, and the only sourcetype literal the
#: view is allowed to carry (spec section 6.2).
JOURNAL_SOURCETYPE = "editappacl:journal"

#: Titles of the eleven panels of the spec, plus the prompt that stands in for the detail
#: panels while no run is selected.
EXPECTED_PANELS = (
    "Entitlement check",
    "Irreversible writes in this window",
    "Runs",
    "Runs started with no journal line",
    "About the estimate",
    "Selected run",
    "Select a run above",
    "Status breakdown - observed vs declared",
    "Stanzas written - before, after, and what a rollback covers",
    "Targets refused or skipped",
    "Errors",
    "What this view cannot show",
)

#: The five panels that need a selected run.
DETAIL_PANELS = (
    "Selected run",
    "Status breakdown - observed vs declared",
    "Stanzas written - before, after, and what a rollback covers",
    "Targets refused or skipped",
    "Errors",
)

#: Panels exempt from the sixty-character rule on a written literal, **named by their
#: title** as the spec requires. The guard rail must direct an action, not merely qualify
#: a state, and its five `case()` strings say what to do.
LONG_LITERAL_EXEMPT = ("Entitlement check",)

#: The only panel allowed to name an index or a sourcetype: it asks whether the journal is
#: readable at all, which cannot be asked through a macro that presumes it is.
INDEX_LITERAL_EXEMPT = "Entitlement check"


def view_path():
    return os.path.join(REPO_ROOT, *VIEW_PARTS)


def read_view():
    with open(view_path(), encoding="utf-8") as handle:
        return handle.read()


def parse_view():
    return ElementTree.parse(view_path()).getroot()


def panels():
    """`{title: panel element}` for every panel of the view."""
    found = {}
    for panel in parse_view().iter("panel"):
        title = panel.find("title")
        if title is not None and title.text:
            found[title.text.strip()] = panel
    return found


def queries():
    """`{panel title: query text}`, one entry per searching panel."""
    found = {}
    for title, panel in panels().items():
        query = panel.find(".//search/query")
        if query is not None and query.text:
            found[title] = query.text
    return found


class TheViewIsWellFormedTest(unittest.TestCase):
    """T1, T2 - a broken XML only shows when somebody opens the page."""

    def test_the_file_exists_and_parses(self):
        self.assertTrue(os.path.exists(view_path()))
        parse_view()

    def test_the_root_is_a_form_because_the_view_carries_inputs(self):
        root = parse_view()
        self.assertEqual(root.tag, "form")
        self.assertEqual(root.get("version"), "1.1")

    def test_the_label_is_present_and_pure_ascii(self):
        label = parse_view().find("label")
        self.assertIsNotNone(label)
        self.assertTrue((label.text or "").strip())
        label.text.encode("ascii")

    def test_the_whole_file_is_pure_ascii(self):
        """An accented character passes the XML parser and fails the language control of
        the repository - in a file nobody rereads."""
        read_view().encode("ascii")


class ThePanelsAreAllThereTest(unittest.TestCase):
    """T3 - a panel dropped during a rework leaves no trace at all."""

    def test_the_expected_panels_are_present_and_no_other(self):
        self.assertEqual(sorted(panels()), sorted(EXPECTED_PANELS))

    def test_the_two_static_notes_carry_html_and_no_search(self):
        for title in ("About the estimate", "What this view cannot show",
                      "Select a run above"):
            with self.subTest(panel=title):
                panel = panels()[title]
                self.assertIsNotNone(panel.find("html"))
                self.assertIsNone(panel.find(".//search"))

    def test_the_irreversible_panel_comes_before_the_run_list(self):
        """**Not a layout preference.** It is the only information of this view whose
        window for acting is already closed when it is read: an auditor opening it after
        a campaign looks first for what can no longer be retrieved."""
        titles = [
            title.text.strip() for title in parse_view().iter("title")
        ]
        self.assertLess(titles.index("Irreversible writes in this window"),
                        titles.index("Runs"))
        self.assertLess(titles.index("Entitlement check"),
                        titles.index("Irreversible writes in this window"))

    def test_the_estimate_note_states_its_five_facts(self):
        """Spec O5: five sentences, visible without any interaction. A number given the
        authority of a screen without its nature would mislead in the reassuring
        direction - measured, this estimate once read zero in the nominal case."""
        html = ElementTree.tostring(panels()["About the estimate"],
                                    encoding="unicode").lower()
        for fact in ("estimate, never a count", "under-count", "lower bound",
                     "private objects are excluded", "has not been measured"):
            with self.subTest(fact=fact):
                self.assertIn(fact, html)

    def test_the_blind_spot_note_names_what_no_source_can_fill(self):
        html = ElementTree.tostring(panels()["What this view cannot show"],
                                    encoding="unicode").lower()
        for spot in ("filtered upstream", "acl_warning", "calling spl", "estimate",
                     "concurrent runs", "non-2xx"):
            with self.subTest(blind_spot=spot):
                self.assertIn(spot, html)


class TheTokenWiringTest(unittest.TestCase):
    """T4 to T8 - five searches launched empty at load, or a panel that never appears."""

    def test_every_detail_panel_depends_on_the_run_token(self):
        for title in DETAIL_PANELS:
            with self.subTest(panel=title):
                self.assertEqual(panels()[title].get("depends"), "$sid$")

    def test_no_overview_panel_depends_on_it(self):
        for title, panel in panels().items():
            if title in DETAIL_PANELS or title == "Select a run above":
                continue
            with self.subTest(panel=title):
                self.assertIsNone(panel.get("depends"))

    def test_exactly_one_panel_rejects_the_run_token(self):
        rejecting = [t for t, p in panels().items() if p.get("rejects") == "$sid$"]
        self.assertEqual(rejecting, ["Select a run above"])

    def test_every_token_used_in_depends_or_rejects_is_set_somewhere(self):
        used = set()
        for panel in panels().values():
            for attribute in ("depends", "rejects"):
                value = panel.get(attribute)
                if value:
                    used.update(re.findall(r"\$(\w+)\$", value))
        source = read_view()
        for token in sorted(used):
            with self.subTest(token=token):
                self.assertRegex(source, r'<set token="%s">' % re.escape(token))

    def test_both_drilldowns_set_the_two_tokens(self):
        """T6. The two panels that carry a drilldown - the run list **and the
        irreversible one** - set `sid` and `form.sid_in`, both to the clicked run."""
        drilldowns = [
            ElementTree.tostring(d, encoding="unicode")
            for d in parse_view().iter("drilldown")
        ]
        self.assertEqual(len(drilldowns), 2)
        for drilldown in drilldowns:
            with self.subTest(drilldown=drilldown[:60]):
                self.assertIn('<set token="sid">$row.sid$</set>', drilldown)
                self.assertIn('<set token="form.sid_in">$row.sid$</set>', drilldown)

    def test_the_irreversible_panel_is_one_of_the_two_that_drill_down(self):
        """An auditor who spots an irreversible write wants the run that produced it
        without going to look for it in another list."""
        self.assertIsNotNone(
            panels()["Irreversible writes in this window"].find(".//drilldown"))
        self.assertIsNotNone(panels()["Runs"].find(".//drilldown"))

    def test_no_drilldown_writes_the_bare_token_of_a_text_input(self):
        """T6bis. An `<input token="X">` binds the displayed value to `$form.X$` and
        rewrites `X` when the widget changes. Setting `X` writes at the far end of the
        wire: the panels open and the field stays empty - the defect the neighbouring
        project shipped before correcting it."""
        inputs = {i.get("token") for i in parse_view().iter("input")
                  if i.get("type") == "text"}
        for drilldown in parse_view().iter("drilldown"):
            for setter in drilldown.iter("set"):
                with self.subTest(token=setter.get("token")):
                    self.assertNotIn(setter.get("token"), inputs)

    def test_the_text_input_carries_no_default(self):
        """T7. An empty `<default>` **defines** the token to the empty string, and a
        token defined to the empty string satisfies `depends`."""
        for element in parse_view().iter("input"):
            if element.get("token") == "sid_in":
                self.assertIsNone(element.find("default"))
                return
        self.fail("the text input is gone")

    def test_emptying_the_field_closes_the_detail_panels(self):
        for element in parse_view().iter("input"):
            if element.get("token") != "sid_in":
                continue
            change = element.find("change")
            self.assertIsNotNone(change)
            unsets = [u.get("token") for u in change.iter("unset")]
            self.assertIn("sid", unsets)
            return
        self.fail("the text input is gone")

    def test_every_search_carries_its_own_time_range(self):
        """T8. A panel without a range runs over all time, and says nothing about it."""
        for title, panel in panels().items():
            search = panel.find(".//search")
            if search is None:
                continue
            with self.subTest(panel=title):
                self.assertIsNotNone(search.find("earliest"))
                self.assertIsNotNone(search.find("latest"))
                self.assertEqual(search.find("earliest").text, "$tr.earliest$")
                self.assertEqual(search.find("latest").text, "$tr.latest$")

    def test_the_time_input_declares_the_shipped_window(self):
        for element in parse_view().iter("input"):
            if element.get("type") == "time":
                default = element.find("default")
                self.assertEqual(default.find("earliest").text, "-7d@d")
                self.assertEqual(default.find("latest").text, "now")
                return
        self.fail("the time input is gone")

    def test_the_fieldset_runs_at_load(self):
        fieldset = parse_view().find("fieldset")
        self.assertEqual(fieldset.get("autoRun"), "true")
        self.assertEqual(fieldset.get("submitButton"), "false")


class TheSearchesAvoidTheMeasuredTrapsTest(unittest.TestCase):
    """T9 to T17 - every one of these controls freezes a trap that was **measured**, most
    of them on the neighbouring project, and each cost a panel that looked healthy."""

    def test_no_query_uses_a_sourcetype_wildcard(self):
        """T9. The app ships four sourcetypes; a wildcard would read the wrong journal."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"sourcetype\s*=\s*[^\s\"]*\*")

    def test_the_guard_rail_names_the_application_level_journal(self):
        """T9, and it is the trap proper to this view: a probe written on
        `editacl:journal` would answer OK while **this** view is blind."""
        query = queries()[INDEX_LITERAL_EXEMPT]
        self.assertIn(JOURNAL_SOURCETYPE, query)
        self.assertNotIn("editacl:journal", query.replace(JOURNAL_SOURCETYPE, ""))

    def test_the_probe_sourcetype_is_the_one_the_source_macro_reads(self):
        """The literal of the probe and the definition of the macro must not drift: the
        first would then attest the readability of a journal the second does not read."""
        macros = read_splunk_conf("default", "macros.conf")
        definition = macros["app_acl_journal_source"]["definition"]
        self.assertIn(JOURNAL_SOURCETYPE, definition)

    def test_only_the_guard_rail_writes_an_index_literal(self):
        """T11. Every other read goes through a source macro, so a redirected index is
        followed by overriding one macro rather than by editing nine searches."""
        for title, query in queries().items():
            if title == INDEX_LITERAL_EXEMPT:
                continue
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"(?<![\w.])index\s*=")

    def test_every_read_goes_through_an_application_level_source_macro(self):
        for title, query in queries().items():
            if title == INDEX_LITERAL_EXEMPT:
                continue
            with self.subTest(panel=title):
                self.assertTrue(
                    any("`%s`" % macro in query for macro in SOURCE_MACROS)
                    or "`app_acl_irreversible(" in query,
                    "%s reads the journal without a source macro" % title,
                )

    def test_no_query_ors_two_source_macros(self):
        """T10. **Measured**, same instance, same window: the parenthesised `OR` form
        returned 9 diagnostic lines and 1 403 journal lines where the `multisearch`
        returned 2 268 and 17 770. The panel then listed nine runs that had written a
        complete journal as having written none - **and gave each of them a cause**."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertNotRegex(
                    query,
                    r"`app_acl_\w+_source`[^\n]*\bOR\b[^\n]*`app_acl_\w+_source`",
                )
                self.assertNotRegex(query, r"\)\s*OR\s*\(\s*`app_acl_\w+_source`")

    def test_the_panel_that_needs_both_sources_uses_a_multisearch(self):
        query = queries()["Runs started with no journal line"]
        self.assertIn("| multisearch", query)
        for macro in SOURCE_MACROS:
            with self.subTest(macro=macro):
                self.assertIn("[search `%s`]" % macro, query)

    def test_no_query_juxtaposes_a_filter_to_a_source_macro(self):
        """T10bis. A legitimate override may end with a piped command - the README
        invites one - and a juxtaposed term then lands in **that command's arguments**.
        Measured: seven detail panels returned *The expression is malformed* while the
        panels composing with a pipe went through, so the operator would have concluded
        the fix did not work."""
        for title, query in queries().items():
            flat = " ".join(query.split())
            for macro in SOURCE_MACROS:
                marker = "`%s`" % macro
                for match in re.finditer(re.escape(marker) + r"\s*([^\s|\]]+)", flat):
                    with self.subTest(panel=title, after=match.group(1)):
                        self.fail(
                            "%s juxtaposes %r to %s instead of composing with | search"
                            % (title, match.group(1), marker))

    def test_the_transpose_is_followed_by_a_positive_filter(self):
        """T10ter. `| fields count_*` does **not** drop the internal fields: `_time`,
        `_raw` and their kin go through, the transpose turns them into rows, and the panel
        displays them **as statuses**. Measured on the healthiest run of a campaign: three
        rows carrying the mismatch message, on an intact journal."""
        for title, query in queries().items():
            if "transpose" not in query:
                continue
            with self.subTest(panel=title):
                self.assertIn('substr(counter, 1, 6) == "count_"', query)
                self.assertNotRegex(query, r"transpose[\s\S]{0,400}?\|\s*fields\s+count_")

    def test_no_query_carries_an_unpaired_dollar(self):
        """T10quater. `$` is the token delimiter of Simple XML, and `$$` is not measured
        on this platform: a regular-expression end anchor must be written without one."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertEqual(query.count("$") % 2, 0)

    def test_no_query_counts_targets_through_a_reconstructed_identity(self):
        """T14. A target presented twice yields **two** outcome lines and **one** write:
        counting distinct endpoints and counting lines gives two different numbers, both
        right, under names that do not distinguish them."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"dc\s*\(\s*endpoint\s*\)")
                self.assertNotRegex(query, r"dc\s*\(\s*stanza\w*\s*\)")

    def test_the_only_distinct_count_of_the_view_counts_applications(self):
        found = [
            (title, match)
            for title, query in queries().items()
            for match in re.findall(r"dc\s*\(\s*(\w+)\s*\)", query)
        ]
        self.assertEqual(found, [("Runs", "app")])

    def test_no_column_says_objects_without_saying_estimate(self):
        """T15. The one quantity of this view that speaks of knowledge objects is the one
        that is **not measured**."""
        for title, query in queries().items():
            for column in re.findall(r"\bAS\s+\"?([\w:.]+)\"?", query):
                if "object" not in column.lower():
                    continue
                with self.subTest(panel=title, column=column):
                    self.assertIn("estimate", column.lower())

    def test_no_state_column_is_aggregated_with_values(self):
        """T15bis. Measured: `values()` on a state column returns a multivalue when a
        target is presented twice, and the most-read column of the view then displayed
        *no change* on an object that had changed."""
        for title, query in queries().items():
            for field in re.findall(r"values\s*\(\s*([\w:.]+)\s*\)", query):
                with self.subTest(panel=title, field=field):
                    self.assertFalse(
                        field.startswith(("before_", "inherited_", "after_")),
                        "%s aggregates the state column %s with values()"
                        % (title, field),
                    )

    def test_the_before_and_the_inherited_are_never_merged(self):
        """T16. **The hole of the 515 objects, on the reading side.** Displaying an
        inherited value in a *before* column would suggest a restorable state that never
        existed. The two sets are selected by `reversible`, never coalesced one on the
        other."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"coalesce\s*\(\s*before_\w+\s*,\s*inherited_")
                self.assertNotRegex(query, r"coalesce\s*\(\s*inherited_\w+\s*,\s*before_")
                self.assertNotRegex(query, r"values\s*\([^)]*before_[^)]*inherited_")

    def test_the_stanzas_panel_selects_the_two_sets_by_reversibility(self):
        query = queries()["Stanzas written - before, after, and what a rollback covers"]
        self.assertRegex(query, r'if\s*\(\s*reversible\s*==\s*"true"')
        self.assertIn("(inherited)", query)

    def test_every_run_token_is_quoted(self):
        """T17. The error class of an unquoted parameter truncated by SPL: on this
        project it produced a restore that reported a success and restored nothing."""
        for title, query in queries().items():
            for match in re.finditer(r"\$sid\$", query):
                start = match.start()
                with self.subTest(panel=title, at=start):
                    self.assertEqual(query[start - 1], '"')
                    self.assertEqual(query[match.end()], '"')

    def test_the_run_filter_composes_with_a_pipe(self):
        for title, query in queries().items():
            if "$sid$" not in query:
                continue
            with self.subTest(panel=title):
                self.assertRegex(query, r'\|\s*search\s+sid="\$sid\$"')

    def test_no_query_uses_the_obvious_and_wrong_error_predicate(self):
        """T12. The contract guarantees `error` is the **empty string**, never null: a
        predicate on its presence would return the whole batch."""
        for title, query in queries().items():
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"search[^|]*isnotnull\s*\(\s*error\s*\)")
                self.assertNotRegex(query, r'search[^|]*error\s*!=\s*""')

    def test_every_status_literal_exists_in_the_core(self):
        """T13. The status enumeration is **read from the module**, never recopied here:
        a status renamed in the code and left in the view would count zero for ever,
        in silence."""
        declared = set(APP_ACL_STATUSES)
        self.assertTrue(declared)
        for title, query in queries().items():
            for literal in re.findall(r'status\s*==\s*"(\w+)"', query):
                with self.subTest(panel=title, status=literal):
                    self.assertIn(literal, declared)
            for group in re.findall(r'status IN \(([^)]+)\)', query):
                for literal in re.findall(r'"(\w+)"', group):
                    with self.subTest(panel=title, status=literal):
                        self.assertIn(literal, declared)

    def test_every_macro_invoked_is_declared(self):
        """T18. A macro renamed on one side only leaves a panel that returns nothing."""
        declared = {
            name.split("(")[0] for name in read_splunk_conf("default", "macros.conf")
        }
        for title, query in queries().items():
            for macro in re.findall(r"`([a-z_]+)(?:\(|`)", query):
                with self.subTest(panel=title, macro=macro):
                    self.assertIn(macro, declared)

    def test_the_irreversible_panel_invokes_the_macro_rather_than_restating_it(self):
        """**Spec section 2.1**, and the reason this view exists at all. Two definitions
        of one notion drift; a safety net and a view that do not pair the same way is the
        defect this project paid for on 2026-08-10."""
        query = queries()["Irreversible writes in this window"]
        self.assertIn("`app_acl_irreversible(*)`", query)
        self.assertNotIn("reversible=\"false\"", query.replace("acl_reversible", ""))
        self.assertNotIn("phase=\"intent\"", query)


class TheCellsStayReadableTest(unittest.TestCase):
    """T15ter - the prose in a cell, unreadable, raised at the rendering audit of the
    neighbouring project. An explanation is read once, beside the table, not once per
    row."""

    MAX_LITERAL = 60
    MAX_COLUMNS = 13

    def test_no_written_literal_exceeds_sixty_characters(self):
        for title, query in queries().items():
            if title in LONG_LITERAL_EXEMPT:
                continue
            for literal in re.findall(r'"([^"]*)"', query):
                if literal.startswith("$") or literal.endswith("$"):
                    continue
                with self.subTest(panel=title, literal=literal[:40]):
                    self.assertLessEqual(len(literal), self.MAX_LITERAL)

    def test_the_exemption_is_named_by_the_title_of_its_panel(self):
        for title in LONG_LITERAL_EXEMPT:
            with self.subTest(panel=title):
                self.assertIn(title, panels())

    def test_no_table_carries_more_than_thirteen_columns(self):
        for title, query in queries().items():
            for match in re.finditer(r"\|\s*table\s+([^\n|]+)", query):
                columns = [c for c in match.group(1).split(",") if c.strip()]
                with self.subTest(panel=title, columns=len(columns)):
                    self.assertLessEqual(len(columns), self.MAX_COLUMNS)

    def test_every_panel_that_needs_an_explanation_carries_it_beside_the_table(self):
        for title in ("Runs started with no journal line",
                      "Stanzas written - before, after, and what a rollback covers",
                      "Status breakdown - observed vs declared"):
            with self.subTest(panel=title):
                self.assertIsNotNone(panels()[title].find("html"))


class ACauseIsAlwaysAccompaniedByItsEvidenceTest(unittest.TestCase):
    """T15quater - a cause the reader cannot check is a **verdict**. The panel that
    attributes one publishes the columns it derives from, and its domain carries a value
    meaning *nothing was established*."""

    def test_the_cause_panel_publishes_its_evidence_columns(self):
        query = queries()["Runs started with no journal line"]
        self.assertIn("fatal_lines", query)
        self.assertIn("journal_open_failures", query)
        table = re.search(r"\|\s*table\s+([^\n|]+)", query).group(1)
        for column in ("cause", "fatal_lines", "journal_open_failures"):
            with self.subTest(column=column):
                self.assertIn(column, table)

    def test_the_cause_domain_carries_a_value_meaning_nothing_established(self):
        query = queries()["Runs started with no journal line"]
        self.assertIn('"no_write_recorded"', query)

    def test_the_diagnostic_fields_are_re_extracted_in_the_view(self):
        """Search-time extractions only apply where `props` is exported: a view relying
        on them loses its fields depending on the app context, **without an error**."""
        query = queries()["Runs started with no journal line"]
        self.assertGreaterEqual(query.count("| rex field=diag_raw"), 4)

    def test_the_sid_extraction_is_anchored_on_non_space(self):
        """Measured: a `.+` absorbs the sentence that follows and produces two rows for
        one run, the usable one carrying the wrong cause."""
        query = queries()["Runs started with no journal line"]
        self.assertIn("sid=(?<diag_sid>\\S+)", query.replace("&lt;", "<")
                      .replace("&gt;", ">"))

    def test_the_fatal_count_reads_a_level_and_not_a_sentence(self):
        """Measured: counting an English wording over a corpus older than a language
        switch returned 1 line out of 19 - the right line, the wrong cause."""
        query = queries()["Runs started with no journal line"]
        self.assertIn('diag_level=="CRITICAL"', query)


class TheDeclarationsAgreeWithEachOtherTest(unittest.TestCase):
    """T19 to T22 - the view, the metadata, the role and the nav must name one thing."""

    @classmethod
    def setUpClass(cls):
        cls.meta = MetadataTest.read_meta()

    def test_the_metadata_declares_the_view_exported_to_the_system(self):
        """The app carries `is_visible = 0`: a view reachable only from a hidden app is
        unreachable in practice. Measured on the neighbouring view - exported it answers
        200 from a third-party app context, `export = none` answers 404."""
        stanza = self.meta.get("views/%s" % VIEW_NAME)
        self.assertIsNotNone(stanza, "the view is not declared in metadata")
        self.assertEqual(stanza.get("export"), "system")

    def test_the_read_and_write_lists_are_exact(self):
        stanza = self.meta["views/%s" % VIEW_NAME]
        self.assertEqual(stanza.get("access"),
                         "read : [ %s ], write : [ admin ]" % ROLE_NAME)

    def test_the_metadata_stanza_names_a_file_that_exists(self):
        """A stanza pointing at a view that does not exist loads without the slightest
        error and does exactly nothing."""
        self.assertEqual(VIEW_PARTS[-1], "%s.xml" % VIEW_NAME)
        self.assertTrue(os.path.exists(view_path()))

    def test_the_read_role_is_the_one_authorize_declares(self):
        """T21. A role renamed on one side only leaves a view nobody can read."""
        roles = read_splunk_conf("default", "authorize.conf")
        self.assertIn("role_%s" % ROLE_NAME, roles)

    def test_the_nav_declares_the_view(self):
        with open(os.path.join(REPO_ROOT, "default", "data", "ui", "nav",
                               "default.xml"), encoding="utf-8") as handle:
            nav = handle.read()
        self.assertIn('<view name="%s" />' % VIEW_NAME, nav)

    def test_the_neighbouring_view_is_untouched(self):
        """T23. This increment adds a view; it does not edit the other one."""
        import hashlib

        path = os.path.join(REPO_ROOT, "default", "data", "ui", "views",
                            "editacl_runs.xml")
        with open(path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(
            digest,
            "eb84f6dddce76b98558ae0e8d6b776f780fae613ec4694a78328c2dab19d537a",
            "editacl_runs.xml changed: this increment must not touch it",
        )


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
