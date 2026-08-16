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

#: Their application-level counterparts (v4.3 section 11.1, **DV-3**). They are a
#: **separate** tuple and not two more entries in the one above, because the two are used
#: for two different things: the view's panels must name one of `SOURCE_MACROS` and only
#: those - a panel counting objects that read the stanza journal would absorb one unit of
#: account into the other - while the "no macro writes an index" sweep must spare all
#: four, they being the four places where an index is legitimately written out.
APP_SOURCE_MACROS = ("app_acl_journal_source", "app_acl_diag_source")

#: Titles of the twelve panels, verbatim. Eleven carry a search; `What this view cannot
#: show` is a static panel. The prompt panel carries no title and is checked separately.
EXPECTED_PANEL_TITLES = (
    "Entitlement check",
    "Runs started with no journal line",
    "Runs",
    "Selected run",
    "Status breakdown - observed vs declared",
    "HTTP code breakdown",
    "Breakdown by application and object type",
    "ACL change breakdown",
    "Objects whose endpoint was resolved",
    "Events refused before endpoint resolution",
    "Errors",
    "What this view cannot show",
)

#: Panels that carry a prose block ALONGSIDE their table, rather than in their cells.
#:
#: Seen on screen by the sponsor, the first rendering feedback this project ever got: a
#: sentence written into a table cell wraps to one word per line in a narrow column, one
#: row then fills a screen, and the columns to its right are pushed out of sight. These
#: two panels need an explanation; it is read once, above the table, instead of once per
#: row.
PANELS_WITH_A_PROSE_BLOCK = (
    "Runs started with no journal line",
    "ACL change breakdown",
)

#: Ceiling on the length of a value a table CELL may carry, in characters.
#:
#: Not a measurement of the rendered width - no test can reach that - but the crude
#: control that separates a label from a paragraph. Everything the searches write into a
#: cell is a code, a name, a number or a date; the one place a long sentence is
#: legitimate is the entitlement guard, whose state string section 15.5 makes normative,
#: and it is named as an exemption rather than left to judgement.
MAX_CELL_LITERAL = 60
CELL_LITERAL_EXEMPT_PANELS = ("Entitlement check",)

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
        "eventstats", "fields", "multisearch", "mvexpand", "rename", "rex",
        "search", "sort", "stats", "table", "transpose", "tstats", "where",
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

    def test_the_panels_that_need_an_explanation_carry_it_beside_their_table(self):
        # The rule the sponsor's first look at the rendered page established: prose goes
        # next to the table, never inside it.
        found = {
            panel_title(panel)
            for panel in panels(self.root)
            if panel.find("html") is not None and panel.findall(".//query")
        }
        self.assertEqual(sorted(found), sorted(PANELS_WITH_A_PROSE_BLOCK))

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
        "ACL change breakdown",
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
        """A click sets the panel token and the **state** of the text box.

        The two names are not symmetrical, and the asymmetry is the whole point.

        `sid` is the token the seven detail panels hang on through `depends`. The
        drilldown sets it directly rather than relying on the input to relay it: if
        the box never reacted, the panels would still open, and the view would stay
        usable by hand. That is the failure mode this ordering buys.

        `form.sid_in` is the state of the box itself. An `<input token="X">` **does
        not read** `X`. The dashboard framework binds the widget value to the token
        `$form.X$` and writes `X` back once the widget changes - `X` is what the input
        *produces*, not what it *reads*. The first version of this drilldown set `X`
        (`sid_in`), that is the far end of the wire, and the box stayed empty on
        click. The `form.` form is also what a deep link uses in the query string,
        so click and link now travel the same path.

        Verified on the shipped framework of the target platform rather than assumed:
        the dashboard bundle builds the input binding as `"$form." + token + "$"`,
        and a drilldown `<set>` writes the token name **verbatim** into the token
        model, adding no prefix of its own. Splunk's own Monitoring Console ships a
        view that drives another input the same way. What no parser can check is the
        click itself - see the validation debt in the README.
        """
        for panel in panels(self.root):
            if panel_title(panel) != "Runs":
                continue
            drilldown = panel.find(".//drilldown")
            self.assertIsNotNone(drilldown)
            tokens = {
                node.get("token"): (node.text or "").strip()
                for node in drilldown.findall("set")
            }
            self.assertEqual(sorted(tokens), ["form.sid_in", "sid"])
            for value in tokens.values():
                self.assertEqual(value, "$row.sid$")
            return
        self.fail("run list panel not found")

    def test_no_drilldown_writes_the_bare_token_of_a_text_input(self):
        """The mistake this view shipped with, named so that it cannot come back.

        Writing the bare token of an input looks right and does nothing visible: the
        panels react, because they read that token, and the box stays empty, because
        it does not. A reviewer reading `<set token="sid_in">` has no reason to
        suspect it. The check is therefore mechanical and covers every drilldown of
        the view, not only the one that carried the defect.

        Time inputs are exempt: their tokens are read as `$tr.earliest$` /
        `$tr.latest$` in searches, which is a legitimate use of the bare name. No
        drilldown of this view sets one, and the assertion below would say so.
        """
        input_tokens = {
            node.get("token")
            for node in self.root.findall(".//input")
            if node.get("token") and node.get("type") != "time"
        }
        self.assertIn("sid_in", input_tokens)
        offenders = [
            node.get("token")
            for node in self.root.findall(".//drilldown//set")
            if node.get("token") in input_tokens
        ]
        self.assertEqual(
            offenders,
            [],
            "a drilldown sets %s, the token an input *produces*; the state of the "
            "widget is the token prefixed with `form.`" % (offenders,),
        )

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

    def test_the_readme_deep_link_matches_the_token_of_the_text_input(self):
        """The way in that does not depend on the click, held to the view by a test.

        A `sid` pasted into the query string of the view URL opens it straight on that
        run. It is the documented way round when the click disappoints, and it is the
        only selection path a reader can use without touching the page. Renaming the
        input token would break it in complete silence: the link would carry a
        parameter no input answers to, the box would stay empty, and the README would
        still show the old name.

        The check is deliberately mechanical - the README string is derived from the
        view, not typed twice.
        """
        text_inputs = [
            node.get("token")
            for node in self.root.findall(".//input")
            if node.get("type") == "text"
        ]
        self.assertEqual(text_inputs, ["sid_in"])
        with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as handle:
            readme = handle.read()
        expected = "?form.%s=" % (text_inputs[0],)
        self.assertIn(
            expected,
            readme,
            "the README must document the deep link as `%s<sid>`; the parameter is "
            "the token of the text input prefixed with `form.`, which is where the "
            "framework keeps the state of the widget" % (expected,),
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
        # Two removed spellings of the same datum, and one live one.
        #
        # D-46 renamed the journal key `host` `member`, because it collided with the
        # `host` METADATA Splunk stamps on every event and came out multivalued at search
        # time. The key is now gone altogether: the metadata carries the same value -
        # measured on the lab, identical on the whole current corpus - and a key that
        # duplicates a metadata field only offers a second version to drift.
        #
        # So `member` must appear nowhere as a field READ, and `host` may appear ONLY as
        # the metadata read into the member column. That distinction is the whole point:
        # forbidding the string `host` outright would forbid the field that replaced the
        # key, and forbidding nothing would let the dead key back in.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotIn("values(member)", query)
                self.assertNotIn("isnotnull(member)", query)
                self.assertNotIn("isnull(member)", query)
                self.assertNotRegex(query, r"(?<![\w.])member\s*=")
                if re.search(r"(?<![\w.])host(?![\w.])", query):
                    self.assertIn("values(host) AS member", query)
                self.assertNotIn('error=="null"', query)
                self.assertNotIn('error="null"', query)

    def test_the_member_column_is_read_from_the_metadata_and_from_nowhere_else(self):
        # The positive form of the rule above: wherever the view still shows a member,
        # the value comes from the platform metadata, which is what made removing the
        # journal key possible in the first place. Exactly the two panels that used to
        # read the removed key still show it, and both display it.
        showing = [
            title for title, query in self.queries if "values(host) AS member" in query
        ]
        self.assertEqual(sorted(showing), ["Runs", "Selected run"])
        for title in showing:
            with self.subTest(panel=title):
                columns = dict(self.queries)[title].split("| table", 1)[1]
                self.assertIn("member", columns)

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

    def test_no_panel_reads_a_second_vocabulary_of_the_object_type(self):
        # ONE notion, ONE field. The command settles the object type before its first
        # control and writes it under `eai_type`, in the vocabulary of the input
        # contract - the very words the operator puts in their own SPL.
        #
        # The panels used to prefer a journaled `handler` path and fall back on the
        # type. Measured on a mixed lab batch, one single run then produced
        # `saved/searches`, `data/ui/views`, `data/macros` AND `no_such_family` in the
        # same column: two vocabularies of one notion, side by side, in a table the
        # operator reads as a list of types.
        #
        # The test is written on the ABSENCE of the second field rather than on the
        # presence of the first: a panel added later that reintroduces it fails here.
        for title, query in self.queries:
            with self.subTest(panel=title):
                for forbidden in ("handler", "handler_path", "family"):
                    self.assertNotIn(forbidden, query)

    def test_the_empty_object_type_is_labelled_wherever_it_is_grouped_on(self):
        # Measured, and named nowhere in the specification before this view: `eai_type`
        # can be empty on a line whose endpoint is resolved and whose status is
        # `updated`. Measured again for the breakdown panel: the saved-search endpoint of
        # the platform emits no `eai:type` at all, so a batch of saved searches read from
        # the native endpoint is entirely untyped. A breakdown by object type that does
        # not label those lines undercounts without a word.
        #
        # The wording is not frozen, the LABELLING is: the breakdown panel turns the
        # value into a column HEADER, so a bare "(none)" would not say what it is that
        # is missing. "not journaled" would be wrong now: the field IS journaled on
        # every object line, and simply holds nothing when no route established a type.
        for title, query in self.queries:
            if "BY" not in query:
                continue
            if not re.search(r"BY[^|]*\beai_type\b|object_type", query):
                continue
            with self.subTest(panel=title):
                self.assertRegex(query, r'"\(type not established\)"')

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

    def test_no_panel_sorts_lines_into_journal_format_generations(self):
        # The exclusion mechanism is GONE, with the key it hung on.
        #
        # `isnotnull(member)` was a format discriminator by accident: the key appeared
        # with D-46, so its presence dated a line. Removing the key removes the marker,
        # and the sponsor ruled out replacing it with a version field - lines of an older
        # format are an artefact of a lab that has been running campaigns for a week, not
        # a deployment problem. A fresh install has none.
        #
        # What the view assumes instead is a HOMOGENEOUS journal, and it says so on the
        # page rather than in a comment nobody reads. Should the format ever change
        # again, the transition is a deployment question, and the README carries it.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotIn("legacy", query.lower())
        self.assertIn("homogeneous", view_source().lower())


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
    DIAGNOSTIC_FIELDS = ("sid", "level", "user", "journal", "max_objects", "journal_file")

    def setUp(self):
        self.root = view_tree().getroot()
        self.query = dict(queries(self.root))[DIAGNOSTIC_PANEL]
        self.props = read_splunk_conf("default", "props.conf")

    def test_the_two_sources_are_unioned_and_not_ored(self):
        """MEASURED, and the panel was wrong because of it.

        `search (`acl_journal_source`) OR (`acl_diag_source`)` parses, runs, returns
        rows, and drops most of both sources. On a lab, one seven-day window, the same
        instance and the same moment:

            search (macro) OR (macro)                        9 diag,  1 403 journal
            search macro OR macro       (no parentheses)     9 diag,      0 journal
            index=... (sourcetype=a OR sourcetype=b)     2 268 diag, 17 770 journal
            multisearch [search macro] [search macro]    2 268 diag, 17 770 journal

        It keeps the newest diagnostic line of each run and the oldest journal lines, so
        the filter of this panel - `journal_lines = 0` - was true for nine runs that had
        each written a complete journal, and the panel listed all nine as having written
        none. Nothing is reported by the platform in either direction.

        `multisearch` unions two independent searches rather than asking one search to
        match two index-and-sourcetype pairs. Both branches still name their source by a
        macro, so D-51 holds.
        """
        self.assertIn("| multisearch", self.query)
        self.assertIn("[search `acl_journal_source`]", self.query)
        self.assertIn("[search `acl_diag_source`]", self.query)
        for title, query in queries(self.root):
            with self.subTest(panel=title):
                self.assertNotRegex(
                    query, r"`(?:acl_journal_source|acl_diag_source)`\s*\)?\s+OR\s"
                )

    def test_the_diagnostic_sourcetype_has_automatic_extraction_turned_off(self):
        # The single line that removes the class rather than one instance of it.
        self.assertEqual(self.props["editacl:diag"].get("KV_MODE"), "none")

    def test_the_props_are_exported_so_that_they_apply_where_searches_run(self):
        # A search-time setting only applies in the namespaces it is exported to.
        # MEASURED: unexported, the stanza above returns 248 clean run identifiers in the
        # namespace of this app and 259 - eleven of them polluted - in the namespace of
        # `search`, which is where the operator types. Without this export the fix is
        # inert exactly where it is needed, and nothing says so.
        meta = MetadataTest.read_meta()
        self.assertIn("props", meta)
        self.assertEqual(meta["props"].get("export"), "system")

    def test_no_extraction_anchors_on_the_prose_of_a_message(self):
        # An extraction anchored on the words of a message loses its fields the day the
        # message is reworded, silently. MEASURED on a corpus written before the
        # repository moved to English: anchors on `editacl startup` and `parameters`
        # extracted `user` on 19 lines out of 248. The contract is the sequence of keys.
        forbidden = ("startup", "parameters", "editacl ")
        for key, value in self.props["editacl:diag"].items():
            if not key.startswith("EXTRACT-"):
                continue
            for word in forbidden:
                with self.subTest(extraction=key, word=word.strip()):
                    self.assertNotIn(word, value)

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
        # disagree on what a sid is, without a message. The panel prefixes every capture
        # name with `diag_`; nothing else may differ.
        for stanza, names in (
            ("EXTRACT-editacl_diag_run", ("level", "sid")),
            ("EXTRACT-editacl_diag_journal", ("journal_file",)),
        ):
            declared = self.props["editacl:diag"][stanza]
            for name in names:
                declared = declared.replace("(?<%s>" % name, "(?<diag_%s>" % name)
            with self.subTest(extraction=stanza):
                self.assertIn(declared, self.query)

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
        # `max_objects` left the panel with the column purge: the ceiling of a run says
        # nothing about why that run wrote no journal line, and it was empty on most of
        # the rows displayed. The DECLARED extraction keeps it - it belongs to the
        # sourcetype, not to this panel - which is why the two lists differ.
        for field in ("user", "journal"):
            with self.subTest(field=field):
                self.assertIn("values(diag_%s)" % field, self.query)
        self.assertNotIn("diag_max_objects", self.query)


class NoCauseIsAttributedFromTheProseOfAMessageTest(unittest.TestCase):
    """R-1 of the re-audit of 2026-08-09.

    The previous increment forbade anchoring on the prose of a message - and enforced
    the rule on the `EXTRACT-` stanzas only. The panel that names the cause of a run
    kept two counters built on `match(_raw, "<an English sentence>")`, and the rule was
    not stated anywhere for the searches.

    MEASURED on the lab, whole retention window: 19 runs ended on a fatal error, 18 of
    which predate the move of this repository to English and read `erreur fatale :`. The
    panel lists the runs with no journal line, and 17 of the 19 have none; the English
    sentence `fatal error:` found **1** of those 17, and the panel reported the other
    **16** as "killed before their first write" - the right line, the wrong cause, which
    is verbatim the defect A-1 was about.

    16 and not 18: two of the eighteen did write a journal line, so the filter of the
    panel (`journal_lines = 0`) never listed them. The severity of the defect is
    unchanged; what changes is what may be claimed about it.

    Recognising two languages was rejected: the second one will not exist on a fresh
    deployment, and a third reworded sentence would reopen the hole. Excluding the older
    lines by their format was rejected too. The journal had a structural marker for that
    - the `member` key, whose presence dated a line - and it has since been removed as a
    duplicate of the `host` metadata, so neither file has one now; detecting the language
    is exactly what we are trying not to do.

    What the counters read instead is what the LOGGING LIBRARY writes, not what the
    message says:

      - the severity token, `CRITICAL`, which `bin/acltools/diag.py` emits for a fatal
        error and for nothing else;
      - the journal FILE NAME, whose shape is a contract (D-3), for the cause "the
        journal could not be opened".

    Both are checked below against the lines the code actually produces, not against a
    fixture written by hand.
    """

    #: Fields whose values the cause counters test. Both come out of the two `rex`
    #: expressions of the panel, never out of a `match()` on the message.
    CAUSE_FIELDS = ("diag_level", "diag_journal_file")

    def setUp(self):
        self.root = view_tree().getroot()
        self.queries = queries(self.root)
        self.query = dict(self.queries)[DIAGNOSTIC_PANEL]

    def emitted_lines(self, action):
        """The diagnostic lines `action` produces, formatted as they land on disk."""
        import logging

        from acltools.diag import Diagnostics

        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Capture()
        diag = Diagnostics("(never opened)", sid="1786259904.10", handler=handler)
        action(diag)
        diag.close()
        return records

    def test_no_query_attributes_a_cause_by_matching_the_prose_of_a_message(self):
        # The rule of the previous increment, extended from the `EXTRACT-` stanzas to
        # the searches - which is where it was broken.
        for title, query in self.queries:
            with self.subTest(panel=title):
                self.assertNotRegex(query, r"match\(\s*(?:_raw|diag_raw)\b")

    def test_the_two_cause_counters_read_a_field_and_not_a_sentence(self):
        self.assertIn('count(eval(diag_level="CRITICAL")) AS fatal_lines', self.query)
        self.assertIn(
            'count(eval(diag_level="WARNING" AND isnotnull(diag_journal_file)))'
            " AS journal_open_failures",
            self.query,
        )
        for field in self.CAUSE_FIELDS:
            with self.subTest(field=field):
                self.assertIn("(?<%s>" % field, self.query)

    def test_the_severity_the_panel_calls_fatal_is_the_one_the_code_emits(self):
        # The tie that makes the anchor a contract rather than a guess: the line the
        # code produces for a fatal error is run through the panel's own expression,
        # and the level it yields must be the one the panel counts.
        lines = self.emitted_lines(lambda diag: diag.fatal("whatever the wording is"))
        self.assertEqual(len(lines), 1)
        expression = re.search(r'rex field=diag_raw "([^"]+)"', self.query).group(1)
        match = re.search(expression.replace("(?<", "(?P<"), lines[0])
        self.assertIsNotNone(match, lines[0])
        self.assertEqual(match.group("diag_level"), "CRITICAL")

    def test_no_other_diagnostic_event_is_emitted_at_that_severity(self):
        # Counting a severity is only sound while that severity means one thing. Every
        # other event of section 8.1 is exercised and must come out below CRITICAL.
        from acltools.model import FieldNames, Params

        quiet = Params(names=FieldNames(), dryrun=True, validate_roles=True,
                       journal=True, max_objects=10, warnings=("something",))

        def everything_but_a_fatal(diag):
            diag.startup(version="1.0.0", user="operator")
            diag.params(quiet)
            diag.capability(True)
            diag.capability(False, detail="denied")
            diag.realtime("refused")
            diag.mapping({"total": 1, "from_json": 1, "from_override": 0})
            diag.journal("/var/log/splunk/editacl_journal_1.log", True)
            diag.journal("/var/log/splunk/editacl_journal_1.log", False)
            diag.info("plain")
            diag.warning("plain")

        for line in self.emitted_lines(everything_but_a_fatal):
            with self.subTest(line=line[:60]):
                self.assertNotIn(" CRITICAL ", line)

    def test_the_journal_open_failure_is_recognised_by_the_file_name(self):
        # The only part of that message which does not change with the language. Its
        # shape is the contract of D-3, and it is the same one `inputs.conf` monitors.
        from acltools.journal import journal_filename

        name = journal_filename("1786259904.10")
        expression = re.search(
            r'rex field=diag_raw "(\(\?<diag_journal_file>[^"]+)"', self.query
        ).group(1)
        self.assertRegex(name, expression.replace("(?<", "(?P<"))

        opened, failed = self.emitted_lines(
            lambda diag: [diag.journal("/var/log/splunk/" + name, True),
                          diag.journal("/var/log/splunk/" + name, False)]
        )
        self.assertRegex(failed, expression.replace("(?<", "(?P<"))
        self.assertIn(" WARNING ", failed)
        # And the successful open, which carries the same file name, is NOT a failure:
        # it is the severity that separates the two.
        self.assertRegex(opened, expression.replace("(?<", "(?P<"))
        self.assertIn(" INFO ", opened)

    def test_the_fatal_count_is_displayed_and_not_only_used(self):
        # A cause the reader cannot check is a verdict. The two counts that decide it
        # are columns of the panel - and they survived the column purge for exactly that
        # reason, being numbers, which cost one narrow column each.
        columns = self.query.split("| table", 1)[1]
        self.assertIn("fatal_lines", columns)
        self.assertIn("journal_open_failures", columns)

    def test_the_cause_is_a_code_and_the_sentence_is_beside_the_table(self):
        # Seen on screen by the sponsor: the cause used to be a whole sentence, up to
        # 106 characters, written into a table CELL. In a narrow column it wraps to one
        # word per line, three runs fill the page, and the columns to its right leave the
        # screen. The codes are short, stable identifiers; the prose that explains them
        # is read once, in the panel description.
        codes = re.findall(r'"([a-z_]+)",?\)?\s*$', self.query, re.MULTILINE)
        expected = {
            "journal_disabled", "journal_not_openable", "fatal_error",
            "no_write_recorded",
        }
        self.assertTrue(expected.issubset(set(codes)), sorted(set(codes)))
        for code in expected:
            with self.subTest(code=code):
                self.assertLessEqual(len(code), 24)
        panel = [
            p for p in panels(self.root) if panel_title(p) == DIAGNOSTIC_PANEL
        ][0]
        description = ElementTree.tostring(panel.find("html"), encoding="unicode")
        for code in expected:
            with self.subTest(code=code):
                self.assertIn(code, description)


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


class TheChangeBreakdownIsBuiltFromTheJournalAndNotFromAGuessTest(unittest.TestCase):
    """The panel that answers *which ACL changes took place, on how many objects*.

    It is the first panel of this view that has to hold a BEFORE and an AFTER side by
    side, and every trap this project has paid for converges on it: the two phases that
    never carry the whole truth on one line, the `null == null` comparison that is false
    in SPL, the count that must be a count of result lines, and the object type that is
    empty far more often than anyone expects.

    The granularity of the two value columns is the WHOLE value of the attribute, and
    that was decided by measurement rather than by taste - over the 1 499 knowledge
    objects of the reference platform there are 4 distinct read combinations, 5 write, 3
    sharing scopes and 1 owner, so the whole-value form is bounded by roughly a dozen
    rows for all four attributes together. The per-role form, closer to what a
    decommissioning looks for but further from the shape asked for, was not needed.
    """

    PANEL = "ACL change breakdown"

    #: The four attributes of an ACL, and the journal fields that carry each side.
    ATTRIBUTES = (
        ("Read", "before_perms_read", "after_perms_read"),
        ("Write", "before_perms_write", "after_perms_write"),
        ("Sharing", "before_sharing", "after_sharing"),
        ("Owner", "before_owner", "after_owner"),
    )

    def setUp(self):
        self.root = view_tree().getroot()
        self.query = dict(queries(self.root))[self.PANEL]

    def test_the_four_attributes_are_covered_and_not_only_the_two_of_the_example(self):
        # The request named read and write. The logic holds for all four, and leaving
        # two out would be an arbitrary silence on a change that did happen.
        for label, before, after in self.ATTRIBUTES:
            with self.subTest(attribute=label):
                self.assertIn("earliest(%s)" % before, self.query)
                self.assertIn("earliest(%s)" % after, self.query)
                self.assertIn('"%s"' % label, self.query)

    def test_the_two_phases_are_merged_by_endpoint(self):
        # Section 8.2: on an object really written the prior state is on the `intent`
        # line and the status on the `outcome` line. Pairing is `BY endpoint`, exactly
        # as the rollback macro of section 8.6 pairs.
        self.assertIn("BY endpoint", self.query)
        self.assertNotIn("phase=outcome", self.query.split("| where", 1)[0])

    def test_the_state_columns_are_aggregated_by_earliest_and_not_by_values(self):
        # Same discipline as the resolved-objects panel: an object presented twice
        # produces two `outcome` lines, and `values()` would merge the prior state of
        # the first pass with the state read back on the second.
        for _label, before, after in self.ATTRIBUTES:
            for field in (before, after):
                with self.subTest(field=field):
                    self.assertNotIn("values(%s)" % field, self.query)

    def test_every_comparison_is_guarded_against_null_equals_null(self):
        # `null == null` is FALSE in SPL. Unguarded, this panel would invent a
        # transition on every object whose prior state was never read - the symmetric
        # form of the defect that once reported "=" on an object that had changed.
        for label, before, after in self.ATTRIBUTES:
            with self.subTest(attribute=label):
                self.assertRegex(
                    self.query,
                    r"isnull\(%s\)\s+OR\s+isnull\(%s\)" % (
                        before.replace("perms_", ""), after.replace("perms_", "")
                    ),
                )

    def test_only_a_pair_that_differs_produces_a_row(self):
        # The literal reading of "only real transitions are displayed": the branch that
        # yields the label is the one where the two sides are present AND different.
        # Equality yields null, and the null rows are dropped before the expansion.
        self.assertEqual(self.query.count("null(), \"Read\""), 1)
        self.assertIn("| where isnotnull(change_type)", self.query)
        expansion = self.query.find("| mvexpand change_type")
        guard = self.query.find("| where isnotnull(change_type)")
        self.assertNotEqual(expansion, -1)
        self.assertLess(guard, expansion, "the null rows reach the expansion")

    def test_the_count_is_a_count_of_result_lines(self):
        # Section 15.6, and the reserve it carried until D-50 was closed: counting is
        # done by counting `outcome` lines, never over a reconstructed object identity.
        self.assertIn('count(eval(phase="outcome")) ', self.query)
        self.assertNotIn("dc(", self.query)

    def test_the_two_status_columns_name_statuses_that_exist(self):
        # A status literal renamed in the code and left here would count zero for ever,
        # without a message. `applied` and `simulated` are what separate a transition
        # the platform accepted from one that was only computed.
        from acltools import model

        for column, status in (("applied", "updated"), ("simulated", "dryrun")):
            with self.subTest(column=column):
                self.assertIn(
                    'count(eval(phase="outcome" AND status="%s"))' % status, self.query
                )
                self.assertIn(status, model.ACL_STATUSES)
        columns = self.query.split("| table", 1)[1]
        self.assertIn("applied", columns)
        self.assertIn("simulated", columns)

    def test_no_status_filter_hides_a_transition_that_was_refused(self):
        # An object whose POST failed carries a prior and an intended state just like
        # one that succeeded. Filtering it out would under-report a run that went wrong,
        # which is the one direction this view must never fail in. The distinction is
        # carried by the two count columns instead.
        self.assertNotRegex(self.query, r"\|\s*search\b[^|]*status\s*=")
        self.assertNotRegex(self.query, r"\|\s*where\b[^|]*status\s*=")

    def test_the_object_type_columns_come_from_the_data(self):
        # One column per type MET, built by writing the value into a field name. A
        # hard-coded list would be right on the day it was written and wrong afterwards:
        # the shipped family table alone carries 27 of them.
        self.assertIn("| eval {object_type} = objects_changed", self.query)
        self.assertIn("| stats sum(*) AS * BY change_type, before, after", self.query)
        families = os.path.join(REPO_ROOT, "lookups", "acl_object_families.csv")
        with open(families, encoding="utf-8") as handle:
            names = [line.split(",")[0].strip() for line in handle.readlines()[1:]]
        written = [name for name in names if name and ('"%s"' % name) in self.query]
        self.assertEqual(written, [], "a family name is written into the panel")

    def test_the_breakdown_ventilates_on_the_single_type_field(self):
        # The column headers of this panel and the values an operator writes in
        # `eai:type` are the SAME WORDS. That is the whole point: a batch read from the
        # native endpoints carries no type, and the command fills one in by inverting
        # the handler path it resolved, so the panel is typed without ever publishing
        # the addressing vocabulary as if it were a type.
        self.assertIn("values(eai_type)             AS object_type", self.query)
        self.assertNotRegex(self.query, r"handler")

    def test_the_lines_with_no_established_type_get_their_own_column(self):
        # The last-resort label means what it says: neither the input row nor the
        # inversion of the resolved handler path gave a type. That covers an event
        # refused before resolution, and an endpoint no single key of the table names.
        # It is a column HEADER, so a bare "(not journaled)" would not say what it is
        # that is missing - and "not journaled" would now be wrong, since the field IS
        # journaled and simply holds nothing.
        self.assertIn('"(type not established)"', self.query)
        self.assertRegex(
            self.query,
            r'eval object_type = if\(coalesce\(object_type,""\)!="",\s*'
            r'object_type,\s*"\(type not established\)"\)',
        )

    def test_the_panel_says_what_it_shows_in_simulation(self):
        # In simulation nothing was written: the "after" value is the one that WOULD be
        # applied. Said on the page, not only in a report.
        panel = [p for p in panels(self.root) if panel_title(p) == self.PANEL][0]
        description = ElementTree.tostring(panel.find("html"), encoding="unicode")
        self.assertIn("simulation", description.lower())
        self.assertIn("would", description.lower())


class NoTableCellCarriesAParagraphTest(unittest.TestCase):
    """The rule the first rendering feedback of this project established.

    The sponsor opened the view. On the panel listing the runs with no journal line, the
    cause was a whole sentence written into a CELL: in a narrow column it wrapped to one
    word per line, three rows filled the screen, and the columns to the right of it were
    pushed out of sight. Two other columns were empty on every row displayed.

    No test can measure a rendered width. What it can do is separate a label from a
    paragraph, which is enough to rule out what is obviously bad: a string literal a
    search writes into a cell stays under `MAX_CELL_LITERAL` characters. The one
    exemption is the entitlement guard, whose state string section 15.5 makes normative -
    it is named here rather than left to a reader's judgement, and its width remains a
    known open point.
    """

    def setUp(self):
        self.root = view_tree().getroot()
        self.queries = queries(self.root)

    def cell_literals(self, query):
        """Double-quoted literals a search can write into a cell.

        Lines carrying a `rex` are skipped: their literal is a regular expression, it
        never reaches a cell, and its length says nothing about a column.
        """
        found = []
        for line in query.splitlines():
            if "rex field=" in line:
                continue
            found.extend(re.findall(r'"([^"]*)"', line))
        return found

    def test_no_search_writes_a_paragraph_into_a_cell(self):
        for title, query in self.queries:
            if title in CELL_LITERAL_EXEMPT_PANELS:
                continue
            for literal in self.cell_literals(query):
                with self.subTest(panel=title, literal=literal[:40]):
                    self.assertLessEqual(len(literal), MAX_CELL_LITERAL)

    def test_the_exemption_is_the_guard_rail_and_it_is_still_over_the_line(self):
        # The exemption is real, and stating it is the point: the guard rail states are
        # sentences, section 15.5 makes their wording normative, and they are displayed
        # in a table. Should they ever be shortened, this test says so rather than
        # letting the exemption outlive its reason.
        query = dict(self.queries)[CELL_LITERAL_EXEMPT_PANELS[0]]
        longest = max(len(literal) for literal in self.cell_literals(query))
        self.assertGreater(longest, MAX_CELL_LITERAL)

    def test_no_table_carries_more_columns_than_a_reader_can_take_in(self):
        # A crude ceiling, and the same reasoning: the panel that was reported unreadable
        # carried nine columns, three of them empty on every row. The resolved-objects
        # table is the deliberate exception - it is the wide one, it is meant to be
        # scrolled, and it is the only place the eight state columns can live.
        # Two exemptions, both stated. `Objects whose endpoint was resolved` is the wide
        # one by design - eight state columns plus their four verdicts have nowhere else
        # to live. `Runs` is the overview list the drilldown hangs on, and eighteen
        # columns is an OPEN POINT rather than a decision: fifteen of them are numbers or
        # short words, its `wrap` is already false so it scrolls rather than stacking,
        # and narrowing it would change the click path the sponsor has just confirmed
        # works. It is reported, not silently trimmed here.
        wide = {"Objects whose endpoint was resolved", "Entitlement check", "Runs"}
        for title, query in self.queries:
            if title in wide or "| table" not in query:
                continue
            columns = query.rsplit("| table", 1)[1].replace("\n", " ").split(",")
            with self.subTest(panel=title, columns=len(columns)):
                self.assertLessEqual(len(columns), 13)


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

    #: Every stanza of `metadata/default.meta` and what it exports, exhaustively.
    #:
    #: R-4 of the re-audit of 2026-08-09: an extra export stanza passed 689 tests. Each
    #: control here named the stanza it cared about, so a stanza nobody had named was
    #: invisible. What this file decides is **which objects of the app are visible
    #: outside it**; widening that set is a decision, and a decision belongs in a diff
    #: somebody has to argue for. The class-wide `[views]` control above says the same
    #: thing about one stanza; this one says it about all of them.
    #: `access` is frozen with `export` and not separately: the two answer the same
    #: question. Widening the default stanza to `write : [ * ]` passed the suite while
    #: only `export` was compared.
    EXPECTED_META = {
        "": ("none", "read : [ * ], write : [ admin ]"),
        "commands": ("system", None),
        "commands/editacl": ("system", "read : [ * ], write : [ admin ]"),
        # v4.3 section 14.1, deliverable 6: one stanza per command object, exported to
        # the system for the same reason as the first - a command invocable only from
        # this app's context would be unusable from the ad hoc search where an operator
        # actually governs an application.
        "commands/editappacl": ("system", "read : [ * ], write : [ admin ]"),
        # v4.3 section 7: the inventory is the FIRST command of the workflow - section
        # 12.2 says to consult it before engaging either write tool - so a command
        # invocable only from a hidden app's own context would be consulted by nobody.
        "commands/appaclinventory": ("system", "read : [ * ], write : [ admin ]"),
        "searchbnf": ("system", "read : [ * ], write : [ admin ]"),
        "macros": ("system", "read : [ * ], write : [ admin ]"),
        "transforms": ("system", "read : [ * ], write : [ admin ]"),
        "props": ("system", "read : [ * ], write : [ admin ]"),
        "lookups": ("system", "read : [ * ], write : [ admin ]"),
        "savedsearches": ("none", "read : [ * ], write : [ admin ]"),
        "views/%s" % VIEW_NAME: ("system", "read : [ %s ], write : [ admin ]" % ROLE_NAME),
        # The application-level audit view, declared like this one and **reusing its read
        # role**: the same person audits the two levels, and a second role attributed to
        # nobody would add a line to the role management chain without opening anything.
        # Its own controls live in `tests/test_appacl_dashboard.py`; what is frozen here
        # is that the metadata of this app declares these stanzas and no others.
        "views/appacl_runs": ("system", "read : [ %s ], write : [ admin ]" % ROLE_NAME),
    }

    def test_the_metadata_declares_exactly_this_and_nothing_more(self):
        self.assertEqual(
            {
                name: (stanza.get("export"), stanza.get("access"))
                for name, stanza in self.meta.items()
            },
            self.EXPECTED_META,
        )

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
        # v4.3 section 8.1: a capability of its own for the application-level write. It
        # neither implies nor is implied by the one above, and both are granted to
        # `admin` at installation - declaring without granting produces an app that is
        # installed, loaded and unusable (D-29).
        "capability::edit_app_acl_bulk": {},
        # v4.3 section 7.6: a capability of its own for the INVENTORY, and its motive is
        # proper to that command - reading the metadata file short-circuits the
        # capability filtering REST applies, so the counters it publishes carry
        # information the API would not serve to a caller without `admin_all_objects`.
        # Bound 3 of section 6.2 reduces the exposure, this capability governs it.
        "capability::list_app_acl": {},
        "role_admin": {
            "edit_acl_bulk": "enabled",
            "edit_app_acl_bulk": "enabled",
            "list_app_acl": "enabled",
        },
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

    #: The two source macros, definition included. D-51 makes them the single place
    #: where the journal index is written; the mutation campaign of the second
    #: remediation changed `index=_internal` to another index there and passed the whole
    #: suite. Every shipped search would then read an index that carries nothing, and
    #: report an empty result as a success - the failure D-51 exists to prevent, entered
    #: through the one file the rule points everybody at.
    #: The application-level pair follows the same rule and gets the same freeze: it is
    #: the same failure mode one increment further along, and DV-3 doubled the number of
    #: places where a redirection has to be applied.
    EXPECTED_SOURCE_MACROS = {
        "acl_journal_source": "index=_internal sourcetype=editacl:journal",
        "acl_diag_source": "index=_internal sourcetype=editacl:diag",
        "app_acl_journal_source": "index=_internal sourcetype=editappacl:journal",
        "app_acl_diag_source": "index=_internal sourcetype=editappacl:diag",
    }

    def test_the_two_journals_are_never_read_through_the_same_macro(self):
        """DV-3 on the reading side: four macros, four distinct sourcetypes.

        A line of `editacl:journal` carries an object, a line of `editappacl:journal`
        carries a stanza whose blast radius is several objects. One macro serving both
        would let an existing panel absorb the application-level writes into its object
        counters - a confident and false view, which is the mode of failure this whole
        separation exists to prevent.
        """
        sourcetypes = [
            definition.rsplit("sourcetype=", 1)[1]
            for definition in self.EXPECTED_SOURCE_MACROS.values()
        ]
        self.assertEqual(len(set(sourcetypes)), len(self.EXPECTED_SOURCE_MACROS))

    def test_both_source_macros_are_declared_and_name_their_sourcetype(self):
        for name, definition in self.EXPECTED_SOURCE_MACROS.items():
            with self.subTest(macro=name):
                self.assertIn(name, self.macros)
                self.assertEqual(self.macros[name]["definition"], definition)
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
    SOURCE_STANZAS = frozenset(SOURCE_MACROS + APP_SOURCE_MACROS)

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

    def collapsed_query(self):
        """The query on one line, so an expression can be matched whatever the
        indentation the XML happens to carry."""
        return re.sub(r"\s+", " ", self.query)

    def test_the_panel_reports_the_date_of_the_most_recent_journal_line(self):
        self.assertIn("max(_time) AS last_journal_event", self.query)
        self.assertIn("last_journal_event", self.query.split("| table", 1)[1])

    def test_the_panel_locates_the_journal_across_the_searchable_indexes(self):
        self.assertIn("tstats", self.query)
        self.assertIn("values(index) AS journal_found_in", self.query)
        self.assertIn("values(index) AS journal_read_from", self.query)

    def test_the_tstats_scope_is_every_index_the_role_may_search(self):
        # R-4 of the re-audit: narrowing this `WHERE` to `index=_internal` passed the
        # whole suite, and it is the exact regression of the fix. The signal then finds
        # the journal only where the view already reads, `journal_found_in` falls back
        # to one index, `unread_events` to zero, and the panel returns to the confident
        # OK state A-2 was about. The scope IS the substance of the signal - naming
        # `tstats` and two field names proves nothing.
        self.assertIn(
            "WHERE (index=* OR index=_*) sourcetype=editacl:journal BY index",
            self.query,
        )
        self.assertIn("| eventcount summarize=false index=* index=_*", self.query)
        self.assertNotRegex(self.query, r"tstats[\s\S]{0,200}index=_internal")

    def test_both_index_sets_are_shown_side_by_side(self):
        columns = self.query.split("| table", 1)[1]
        self.assertIn("journal_read_from", columns)
        self.assertIn("journal_found_in", columns)

    def test_a_line_outside_what_the_view_reads_changes_the_state(self):
        self.assertRegex(
            self.query,
            r"unread_events\s*>\s*0\s*OR\s*found_index_count\s*>\s*read_index_count",
        )

    #: The one threshold of this panel. It is a chosen value, and the point of freezing
    #: it here is that changing it must be a decision, not a diff nobody reads.
    SILENCE_THRESHOLD_PCT = 25

    def test_a_silent_end_of_window_changes_the_state(self):
        self.assertIn("silent_tail_pct", self.query)
        self.assertRegex(self.query, r"silent_tail_pct\s*>\s*\d+")

    def test_the_silence_threshold_is_the_value_that_was_decided(self):
        # R-6 of the re-audit. The previous control was `silent_tail_pct\s*>\s*\d+`,
        # which accepts 99 exactly as it accepts 25 - a threshold of 99 % empties the
        # signal of any meaning and passed 689 tests (mutation N10). `\d+` checked that
        # a threshold was PRESENT, never that it was the one that had been argued for.
        thresholds = [
            int(value)
            for value in re.findall(r"silent_tail_pct\s*>\s*(\d+)", self.query)
        ]
        self.assertEqual(thresholds, [self.SILENCE_THRESHOLD_PCT])

    def test_the_threshold_is_read_as_a_choice_and_not_as_a_measurement(self):
        # A threshold nobody can discuss is a threshold everybody suffers. It is stated
        # for what it is, at the place where it is read - the state itself - together
        # with what it costs on the default window.
        for wording in (
            "%d%%" % self.SILENCE_THRESHOLD_PCT,
            "CHOSEN VALUE, NOT A MEASURED ONE",
            # What the threshold costs on the shipped range, stated as the band it is
            # and not as the round figure it is not: `-7d@d .. now` is seven days plus
            # the hours already elapsed today, so a quarter of it moves with the clock.
            "between 42 and 48 hours",
        ):
            with self.subTest(wording=wording):
                self.assertIn(wording, self.query)

    def test_the_date_of_the_last_line_opens_the_state_on_every_state(self):
        # R-2 of the re-audit. The two signals of this panel are both defeatable by an
        # entitlement or by a threshold, and their combination leaves a role holder
        # entitled to the ORIGIN index only reading `OK` while the run list has stopped
        # at the date of the redirection. MEASURED, on the default window of the view.
        #
        # No automatic detection can close that without reading an index the reader is
        # not entitled to read. What CAN be made unconditional is the fact itself: the
        # state string opens on the date of the most recent journal line and on its age,
        # before any branch, so that the one piece of knowledge the panel does not have
        # - how often runs are expected here - meets the one fact it does.
        self.assertRegex(
            self.query,
            r'eval state = "LAST JOURNAL LINE READ: " \. last_journal_event'
            r' \. ", age at the end of the window " \. journal_age',
        )
        # After every branch of the case, so no branch can drop it.
        self.assertLess(self.query.index("eval state = case("),
                        self.query.index('eval state = "LAST JOURNAL LINE READ'))
        # And rendered as columns of their own, next to the state and not at the end.
        columns = [c.strip() for c in
                   self.query.split("| table", 1)[1].replace("\n", " ").split(",")]
        self.assertEqual(columns[:3], ["state", "last_journal_event", "journal_age"])

    def test_the_age_of_the_last_line_is_computed_and_not_only_its_ratio(self):
        self.assertIn(
            'eval journal_age = if(isnull(silent_tail_s), "(no journal line in this window)",',
            self.query,
        )
        self.assertIn('tostring(silent_tail_s, "duration")', self.query)

    def test_the_window_bounds_come_from_the_search_and_not_from_a_constant(self):
        # `addinfo` is what makes the silence relative to the window the operator asked
        # for. A hard-coded duration would be right for one time range and wrong for the
        # rest, silently.
        self.assertIn("| addinfo", self.query)
        self.assertIn("info_max_time", self.query)
        self.assertIn("info_min_time", self.query)

    def test_the_age_is_measured_against_the_end_of_the_window_and_not_the_present(self):
        """S-3 of the second re-audit of 2026-08-09.

        The test above proved that `addinfo` is invoked and its two fields named; it
        never proved that `window_end` is the **operand of the subtraction**. Replacing
        it with `now()` therefore passed the whole suite, and it is invisible on the
        shipped default range, where `latest = now` makes the two equal. On any
        historical window - an operator going back to last week to work an incident -
        the age would be counted against the present, `silent_tail_pct` would run past
        every threshold, and the panel would report SILENT over a period that is not.

        A guard rail whose reading depends on the time range it is read through is
        worse than none: it is the confident and wrong message this panel exists to
        avoid, one level up.
        """
        self.assertIn(
            "round(window_end - last_journal_event, 0)", self.collapsed_query()
        )

    def test_the_present_is_only_ever_the_fallback_of_the_window_end(self):
        # `now()` has exactly one legitimate use in this panel: standing in for
        # `info_max_time` when it is not a number, which is what an all-time range
        # gives. Any second occurrence is an age or a width computed against the
        # present rather than against the window.
        collapsed = self.collapsed_query()
        self.assertIn(
            "eval window_end = if(isnum(info_max_time), info_max_time, now())", collapsed
        )
        self.assertEqual(
            collapsed.count("now()"),
            1,
            "the present is used somewhere other than the fallback of the window end",
        )

    def test_the_width_of_the_window_is_measured_between_its_own_two_bounds(self):
        # The denominator of the ratio has the same failure mode as its numerator.
        self.assertIn(
            "eval window_s = if(isnum(info_min_time), window_end - info_min_time, null())",
            self.collapsed_query(),
        )

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
