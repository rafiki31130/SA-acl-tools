"""The README says true things about what it ships (v4.8 section 14.2).

**Three of these controls did not exist, and that is why the errors survived three
readings.** The third reading trial - a fresh reader given the delivered `README.md` and a
raw output, nothing else - found the announced column order wrong, five macros announced
where seven were described, and a domain missing from a column that publishes three values.
None of those was exigible by any clause: the deliverable list said *the field table*, and
a table can be present and wrong.

The instruments here are all of one kind: **the document is compared to what the app
actually declares** - the writer's field list, `macros.conf`, `savedsearches.conf`, the
files of the archive - never to a second list written by hand in the test. A control that
recopies the thing it checks freezes today's mistake instead of finding tomorrow's.
"""

import io
import os
import re
import unittest

from acltools.appacl_inventory import INVENTORY_OUTPUT_FIELDS

from . import REPO_ROOT

README_PATH = os.path.join(REPO_ROOT, "README.md")


def _readme():
    with io.open(README_PATH, encoding="utf-8") as handle:
        return handle.read()


def _conf_stanzas(name):
    """Stanza names declared by a shipped `.conf`, in declaration order."""
    path = os.path.join(REPO_ROOT, "default", name)
    with io.open(path, encoding="utf-8") as handle:
        return [
            line.strip()[1:-1]
            for line in handle
            if line.strip().startswith("[") and line.strip().endswith("]")
        ]


def _anchor(title):
    """GitHub's anchor for a heading, applied the same way to both sides."""
    text = re.sub(r"[`*]", "", title.lower())
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text.strip())


class TheAnnouncedColumnOrderIsTheEmittedOrderTest(unittest.TestCase):
    """*Raised* at the third reading trial: the README grouped the columns by group and
    announced that order as the output's. A reader who trusts it looks for the fifth cell
    and reads the ninth.

    The control reads the **writer's declaration** in the code, so the day a column moves,
    the document fails rather than the reader."""

    def setUp(self):
        section = _readme()
        start = section.index("### What it gives you, column by column")
        self.section = section[start:]
        self.rows = [
            match.group(1)
            for match in re.finditer(r"^\| *\d+ *\| `([^`]+)` *\|", self.section, re.M)
        ]

    def test_the_table_lists_every_emitted_column_and_no_other(self):
        self.assertEqual(sorted(self.rows), sorted(INVENTORY_OUTPUT_FIELDS))

    def test_the_table_lists_them_in_the_order_they_come_out(self):
        self.assertEqual(
            self.rows, list(INVENTORY_OUTPUT_FIELDS),
            "the announced order is not the emitted order: a reader counting cells lands "
            "on the wrong column",
        )

    def test_the_announced_count_is_the_declared_count(self):
        flat = " ".join(self.section.split())
        self.assertIn("Nineteen columns", flat)
        self.assertEqual(len(INVENTORY_OUTPUT_FIELDS), 19)

    def test_the_rows_are_numbered_in_sequence(self):
        numbers = [
            int(match.group(1))
            for match in re.finditer(r"^\| *(\d+) *\| `", self.section, re.M)
        ]
        self.assertEqual(numbers, list(range(1, len(INVENTORY_OUTPUT_FIELDS) + 1)))


class EveryColumnPublishesItsDomainTest(unittest.TestCase):
    """A column whose values are not published is a column nobody can filter on.

    *Raised*: `acl_file_export` had **no** domain at all in the table, while the output
    produces three shapes for it - a literal, a blank, and a token the text never named.
    """

    #: Columns with an **open** domain: the table cannot enumerate them, so what it owes
    #: the reader is the **reserved tokens** and the meaning of a blank.
    OPEN_DOMAIN = ("eai:acl.app", "acl_stanza", "acl_handler", "eai:acl.perms.read",
                   "eai:acl.perms.write", "acl_file_perms_read", "acl_file_perms_write",
                   "acl_file_export", "acl_objects_with_own_perms",
                   "acl_families_with_own_perms", "acl_member")

    def setUp(self):
        readme = _readme()
        start = readme.index("### What it gives you, column by column")
        self.section = readme[start:]
        self.cells = {}
        for match in re.finditer(r"^\| *\d+ *\| `([^`]+)` *\|([^|]*)\|([^|]*)\|([^|]*)\|",
                                 self.section, re.M):
            self.cells[match.group(1)] = match.group(4).strip()

    def test_every_column_carries_a_values_cell(self):
        for field in INVENTORY_OUTPUT_FIELDS:
            with self.subTest(column=field):
                self.assertTrue(self.cells.get(field, "").strip(),
                                "%s publishes no domain at all" % field)

    def test_the_columns_that_can_return_the_token_say_so(self):
        """`(absent)` is a reserved token of this app, not a value of the platform: the
        five columns that can return it name it where the reader is looking."""
        for field in ("acl_file_perms_read", "acl_file_perms_write", "acl_file_export",
                      "acl_objects_with_own_perms", "acl_families_with_own_perms"):
            with self.subTest(column=field):
                self.assertIn("(absent)", self.cells[field])

    def test_an_open_domain_is_described_rather_than_enumerated(self):
        """The test does not ask an open domain to be closed; it asks it to be answered."""
        for field in self.OPEN_DOMAIN:
            with self.subTest(column=field):
                self.assertGreater(len(self.cells[field]), 3)

    def test_the_meaning_of_a_blank_is_stated_for_the_file_columns(self):
        flat = " ".join(self.section.split())
        self.assertIn("a blank means the key is written and carries", flat)


class TheShippedArtefactsAreNamedOneByOneTest(unittest.TestCase):
    """*Raised* at the third reading trial: **five** macros announced, **seven** described.

    The control compares the README to `macros.conf` and `savedsearches.conf`, both ways:
    a macro the app declares and the README ignores is as much a defect as a macro the
    README describes and the app does not ship."""

    def setUp(self):
        self.readme = _readme()
        self.macros = sorted({
            name.split("(")[0] for name in _conf_stanzas("macros.conf")
        })
        self.searches = _conf_stanzas("savedsearches.conf")

    def test_every_declared_macro_is_named_in_the_readme(self):
        missing = [name for name in self.macros
                   if "`%s`" % name not in self.readme
                   and "`%s(" % name not in self.readme]
        self.assertEqual([], missing,
                         "macro(s) shipped and never named to the operator: %s" % missing)

    def test_every_declared_saved_search_is_named_in_the_readme(self):
        missing = [name for name in self.searches
                   if "`%s`" % name not in self.readme]
        self.assertEqual([], missing,
                         "saved search(es) shipped and never named: %s" % missing)

    def test_the_announced_counts_equal_the_declared_counts(self):
        """The number the README announces is the number it lists, and the number the app
        declares. A document that miscounts what it ships cannot be believed on what it
        explains."""
        flat = " ".join(self.readme.split()).lower()
        words = {5: "five", 6: "six", 7: "seven", 10: "ten", 11: "eleven",
                 12: "twelve"}
        self.assertIn("**%s macros**" % words[len(self.macros)], flat,
                      "the announced macro count is not the declared one (%d)"
                      % len(self.macros))
        self.assertIn("**%s saved searches**" % words[len(self.searches)], flat)
        # The wording the trial found: five announced, seven described.
        self.assertNotIn("five rollback and reporting macros", flat)

    def test_the_inventory_section_exists_and_is_reachable(self):
        self.assertIn("## What is shipped, named one by one", self.readme)
        self.assertIn("#what-is-shipped-named-one-by-one", self.readme)

    def test_no_phantom_macro_is_described(self):
        """The other direction: a name in backticks that looks like one of ours and that
        `macros.conf` does not declare."""
        declared = set(self.macros)
        cited = {
            match.group(1)
            for match in re.finditer(r"`(app_acl_[a-z_]+|acl_inventory[a-z_]*|"
                                     r"editacl_rollback[a-z_]*)`", self.readme)
        }
        phantom = sorted(name for name in cited if name not in declared)
        self.assertEqual([], phantom,
                         "the README describes macro(s) the app does not declare: %s"
                         % phantom)


class EveryInternalLinkResolvesTest(unittest.TestCase):
    """v4.8: an internal link that does not resolve is a reference to nothing, and it
    fails **more quietly** than a missing file - the reader concludes he misread.

    Two things are checked, and the second is the one the reading trial raised: the anchor
    must exist, **and the link text must name the section it leads to**. A link labelled
    *Rollback* pointing at a section called something else sends the reader looking for a
    heading that does not exist."""

    def setUp(self):
        self.readme = _readme()
        self.headings = [
            match.group(1).strip()
            for match in re.finditer(r"^\s*>?\s*#{2,4}\s+(.*)$", self.readme, re.M)
        ]
        self.anchors = {_anchor(title) for title in self.headings}
        self.links = re.findall(r"\[([^\]]+)\]\(#([^)]+)\)", self.readme)

    def test_the_document_has_internal_links_to_check(self):
        self.assertTrue(self.links)

    def test_every_anchor_resolves_to_a_heading(self):
        broken = [target for _text, target in self.links if target not in self.anchors]
        self.assertEqual([], broken,
                         "internal link(s) pointing at no section: %s" % broken)

    def test_every_link_text_names_the_section_it_leads_to(self):
        mismatched = [
            "%s -> #%s" % (text, target)
            for text, target in self.links if _anchor(text) != target
        ]
        self.assertEqual(
            [], mismatched,
            "internal link(s) whose text names a section that does not exist under that "
            "name: %s" % mismatched,
        )


class TheReadmeSaysWhereAFatalErrorAppearsTest(unittest.TestCase):
    """Statement 17 of deliverable 9, added in v4.8 - and it is the statement the whole
    amendment turns on. The README promised the operator a diagnosis at the exact place a
    first deployment fails; the command gave none."""

    def setUp(self):
        self.readme = _readme()
        self.flat = " ".join(self.readme.split())

    def test_it_says_the_diagnosis_appears_in_the_job(self):
        self.assertIn("## When a command stops: where the reason appears", self.readme)
        self.assertIn("says why, and it says it in the job", self.flat)

    def test_it_holds_for_the_three_commands_whatever_their_mode(self):
        self.assertIn("This holds for all three commands and for every fatal error",
                      self.flat)
        for command in ("editacl:", "appaclinventory:", "editappacl:"):
            with self.subTest(prefix=command):
                self.assertIn(command, self.flat)

    def test_it_names_the_certificate_error_and_its_remedy(self):
        self.assertIn("self-signed certificate", self.flat)
        self.assertIn("verify_ssl = false", self.flat)
        self.assertIn("local/editacl.conf", self.flat)

    def test_it_sends_nobody_to_a_log_file_for_the_cause_of_a_stop(self):
        """The property is stated on the **job**: a file is a complement, never a
        substitute, and pointing at one here would restate the defect as a workaround."""
        self.assertIn("Do not go looking in a log file for the reason a run stopped",
                      self.flat)

    def test_it_names_the_generic_sentence_as_a_defect_rather_than_a_diagnosis(self):
        self.assertIn("External search command exited unexpectedly", self.flat)
        self.assertIn("that is not a diagnosis", self.flat)


class TheContentsListIsTheDocumentTest(unittest.TestCase):
    """**The contents list names exactly the headings of the document, and in order.**

    A list written by hand desynchronises at the first section added, and this README has
    already produced three statements of that family: a column order announced wrong, five
    macros announced for seven described, and a pointer at a file that was not shipped. A
    false contents list would be the fourth, this time at the top of the page - the first
    thing a reader trusts.

    The control is an equality **both ways** plus the order: a heading missing from the
    list, a line of the list naming no heading, or two that have drifted apart, all fail.
    """

    @classmethod
    def setUpClass(cls):
        cls.readme = _readme()

    def _headings(self):
        """Every heading of the document, code fences excluded - a `#` at the start of a
        line inside a shell block is a comment, not a section."""
        found, fenced = [], False
        for line in self.readme.split("\n"):
            if line.startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            match = re.match(r"^(#{2,4}) (.+)$", line)
            if match and match.group(2).strip() != "Contents":
                found.append((len(match.group(1)) - 2, match.group(2).strip()))
        return found

    def _listed(self):
        """The entries of the contents list, with their indentation level."""
        start = self.readme.index("## Contents")
        end = self.readme.index("\n## ", start + 5)
        entries = []
        for line in self.readme[start:end].split("\n"):
            match = re.match(r"^( *)- \[(.+)\]\(#([^)]+)\)$", line)
            if match:
                entries.append((len(match.group(1)) // 2, match.group(2), match.group(3)))
        return entries

    def test_the_document_has_a_contents_list(self):
        self.assertIn("## Contents", self.readme)
        self.assertTrue(self._listed())

    def test_it_lists_every_heading_and_no_other(self):
        listed = [(depth, title) for depth, title, _a in self._listed()]
        self.assertEqual(listed, self._headings(),
                         "the contents list and the headings have drifted apart")

    def test_every_entry_resolves_to_its_section(self):
        for _depth, title, target in self._listed():
            with self.subTest(entry=title):
                self.assertEqual(_anchor(title), target)

    def test_the_three_commands_are_listed_as_a_numbered_suite(self):
        """The order of use is visible in the contents list itself: decide, govern the
        generic, then the exception at object level."""
        titles = [title for _d, title, _a in self._listed()]
        numbered = [t for t in titles if re.match(r"^\d\. ", t)]
        self.assertEqual(len(numbered), 3)
        for rank, command in enumerate(("appaclinventory", "editappacl", "editacl"), 1):
            with self.subTest(command=command):
                self.assertTrue(
                    numbered[rank - 1].startswith("%d. `%s`" % (rank, command)),
                    "the suite is not in the order of use: %s" % numbered)

    def test_the_rule_of_use_comes_before_the_three_commands(self):
        titles = [title for _d, title, _a in self._listed()]
        rule = next(i for i, t in enumerate(titles) if "orders everything" in t)
        first = next(i for i, t in enumerate(titles) if t.startswith("1. "))
        self.assertLess(rule, first)

    def test_the_document_has_three_levels_of_heading(self):
        """A thousand lines under fifteen headings is a document nobody navigates."""
        depths = {depth for depth, _t in self._headings()}
        self.assertEqual(depths, {0, 1, 2})

    def test_no_section_runs_longer_than_the_eye(self):
        """The two blocks the reader stumbled on ran 120 and 180 lines with nothing
        between them. Nothing here is allowed back to that length."""
        positions, fenced = [], False
        for number, line in enumerate(self.readme.split("\n")):
            if line.startswith("```"):
                fenced = not fenced
                continue
            if not fenced and re.match(r"^#{2,4} ", line):
                positions.append((number, line.strip()))
        positions.append((len(self.readme.split("\n")), "(end)"))
        for (start, title), (end, _next) in zip(positions, positions[1:]):
            with self.subTest(section=title):
                self.assertLess(end - start, 115,
                                "%s runs %d lines without a heading" % (title,
                                                                        end - start))


class TheSeventeenStatementsSurviveTheRestructuringTest(unittest.TestCase):
    """**Deliverable 9 of the contract lists seventeen statements the README must carry**,
    and it is the only source of the README's obligations.

    A restructuring that lost one would trade a defect of plan for a defect of substance,
    and the existing tests would not all see it: several of them look inside a section **by
    name**, so a statement that fell out with its section would take its own test with it.
    This class checks the seventeen on the **whole document**, by markers, wherever they
    now live.
    """

    #: Two markers per statement: the words that carry the obligation, not the sentence
    #: around them. A reformulation must not fail this test; a disappearance must.
    STATEMENTS = {
        1: ("Writes?", "appaclinventory"),
        2: ("`acl_inventory`", "macro"),
        3: ("cannot be undone", "allow_create"),
        4: ("Generic first, specific by exception", "Never the other way round"),
        5: ("searchbnf", "unreachable"),
        6: ("search head cluster", "replication is healthy"),
        7: ("local/inputs.conf", "local/macros.conf"),
        8: ("not transactional", "rollback"),
        9: ("acl_handler", "any handler"),
        10: ("at a time on a given application", "nothing enforces it"),
        11: ("back your override up", "upgrad"),
        12: ("splunk_server", "unknown"),
        13: ("inherited", "materialise"),
        14: ("ceiling", "choice"),
        15: ("private", "blind"),
        16: ("Nineteen columns", "in the order they come out"),
        17: ("says it in the job", "self-signed certificate"),
    }

    @classmethod
    def setUpClass(cls):
        cls.flat = " ".join(_readme().split()).lower()

    def test_every_statement_of_the_deliverable_is_still_carried(self):
        missing = []
        for number, markers in sorted(self.STATEMENTS.items()):
            for marker in markers:
                if marker.lower() not in self.flat:
                    missing.append("%d: %r" % (number, marker))
        self.assertEqual([], missing,
                         "statement(s) of deliverable 9 lost in the restructuring: %s"
                         % missing)

    def test_the_status_enumeration_is_still_the_anchor_of_the_document(self):
        """The README anchors on the enumeration of statuses rather than on prose, and a
        control watches it: the statuses must stay named, wherever the sections moved."""
        for status in ("updated", "created", "noop_inherited", "rejected",
                       "skipped_ceiling", "not_found", "forbidden", "invalid_role"):
            with self.subTest(status=status):
                self.assertIn("`%s`" % status, self.flat)


class TheReadmeCarriesTheAuditViewStatementsTest(unittest.TestCase):
    """The five statements the dashboard spec adds to the README, all of them facts the
    operator cannot discover from the app itself.

    They are exigible here for the same reason as the rest: a clause that assigns content
    to the README without creating a verifiable obligation produces nothing."""

    def setUp(self):
        self.readme = _readme()
        self.flat = " ".join(self.readme.split())

    def test_the_role_is_declared_and_granted_to_nobody(self):
        self.assertIn("granted to nobody", self.flat)
        self.assertIn("role management chain", self.flat)

    def test_an_account_without_the_role_gets_a_404(self):
        self.assertIn("gets a **`404`** on the view, not a `403`", self.flat)

    def test_admin_all_objects_short_circuits_the_restriction(self):
        self.assertIn("`admin_all_objects` short-circuits the restriction", self.flat)

    def test_redirecting_the_journal_takes_two_places_and_the_app_has_four(self):
        self.assertIn("local/inputs.conf", self.flat)
        self.assertIn("local/macros.conf", self.flat)
        self.assertIn("four in all", self.flat)

    def test_the_estimate_sentence_is_carried_over_word_for_word(self):
        """The panel of the view and the README say the same thing, so an operator who
        reads one has read the other."""
        for fact in ("is an estimate, never a count",
                     "under-counts",
                     "lower bound",
                     "private objects are excluded from the count",
                     "has not been measured"):
            with self.subTest(fact=fact):
                self.assertIn(fact, self.flat.lower())

    def test_the_sentence_that_summarises_the_guard_rail_is_there(self):
        """Written as the spec asks: an empty dashboard does not prove that no write
        took place."""
        self.assertIn("A dashboard that shows nothing does not prove that no write took "
                      "place", self.flat)

    def test_both_views_are_named_with_what_they_audit(self):
        for view in ("editacl_runs", "appacl_runs"):
            with self.subTest(view=view):
                self.assertIn("`%s`" % view, self.flat)


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
