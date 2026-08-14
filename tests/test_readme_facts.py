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
        start = section.index("## What the inventory gives you")
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
        start = readme.index("## What the inventory gives you")
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


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
