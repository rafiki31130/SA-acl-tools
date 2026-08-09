"""The repository is written in English - a check, not an intention.

This app is published, and its comments are not decoration: they carry measurements and
reasoning that a Splunk developer reading the source needs. Half of that value is lost
if the reader does not speak French. The repository was therefore translated in full,
and this module is what keeps it translated: a French sentence written back into a
comment, a docstring, a `.conf` header or a lookup value fails the suite, naming the
file, the line and the offending fragment.

How the detection works, and why it is built this way
-----------------------------------------------------

Three detectors, deliberately layered. Any one of them firing is a fault.

1. **French function words** - articles, pronouns, prepositions, conjunctions, common
   auxiliaries. The main instrument, described below.
2. **`et`**, with a lookahead sparing the Latin `et al.` / `et cetera`. It exists
   because the word list alone misses a *telegraphic* fragment: a docstring title or a
   table caption such as "Machine a etats, invariants de journal, plafond et
   deduplication" carries no article and no pronoun at all. That gap was found by
   running the check against a real untranslated file, not by reasoning about it.
3. **French elision** - `d'un`, `l'objet`, `n'est`, `qu'il`, `jusqu'a`. This is the
   strongest signal available, because English apostrophes work the other way round:
   in `don't`, `it's`, `Splunk's`, the apostrophe follows the END of a word, whereas an
   elided French article is a lone letter before it. Measured over the translated
   repository, and over its SPL and Python string literals: zero hits.

The word list rests on **French function words** - articles, pronouns, prepositions,
conjunctions, common auxiliaries. Two properties make them the right instrument:

- they are unavoidable. A French sentence of any length carries several of them, so a
  passage reinserted in French is caught whatever its subject;
- the ones retained here **do not exist in English**, and are not plausible identifiers
  in this code base.

The second property is the whole difficulty, and the list below is the result of
excluding, deliberately, every word that would make the check unreliable:

- English words that are also French words: `on`, `car`, `son`, `pas`, `plus`, `note`,
  `port`, `date`, `type`, `simple`, `possible`, `distinct`, `important`, `capable`,
  `instance`, `application`, `configuration`, `information`, `journal`, `notre`, `nom`;
- French words borrowed into English, where a correct English sentence may legitimately
  use them: `sans` (sans serif), `encore`, `genre`, `role`;
- words too short or too close to a technical abbreviation to be safe: `de`, `ne`,
  `si`, `ou`, `par`, `en`, `au`, `ce` alone, `il` alone.

What is left is narrow on purpose. A check that cried wolf on correct English would be
switched off within the month, and would then protect nothing.

The two directions are exercised. `test_no_french_residue_in_scope` proves the check
passes on the translated repository; `TheDetectorActuallyDetectsTest` proves it fails
on French witness sentences, including ones whose subject matter is entirely technical.

Typographic residue is checked separately. `section`, straight quotes and `...` replace
the `SS`-sign, the French angle quotes and the ellipsis character; those characters are
never legitimate here, and unlike accented letters they never appear in an encoding
fixture.

Scope
-----

Every text file tracked in the repository, with two declared exclusions:

- `bin/lib/` - the vendored Splunk SDK. It is third-party code, its integrity is held
  by `bin/lib/MANIFEST.sha256` and by `tests/test_vendor_manifest.py`, and touching it
  would break both;
- this module itself. Its vocabulary *is* the French word list; scanning it would make
  the check fail on its own instrument. It is the only file whose exclusion buys
  nothing but the check's own existence.

`README.md` used to carry a third, temporary exclusion, while the split into an operator
document and a developer document was still pending. Both documents are now in English
and both are in scope, together with `docs/DESIGN.md`. The exclusion is gone, and so is
the test that watched over its justification: an exclusion that no longer has a reason
must not survive as a habit.
"""

import os
import re
import unittest

from . import REPO_ROOT

#: File extensions scanned. Binary and archive formats are out: they carry no prose.
TEXT_SUFFIXES = (
    ".py", ".conf", ".csv", ".example", ".json", ".md", ".meta", ".sh", ".txt",
    ".xml", ".cfg", ".ini",
)

#: Extension-less files that are nonetheless text and in scope.
TEXT_FILENAMES = (".gitattributes", ".gitignore", "LICENSE")

#: Declared exclusions. Each one is named and justified in the module docstring; none
#: is implicit. A path prefix, in repository-relative POSIX form.
EXCLUDED_PATHS = (
    "bin/lib/",              # vendored SDK, third party, integrity held by a manifest
    "tests/test_language.py",  # this module: its content is the detector's vocabulary
)

#: French function words that do not exist in English and are not plausible identifiers
#: here. See the module docstring for what was deliberately left out and why.
FRENCH_MARKERS = (
    # determiners
    "le", "la", "les", "une", "des", "du", "aux", "cet", "cette", "ces",
    # pronouns and relatives
    "qui", "que", "dont", "elle", "elles", "ils", "lui", "leur", "leurs",
    "celui", "celle", "ceux", "cela", "nous", "vous",
    # prepositions
    "avec", "dans", "sous", "chez", "pour", "depuis", "entre", "sur", "vers",
    # conjunctions and adverbs
    "donc", "ainsi", "alors", "aussi", "mais", "meme", "toujours", "jamais",
    "deja", "plutot", "ensuite", "cependant", "neanmoins", "lorsque", "puisque",
    "tandis", "quand", "comme", "afin",
    # auxiliaries and very common verbs
    "est", "sont", "etait", "etaient", "sera", "seront", "etre", "ete",
    "avoir", "avait", "ont", "peut", "peuvent", "doit", "doivent", "faut",
    # quantifiers
    "tout", "tous", "toute", "toutes", "chaque", "plusieurs", "aucun", "aucune",
    "rien",
)

#: Typographic characters inherited from the French text. Unlike accented letters -
#: which a URI-encoding fixture legitimately carries - none of these has any business
#: in this repository.
FORBIDDEN_TYPOGRAPHY = {
    "§": "section sign; write 'section 5.4'",
    "«": "left angle quote; use a straight double quote",
    "»": "right angle quote; use a straight double quote",
    "—": "em dash; use ' - ' or restructure the sentence",
    "–": "en dash; use '-'",
    "‘": "curly quote; use a straight quote",
    "’": "curly apostrophe; use a straight apostrophe",
    "“": "curly quote; use a straight double quote",
    "”": "curly quote; use a straight double quote",
    "…": "ellipsis character; write '...'",
}

#: One alternation, case-insensitive, on word boundaries. Built once: the scan walks a
#: few hundred files.
_MARKER_RE = re.compile(
    r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(sorted(FRENCH_MARKERS, key=len, reverse=True))
)

#: `et`, with the one exception that makes it safe. It is by far the most frequent
#: French word, and it is what catches a telegraphic fragment - a docstring title, a
#: table caption - that carries no other function word. The only English use is the
#: Latin `et al.` / `et cetera`, which the lookahead spares.
_ET_RE = re.compile(r"(?i)(?<![\w-])et(?![\w-])(?!\s+(?:al\b|cetera\b))")

#: French elision: a single-letter (or `qu`-family) word joined to the next one by an
#: apostrophe - `d'un`, `l'objet`, `n'est`, `qu'il`, `jusqu'a`.
#:
#: It is the strongest signal available, because English apostrophes work the other way
#: round: in `don't`, `it's`, `Splunk's`, the apostrophe follows the END of a word. The
#: lookbehind requires the letter before the apostrophe to be preceded by a non-letter,
#: which is exactly what an elided French article is and what an English contraction
#: never is. Measured over the translated repository: zero hits.
_ELISION_RE = re.compile(
    r"(?<![A-Za-z])(?:jusqu|lorsqu|puisqu|quelqu|aujourd|qu|d|l|n|s|j|m|t|c)"
    r"['’][A-Za-z]"
)


def _is_excluded(relative_path):
    return any(relative_path.startswith(prefix) for prefix in EXCLUDED_PATHS)


def _is_text(relative_path):
    name = os.path.basename(relative_path)
    if name in TEXT_FILENAMES:
        return True
    return any(name.endswith(suffix) for suffix in TEXT_SUFFIXES)


def scan_text(text):
    """Return `[(line number, matched word, line)]` for one file's content.

    Exposed as a function so the detector can be exercised on witness strings without
    writing anything to disk.
    """
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        for regex in (_MARKER_RE, _ET_RE, _ELISION_RE):
            for match in regex.finditer(line):
                hits.append((number, match.group(0), line.strip()))
    return hits


def in_scope_files():
    """Every text file of the repository outside the declared exclusions."""
    found = []
    for root, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for name in filenames:
            absolute = os.path.join(root, name)
            relative = os.path.relpath(absolute, REPO_ROOT).replace(os.sep, "/")
            if _is_excluded(relative) or not _is_text(relative):
                continue
            found.append((relative, absolute))
    return sorted(found)


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


class RepositoryIsInEnglishTest(unittest.TestCase):
    """Direction 1: the check passes on the translated repository."""

    @classmethod
    def setUpClass(cls):
        cls.files = in_scope_files()

    def test_the_scan_actually_reads_the_deliverables(self):
        """A scan that reads nothing would pass forever.

        The listed files are the ones the translation had to cover; if the walk stops
        seeing them, the two tests below are worthless.
        """
        scanned = {relative for relative, _absolute in self.files}
        for expected in (
            "README.md",
            "docs/DESIGN.md",
            "bin/editacl.py",
            "bin/acltools/pipeline.py",
            "bin/acltools/preflight.py",
            "default/macros.conf",
            "default/savedsearches.conf",
            "default/searchbnf.conf",
            "default/data/ui/views/editacl_runs.xml",
            "metadata/default.meta",
            "lookups/acl_decommissioned_roles.csv",
            "tests/test_pipeline.py",
            "tools/revalidate_mapping.py",
        ):
            self.assertIn(expected, scanned)
        self.assertGreater(len(scanned), 40)

    def test_no_french_residue_in_scope(self):
        faults = []
        for relative, absolute in self.files:
            for number, word, line in scan_text(_read(absolute)):
                faults.append("  %s:%d  [%s]  %s" % (relative, number, word, line[:120]))
        self.assertEqual(
            faults,
            [],
            "French residue found in %d place(s):\n%s"
            % (len(faults), "\n".join(faults[:60])),
        )

    def test_no_typographic_residue_in_scope(self):
        faults = []
        for relative, absolute in self.files:
            content = _read(absolute)
            for number, line in enumerate(content.splitlines(), 1):
                for char, reason in FORBIDDEN_TYPOGRAPHY.items():
                    if char in line:
                        faults.append(
                            "  %s:%d  U+%04X (%s)  %s"
                            % (relative, number, ord(char), reason, line.strip()[:100])
                        )
        self.assertEqual(
            faults,
            [],
            "typographic residue found in %d place(s):\n%s"
            % (len(faults), "\n".join(faults[:60])),
        )

    def test_no_path_is_excluded_without_a_standing_reason(self):
        """An exclusion is a hole opened by hand, and holes outlive their reason.

        Only two exclusions are admitted, both named and justified in the module
        docstring. Adding a third one has to be a deliberate act, visible in this diff -
        which is what stopped the temporary `README.md` exclusion from becoming
        permanent once the split-and-translate work had landed.
        """
        self.assertEqual(
            ("bin/lib/", "tests/test_language.py"),
            EXCLUDED_PATHS,
            "the set of exclusions changed: justify the new one in the module "
            "docstring, or remove it",
        )


class TheDetectorActuallyDetectsTest(unittest.TestCase):
    """Direction 2: the check fails on French, and only on French.

    Without this class the previous one proves nothing: a detector matching nothing
    also reports zero faults.
    """

    def test_a_french_technical_sentence_is_caught(self):
        witness = (
            "# La presence de la colonne decide seule de modifier ou de preserver, "
            "et la cellule ne decide que de la valeur."
        )
        hits = scan_text(witness)
        self.assertTrue(hits, "witness French sentence not detected")
        self.assertEqual(hits[0][0], 1)

    def test_a_french_docstring_is_caught(self):
        witness = '"""Le journal est le seul filet de securite de cette operation."""'
        self.assertTrue(scan_text(witness))

    def test_a_single_french_clause_inside_english_is_caught(self):
        """Residue is rarely a whole paragraph; it is usually one clause left behind."""
        witness = "# The ceiling is checked before the GET, donc avant tout echange."
        self.assertTrue(scan_text(witness))

    def test_a_french_conf_comment_is_caught(self):
        witness = "# Cette stanza est un glob : un fichier par execution."
        self.assertTrue(scan_text(witness))

    def test_correct_english_prose_is_not_flagged(self):
        """Zero false positives is the other half of the requirement.

        These sentences are deliberately taken from the vocabulary of this repository -
        the register in which a false positive would actually happen.
        """
        for witness in (
            "The presence of the column alone decides whether to modify or to "
            "preserve; the cell only decides the value.",
            "One file per sid, with no size-based rotation: a shared rotating handler "
            "is not safe across processes.",
            "The ceiling is no longer a fatal error; it surfaces as a per-event "
            "status and the output of the search stays complete.",
            "Measured on 9.4.6: the POST is refused, the runtime view is nevertheless "
            "mutated, and the disk stays intact.",
            "An empty tuple yields the empty string, never a wildcard.",
            "Note the port, the date, the type and the role are all unchanged on "
            "this instance, so the configuration is simple and the information "
            "distinct.",
        ):
            self.assertEqual(
                scan_text(witness), [], "false positive on: %r" % witness
            )

    def test_technical_identifiers_are_not_flagged(self):
        """Splunk vocabulary must survive the check untouched."""
        for witness in (
            'output["acl_status"] = result.status',
            "| `acl_inventory(savedsearch,views)` | search ... | editacl dryrun=f",
            "eai:acl.perms.read / eai:acl.perms.write / eai:acl.sharing",
            "servicesNS/nobody/my_app/saved/searches/my-object",
            "TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z",
            "legacy_role,new_role_read,new_role_admin",
            "handler_path, family, eai_type, skipped_ceiling, not_found",
        ):
            self.assertEqual(
                scan_text(witness), [], "false positive on: %r" % witness
            )

    def test_a_marker_inside_a_larger_word_is_not_flagged(self):
        """`est` inside `latest`, `la` inside `class`: word boundaries do their job."""
        for witness in (
            "latest_time, earliest_time, request, test, nested",
            "class Mapping(object):  # 'files' holds the marker as a substring",
            "measure, sources, content, latest, request, closest, tous_placeholder",
        ):
            self.assertEqual(
                [hit[1] for hit in scan_text(witness)],
                [],
                "false positive on: %r" % witness,
            )

    def test_a_hyphenated_identifier_is_not_split_into_markers(self):
        """`conf-times`, `lookup-table-file`: a hyphen is not a word boundary here."""
        self.assertEqual(scan_text("collections-conf, lookup-table-file, nav"), [])

    def test_a_telegraphic_french_fragment_with_no_function_word_is_caught(self):
        """The case the word list alone would miss.

        A docstring title such as "Machine a etats, invariants de journal, plafond et
        deduplication" carries no article and no pronoun. `et` catches it.
        """
        witness = (
            '"""Machine a etats, invariants de journal, plafond et deduplication."""'
        )
        self.assertTrue(scan_text(witness), "telegraphic French fragment not detected")

    def test_latin_et_al_is_not_flagged(self):
        """The one English use of `et`, spared on purpose."""
        for witness in (
            "See Lamport et al. for the ordering argument.",
            "roles, capabilities, et cetera",
        ):
            self.assertEqual(scan_text(witness), [], "false positive on: %r" % witness)

    def test_a_french_elision_is_caught(self):
        """`d'un`, `l'objet`, `n'est`, `qu'il`: the strongest signal available."""
        for witness in (
            "# Le POST n'est pas rejoue.",
            "# resolution de l'endpoint",
            "# une ligne d'intention par objet",
            "# tant qu'aucun porteur n'existe",
            "# jusqu'a la fin du lot",
        ):
            self.assertTrue(scan_text(witness), "not detected: %r" % witness)

    def test_english_contractions_and_possessives_are_not_flagged(self):
        """An English apostrophe follows the END of a word; a French one precedes it."""
        for witness in (
            "It doesn't retry, and it won't: the POST isn't idempotent.",
            "the platform's own grammar, splunkd's response, the operator's pipeline",
            "record.get('name'), parser.get('editacl', name), if x == 'derived'",
            'eval acl_side = case(\'eai:type\'=="eventtypes", "carrier")',
            "O'Brien is not a French elision either",
        ):
            self.assertEqual(scan_text(witness), [], "false positive on: %r" % witness)


if __name__ == "__main__":                                           # pragma: no cover
    unittest.main()
