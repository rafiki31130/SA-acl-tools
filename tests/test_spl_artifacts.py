"""SPL artifacts: macros, shipped searches, lookups (sections 6.5, 6.7, 8.6, 12.7).

These files are normative deliverables just as much as the code, and they can only be
exercised on an instance by having one at hand. This module freezes outside Splunk what
can be frozen: the presence of the stanzas, the set of emitted fields, the inventory
source, and above all the **consistency between the table read by the Python code and
the lookup read by the inventory macro**. That is the same information under two forms,
and a divergence between them would make the inventory and the endpoint resolution
inconsistent without a single message.
"""

import csv
import json
import os
import re
import unittest

from . import BIN_DIR, REPO_ROOT
from .test_journal import ROLLBACK_FIELDS_FROM_INTENT

#: Set of fields required by section 6.7 constraint 3, in order, exactly.
INPUT_CONTRACT = (
    "title",
    "eai:acl.app",
    "eai:acl.owner",
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    "eai:type",
    "id",
)

#: Fields produced by `editacl_rollback` (section 8.6). `id` is not among them: it is
#: not journaled, and that is precisely why the inventory macro has to synthesize
#: `eai:type` (section 6.7 constraint 4).
#: The order is the one of section 8.6, taken literally.
ROLLBACK_CONTRACT = (
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    "eai:acl.owner",
    "eai:acl.app",
    "title",
    "eai:type",
)


def read_splunk_conf(*parts):
    """Splunk `.conf` reader: handles line continuation by a trailing `\\`.

    `configparser` cannot deal with it - it only joins indented lines - and would
    therefore make any multi-line macro definition unreadable.
    """
    path = os.path.join(REPO_ROOT, *parts)
    stanzas = {}
    current = None
    key = None
    buffer = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if buffer is not None:
                more = line.endswith("\\")
                buffer.append(line[:-1] if more else line)
                if not more:
                    stanzas[current][key] = " ".join(
                        part.strip() for part in buffer
                    ).strip()
                    buffer = None
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                stanzas.setdefault(current, {})
                continue
            if "=" in stripped and current is not None:
                key, value = stripped.split("=", 1)
                key = key.strip()
                if line.endswith("\\"):
                    buffer = [value[: value.rindex("\\")] if "\\" in value else value]
                else:
                    stanzas[current][key] = value.strip()
    return stanzas


def read_csv_lookup(name):
    path = os.path.join(REPO_ROOT, "lookups", name)
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def endpoint_map():
    with open(os.path.join(BIN_DIR, "acl_endpoint_map.json"), encoding="utf-8") as f:
        return json.load(f)


def table_fields(definition):
    """Extract the field list of the last `| table ...` of an SPL definition."""
    segment = definition.rsplit("| table ", 1)[1]
    return [c.strip().strip('"').strip("'") for c in segment.split(",") if c.strip()]


class MacrosTest(unittest.TestCase):
    def setUp(self):
        self.conf = read_splunk_conf("default", "macros.conf")
        self.families = read_csv_lookup("acl_object_families.csv")

    def test_the_macros_of_the_specification_are_declared(self):
        for stanza in ("acl_inventory", "acl_inventory(1)",
                       "editacl_rollback(1)", "editacl_rollback_apply(1)"):
            self.assertIn(stanza, self.conf)

    def test_one_stanza_per_arity_up_to_the_number_of_families(self):
        # Splunk indexes macros by ARITY: `acl_inventory(savedsearch,views)` is a call
        # with two arguments. Without an `[acl_inventory(2)]` stanza, the parameterized
        # form of section 13 fails with "macro cannot be found".
        arities = {
            int(m.group(1))
            for m in (re.match(r"^acl_inventory\((\d+)\)$", s) for s in self.conf)
            if m
        }
        self.assertEqual(arities, set(range(1, len(self.families) + 1)))

    def test_the_inventory_does_not_rely_on_the_aggregation_handler(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertNotIn("admin/directory", definition)
        self.assertIn("inputlookup acl_object_families", definition)

    def test_the_inventory_emits_exactly_the_input_contract(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertEqual(tuple(table_fields(definition)), INPUT_CONTRACT)

    def test_the_inventory_synthesizes_eai_type(self):
        # Without that synthesis the outbound leg works - `id` is usable - but the
        # rollback is impossible: the restore resolves by `eai:type` (section 6.7-4).
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertIn("acl_family", definition)
        self.assertRegex(
            definition,
            r"eval \"eai:type\" = if\(isnull\('eai:type'\).*acl_family",
        )

    def test_the_selection_precedes_the_rest_calls(self):
        # The cost lever of section 6.7-2: a family that was not asked for must cost no
        # REST call. If the `where` came after the `map`, everything would be
        # enumerated.
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertLess(definition.index("| where match(family"),
                        definition.index("| map "))

    def test_the_family_argument_is_filtered_before_injection_into_a_regex(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertIn('replace("$families$", "[^A-Za-z0-9_,-]", "")', definition)

    def test_the_rollback_produces_exactly_the_seven_expected_fields(self):
        definition = self.conf["editacl_rollback(1)"]["definition"]
        emitted = re.findall(r'AS\s+"?([A-Za-z:._*]+)"?', definition)
        self.assertEqual(
            tuple(c for c in emitted if c != "restorable"), ROLLBACK_CONTRACT
        )

    def test_the_rollback_consumes_only_journaled_fields(self):
        definition = self.conf["editacl_rollback(1)"]["definition"]
        for field in ("before_perms_read", "before_perms_write", "before_sharing",
                      "before_owner", "app", "title", "eai_type", "endpoint", "phase",
                      "status", "sid"):
            self.assertIn(field, definition)
            self.assertIn(field, ROLLBACK_FIELDS_FROM_INTENT + ("status",))

    def test_the_rollback_pairs_only_completed_writes(self):
        # An object whose POST failed was not modified: "restoring" it would write it
        # towards a state it never left.
        definition = self.conf["editacl_rollback(1)"]["definition"]
        self.assertIn('phase="outcome" AND status="updated"', definition)
        self.assertIn("eventstats max(_restorable) AS restorable BY endpoint",
                      definition)

    def test_the_applied_rollback_delegates_to_the_preview_rollback(self):
        # Two copies of the same pipeline would diverge at the first amendment, and the
        # forgotten copy would be the one that writes.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn("`editacl_rollback($sid$)`", definition)

    def test_the_applied_rollback_carries_the_complete_invocation(self):
        # D-13: the macro exists so that the operator has nothing to type at the moment
        # of restoring after an incident.
        #
        # It no longer carries ANY field-naming parameter: the macro emits the
        # platform's native field names, which the four target values pick up by
        # default. The error class of v1.3 - an unquoted `fields` list, truncated by SPL
        # to its first value, a restore that only put `perms.read` back while reporting
        # a success - is eliminated by construction: there is no list left to quote.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn("| editacl ", definition)
        self.assertIn("dryrun=f", definition)
        self.assertNotIn("fields=", definition)

    def test_the_applied_rollback_raises_the_default_ceiling(self):
        # The default is ten (D-30): a restore would hit it at the eleventh object. The
        # volume was already decided by the operator on the outbound leg, and the `sid`
        # delimits the set.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn("max_objects=", definition)

    def test_the_rollback_materializes_the_permission_columns(self):
        # Section 8.6, D-32: restoring an EMPTY permission must clear the attribute.
        # Measured on 9.4.6, the journal -> indexing -> `stats` chain does NOT lose an
        # empty permission: the column is extracted and survives the aggregation. The
        # `coalesce` is therefore DEFENSE IN DEPTH - it materializes the column
        # unconditionally, which holds for a platform version that would not keep this
        # behavior - and not the fix of an observed defect.
        definition = self.conf["editacl_rollback(1)"]["definition"]
        for field in ("eai:acl.perms.read", "eai:acl.perms.write"):
            self.assertIn("coalesce('%s'" % field, definition)

    def test_the_rollback_materializes_neither_sharing_nor_owner(self):
        # Their empty value does not exist on the platform side: materializing an empty
        # column would only turn a correct preservation into a rejection.
        definition = self.conf["editacl_rollback(1)"]["definition"]
        for field in ("eai:acl.sharing", "eai:acl.owner"):
            self.assertNotIn("coalesce('%s'" % field, definition)

    def test_the_rollback_reemits_the_previous_owner(self):
        # Section 8.6, D-22 + D-27: the macro emits `eai:acl.owner` carrying the
        # PREVIOUS owner, which the default of `new_owner` picks up with no explicit
        # parameter. This is what the parameter model makes expressible and what v1
        # could not do - finding C-1 of the scoping stage rested on that impossibility.
        definition = self.conf["editacl_rollback(1)"]["definition"]
        self.assertIn('earliest(before_owner)', definition)
        self.assertIn('AS "eai:acl.owner"', definition)

    def test_only_the_applied_rollback_writes(self):
        # `editacl_rollback(1)` remains the preview form: it must carry no invocation of
        # the command (the `sourcetype=editacl:journal` is not one: what is looked for
        # is the command in pipe position).
        self.assertNotIn("| editacl ", self.conf["editacl_rollback(1)"]["definition"])

    def test_the_rollback_is_invocable_in_generating_position(self):
        # Invoked as `| `editacl_rollback(...)``, the definition must start with a
        # command. Section 8.6 writes the SPL without its leading `search`.
        self.assertTrue(
            self.conf["editacl_rollback(1)"]["definition"].startswith("search index=")
        )


class TableAndLookupConsistencyTest(unittest.TestCase):
    """The table is read by the Python code, the lookup by the macro. A divergence
    between the two only shows up at run time, and with no message."""

    def setUp(self):
        self.families = {
            row["family"]: row["handler_path"]
            for row in read_csv_lookup("acl_object_families.csv")
        }
        self.table = endpoint_map()

    def test_every_family_is_a_key_of_the_table(self):
        for family, handler in self.families.items():
            self.assertIn(family, self.table)
            self.assertEqual(self.table[family], handler)

    def test_every_handler_of_the_table_is_inventoried(self):
        self.assertEqual(set(self.families.values()), set(self.table.values()))

    def test_a_single_record_per_handler(self):
        # Two keys of the table may aim at the same handler; the inventory must only
        # enumerate it once, otherwise it produces duplicates.
        handlers = list(self.families.values())
        self.assertEqual(len(handlers), len(set(handlers)))


class SavedsearchesTest(unittest.TestCase):
    def setUp(self):
        self.conf = read_splunk_conf("default", "savedsearches.conf")

    NAMES = (
        "ACL - inventory by role",
        "ACL - references to decommissioned roles",
        "ACL - change journal",
    )

    def test_the_three_searches_of_section_12_7_are_shipped(self):
        for name in self.NAMES:
            self.assertIn(name, self.conf)

    def test_the_inventories_are_built_on_the_macro_and_not_on_the_handler(self):
        for name in self.NAMES[:2]:
            search = self.conf[name]["search"]
            self.assertIn("`acl_inventory`", search)
            self.assertNotIn("admin/directory", search)

    def test_the_decommissioned_roles_search_feeds_editacl_directly(self):
        search = self.conf[self.NAMES[1]]["search"]
        self.assertIn("lookup acl_decommissioned_roles", search)
        emitted = table_fields(search)
        for field in INPUT_CONTRACT:
            self.assertIn(field, emitted)

    def test_no_search_is_scheduled(self):
        # The inventory is a macro invocable inline; scheduling is a recommended usage,
        # never the way it is reached (section 6.7 constraint 1).
        for name in self.NAMES + (self.AUDIT,):
            self.assertEqual(self.conf[name]["enableSched"], "0")

    # -- section 12.7, blocking deliverable ---------------------------------- #

    AUDIT = "ACL - eventtype / derived object divergences"

    def test_the_divergence_audit_search_is_shipped(self):
        """**Blocking** deliverable of section 12.

        It covers exactly the blind spot of D-18: a diverging derived object whose
        carrier enters no batch is reached by no cascade, and the command will never
        write it. Without this search, the volume concerned is not measurable on the
        target platform.
        """
        self.assertIn(self.AUDIT, self.conf)

    def test_the_audit_is_built_on_the_inventory_macro(self):
        search = self.conf[self.AUDIT]["search"]
        self.assertIn("`acl_inventory(eventtypes,fvtags)`", search)
        self.assertNotIn("admin/directory", search)

    def test_the_audit_compares_the_derived_object_to_its_carrier(self):
        search = self.conf[self.AUDIT]["search"]
        # Both sides are paired, then their ACL digests are compared.
        self.assertIn("acl_acl_carrier", search)
        self.assertIn("acl_acl_derived", search)
        self.assertIn("acl_acl_carrier != acl_acl_derived", search)

    def test_the_audit_reports_roles_referenced_by_the_derived_object_only(self):
        """The second half of section 12.7, distinct from a plain ACL divergence."""
        search = self.conf[self.AUDIT]["search"]
        self.assertIn("lookup acl_decommissioned_roles", search)
        self.assertIn("acl_role_uncovered", search)

    def test_the_audit_pairs_by_decomposition_never_by_concatenation(self):
        """Same discipline as rank 0 of section 5.4 (section 3.4, property 3).

        The pairing starts from the composite key of the derived object and
        **decomposes** it; it never recomposes the name of a derived object from the
        name of a carrier. An `eventtype=` followed by a concatenation would signal the
        fault.
        """
        search = self.conf[self.AUDIT]["search"]
        self.assertIn("acl_pair_field", search)
        self.assertIn("acl_pair_value", search)
        self.assertNotIn('"eventtype=" .', search)
        self.assertNotIn('. "eventtype="', search)


class LookupsAndMetadataTest(unittest.TestCase):
    def test_the_lookup_definitions_point_at_shipped_files(self):
        conf = read_splunk_conf("default", "transforms.conf")
        for stanza in ("acl_object_families", "acl_decommissioned_roles"):
            self.assertIn(stanza, conf)
            path = os.path.join(REPO_ROOT, "lookups", conf[stanza]["filename"])
            self.assertTrue(os.path.exists(path), path)

    def test_the_roles_lookup_only_carries_generic_identifiers(self):
        # The repository is public: the shipped list is a template, never real roles.
        roles = {row["role"] for row in read_csv_lookup("acl_decommissioned_roles.csv")}
        self.assertEqual(roles, {"legacy_role", "role_a", "role_b"})

    def test_macros_transforms_and_lookups_are_exported_to_the_system(self):
        # A macro confined to the context of its app is not invocable inline from an ad
        # hoc search, and an exported macro that relies on a lookup that is not exported
        # fails outside its own app.
        meta = read_splunk_conf("metadata", "default.meta")
        for stanza in ("macros", "transforms", "lookups"):
            self.assertEqual(meta[stanza]["export"], "system")


class RevalidationTest(unittest.TestCase):
    """Section 6.5: the procedure reuses the core, it does not reimplement it."""

    def setUp(self):
        path = os.path.join(REPO_ROOT, "tools", "revalidate_mapping.py")
        with open(path, encoding="utf-8") as handle:
            self.source = handle.read()

    def test_the_procedure_is_shipped(self):
        self.assertTrue(self.source)

    def test_it_reuses_the_core_rather_than_rewriting_it(self):
        self.assertIn("from acltools.mapping import load_mapping", self.source)
        self.assertIn("from acltools.endpoint import build_object_path", self.source)

    def test_it_produces_the_three_required_lists(self):
        for marker in ("== A. ", "== B. ", "== C. "):
            self.assertIn(marker, self.source)

    def test_the_password_is_never_a_command_line_argument(self):
        self.assertIn("sys.stdin.readline()", self.source)
        self.assertNotIn("--password", self.source)


class FieldsParameterIsGoneTest(unittest.TestCase):
    """Mechanical scan of the repository: the `fields` parameter no longer exists
    (D-23), and no copyable line may still offer it.

    This test replaces the one of v1.3, which scanned the repository looking for an
    **unquoted** `fields` list. SPL truncated it to its first value with no error, and a
    restore truncated that way reported a success without restoring. It was the most
    serious defect this project has known.

    The redesign eliminates it **by construction**: each parameter now carries a single
    field name, with no comma, and silent truncation has nothing left to act on. What
    remains worth guarding is that no documentation and no example still offers the form
    that disappeared - an operator copying it would get an unknown-parameter error, and
    above all a syntax that no longer does what it says.

    The tests directory is excluded: it **must** be able to name the parameter that
    disappeared in order to prove that it did.
    """

    #: Built by concatenation so that this file cannot be its own counter-example. The
    #: pattern matches the SPL option assignment `fields=`, not the `| fields ...`
    #: command nor a Python identifier such as `field_present`.
    PATTERN = re.compile("fields" + r"\s*=")

    EXCLUDED = ("/.git/", "/__pycache__/", "/bin/lib/", "/tests/")

    EXTENSIONS = (".py", ".md", ".conf", ".csv", ".json", ".xml", ".sh", ".example",
                  ".txt", ".meta", ".gitattributes", ".gitignore")

    def _files(self):
        for root, dirnames, filenames in os.walk(REPO_ROOT):
            dirnames[:] = [
                d for d in dirnames if d not in (".git", "__pycache__", "lib", "tests")
            ]
            for name in filenames:
                path = os.path.join(root, name)
                normalized = path.replace(os.sep, "/")
                if any(prefix in normalized for prefix in self.EXCLUDED):
                    continue
                if not normalized.endswith(self.EXTENSIONS):
                    continue
                yield path

    def test_the_scan_really_covers_the_deliverables(self):
        """A scan that reads nothing would always pass."""
        scanned = [os.path.basename(p) for p in self._files()]
        for expected in ("README.md", "macros.conf", "editacl.py", "rest.py",
                         "searchbnf.conf"):
            self.assertIn(expected, scanned)

    def test_the_pattern_matches_the_removed_form_and_spares_the_legitimate_ones(self):
        self.assertTrue(self.PATTERN.search("| editacl " + "fields=perms.write"))
        self.assertTrue(self.PATTERN.search("| editacl " + 'fields="a.b,c.d"'))
        self.assertIsNone(self.PATTERN.search('| fields title "eai:acl.*"'))
        self.assertIsNone(self.PATTERN.search("def field_present(record, name):"))
        self.assertIsNone(self.PATTERN.search("FIELD_NAME_PARAMS = ("))

    def test_the_fields_parameter_no_longer_appears_in_the_deliverables(self):
        offenders = []
        for path in self._files():
            try:
                with open(path, encoding="utf-8") as handle:
                    lines = handle.readlines()
            except (UnicodeDecodeError, OSError):
                continue
            for number, line in enumerate(lines, 1):
                if self.PATTERN.search(line):
                    offenders.append(
                        "%s:%d" % (os.path.relpath(path, REPO_ROOT), number)
                    )
        self.assertEqual(
            offenders, [],
            "the `fields` parameter is gone (D-23) but is still offered here: %s"
            % ", ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
