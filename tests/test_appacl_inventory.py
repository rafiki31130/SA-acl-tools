"""The inventory core (v4.1 section 7), and the bounds it inherits from section 6.

What this module holds, and it is the whole reason the command exists: **the distinction
between an inherited value and a frozen one**. Measured (Q0-4), REST answers the same
block for both, so every test below that touches `acl_present_local`,
`acl_frozen_stanzas`, `acl_provenance` or `acl_governable` is exercising the one thing
no REST source can give.

No Splunk, no network, no file system: the REST port is an in-memory double, and the
provenance is the **real** reader fed with the text of a `.meta` file - substituting the
reader would replace the thing under test by a description of it.
"""

import ast
import os
import unittest

from acltools.appacl_impact import ImpactEstimator
from acltools.appacl_inventory import (
    GOVERNABLE_PARTIAL,
    GOVERNABLE_UNKNOWN,
    GOVERNABLE_YES,
    INVENTORY_OUTPUT_FIELDS,
    SERVER_INFO_PATH,
    WRITE_PATH_MAPPED,
    WRITE_PATH_UNMAPPED,
    InventoryBuilder,
    app_matches,
    export_of,
    families_to_emit,
    governable_of,
    list_applications,
    parse_app_filter,
    parse_family_list,
    resolve_member,
    sanitize_filter,
    split_access,
)
from acltools.appacl_model import (
    DEFAULT_APP_FIELD_NAMES,
    STANZA_KIND_APP,
    STANZA_KIND_FAMILY,
    AppInventoryParams,
)
from acltools.appacl_preflight import (
    REQUIRED_INVENTORY_CAPABILITY,
    validate_inventory_params,
)
from acltools.errors import FatalConfigError

from . import BIN_DIR
from .appacl_helpers import (
    FIXTURE_TABLE,
    FakeAppRest,
    FakeProvenanceReader,
    app_acl_body,
    object_listing_body,
    provenance,
)
from .test_spl_artifacts import read_splunk_conf

#: A `local.meta` of an application that is **governed**: it carries generic stanzas and
#: not a single object stanza. That is the shape `acl_governable = "yes"` describes.
GOVERNED_META = """[]
access = read : [ power ], write : [ admin ]
export = none

[views]
access = read : [ power, user ], write : [ power ]
export = none
"""

#: A `local.meta` of an application that is **frozen**: three of its views carry their
#: own stanza, which no measured REST path removes. Writing `[views]` will not move them.
FROZEN_META = """[]
access = read : [ power ], write : [ admin ]
export = none

[views]
access = read : [ power ], write : [ power ]
export = none

[views/dashboard_one]
access = read : [ admin ], write : [ admin ]
export = none

[views/dashboard_two]
access = read : [ admin ], write : [ admin ]
export = none

[savedsearches/nightly_report]
access = read : [ admin ], write : [ admin ]
export = none
"""


def _executable_source(source):
    """The source stripped of its comments and of its docstrings.

    Naming a trap is how it stays named, so a docstring that spells `SPLUNK_SERVER_NAME`
    out must not fail the control that forbids **reaching** it. What is left after this
    stripping is exactly what runs.
    """
    without_comments = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )
    tree = ast.parse(without_comments)
    rendered = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue                                  # bare string: a docstring
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Name)):
            rendered.append(ast.unparse(node))
    return "\n".join(rendered)


def make_params(apps=("*",), families=(), count_objects=False):
    return AppInventoryParams(
        apps=tuple(apps), families=tuple(families), count_objects=count_objects
    )


def builder(rest=None, prov=None, table=FIXTURE_TABLE, impact=None, member=""):
    rest = rest or FakeAppRest()
    reader = FakeProvenanceReader(prov if prov is not None else provenance())
    return InventoryBuilder(
        rest=rest,
        provenance_reader=reader,
        table=table,
        impact=impact,
        member=member,
    )


# --------------------------------------------------------------------------- #
# Section 7.3 - the parameters, and the allow list that guards them
# --------------------------------------------------------------------------- #

class TheParametersTest(unittest.TestCase):
    """Three parameters, and the filter convention of the repository applied to two."""

    def test_the_application_filter_defaults_to_everything(self):
        for raw in (None, "", "   ", ",,,"):
            with self.subTest(raw=raw):
                self.assertEqual(parse_app_filter(raw), ("*",))

    def test_the_application_filter_splits_on_commas(self):
        self.assertEqual(parse_app_filter("a, b ,c"), ("a", "b", "c"))

    def test_the_family_list_is_empty_by_default(self):
        for raw in (None, "", " , "):
            with self.subTest(raw=raw):
                self.assertEqual(parse_family_list(raw), ())

    def test_a_character_outside_the_allow_list_is_dropped(self):
        """Section 7.3: the argument is filtered before it is used as a pattern.

        Dropping and not rejecting is the convention of the repository, and here it is
        also the conservative choice: the filter governs what is SHOWN, so a mangled
        pattern shows too little and never too much.
        """
        self.assertEqual(sanitize_filter("a|b;c`d$e"), "abcde")
        self.assertEqual(sanitize_filter("my_app-1,other*"), "my_app-1,other*")

    def test_a_regex_metacharacter_cannot_reach_the_matcher(self):
        """The whole point of the allow list: `.` and `+` are not patterns here."""
        self.assertEqual(parse_app_filter(".*"), ("*",))
        self.assertFalse(app_matches("anything", parse_app_filter("a.c")))
        self.assertTrue(app_matches("ac", parse_app_filter("a.c")))

    def test_the_star_is_the_only_metacharacter(self):
        cases = (
            ("my_app", "*", True),
            ("my_app", "my_app", True),
            ("my_app", "my_*", True),
            ("my_app", "*_app", True),
            ("my_long_app", "my_*_app", True),
            ("my_app", "*x*", False),
            ("my_app", "other", False),
            ("", "*", True),
        )
        for name, pattern, expected in cases:
            with self.subTest(name=name, pattern=pattern):
                self.assertEqual(app_matches(name, (pattern,)), expected)

    def test_a_question_mark_is_not_a_metacharacter(self):
        """`fnmatch` would honour `?` and `[...]`; the allow list does not let them
        through, so an operator would see them silently deleted and get a filter doing
        something else than what is on screen."""
        self.assertEqual(parse_app_filter("my?app"), ("myapp",))

    def test_count_objects_is_a_boolean_and_an_invalid_one_is_fatal(self):
        self.assertFalse(validate_inventory_params().count_objects)
        self.assertTrue(validate_inventory_params(count_objects="t").count_objects)
        with self.assertRaises(FatalConfigError):
            validate_inventory_params(count_objects="perhaps")

    def test_the_validated_parameters_carry_the_contractual_defaults(self):
        params = validate_inventory_params()
        self.assertEqual(params.apps, ("*",))
        self.assertEqual(params.families, ())
        self.assertFalse(params.count_objects)

    def test_the_capability_is_the_one_the_contract_names(self):
        self.assertEqual(REQUIRED_INVENTORY_CAPABILITY, "list_app_acl")


# --------------------------------------------------------------------------- #
# Section 6.4 - literal values read from the file
# --------------------------------------------------------------------------- #

class TheLiteralValuesTest(unittest.TestCase):
    """`access` carries both permissions on ONE line, so the two columns come from
    splitting it - there is no `perms.read` key in a `.meta` file to look up.

    Every case below is a shape the reader must survive rather than raise on: the reader
    of section 6.4 is total.
    """

    def test_the_measured_shape_is_split_into_two_literals(self):
        literal = {"access": "read : [ power ], write : [ admin ]"}
        self.assertEqual(split_access(literal), ("power", "admin"))

    def test_several_roles_keep_their_literal_form(self):
        literal = {"access": "read : [ power, user ], write : [ admin ]"}
        self.assertEqual(split_access(literal), ("power, user", "admin"))

    def test_an_empty_permission_reads_back_as_the_empty_string(self):
        """Measured (Q0-1 case E): after a POST carrying `perms.read=`, the file holds
        `read : [  ]`. It is an EMPTY permission, which leaves the objects unreachable -
        not an absent one, which would let them inherit."""
        self.assertEqual(split_access({"access": "read : [  ], write : [ admin ]"}),
                         ("", "admin"))

    def test_the_reader_survives_every_malformed_shape(self):
        for raw in (None, {}, {"access": ""}, {"access": "garbage"},
                    {"access": "read : [ power"}, {"access": "read power ]"},
                    {"access": "write : [ admin ], read : [ power ]"}):
            with self.subTest(raw=raw):
                result = split_access(raw)
                self.assertEqual(len(result), 2)
                self.assertTrue(all(isinstance(part, str) for part in result))

    def test_the_order_of_the_two_clauses_does_not_matter(self):
        self.assertEqual(
            split_access({"access": "write : [ admin ], read : [ power ]"}),
            ("power", "admin"),
        )

    def test_the_export_key_is_read_literally(self):
        self.assertEqual(export_of({"export": "system"}), "system")
        self.assertEqual(export_of({}), "")
        self.assertEqual(export_of(None), "")


# --------------------------------------------------------------------------- #
# Section 7.4 - governability, a derivation and not an appreciation
# --------------------------------------------------------------------------- #

class TheGovernabilityIsADerivationTest(unittest.TestCase):
    """The table of section 7.4, cell by cell, both kinds of row.

    The property that matters is not the value but its **recomputability**: every one of
    these verdicts is a function of columns the same row publishes, so an operator who
    distrusts it can redo the arithmetic in SPL without leaving the table.
    """

    def test_a_family_with_no_frozen_object_is_governable(self):
        self.assertEqual(
            governable_of(STANZA_KIND_FAMILY, True, 0, 0), GOVERNABLE_YES
        )

    def test_a_family_with_a_frozen_object_is_only_partly_governable(self):
        self.assertEqual(
            governable_of(STANZA_KIND_FAMILY, True, 1, 0), GOVERNABLE_PARTIAL
        )

    def test_the_application_default_needs_neither_header_nor_frozen_object(self):
        self.assertEqual(governable_of(STANZA_KIND_APP, True, 0, 0), GOVERNABLE_YES)

    def test_a_family_header_takes_a_family_out_of_the_reach_of_the_default(self):
        """Measured inheritance chain (Q0-3 verdict 4): an interposed header is read
        instead of `[]`, so the application default no longer governs that family."""
        self.assertEqual(governable_of(STANZA_KIND_APP, True, 0, 1), GOVERNABLE_PARTIAL)

    def test_a_frozen_object_alone_is_enough_to_degrade_the_application_default(self):
        self.assertEqual(governable_of(STANZA_KIND_APP, True, 1, 0), GOVERNABLE_PARTIAL)

    def test_an_unreadable_provenance_yields_unknown_on_both_kinds(self):
        """`unavailable` supports NO conclusion. `partial` would be one, and a wrong one
        in the direction that matters: it would let an operator believe the file said
        something."""
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            with self.subTest(kind=kind):
                self.assertEqual(
                    governable_of(kind, False, 0, 0), GOVERNABLE_UNKNOWN
                )
                self.assertEqual(
                    governable_of(kind, False, 5, 5), GOVERNABLE_UNKNOWN
                )

    def test_the_domain_is_closed(self):
        values = set()
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            for available in (True, False):
                for frozen in (0, 3):
                    for headers in (0, 3):
                        values.add(governable_of(kind, available, frozen, headers))
        self.assertEqual(
            values, {GOVERNABLE_YES, GOVERNABLE_PARTIAL, GOVERNABLE_UNKNOWN}
        )


# --------------------------------------------------------------------------- #
# Section 7.5 - which rows are emitted
# --------------------------------------------------------------------------- #

class TheEmittedRowsTest(unittest.TestCase):

    def test_a_family_header_of_local_meta_produces_a_row(self):
        self.assertIn("views", families_to_emit(provenance(local=GOVERNED_META), ()))

    def test_a_family_header_of_default_meta_produces_a_row(self):
        self.assertIn("views", families_to_emit(provenance(default=GOVERNED_META), ()))

    def test_a_frozen_object_produces_the_row_of_its_family(self):
        """Condition 2, and it is the one that carries the value of the whole command: a
        family nobody governs but whose objects are frozen is exactly what an operator
        has to see BEFORE deciding to govern it."""
        emitted = families_to_emit(provenance(local=FROZEN_META), ())
        self.assertIn("savedsearches", emitted)

    def test_a_family_named_in_the_parameter_is_emitted_even_with_nothing_in_the_file(
        self,
    ):
        emitted = families_to_emit(provenance(), ("macros",))
        self.assertEqual(emitted, ("macros",))

    def test_a_family_present_in_none_of_the_three_conditions_is_absent(self):
        self.assertNotIn("macros", families_to_emit(provenance(local=GOVERNED_META), ()))

    def test_the_order_is_stable(self):
        """An inventory is compared with the one from another member (section 6.3). Two
        runs ordering their rows by whatever a set iteration returned would diverge for
        no reason at all."""
        emitted = families_to_emit(provenance(local=FROZEN_META), ("macros", "nav"))
        self.assertEqual(list(emitted), sorted(emitted))

    def test_the_application_default_row_is_emitted_unconditionally(self):
        rows = list(
            builder().rows(make_params(), applications=["app_with_nothing"])
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["acl_stanza_kind"], STANZA_KIND_APP)
        self.assertEqual(rows[0]["acl_present_local"], "false")

    def test_the_filter_selects_the_applications(self):
        rows = list(
            builder().rows(
                make_params(apps=("keep_*",)),
                applications=["keep_one", "keep_two", "drop_me"],
            )
        )
        self.assertEqual(
            [row["eai:acl.app"] for row in rows], ["keep_one", "keep_two"]
        )

    def test_the_applications_come_out_sorted(self):
        rows = list(
            builder().rows(make_params(), applications=["zeta", "alpha", "mu"])
        )
        self.assertEqual([row["eai:acl.app"] for row in rows], ["alpha", "mu", "zeta"])


# --------------------------------------------------------------------------- #
# Section 7.4 - the rows themselves
# --------------------------------------------------------------------------- #

class TheRowsTest(unittest.TestCase):

    def test_every_row_carries_exactly_the_declared_field_set(self):
        """v3.14 section 5.7, D-33, and it bites harder on a generating command: the
        writer freezes the header on the FIRST record, and the first record of an
        inventory is always an `app_default` row - the one row that leaves
        `acl_objects_*` empty when `count_objects` is off."""
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(families=("macros",)), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(stanza=row["acl_stanza"]):
                self.assertEqual(sorted(row), sorted(INVENTORY_OUTPUT_FIELDS))

    def test_the_first_fields_are_the_input_contract_of_the_write_command(self):
        """Section 7.3 of the write command: every parameter defaults to a field name
        THIS command emits, so a pipeline built on it needs no parameter at all. The
        control is on the names the other command reads, not on a copied list."""
        defaults = DEFAULT_APP_FIELD_NAMES
        for name in (defaults.app, defaults.stanza_kind, defaults.handler,
                     defaults.stanza, defaults.new_perms_read,
                     defaults.new_perms_write, defaults.new_sharing):
            with self.subTest(field=name):
                self.assertIn(name, INVENTORY_OUTPUT_FIELDS)

    def test_the_effective_values_come_from_rest(self):
        rest = FakeAppRest(
            default_get=RestOk(app_acl_body(sharing="global", read=("a", "b"),
                                            write=("c",)))
        )
        row = builder(rest=rest).app_default_row("my_app", provenance())
        self.assertEqual(row["eai:acl.sharing"], "global")
        self.assertEqual(row["eai:acl.perms.read"], "a,b")
        self.assertEqual(row["eai:acl.perms.write"], "c")

    def test_the_provenance_columns_come_from_the_file(self):
        row = builder().app_default_row("my_app", provenance(local=GOVERNED_META))
        self.assertEqual(row["acl_present_local"], "true")
        self.assertEqual(row["acl_present_default"], "false")
        self.assertEqual(row["acl_file_perms_read"], "power")
        self.assertEqual(row["acl_file_perms_write"], "admin")
        self.assertEqual(row["acl_file_export"], "none")
        self.assertEqual(row["acl_provenance"], "local")

    def test_the_file_and_the_platform_are_reported_side_by_side(self):
        """The whole point of publishing both: `acl_file_*` says what the LOCAL layer
        holds, `eai:acl.*` what splunkd SERVES. A divergence between them is the signal
        that something else - the default layer, an upper generic - is deciding."""
        rest = FakeAppRest(default_get=RestOk(app_acl_body(read=("effective_role",))))
        row = builder(rest=rest).app_default_row("my_app", provenance(local=GOVERNED_META))
        self.assertEqual(row["acl_file_perms_read"], "power")
        self.assertEqual(row["eai:acl.perms.read"], "effective_role")

    def test_a_failed_rest_read_leaves_the_effective_columns_empty(self):
        """A read failure costs one row three cells, never the whole table: the columns
        that carry the decision are the provenance ones, and they are read from a file."""
        rest = FakeAppRest(default_get=RestFail())
        row = builder(rest=rest).app_default_row("my_app", provenance(local=GOVERNED_META))
        self.assertEqual(row["eai:acl.perms.read"], "")
        self.assertEqual(row["eai:acl.sharing"], "")
        self.assertEqual(row["acl_file_perms_read"], "power")

    def test_the_application_row_counts_every_frozen_stanza_of_the_application(self):
        """It counts them over the WHOLE application, not per family, which is what
        makes the `app_default` line of the governability table recomputable from the
        columns of its own row."""
        row = builder().app_default_row("my_app", provenance(local=FROZEN_META))
        self.assertEqual(row["acl_frozen_stanzas"], 3)
        self.assertEqual(row["acl_family_headers"], 1)
        self.assertEqual(row["acl_governable"], GOVERNABLE_PARTIAL)

    def test_the_family_row_counts_only_its_own_family(self):
        prov = provenance(local=FROZEN_META)
        views = builder().family_row("my_app", "views", prov)
        savedsearches = builder().family_row("my_app", "savedsearches", prov)
        self.assertEqual(views["acl_frozen_stanzas"], 2)
        self.assertEqual(savedsearches["acl_frozen_stanzas"], 1)

    def test_the_family_row_leaves_the_header_count_empty(self):
        """Section 7.4 confines `acl_family_headers` to the `app_default` line. Repeating
        an application-wide figure on every family row would invite a `stats sum()` that
        counts it once per family."""
        row = builder().family_row("my_app", "views", provenance(local=FROZEN_META))
        self.assertEqual(row["acl_family_headers"], "")

    def test_a_family_of_the_table_carries_its_handler_and_a_write_path(self):
        row = builder().family_row("my_app", "views", provenance(local=GOVERNED_META))
        self.assertEqual(row["acl_handler"], "data/ui/views")
        self.assertEqual(row["acl_write_path"], WRITE_PATH_MAPPED)

    def test_a_family_absent_from_the_table_is_reported_as_unmapped(self):
        """Section 6.4: a stanza whose name matches no expected shape is reported AS IT
        STANDS, with an empty handler. It is a fact about the tool - the table does not
        cover it - and never a claim about the platform."""
        row = builder().family_row("my_app", "unknown_family", provenance())
        self.assertEqual(row["acl_handler"], "")
        self.assertEqual(row["acl_write_path"], WRITE_PATH_UNMAPPED)
        self.assertEqual(row["eai:acl.perms.read"], "")

    def test_the_application_default_row_is_always_mapped(self):
        """Its URI is entirely determined by the application name: there is no family to
        resolve and therefore nothing that can fail to resolve."""
        row = builder().app_default_row("my_app", provenance())
        self.assertEqual(row["acl_write_path"], WRITE_PATH_MAPPED)
        self.assertEqual(row["acl_handler"], "")
        self.assertEqual(row["acl_stanza"], "")

    def test_an_absent_stanza_is_reported_inherited_and_not_as_a_failure(self):
        """Measured: a freshly installed application has no `local.meta` at all. That is
        a valid and informative answer, and the command turns it into `inherited`."""
        row = builder().family_row("my_app", "views", provenance())
        self.assertEqual(row["acl_present_local"], "false")
        self.assertEqual(row["acl_provenance"], "inherited")
        self.assertEqual(row["acl_provenance_error"], "")

    def test_an_unreadable_file_yields_unavailable_with_its_error_class(self):
        row = builder().app_default_row(
            "my_app", provenance(local_error="PermissionError")
        )
        self.assertEqual(row["acl_provenance"], "unavailable")
        self.assertEqual(row["acl_provenance_error"], "PermissionError")
        self.assertEqual(row["acl_governable"], GOVERNABLE_UNKNOWN)

    def test_the_skipped_line_count_is_reported(self):
        row = builder().app_default_row(
            "my_app", provenance(local="[]\nthis line has no equals sign\n")
        )
        self.assertEqual(row["acl_provenance_error"], "parse_skipped:1")

    def test_the_booleans_are_emitted_in_the_lower_case_form_of_the_platform(self):
        row = builder().app_default_row("my_app", provenance(local=GOVERNED_META))
        self.assertIn(row["acl_present_local"], ("true", "false"))
        self.assertNotIn("True", row.values())


# --------------------------------------------------------------------------- #
# Section 6.2 bound 3 - counts, never names
# --------------------------------------------------------------------------- #

class TheOutputCarriesCountsAndNeverObjectNamesTest(unittest.TestCase):
    """**The reason the capability exists** (section 7.6).

    Reading the file short-circuits the capability filtering REST applies: a caller
    without `admin_all_objects` would see, through this command, object names the API
    refuses them. A count exposes no name, and this is the test that says so about the
    thing the operator actually receives - the emitted rows - rather than about the
    module that builds them.
    """

    #: Names carried by the fixture's object stanzas. None may appear anywhere in the
    #: emitted rows, in any field, in any form.
    OBJECT_NAMES = ("dashboard_one", "dashboard_two", "nightly_report")

    def test_no_emitted_value_contains_an_object_name(self):
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        rendered = " ".join(
            "%s" % value for row in rows for value in row.values()
        )
        for name in self.OBJECT_NAMES:
            with self.subTest(object=name):
                self.assertNotIn(name, rendered)

    def test_the_frozen_objects_are_nonetheless_counted(self):
        """The negative control that makes the test above conclusive: if the fixture
        carried no frozen object, "no name leaked" would be true by vacuity."""
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertEqual(
            sum(int(row["acl_frozen_stanzas"] or 0) for row in rows), 6
        )


# --------------------------------------------------------------------------- #
# Section 7.4 - the object counts, and what they cost
# --------------------------------------------------------------------------- #

class TheObjectCountsTest(unittest.TestCase):
    """`count_objects` is off by default because it costs one REST call per (application,
    family), where the columns that carry the decision are read from one file."""

    def _rest(self):
        return FakeAppRest(
            json_responses={
                "/servicesNS/nobody/my_app/data/ui/views": RestOk(
                    object_listing_body(
                        [("dashboard_one", "my_app"), ("dashboard_two", "my_app"),
                         ("dashboard_three", "my_app"), ("foreign", "other_app")]
                    )
                ),
            },
            default_json=RestOk(object_listing_body([])),
        )

    def _builder_with_impact(self, prov):
        rest = self._rest()
        reader = FakeProvenanceReader(prov)
        impact = ImpactEstimator(rest, reader, FIXTURE_TABLE)
        return rest, InventoryBuilder(
            rest=rest, provenance_reader=reader, table=FIXTURE_TABLE, impact=impact
        )

    def test_the_columns_stay_empty_when_the_enumeration_was_not_asked_for(self):
        _rest, build = self._builder_with_impact(provenance(local=FROZEN_META))
        row = build.family_row("my_app", "views", provenance(local=FROZEN_META))
        self.assertEqual(row["acl_objects_total"], "")
        self.assertEqual(row["acl_objects_inheriting"], "")

    def test_empty_is_not_zero(self):
        """Zero is an ANSWER - the family is empty in this application - and confusing
        the two would let a column nobody computed pass for a family nobody uses."""
        _rest, build = self._builder_with_impact(provenance())
        row = build.family_row("my_app", "macros", provenance(), count_objects=True)
        self.assertEqual(row["acl_objects_total"], 0)
        self.assertNotEqual(row["acl_objects_total"], "")

    def test_the_enumeration_excludes_the_objects_of_other_applications(self):
        """Measured on the lab: a namespace exposes the objects other applications share
        globally - 33 entries for one that belonged to the app. A naive count would
        overstate the population by a factor of 33."""
        prov = provenance(local=FROZEN_META)
        _rest, build = self._builder_with_impact(prov)
        row = build.family_row("my_app", "views", prov, count_objects=True)
        self.assertEqual(row["acl_objects_total"], 3)

    def test_the_inheriting_count_subtracts_the_frozen_stanzas(self):
        prov = provenance(local=FROZEN_META)
        _rest, build = self._builder_with_impact(prov)
        row = build.family_row("my_app", "views", prov, count_objects=True)
        self.assertEqual(row["acl_objects_total"], 3)
        self.assertEqual(row["acl_frozen_stanzas"], 2)
        self.assertEqual(row["acl_objects_inheriting"], 1)

    def test_the_two_columns_and_the_frozen_count_agree(self):
        """Publishing the three lets the operator check one against the other, which is
        what an estimate named as such is worth."""
        prov = provenance(local=FROZEN_META)
        _rest, build = self._builder_with_impact(prov)
        row = build.family_row("my_app", "views", prov, count_objects=True)
        self.assertEqual(
            row["acl_objects_inheriting"],
            row["acl_objects_total"] - row["acl_frozen_stanzas"],
        )

    def test_an_unmapped_family_cannot_be_enumerated(self):
        prov = provenance()
        _rest, build = self._builder_with_impact(prov)
        row = build.family_row("my_app", "unknown_family", prov, count_objects=True)
        self.assertEqual(row["acl_objects_total"], "")

    def test_the_application_row_counts_the_population_it_still_governs(self):
        """For `app_default` the inheriting part spans the families with NO header: a
        family carrying one reads that header, not the application default (Q0-3
        verdict 4)."""
        prov = provenance(local=GOVERNED_META)
        _rest, build = self._builder_with_impact(prov)
        row = build.app_default_row("my_app", prov, count_objects=True)
        self.assertEqual(row["acl_objects_total"], 3)
        # `views` carries a header in GOVERNED_META, so its three objects are out of the
        # blast radius of `[]`.
        self.assertEqual(row["acl_objects_inheriting"], 0)

    def test_the_enumeration_is_memoized_across_rows(self):
        prov = provenance(local=FROZEN_META)
        rest, build = self._builder_with_impact(prov)
        build.family_row("my_app", "views", prov, count_objects=True)
        before = rest.count("JSON")
        build.family_row("my_app", "views", prov, count_objects=True)
        self.assertEqual(rest.count("JSON"), before)


# --------------------------------------------------------------------------- #
# Section 6.3 - the execution member
# --------------------------------------------------------------------------- #

class TheExecutionMemberTest(unittest.TestCase):
    """`acl_member` turns the SHC reservation into an instrument: run the inventory on
    each member and compare, and a metadata replication gap becomes visible - which no
    configuration audit sees, the change tracking of Splunk recording `.conf` files and
    not `.meta` ones."""

    def test_it_is_read_from_the_cheap_rest_call(self):
        """HY-4, remaining branch, measured positive: `entry[0].content.serverName` of
        `/services/server/info` carries the instance name."""
        rest = FakeAppRest(
            json_responses={
                SERVER_INFO_PATH: RestOk(
                    b'{"entry":[{"name":"server-info",'
                    b'"content":{"serverName":"member_two"}}]}'
                )
            }
        )
        self.assertEqual(resolve_member(rest), "member_two")

    def test_it_falls_back_on_the_empty_string(self):
        """Specified fallback of section 6.3: emitted empty, the README saying to
        discriminate by `splunk_server`. An empty column is honest; a plausible and false
        member name would make two members look like one."""
        for response in (RestFail(), RestOk(b"{}"), RestOk(b"not json"),
                         RestOk(b'{"entry":[{"content":{}}]}')):
            with self.subTest(response=response):
                rest = FakeAppRest(json_responses={SERVER_INFO_PATH: response})
                self.assertEqual(resolve_member(rest), "")

    def test_it_reaches_every_row(self):
        rows = list(
            builder(member="member_two").rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["acl_member"], "member_two")

    def test_the_environment_variable_named_by_the_measurement_is_never_read(self):
        """**Named trap** of HY-4: `SPLUNK_SERVER_NAME` carries the name of the systemd
        SERVICE, not the `serverName` of the instance. It is exactly the kind of value
        that is plausible and false, and the whole column exists to compare members."""
        paths = [
            os.path.join(BIN_DIR, "acltools", "appacl_inventory.py"),
            os.path.join(BIN_DIR, "app_acl_inventory.py"),
        ]
        named_somewhere = False
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
            named_somewhere = named_somewhere or "SPLUNK_SERVER_NAME" in source
            with self.subTest(module=os.path.basename(path)):
                # Docstrings and comments MAY name it - naming a trap is how it stays
                # named. The executable part may not, in any construct at all.
                self.assertNotIn(
                    "SPLUNK_SERVER_NAME", _executable_source(source),
                    "the trap is reachable from the code of %s" % path,
                )
        self.assertTrue(
            named_somewhere,
            "the trap is no longer named anywhere: a control that guards a rule nobody "
            "states is a control the next contributor deletes",
        )


# --------------------------------------------------------------------------- #
# Section 6.2 bound 4 - the read perimeter is the list of applications
# --------------------------------------------------------------------------- #

class TheReadPerimeterIsTheApplicationListTest(unittest.TestCase):

    def test_the_applications_come_from_the_platform(self):
        rest = FakeAppRest(
            json_responses={
                "/services/apps/local": RestOk(
                    b'{"entry":[{"name":"one"},{"name":"two"}]}'
                )
            }
        )
        self.assertEqual(list_applications(rest), ["one", "two"])

    def test_a_failed_listing_yields_no_application_rather_than_an_exception(self):
        rest = FakeAppRest(json_responses={"/services/apps/local": RestFail()})
        self.assertEqual(list_applications(rest), [])

    def test_only_the_listed_applications_are_read(self):
        """Bound 4: no `.meta` outside the applications the platform returns is opened -
        not `etc/system`, not `etc/users`, not a path built from an input datum."""
        rest = FakeAppRest(
            json_responses={
                "/services/apps/local": RestOk(b'{"entry":[{"name":"only_this_one"}]}')
            }
        )
        reader = FakeProvenanceReader(provenance())
        build = InventoryBuilder(
            rest=rest, provenance_reader=reader, table=FIXTURE_TABLE
        )
        list(build.rows(make_params()))
        self.assertEqual(reader.reads, ["only_this_one"])


# --------------------------------------------------------------------------- #
# Section 7.2 - the generating character, and where it is declared (HY-1)
# --------------------------------------------------------------------------- #

class TheGeneratingCharacterIsCarriedByTheSdkTest(unittest.TestCase):
    """**HY-1, established rather than assumed, and frozen here.**

    The contract left the point open and asked for it to be settled by trial. It is
    settled from the vendored SDK itself, which is the artifact that decides: under the
    chunked protocol the generating character is a **read-only configuration setting of
    the base class**, fixed to `True` and announced for both protocol versions. No key of
    `commands.conf` carries it, and none was added.

    The precedent the contract cites is the symmetric one: `@Configuration(type=...)` is
    REFUSED on a `StreamingCommand`, `type` being pinned by the base class there. Both
    facts have the same shape - the base class decides, and the decorator must not
    contradict it.
    """

    def _sdk_source(self):
        path = os.path.join(
            BIN_DIR, "lib", "splunklib", "searchcommands", "generating_command.py"
        )
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_the_sdk_pins_the_generating_setting(self):
        source = self._sdk_source()
        self.assertRegex(
            source, r"generating\s*=\s*ConfigurationSetting\(\s*readonly=True,\s*value=True"
        )

    def test_the_setting_is_announced_for_the_chunked_protocol(self):
        path = os.path.join(BIN_DIR, "lib", "splunklib", "searchcommands", "internals.py")
        with open(path, encoding="utf-8") as handle:
            internals = handle.read()
        self.assertRegex(
            internals,
            r'"generating":\s*specification\(\s*type=bool,\s*constraint=None,'
            r'\s*supporting_protocols=\[1,\s*2\]',
        )

    def test_commands_conf_declares_no_generating_key(self):
        """If a key ever proves necessary, it goes into the normative set AND into the
        test that freezes it - never glossed in on the side (section 7.2)."""
        conf = read_splunk_conf("default", "commands.conf")
        for stanza, keys in conf.items():
            with self.subTest(command=stanza):
                self.assertNotIn("generating", keys)


class RestOk(object):
    """Minimal successful REST response. Not a mock of the client: the client under test
    is the real one everywhere else, and what is doubled here is the platform."""

    ok = True
    status = 200

    def __init__(self, body=b"{}"):
        self.body = body


class RestFail(object):
    ok = False
    status = 0
    body = b""


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
