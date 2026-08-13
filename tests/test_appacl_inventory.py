"""The inventory core (v4.5 section 7), and the bounds it inherits from section 6.

What this module holds, and it is the whole reason the command exists: **the distinction
between an inherited value and one the object carries itself**. Measured (Q0-4), REST
answers the same block for both, so every test below that touches `acl_perms_source`,
`acl_objects_with_own_perms` or `acl_reach` is exercising the one thing no REST source can
give.

**The output contract was rewritten in v4.5**, after the command was first opened in Splunk
Web: 21 columns became 18, organised in four named levels, under one rule - *no column is
ever empty without another saying why*. The tests here are written against that rule rather
than against the column list, because the list is the consequence and the rule is the
contract.

No Splunk, no network, no file system: the REST port is an in-memory double, and the
provenance is the **real** reader fed with the text of a `.meta` file - substituting the
reader would replace the thing under test by a description of it.
"""

import ast
import os
import unittest

from acltools.appacl_inventory import (
    APP_STANZA_LABEL,
    EFFECTIVE_APP_DISABLED,
    EFFECTIVE_OK,
    EFFECTIVE_UNREADABLE,
    MEMBER_UNKNOWN,
    INVENTORY_OUTPUT_FIELDS,
    REACH_ALL,
    REACH_PARTIAL,
    REACH_UNKNOWN,
    ROW_REASON_APP,
    ROW_REASON_OBJECTS,
    ROW_REASON_REQUESTED,
    ROW_REASON_STANZA,
    SERVER_INFO_PATH,
    InventoryBuilder,
    app_matches,
    export_of,
    families_to_emit,
    list_applications,
    parse_app_filter,
    parse_family_list,
    WRITE_EFFECT_CREATE,
    WRITE_EFFECT_NO_ROUTE,
    WRITE_EFFECT_OVERWRITE,
    reach_of,
    resolve_member,
    sanitize_filter,
    split_access,
    stanza_label,
    write_effect_of,
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
from acltools.appacl_provenance import (
    FILE_READ_OK,
    FILE_READ_PARTIAL_PREFIX,
    FILE_READ_UNREADABLE,
    LAYER_DEFAULT,
    LAYER_LOCAL,
    LAYER_NONE,
)

from . import BIN_DIR
from .appacl_helpers import (
    FIXTURE_TABLE,
    FakeAppRest,
    FakeProvenanceReader,
    app_acl_body,
    frozen_stanza,
    provenance,
    scoped_stanza,
    touched_stanza,
)
from .test_spl_artifacts import read_splunk_conf

#: A `local.meta` of an application nobody has frozen: a `[]`, a `[views]` header, and no
#: object stanza at all.
GOVERNED_META = frozen_stanza("") + frozen_stanza("views")

#: An application frozen object by object: two views and one saved search carry their own
#: permissions.
FROZEN_META = (
    frozen_stanza("")
    + frozen_stanza("views")
    + frozen_stanza("views/dashboard_one")
    + frozen_stanza("views/dashboard_two")
    + frozen_stanza("savedsearches/nightly_report")
)


def _executable_source(source):
    """The source stripped of its comments and of its docstrings."""
    without_comments = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )
    tree = ast.parse(without_comments)
    rendered = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Name)):
            rendered.append(ast.unparse(node))
    return "\n".join(rendered)


def make_params(apps=("*",), families=()):
    return AppInventoryParams(apps=tuple(apps), families=tuple(families))


def builder(rest=None, prov=None, table=FIXTURE_TABLE, member="", disabled=None):
    rest = rest or FakeAppRest()
    reader = FakeProvenanceReader(prov if prov is not None else provenance())
    return InventoryBuilder(
        rest=rest,
        provenance_reader=reader,
        table=table,
        member=member,
        app_disabled_fn=disabled,
    )


class RestOk(object):
    """Minimal successful REST response. What is doubled here is the platform."""

    ok = True
    status = 200

    def __init__(self, body=b"{}"):
        self.body = body


class RestFail(object):
    ok = False
    status = 0
    body = b""


# --------------------------------------------------------------------------- #
# Section 7.4 - the field set, its order, and the rule that governs it
# --------------------------------------------------------------------------- #

class TheDeclaredFieldSetTest(unittest.TestCase):
    """v3.14 D-33, and the ordering clause v4.5 adds to it.

    The SDK writer fixes the stream header on the keys of the **first** record, so a field
    absent from it disappears from the whole output with no signal - and the **order** of
    that record is the order the operator sees. Measured before the revision: the emitted
    order did not match the declared one, `acl_member` coming out ninth instead of last.
    """

    def test_there_are_nineteen_of_them(self):
        self.assertEqual(len(INVENTORY_OUTPUT_FIELDS), 19)

    def test_the_declaration_has_no_duplicate(self):
        self.assertEqual(
            len(INVENTORY_OUTPUT_FIELDS), len(set(INVENTORY_OUTPUT_FIELDS))
        )

    def test_the_first_seven_are_the_input_contract_of_the_write_command(self):
        """Read from the code of the other command, never recopied: a renamed default
        would otherwise leave `| appaclinventory | editappacl` silently needing
        parameters."""
        names = DEFAULT_APP_FIELD_NAMES
        self.assertEqual(
            list(INVENTORY_OUTPUT_FIELDS[:7]),
            [names.app, names.stanza_kind, names.stanza, names.handler,
             names.new_perms_read, names.new_perms_write, names.new_sharing],
        )

    def test_every_row_carries_exactly_the_declared_fields_in_the_declared_order(self):
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(families=("macros",)), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(stanza=row["acl_stanza"]):
                self.assertEqual(list(row), list(INVENTORY_OUTPUT_FIELDS))

    def test_the_withdrawn_columns_are_gone(self):
        """Six columns removed in v4.5. A consumer still reading them must break loudly
        rather than read an empty cell for ever."""
        for gone in ("acl_write_path", "acl_present_local", "acl_present_default",
                     "acl_objects_total", "acl_objects_inheriting",
                     "acl_provenance_error", "acl_provenance", "acl_frozen_stanzas",
                     "acl_family_headers", "acl_governable", "acl_stanza_layer"):
            with self.subTest(column=gone):
                self.assertNotIn(gone, INVENTORY_OUTPUT_FIELDS)


class NoColumnIsEmptyWithoutAnotherSayingWhyTest(unittest.TestCase):
    """**The structural rule of v4.5**, and the one that replaces four semantics of the
    empty cell.

    The fixture below covers the four measured causes side by side: a family outside the
    table, a disabled application, an unreadable metadata file, and a stanza that simply is
    not there. For each row, either every column is filled, or a status column names the
    reason.
    """

    #: The columns allowed to be empty, and the column that must then explain each.
    #:
    #: **Two cells the contract's rule does not cover, and both are reported rather than
    #: papered over** (see the run report):
    #:
    #: - `acl_handler` on an **application** row. The rule names
    #:   `acl_effective_status = no_handler` as its explanation, which is right on a family
    #:   row and false on an application row: there the read succeeds and the handler is
    #:   empty because a `[]` URI is determined by the application alone. The column that
    #:   says so is `acl_stanza_kind`, and it is always filled;
    #: - `acl_member`. The rule lists it among the columns "always filled", while section
    #:   6.3 specifies an **empty** value as the measured fallback, with `splunk_server` as
    #:   the documented remedy. It is a **run-level** fact, identical on every row, not a
    #:   per-row mystery - so it is excluded here and explained in the README.
    EXPLAINED = {
        "eai:acl.perms.read": "acl_effective_status",
        "eai:acl.perms.write": "acl_effective_status",
        "eai:acl.sharing": "acl_effective_status",
        "acl_file_perms_read": "acl_perms_source",
        "acl_file_perms_write": "acl_perms_source",
        "acl_file_export": "acl_perms_source",
    }

    #: Excluded from the "always filled" sweep, with the reason above.
    RUN_LEVEL = ("acl_member",)

    def _rows(self):
        rest = FakeAppRest(
            get_responses={
                "/servicesNS/nobody/my_app/data/ui/views/_acl": RestFail(),
            },
            default_get=RestOk(app_acl_body()),
        )
        prov = provenance(local=FROZEN_META + touched_stanza("unknown_family/x"))
        return list(
            builder(rest=rest, prov=prov, disabled=lambda app: False).rows(
                make_params(families=("macros",)), applications=["my_app"]
            )
        )

    def test_every_empty_cell_is_explained_by_another_column(self):
        rows = self._rows()
        self.assertTrue(rows)
        for row in rows:
            for column, explainer in self.EXPLAINED.items():
                if str(row[column]) != "":
                    continue
                with self.subTest(stanza=row["acl_stanza"], column=column):
                    self.assertNotEqual(
                        str(row[explainer]), "",
                        "%s is empty and %s says nothing" % (column, explainer),
                    )
                    if explainer == "acl_effective_status":
                        self.assertNotEqual(row[explainer], EFFECTIVE_OK)
                    else:
                        self.assertEqual(row[explainer], LAYER_NONE)

    def test_an_empty_handler_is_always_explained_by_one_column_or_the_other(self):
        """On a family row it is `acl_effective_status = no_handler`; on an application
        row it is `acl_stanza_kind = app_default`, the `[]` URI needing no handler."""
        for row in self._rows():
            if str(row["acl_handler"]) != "":
                continue
            with self.subTest(stanza=row["acl_stanza"]):
                if row["acl_stanza_kind"] == STANZA_KIND_APP:
                    self.assertEqual(row["acl_effective_status"], EFFECTIVE_OK)
                else:
                    self.assertEqual(row["acl_write_effect"], WRITE_EFFECT_NO_ROUTE)

    def test_the_columns_outside_that_map_are_never_empty(self):
        always = [
            f for f in INVENTORY_OUTPUT_FIELDS
            if f not in self.EXPLAINED and f not in self.RUN_LEVEL
            and f != "acl_handler"
        ]
        for row in self._rows():
            for column in always:
                with self.subTest(stanza=row["acl_stanza"], column=column):
                    self.assertNotEqual(str(row[column]), "")

    def test_the_member_is_filled_when_the_platform_gives_it(self):
        """The exclusion above is about the fallback, not a licence: given a member name,
        every row carries it."""
        rows = list(
            builder(member="member_two").rows(make_params(), applications=["my_app"])
        )
        for row in rows:
            self.assertEqual(row["acl_member"], "member_two")

    def test_a_family_outside_the_table_says_no_handler(self):
        row = builder().family_row("my_app", "unknown_family", provenance())
        self.assertEqual(row["acl_handler"], "")
        self.assertEqual(row["acl_write_effect"], WRITE_EFFECT_NO_ROUTE)
        self.assertEqual(row["acl_effective_status"], EFFECTIVE_UNREADABLE)
        self.assertEqual(row["eai:acl.perms.read"], "")
        self.assertEqual(row["acl_reach"], REACH_UNKNOWN)

    def test_a_failed_read_says_unreadable(self):
        rest = FakeAppRest(default_get=RestFail())
        row = builder(rest=rest, disabled=lambda app: False).app_default_row(
            "my_app", provenance(local=GOVERNED_META)
        )
        self.assertEqual(row["acl_effective_status"], EFFECTIVE_UNREADABLE)
        self.assertEqual(row["eai:acl.sharing"], "")
        self.assertEqual(row["acl_file_perms_read"], "power")

    def test_a_disabled_application_says_so_rather_than_unreadable(self):
        """Three causes were indistinguishable on 26 rows out of 124. The most specific
        one wins, and it costs one memoized call, only on a read that already failed."""
        rest = FakeAppRest(default_get=RestFail())
        row = builder(rest=rest, disabled=lambda app: True).app_default_row(
            "my_app", provenance(local=GOVERNED_META)
        )
        self.assertEqual(row["acl_effective_status"], EFFECTIVE_APP_DISABLED)

    def test_a_successful_read_says_ok(self):
        row = builder().app_default_row("my_app", provenance(local=GOVERNED_META))
        self.assertEqual(row["acl_effective_status"], EFFECTIVE_OK)


class TheClosedDomainsTest(unittest.TestCase):
    """Six columns carry a closed domain, and every emitted value belongs to it.

    The domains are **derived from the core**, never recopied here: a value added to the
    code and not to the contract fails on the contract, not on a duplicate list.
    """

    DOMAINS = {
        "acl_stanza_kind": (STANZA_KIND_APP, STANZA_KIND_FAMILY),
        "acl_row_reason": (ROW_REASON_APP, ROW_REASON_STANZA, ROW_REASON_OBJECTS,
                           ROW_REASON_REQUESTED),
        "acl_effective_status": (EFFECTIVE_OK, EFFECTIVE_APP_DISABLED,
                                 EFFECTIVE_UNREADABLE),
        "acl_write_effect": (WRITE_EFFECT_OVERWRITE, WRITE_EFFECT_CREATE,
                             WRITE_EFFECT_NO_ROUTE),
        "acl_perms_source": (LAYER_LOCAL, LAYER_DEFAULT, LAYER_NONE),
        "acl_reach": (REACH_ALL, REACH_PARTIAL, REACH_UNKNOWN),
    }

    def test_every_emitted_value_belongs_to_its_domain(self):
        rest = FakeAppRest(
            get_responses={"/servicesNS/nobody/my_app/data/ui/views/_acl": RestFail()},
            default_get=RestOk(app_acl_body()),
        )
        rows = list(
            builder(rest=rest, prov=provenance(local=FROZEN_META, default=GOVERNED_META),
                    disabled=lambda app: False).rows(
                make_params(families=("macros",)), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        for row in rows:
            for column, domain in self.DOMAINS.items():
                with self.subTest(stanza=row["acl_stanza"], column=column):
                    self.assertIn(row[column], domain)

    def test_the_file_read_domain_admits_its_three_shapes(self):
        cases = (
            (provenance(local=GOVERNED_META), FILE_READ_OK),
            (provenance(local="[]\nthis line has no equals sign\n"),
             FILE_READ_PARTIAL_PREFIX + "1"),
            (provenance(local_error="PermissionError"), FILE_READ_UNREADABLE),
        )
        for prov, expected in cases:
            with self.subTest(expected=expected):
                row = builder().app_default_row("my_app", prov)
                self.assertEqual(row["acl_file_read"], expected)


# --------------------------------------------------------------------------- #
# Section 7.4 - the file level, both layers
# --------------------------------------------------------------------------- #

class TheFileColumnsReadBothLayersTest(unittest.TestCase):
    """**The measured defect of the v4.4 output**: `acl_file_*` read `local.meta` alone -
    zero non-empty value on 124 rows, while 97 of them carried a filled stanza in
    `default.meta`. It was never "the stanza does not exist"; it was "we read one layer out
    of two".
    """

    def test_a_stanza_of_the_default_layer_is_quoted(self):
        row = builder().family_row("my_app", "views", provenance(default=GOVERNED_META))
        self.assertEqual(row["acl_perms_source"], LAYER_DEFAULT)
        self.assertEqual(row["acl_file_perms_read"], "power")
        self.assertEqual(row["acl_file_perms_write"], "admin")
        self.assertEqual(row["acl_file_export"], "none")

    def test_the_local_layer_wins_when_both_carry_it(self):
        """At equal specificity the local layer is the one splunkd applies (HY-2), so it
        is the one the literal columns quote."""
        local = "[views]\naccess = read : [ local_role ], write : [ admin ]\n"
        row = builder().family_row(
            "my_app", "views", provenance(local=local, default=GOVERNED_META)
        )
        self.assertEqual(row["acl_perms_source"], LAYER_LOCAL)
        self.assertEqual(row["acl_file_perms_read"], "local_role")

    def test_an_absent_stanza_says_none_and_leaves_the_literals_empty(self):
        row = builder().family_row("my_app", "views", provenance())
        self.assertEqual(row["acl_perms_source"], LAYER_NONE)
        self.assertEqual(row["acl_file_perms_read"], "")
        self.assertEqual(row["acl_file_export"], "")

    def test_a_stanza_carrying_only_export_sources_its_permissions_nowhere(self):
        """**The `[commands]` case, and the v4.6 redefinition.**

        A stanza can exist in a layer and carry no `access` key at all - `[commands]` of
        this very app carries only `export = system`. Its permissions come from `[]`, that
        is they are inherited, so `acl_perms_source` says `none` while `acl_file_export`
        still shows what the stanza does write. Under v4.5 the column said `default`, which
        was true about the stanza and false about the permissions - and that is the promise
        v4.6 stops making.
        """
        row = builder().family_row(
            "my_app", "views", provenance(default=scoped_stanza("views"))
        )
        self.assertEqual(row["acl_perms_source"], LAYER_NONE)
        self.assertEqual(row["acl_file_perms_read"], "")
        self.assertEqual(row["acl_file_export"], "system")


# --------------------------------------------------------------------------- #
# Section 7.5 - why a row is there
# --------------------------------------------------------------------------- #

class TheRowReasonTest(unittest.TestCase):
    """**The column that closes the puzzle that opened the revision.**

    A row emitted because of an object stanza described an **absent** header on three
    columns and named nowhere the stanza that had triggered it.
    """

    def test_the_application_row_says_app_row(self):
        row = builder().app_default_row("my_app", provenance())
        self.assertEqual(row["acl_row_reason"], ROW_REASON_APP)

    def test_a_header_says_stanza_exists(self):
        self.assertEqual(
            dict(families_to_emit(provenance(local=GOVERNED_META), ())),
            {"views": ROW_REASON_STANZA},
        )

    def test_an_object_stanza_alone_says_objects_exist(self):
        """The measured edge case: two `[macros/...]` stanzas carrying only `version` and
        `modtime` are enough to emit the family, and the row then says exactly that."""
        prov = provenance(
            local=touched_stanza("macros/one") + touched_stanza("macros/two")
        )
        self.assertEqual(
            dict(families_to_emit(prov, ())), {"macros": ROW_REASON_OBJECTS}
        )
        row = builder().family_row("my_app", "macros", prov, ROW_REASON_OBJECTS)
        self.assertEqual(row["acl_row_reason"], ROW_REASON_OBJECTS)
        self.assertEqual(row["acl_objects_with_own_perms"], 0)
        self.assertEqual(row["acl_reach"], REACH_ALL)

    def test_a_named_family_says_requested(self):
        self.assertEqual(
            dict(families_to_emit(provenance(), ("macros",))),
            {"macros": ROW_REASON_REQUESTED},
        )

    def test_the_first_condition_met_names_the_reason(self):
        """A family with both a header and object stanzas is there for the header: the
        conditions are ordered, and the reason names the first one."""
        prov = provenance(local=GOVERNED_META + touched_stanza("views/x"))
        self.assertEqual(dict(families_to_emit(prov, ("views",)))["views"],
                         ROW_REASON_STANZA)

    def test_emission_is_presence_and_not_freezing(self):
        """Section 7.5 condition 2, in its own words. Restricting it to the freeze
        predicate would hide families that do exist - emission and governance answer two
        different questions."""
        prov = provenance(local=touched_stanza("views/edited"))
        self.assertIn("views", dict(families_to_emit(prov, ())))

    def test_every_emitted_row_carries_a_reason(self):
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(families=("macros",)), applications=["my_app"]
            )
        )
        for row in rows:
            with self.subTest(stanza=row["acl_stanza"]):
                self.assertNotEqual(row["acl_row_reason"], "")

    def test_the_order_is_stable(self):
        """An inventory is compared with the one from another member (section 6.3): two
        runs ordering their rows by whatever a set returned would diverge for nothing."""
        emitted = [f for f, _r in families_to_emit(
            provenance(local=FROZEN_META), ("macros", "nav"))]
        self.assertEqual(emitted, sorted(emitted))


# --------------------------------------------------------------------------- #
# Section 7.4 - the verdict
# --------------------------------------------------------------------------- #

class TheReachVerdictTest(unittest.TestCase):
    """`acl_reach` is a **derivation**, recomputable from the columns beside it."""

    def test_a_family_nothing_escapes_is_reached_in_full(self):
        self.assertEqual(
            reach_of(STANZA_KIND_FAMILY, FILE_READ_OK, 0, 0,
                     WRITE_EFFECT_OVERWRITE), REACH_ALL)

    def test_one_object_with_its_own_permissions_makes_it_partial(self):
        self.assertEqual(
            reach_of(STANZA_KIND_FAMILY, FILE_READ_OK, 1, 0,
                     WRITE_EFFECT_CREATE), REACH_PARTIAL)

    def test_a_family_header_takes_a_family_out_of_the_reach_of_the_default(self):
        self.assertEqual(
            reach_of(STANZA_KIND_APP, FILE_READ_OK, 0, 1,
                     WRITE_EFFECT_CREATE), REACH_PARTIAL)

    def test_a_family_header_does_not_affect_a_family_row(self):
        """The count is an application fact, emitted everywhere; it only enters the
        verdict of the application row."""
        self.assertEqual(
            reach_of(STANZA_KIND_FAMILY, FILE_READ_OK, 0, 3,
                     WRITE_EFFECT_OVERWRITE), REACH_ALL)

    def test_an_unreadable_file_yields_unknown_on_both_kinds(self):
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            for status in (FILE_READ_UNREADABLE, FILE_READ_PARTIAL_PREFIX + "3"):
                with self.subTest(kind=kind, status=status):
                    self.assertEqual(
                        reach_of(kind, status, 0, 0, WRITE_EFFECT_CREATE),
                        REACH_UNKNOWN)

    def test_the_domain_is_closed(self):
        values = set()
        for kind in (STANZA_KIND_APP, STANZA_KIND_FAMILY):
            for status in (FILE_READ_OK, FILE_READ_UNREADABLE):
                for objects in (0, 3):
                    for families in (0, 3):
                        for effect in (WRITE_EFFECT_OVERWRITE,
                                       WRITE_EFFECT_NO_ROUTE):
                            values.add(reach_of(kind, status, objects,
                                                families, effect))
        self.assertEqual(values, {REACH_ALL, REACH_PARTIAL, REACH_UNKNOWN})

    def test_the_verdict_recomputes_from_the_row(self):
        """The property that matters is not the value but its recomputability."""
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        for row in rows:
            with self.subTest(stanza=row["acl_stanza"]):
                self.assertEqual(
                    row["acl_reach"],
                    reach_of(row["acl_stanza_kind"], row["acl_file_read"],
                             row["acl_objects_with_own_perms"],
                             row["acl_families_with_own_perms"],
                             row["acl_write_effect"]),
                )


class TheDecisionCountersTest(unittest.TestCase):

    def test_the_application_row_counts_the_whole_application(self):
        row = builder().app_default_row("my_app", provenance(local=FROZEN_META))
        self.assertEqual(row["acl_objects_with_own_perms"], 3)
        self.assertEqual(row["acl_families_with_own_perms"], 1)
        self.assertEqual(row["acl_reach"], REACH_PARTIAL)

    def test_a_family_row_counts_its_own_family(self):
        prov = provenance(local=FROZEN_META)
        self.assertEqual(
            builder().family_row("my_app", "views", prov)["acl_objects_with_own_perms"],
            2,
        )
        self.assertEqual(
            builder().family_row(
                "my_app", "savedsearches", prov)["acl_objects_with_own_perms"],
            1,
        )

    def test_the_family_count_is_emitted_on_every_row_of_the_application(self):
        """It carries an **application** fact. Blanking it on family rows created one more
        semantics of emptiness for nothing."""
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertGreater(len(rows), 1)
        for row in rows:
            with self.subTest(stanza=row["acl_stanza"]):
                self.assertEqual(row["acl_families_with_own_perms"], 1)

    def test_only_what_really_freezes_is_counted(self):
        """A stanza carrying only `owner`, `version` and `modtime` - what splunkd writes
        for every object it touches - freezes nothing."""
        prov = provenance(
            local=touched_stanza("views/a") + touched_stanza("views/b")
                  + frozen_stanza("views/c")
        )
        row = builder().family_row("my_app", "views", prov)
        self.assertEqual(row["acl_objects_with_own_perms"], 1)


# --------------------------------------------------------------------------- #
# Sections 7.3, 6.2, 6.3 - unchanged ground, re-exercised
# --------------------------------------------------------------------------- #

class TheParametersTest(unittest.TestCase):
    """Two parameters, and the allow list that guards them."""

    def test_the_application_filter_defaults_to_everything(self):
        for raw in (None, "", "   ", ",,,"):
            with self.subTest(raw=raw):
                self.assertEqual(parse_app_filter(raw), ("*",))

    def test_the_family_list_is_empty_by_default(self):
        for raw in (None, "", " , "):
            with self.subTest(raw=raw):
                self.assertEqual(parse_family_list(raw), ())

    def test_a_regex_metacharacter_cannot_reach_the_matcher(self):
        self.assertEqual(sanitize_filter("a|b;c`d$e"), "abcde")
        self.assertEqual(parse_app_filter(".*"), ("*",))
        self.assertFalse(app_matches("anything", parse_app_filter("a.c")))

    def test_the_star_is_the_only_metacharacter(self):
        for name, pattern, expected in (
            ("my_app", "*", True), ("my_app", "my_*", True), ("my_app", "*_app", True),
            ("my_long_app", "my_*_app", True), ("my_app", "*x*", False),
            ("my_app", "other", False),
        ):
            with self.subTest(name=name, pattern=pattern):
                self.assertEqual(app_matches(name, (pattern,)), expected)

    def test_there_are_exactly_two_parameters(self):
        """`count_objects` was withdrawn with the two columns it fed: +790 REST calls and
        a factor 6,4 to 7,3 on 41 applications, for a lower bound that came out empty by
        default."""
        params = validate_inventory_params()
        self.assertEqual(
            sorted(params.__dataclass_fields__), ["apps", "families"]
        )

    def test_no_parameter_of_this_command_can_be_fatally_invalid(self):
        """The honest shape for a command that only reads: both filters pass through the
        allow list, so nothing rejects the run."""
        params = validate_inventory_params(apps="a|b", families="x;y")
        self.assertEqual(params.apps, ("ab",))
        self.assertEqual(params.families, ("xy",))

    def test_the_capability_is_the_one_the_contract_names(self):
        self.assertEqual(REQUIRED_INVENTORY_CAPABILITY, "list_app_acl")


class TheLiteralValuesTest(unittest.TestCase):
    """`access` carries both permissions on ONE line, so the two columns come from
    splitting it. Every case below is a shape the total reader must survive."""

    def test_the_measured_shape_is_split_into_two_literals(self):
        self.assertEqual(
            split_access({"access": "read : [ power ], write : [ admin ]"}),
            ("power", "admin"),
        )

    def test_several_roles_keep_their_literal_form(self):
        self.assertEqual(
            split_access({"access": "read : [ power, user ], write : [ admin ]"}),
            ("power, user", "admin"),
        )

    def test_an_empty_permission_reads_back_as_the_empty_string(self):
        self.assertEqual(
            split_access({"access": "read : [  ], write : [ admin ]"}), ("", "admin")
        )

    def test_the_reader_survives_every_malformed_shape(self):
        for raw in (None, {}, {"access": ""}, {"access": "garbage"},
                    {"access": "read : [ power"}, {"access": "read power ]"}):
            with self.subTest(raw=raw):
                result = split_access(raw)
                self.assertEqual(len(result), 2)
                self.assertTrue(all(isinstance(part, str) for part in result))

    def test_the_export_key_is_read_literally(self):
        self.assertEqual(export_of({"export": "system"}), "system")
        self.assertEqual(export_of(None), "")


class TheOutputCarriesCountsAndNeverObjectNamesTest(unittest.TestCase):
    """Bound 3 of section 6.2, and **the reason the capability exists**.

    Reading the file short-circuits the capability filtering REST applies: a caller without
    `admin_all_objects` would otherwise see object names the API refuses them.
    """

    OBJECT_NAMES = ("dashboard_one", "dashboard_two", "nightly_report")

    def test_no_emitted_value_contains_an_object_name(self):
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertTrue(rows)
        rendered = " ".join("%s" % v for row in rows for v in row.values())
        for name in self.OBJECT_NAMES:
            with self.subTest(object=name):
                self.assertNotIn(name, rendered)

    def test_the_frozen_objects_are_nonetheless_counted(self):
        """The negative control: without it, "no name leaked" would be true by vacuity."""
        rows = list(
            builder(prov=provenance(local=FROZEN_META)).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertEqual(
            sum(int(row["acl_objects_with_own_perms"] or 0) for row in rows), 6
        )


class TheExecutionMemberTest(unittest.TestCase):
    """HY-4: the `searchinfo` branch is measured negative, the cheap REST call positive."""

    def test_it_is_read_from_the_cheap_rest_call(self):
        rest = FakeAppRest(json_responses={SERVER_INFO_PATH: RestOk(
            b'{"entry":[{"name":"server-info","content":{"serverName":"member_two"}}]}')})
        self.assertEqual(resolve_member(rest), "member_two")

    def test_it_falls_back_on_the_empty_string(self):
        for response in (RestFail(), RestOk(b"{}"), RestOk(b"not json"),
                         RestOk(b'{"entry":[{"content":{}}]}')):
            with self.subTest(response=response):
                rest = FakeAppRest(json_responses={SERVER_INFO_PATH: response})
                self.assertEqual(resolve_member(rest), "")

    def test_it_reaches_every_row(self):
        rows = list(
            builder(member="member_two").rows(make_params(), applications=["my_app"])
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["acl_member"], "member_two")

    def test_the_member_reads_unknown_rather_than_empty(self):
        """v4.6: the v4.5 fallback was an empty cell plus a README pointing at
        `splunk_server` - a field ABSENT from this output, so the advice could not be
        followed from the table. A named value can at least be filtered on."""
        rows = list(builder().rows(make_params(), applications=["my_app"]))
        for row in rows:
            self.assertEqual(row["acl_member"], MEMBER_UNKNOWN)

    def test_the_environment_variable_named_by_the_measurement_is_never_read(self):
        """**Named trap** of HY-4: `SPLUNK_SERVER_NAME` carries the name of the systemd
        service, not the `serverName` of the instance."""
        paths = [
            os.path.join(BIN_DIR, "acltools", "appacl_inventory.py"),
            os.path.join(BIN_DIR, "appaclinventory.py"),
        ]
        named_somewhere = False
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
            named_somewhere = named_somewhere or "SPLUNK_SERVER_NAME" in source
            with self.subTest(module=os.path.basename(path)):
                self.assertNotIn("SPLUNK_SERVER_NAME", _executable_source(source))
        self.assertTrue(named_somewhere, "the trap is no longer named anywhere")


class TheReadPerimeterIsTheApplicationListTest(unittest.TestCase):

    def test_the_applications_come_from_the_platform(self):
        rest = FakeAppRest(json_responses={"/services/apps/local": RestOk(
            b'{"entry":[{"name":"one"},{"name":"two"}]}')})
        self.assertEqual(list_applications(rest), ["one", "two"])

    def test_a_failed_listing_yields_no_application(self):
        rest = FakeAppRest(json_responses={"/services/apps/local": RestFail()})
        self.assertEqual(list_applications(rest), [])

    def test_only_the_listed_applications_are_read(self):
        """Bound 4: no `.meta` outside the applications the platform returns is opened."""
        rest = FakeAppRest(json_responses={"/services/apps/local": RestOk(
            b'{"entry":[{"name":"only_this_one"}]}')})
        reader = FakeProvenanceReader(provenance())
        build = InventoryBuilder(
            rest=rest, provenance_reader=reader, table=FIXTURE_TABLE
        )
        list(build.rows(make_params()))
        self.assertEqual(reader.reads, ["only_this_one"])

    def test_the_applications_come_out_sorted(self):
        rows = list(builder().rows(make_params(), applications=["zeta", "alpha", "mu"]))
        self.assertEqual([r["eai:acl.app"] for r in rows], ["alpha", "mu", "zeta"])

    def test_the_filter_selects_the_applications(self):
        rows = list(builder().rows(
            make_params(apps=("keep_*",)),
            applications=["keep_one", "keep_two", "drop_me"]))
        self.assertEqual([r["eai:acl.app"] for r in rows], ["keep_one", "keep_two"])


class TheApplicationStanzaIsWrittenAsItIsWrittenTest(unittest.TestCase):
    """`[]` rather than an empty cell. The empty string was accurate and unreadable: a cell
    nobody can see is a cell an operator reads as a bug."""

    def test_the_application_row_shows_the_bracket_pair(self):
        row = builder().app_default_row("my_app", provenance())
        self.assertEqual(row["acl_stanza"], APP_STANZA_LABEL)
        self.assertEqual(row["acl_stanza"], "[]")

    def test_a_family_row_shows_the_family_name(self):
        row = builder().family_row("my_app", "views", provenance())
        self.assertEqual(row["acl_stanza"], "[views]")

    def test_the_kind_column_remains_the_discriminant(self):
        """The write command reads `acl_stanza_kind`, never the stanza name alone."""
        row = builder().app_default_row("my_app", provenance())
        self.assertEqual(row["acl_stanza_kind"], STANZA_KIND_APP)


# --------------------------------------------------------------------------- #
# Section 7.2 - what the command declares
# --------------------------------------------------------------------------- #

class TheGeneratingCharacterIsCarriedByTheSdkTest(unittest.TestCase):
    """HY-1, established from the vendored SDK and frozen from both ends."""

    def _sdk_source(self, name):
        path = os.path.join(BIN_DIR, "lib", "splunklib", "searchcommands", name)
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_the_sdk_pins_the_generating_setting(self):
        self.assertRegex(
            self._sdk_source("generating_command.py"),
            r"generating\s*=\s*ConfigurationSetting\(\s*readonly=True,\s*value=True",
        )

    def test_the_sdk_leaves_the_type_setting_modifiable(self):
        """`generating` says the command **opens** the pipeline; `type` says **which**. The
        two are independent, and only the second is ours to set."""
        source = self._sdk_source("generating_command.py")
        marker = source.index("type = ConfigurationSetting(")
        self.assertNotIn("readonly=True", source[marker:marker + 200])

    def test_commands_conf_declares_no_generating_key(self):
        conf = read_splunk_conf("default", "commands.conf")
        for stanza, keys in conf.items():
            with self.subTest(command=stanza):
                self.assertNotIn("generating", keys)


class TheReadmeFieldTableIsADeliverableTest(unittest.TestCase):
    """**Deliverable 9, sixteenth statement** - and it is exigible, not decorative.

    The contract required a document usable without it, and did not hold that promise: the
    first operator to open the command in the interface reported that a good part of the
    columns were obscure and that the documentation said nothing about the new ones. So the
    table is now a **deliverable**, and a deliverable that nothing checks drifts on the
    first rename.

    What is checked here is what the contract asks for: **every** column present, grouped by
    the four levels, each with the question it answers, and the emission rule stated in the
    words of section 7.5 - **presence, not freezing**.

    What is not checked, and cannot be: whether the prose is *good*. That is the reading
    trial of integration scenario 14bis, which is a person, not an assertion.
    """

    @classmethod
    def setUpClass(cls):
        from . import REPO_ROOT

        with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as handle:
            cls.readme = handle.read()
        start = cls.readme.index("## What the inventory gives you, column by column")
        cls.section = cls.readme[start:cls.readme.index("\n## ", start + 10)]

    def test_the_section_exists_and_is_not_a_stub(self):
        self.assertGreater(len(self.section.splitlines()), 40)

    def test_every_column_appears_in_the_table(self):
        """A column the operator receives and the README never names is a column they have
        to guess."""
        missing = [
            field for field in INVENTORY_OUTPUT_FIELDS
            if "`%s`" % field not in self.section
        ]
        self.assertEqual(
            [], missing,
            "column(s) emitted by the command and absent from the README table: %s"
            % missing,
        )

    def test_no_withdrawn_column_lingers_in_the_table(self):
        """The other direction. A README that still describes a column nobody emits sends
        the operator looking for a cell that is not there."""
        for gone in ("acl_write_path", "acl_present_local", "acl_present_default",
                     "acl_objects_total", "acl_objects_inheriting", "acl_provenance",
                     "acl_governable", "acl_frozen_stanzas", "acl_family_headers",
                     "count_objects"):
            with self.subTest(column=gone):
                self.assertNotIn("`%s`" % gone, self.section)

    def test_the_four_levels_are_named_as_headings(self):
        """The levels are the reading key, not a classification for the archives: a table
        of eighteen columns with nothing separating them is what produced the two most
        serious findings."""
        for level in ("Identification", "Platform", "File", "Decision"):
            with self.subTest(level=level):
                self.assertIn("### %s" % level, self.section)

    def test_the_closed_domains_are_published(self):
        """An operator filtering on a value needs to know which values exist."""
        for value in (ROW_REASON_APP, ROW_REASON_STANZA, ROW_REASON_OBJECTS,
                      ROW_REASON_REQUESTED, EFFECTIVE_OK, EFFECTIVE_APP_DISABLED,
                      EFFECTIVE_UNREADABLE, WRITE_EFFECT_OVERWRITE, WRITE_EFFECT_CREATE,
                      WRITE_EFFECT_NO_ROUTE, LAYER_LOCAL, LAYER_DEFAULT, LAYER_NONE,
                      REACH_ALL, REACH_PARTIAL, REACH_UNKNOWN, FILE_READ_OK,
                      FILE_READ_UNREADABLE, MEMBER_UNKNOWN):
            with self.subTest(value=value):
                self.assertIn("`%s`" % value, self.section)

    def test_the_rule_about_empty_cells_is_stated(self):
        """It is the rule the whole table is built on, so it is the first thing to read."""
        self.assertIn("No column is ever empty without another saying why", self.section)

    def test_the_emission_rule_is_stated_as_presence_and_not_freezing(self):
        """*Relevé* by the contract: the class docstring of the deliverable announced a row
        per family carrying a header or a **frozen** object, which section 7.5 contradicts
        explicitly. The README must not repeat the mistake."""
        flat = " ".join(self.section.lower().split())
        self.assertIn("presence, not freezing", flat)
        self.assertIn("whether or not it freezes anything", flat)

    def test_the_layer_column_does_not_promise_the_effective_value(self):
        """The promise was withdrawn, not repaired. A README that reinstated it would be
        the contradiction the revision removed."""
        flat = " ".join(self.section.split())
        self.assertIn("It does not say where the effective permissions come from",
                      flat)


class TheWriteEffectUsesTheSamePredicateAsTheWriteCommandTest(unittest.TestCase):
    """**The correction of v4.6, and the one the reading trial made necessary.**

    A lecteur given only the README and a raw output could not tell whether the write he
    was about to launch would be undoable - on the commonest case: all eight stanzas of the
    inventoried application live in the `default` layer, so every write there is a
    creation. He deduced it, **without certainty**.

    The property that matters here is not the value but its **provenance**: the column is
    the section 9.2 predicate applied to reading, and the tests below derive the expected
    answer from the write command's own method rather than restating it. Two
    implementations of one rule would be two answers to a question both commands must
    answer identically.
    """

    def _both(self, prov, stanza="views"):
        """(what the write command would decide, what the inventory publishes)."""
        row = builder().family_row("my_app", stanza, prov)
        return prov.materialized_local(stanza), row["acl_write_effect"]

    def test_permissions_in_the_local_layer_make_the_write_reversible(self):
        materialized, effect = self._both(provenance(local=frozen_stanza("views")))
        self.assertTrue(materialized)
        self.assertEqual(effect, WRITE_EFFECT_OVERWRITE)

    def test_permissions_only_in_the_default_layer_make_the_write_a_creation(self):
        """**The commonest case, and the one the reader had to guess.** A write lands in
        `local.meta`; there is nothing there, so it materializes - and nothing removes it."""
        materialized, effect = self._both(provenance(default=frozen_stanza("views")))
        self.assertFalse(materialized)
        self.assertEqual(effect, WRITE_EFFECT_CREATE)

    def test_no_permissions_anywhere_make_the_write_a_creation(self):
        materialized, effect = self._both(provenance())
        self.assertFalse(materialized)
        self.assertEqual(effect, WRITE_EFFECT_CREATE)

    def test_a_stanza_without_an_access_key_is_a_creation_too(self):
        """A stanza carrying only `export`, or only the bookkeeping keys, materializes
        nothing - which is exactly what the write command decides on the same input."""
        for text in (scoped_stanza("views"), touched_stanza("views")):
            with self.subTest(stanza=text.splitlines()[1]):
                materialized, effect = self._both(provenance(local=text))
                self.assertFalse(materialized)
                self.assertEqual(effect, WRITE_EFFECT_CREATE)

    def test_the_two_commands_never_disagree(self):
        """The invariant, swept over every shape a stanza takes: whatever the write command
        would call reversible, the inventory calls `overwrite_reversible`, and conversely."""
        shapes = (
            ("access in local", provenance(local=frozen_stanza("views"))),
            ("access in default", provenance(default=frozen_stanza("views"))),
            ("access in both", provenance(local=frozen_stanza("views"),
                                          default=frozen_stanza("views"))),
            ("export only", provenance(local=scoped_stanza("views"))),
            ("bookkeeping only", provenance(local=touched_stanza("views"))),
            ("no stanza", provenance()),
        )
        for label, prov in shapes:
            with self.subTest(shape=label):
                materialized, effect = self._both(prov)
                self.assertEqual(
                    effect,
                    WRITE_EFFECT_OVERWRITE if materialized else WRITE_EFFECT_CREATE,
                    "the inventory and the write command disagree on %s" % label,
                )

    def test_no_route_wins_over_the_reversibility_question(self):
        """With no handler there is nothing to say about reversibility: the tool cannot
        write to that family by name at all."""
        row = builder().family_row(
            "my_app", "unknown_family", provenance(local=frozen_stanza("unknown_family"))
        )
        self.assertEqual(row["acl_write_effect"], WRITE_EFFECT_NO_ROUTE)

    def test_an_application_row_always_has_a_route(self):
        """A `[]` address is determined by the application alone."""
        row = builder().app_default_row("my_app", provenance())
        self.assertNotEqual(row["acl_write_effect"], WRITE_EFFECT_NO_ROUTE)

    def test_the_function_is_the_only_implementation(self):
        """Read on the source: the inventory computes the effect in one place, and that
        place consults `perms_source`, which consults the shared predicate."""
        import os

        from . import BIN_DIR

        path = os.path.join(BIN_DIR, "acltools", "appacl_inventory.py")
        with open(path, encoding="utf-8") as handle:
            lines = [l for l in handle if not l.strip().startswith("#")]
        source = "".join(lines)
        self.assertEqual(source.count("def write_effect_of("), 1,
                         "one definition, or the rule has two implementations")
        calls = source.count("write_effect_of(") - 1
        self.assertEqual(calls, 1, "the effect must be computed once, in the row builder")
        self.assertIn("provenance.perms_source(stanza)", source)


class TheForbiddenStateTest(unittest.TestCase):
    """**`acl_reach = all` together with `acl_write_effect = no_route` is forbidden.**

    Found at the reading trial: `searchbnf` came out `all` - announced reached in full -
    and `no_handler`, that is unreachable by the tool. An operator sorting on
    `acl_reach = all` was picking up a target the write fails on.
    """

    def test_the_pair_never_occurs_on_a_real_run(self):
        prov = provenance(
            local=FROZEN_META + touched_stanza("unknown_family/x")
                  + touched_stanza("searchbnf/y")
        )
        rows = list(
            builder(prov=prov).rows(
                make_params(families=("macros", "another_unknown")),
                applications=["my_app"],
            )
        )
        self.assertTrue(rows)
        offenders = [
            row["acl_stanza"] for row in rows
            if row["acl_reach"] == REACH_ALL
            and row["acl_write_effect"] == WRITE_EFFECT_NO_ROUTE
        ]
        self.assertEqual([], offenders,
                         "row(s) announced reached in full with no route: %s" % offenders)

    def test_the_negative_control_shows_the_fixture_reaches_that_case(self):
        """Without a row that has no route, the sweep above would pass by vacuity."""
        rows = list(
            builder(prov=provenance(local=touched_stanza("searchbnf/y"))).rows(
                make_params(), applications=["my_app"]
            )
        )
        self.assertTrue(
            any(row["acl_write_effect"] == WRITE_EFFECT_NO_ROUTE for row in rows)
        )

    def test_the_derivation_itself_refuses_the_pair(self):
        self.assertEqual(
            reach_of(STANZA_KIND_FAMILY, FILE_READ_OK, 0, 0, WRITE_EFFECT_NO_ROUTE),
            REACH_UNKNOWN,
        )


class TheEmptyCellSaysWhichKindOfEmptyTest(unittest.TestCase):
    """The rule of v4.5 covered the **breakdown**; the reading trial showed it did not
    cover the **semantics**, and that it is the semantics which decides.

    "The `access` key is absent" and "the key is there and the permission is empty" are two
    **opposite** states everywhere else in this contract - an empty permission leaves the
    object unreachable, an absent stanza makes it inherit - and they are the two states that
    decide `updated` against `created` on a write.
    """

    def test_an_absent_key_reads_as_none(self):
        row = builder().family_row("my_app", "views", provenance())
        self.assertEqual(row["acl_file_perms_read"], "")
        self.assertEqual(row["acl_perms_source"], LAYER_NONE)

    def test_a_present_key_with_an_empty_permission_names_its_layer(self):
        """Same empty cell, opposite meaning - and now distinguishable."""
        empty = "[views]\naccess = read : [  ], write : [ admin ]\n"
        row = builder().family_row("my_app", "views", provenance(local=empty))
        self.assertEqual(row["acl_file_perms_read"], "")
        self.assertEqual(row["acl_perms_source"], LAYER_LOCAL)
        self.assertEqual(row["acl_file_perms_write"], "admin")

    def test_the_two_cases_differ_only_by_the_column_that_explains_them(self):
        absent = builder().family_row("my_app", "views", provenance())
        empty = builder().family_row(
            "my_app", "views",
            provenance(local="[views]\naccess = read : [  ], write : [  ]\n"))
        self.assertEqual(absent["acl_file_perms_read"], empty["acl_file_perms_read"])
        self.assertNotEqual(absent["acl_perms_source"], empty["acl_perms_source"])

    def test_and_they_decide_opposite_write_effects(self):
        """Which is why the distinction is not presentation: it changes the act."""
        absent = builder().family_row("my_app", "views", provenance())
        empty = builder().family_row(
            "my_app", "views",
            provenance(local="[views]\naccess = read : [  ], write : [  ]\n"))
        self.assertEqual(absent["acl_write_effect"], WRITE_EFFECT_CREATE)
        self.assertEqual(empty["acl_write_effect"], WRITE_EFFECT_OVERWRITE)


class TheStanzaIsQuotedWithItsBracketsEverywhereTest(unittest.TestCase):
    """v4.6: the column cited the file for `[]` and dropped the brackets for `commands` -
    the same column in two registers. And the chaining must survive it."""

    def test_both_kinds_carry_brackets(self):
        self.assertEqual(
            builder().app_default_row("my_app", provenance())["acl_stanza"], "[]")
        self.assertEqual(
            builder().family_row("my_app", "views", provenance())["acl_stanza"],
            "[views]")

    def test_the_label_helper_is_the_single_source(self):
        self.assertEqual(stanza_label(""), APP_STANZA_LABEL)
        self.assertEqual(stanza_label("views"), "[views]")

    def test_the_write_command_resolves_the_bracketed_form(self):
        """Section 8.3: the brackets are stripped before resolution, and nothing else is
        normalized. Without this, chaining without parameters would break on every family
        row the inventory emits."""
        from acltools.appacl_model import AppEventInput
        from acltools.appacl_target import resolve_target

        for value in ("[views]", "views"):
            with self.subTest(stanza=value):
                target = resolve_target(
                    AppEventInput(app="my_app", stanza_kind=STANZA_KIND_FAMILY,
                                  handler="", stanza=value),
                    FIXTURE_TABLE)
                self.assertEqual(target.handler, "data/ui/views")

    def test_an_unknown_family_is_reported_without_its_brackets(self):
        from acltools.appacl_model import AppEventInput
        from acltools.appacl_target import resolve_target
        from acltools.errors import EventRejected

        with self.assertRaises(EventRejected) as caught:
            resolve_target(
                AppEventInput(app="my_app", stanza_kind=STANZA_KIND_FAMILY,
                              handler="", stanza="[nope]"),
                FIXTURE_TABLE)
        self.assertEqual(caught.exception.error, "unresolved_family:nope")


class TheDocumentationNeverPointsOutsideTheArchiveTest(unittest.TestCase):
    """**Normative clause of v4.6**, deliverable 9: the README never sends the operator to a
    document absent from the deployable archive.

    `DEVNOTES.md` is excluded from the archive by construction - the README says what to do,
    the notes say why, and only the first is shipped. The README cited it **three times** as
    the place where the answers live: the independent reader was tempted to open it, and an
    operator in production could not.
    """

    @classmethod
    def setUpClass(cls):
        import os
        import re

        from . import REPO_ROOT

        cls.re = re
        with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as handle:
            cls.readme = handle.read()
        with open(os.path.join(REPO_ROOT, ".gitattributes"), encoding="utf-8") as handle:
            cls.gitattributes = handle.read()

    def _excluded(self):
        """Paths `git archive` leaves out, read from `.gitattributes` rather than listed."""
        names = []
        for line in self.gitattributes.splitlines():
            if "export-ignore" in line and not line.strip().startswith("#"):
                names.append(line.split()[0].rstrip("/"))
        return names

    def test_the_exclusions_are_read_and_not_assumed(self):
        excluded = self._excluded()
        self.assertIn("DEVNOTES.md", excluded)
        self.assertIn("tests", excluded)

    def test_no_markdown_link_points_at_an_excluded_document(self):
        targets = self.re.findall(r"\]\(([^)#]+)\)", self.readme)
        offenders = sorted({
            target for target in targets
            for name in self._excluded()
            if target.strip().rstrip("/").endswith(name)
        })
        self.assertEqual(
            [], offenders,
            "the README links to document(s) absent from the deployable archive: %s. "
            "An operator in production cannot open them - bring the answer into the "
            "README, or drop the reference." % offenders,
        )

    def test_devnotes_is_not_named_as_the_place_where_answers_live(self):
        """A bare mention is not a link, and still sends the reader nowhere."""
        body = self.readme
        # The installation section may legitimately state what the archive excludes.
        allowed = body.count("are left out by `.gitattributes`")
        self.assertLessEqual(
            body.count("DEVNOTES.md") - allowed, 0,
            "DEVNOTES.md is still named in the README outside the sentence that says it "
            "is not shipped.",
        )

    def test_the_readme_says_per_command_whether_it_writes(self):
        """v4.6: the introduction announced three commands that rewrite permissions, while
        the inventory writes nothing. The table must say so per command."""
        flat = " ".join(self.readme.split())
        self.assertIn("Writes?", flat)
        for command in ("editacl", "appaclinventory", "editappacl"):
            with self.subTest(command=command):
                self.assertIn("`%s`" % command, flat)


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
