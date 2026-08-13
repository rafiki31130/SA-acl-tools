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

#: Fields **aggregated** by `editacl_rollback` (section 8.6), in the order of that
#: section taken literally. `id` is not among them because it is not aggregated: it is
#: derived from the `endpoint` group key by an `eval`, and `IdIsReEmittedFromTheJournalledEndpointTest`
#: covers it. The macro therefore emits eight fields, of which seven are aggregated.
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
        # Section 6.7-4. The value comes from the `eai_type` column of the lookup, that
        # is, from the key of the mapping table - the same word the command journals
        # and the monitoring view groups on. It gives the operator a type to filter on
        # before the command has seen the row.
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertIn("acl_synthesized_type", definition)
        self.assertRegex(
            definition,
            r"eval \"eai:type\" = if\(isnull\('eai:type'\).*acl_synthesized_type",
        )
        self.assertIn('eval acl_synthesized_type=\\"$eai_type$\\"', definition)

    def test_the_selection_precedes_the_rest_calls(self):
        # The cost lever of section 6.7-2: a family that was not asked for must cost no
        # REST call. If the `where` came after the `map`, everything would be
        # enumerated.
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertLess(definition.index("| where match(eai_type"),
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
        #
        # The VALUE is frozen, not merely the presence of the key. Checking that
        # `max_objects=` appears accepts `max_objects=10`, which puts the default back
        # and stops a restore at the eleventh object - on the safety net of an
        # irreversible operation, reported as a success. Found by the mutation campaign
        # of the second remediation, in the family R-4 named.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn("max_objects=100000", definition)

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
        #
        # The source that follows is the `acl_journal_source` macro and no longer a
        # written-out index (D-51, section 8.3.bis): a redirection of the journal index
        # would otherwise have left this macro - the only safety net of an irreversible
        # operation - returning an EMPTY rollback set, reported as a success.
        self.assertTrue(
            self.conf["editacl_rollback(1)"]["definition"].startswith(
                "search `acl_journal_source`"
            )
        )


#: Sentinel standing for **the absence of the by-field** in the `eventstats` model
#: below. It is not the empty string: Splunk tells a missing field from a field holding
#: `""`, and the whole point of the `summary` line carrying no `endpoint` (section 8.5)
#: is that it lands in a group of its own.
_NO_ENDPOINT = object()


def _group_key(line):
    return line["endpoint"] if "endpoint" in line else _NO_ENDPOINT


def run_rollback_macro(lines, sid):
    """Model of `editacl_rollback(1)` applied to a set of journal lines.

    It follows the SPL of `macros.conf` step by step, and nothing else - the point is
    to be able to say what the macro produces from a given journal **without a Splunk
    instance**, in order to compare two journals that differ only by the presence of
    the end-of-run line.

    What is modelled, and where the fidelity lies:

    - `eventstats max(_restorable) AS restorable BY endpoint` - a line that carries no
      `endpoint` forms a group of its own, it does not join the group of the lines
      whose `endpoint` is the empty string;
    - `search phase="intent" restorable=1` - a line whose `restorable` is null is
      dropped, as `restorable=1` is false on a missing field;
    - `earliest(<field>)` - the value carried by the earliest line of the group **that
      carries that field**; a line where the field is missing does not contribute.
      A field holding the empty string does contribute (D-32, measured on 9.4.6);
    - the `coalesce(..., "")` on the two permission columns, and the final `fields`.
    """
    selected = [line for line in lines if line.get("sid") == sid]

    for line in selected:
        line["_restorable"] = (
            1 if line.get("phase") == "outcome" and line.get("status") == "updated"
            else 0
        )

    groups = {}
    for line in selected:
        groups.setdefault(_group_key(line), []).append(line)
    for key, members in groups.items():
        top = max(member["_restorable"] for member in members)
        for member in members:
            member["restorable"] = top

    intents = [
        line for line in selected
        if line.get("phase") == "intent" and line.get("restorable") == 1
    ]

    restorable_groups = {}
    for line in intents:
        restorable_groups.setdefault(_group_key(line), []).append(line)

    emitted = {}
    for key, members in restorable_groups.items():
        ordered = sorted(members, key=lambda line: line["ts"])
        row = {}
        for journal_field, output_field in (
            ("before_perms_read", "eai:acl.perms.read"),
            ("before_perms_write", "eai:acl.perms.write"),
            ("before_sharing", "eai:acl.sharing"),
            ("before_owner", "eai:acl.owner"),
            ("app", "eai:acl.app"),
            ("title", "title"),
            ("eai_type", "eai:type"),
        ):
            for line in ordered:
                if line.get(journal_field) is not None and journal_field in line:
                    row[output_field] = line[journal_field]
                    break
        row["eai:acl.perms.read"] = row.get("eai:acl.perms.read", "")
        row["eai:acl.perms.write"] = row.get("eai:acl.perms.write", "")
        # `| eval id = endpoint`: the group key IS the journaled endpoint, so the
        # identifier costs no aggregation and cannot disagree with the pairing.
        row["id"] = key
        emitted[key] = {
            name: value for name, value in row.items()
            if name in ("title", "eai:type", "id") or name.startswith("eai:acl.")
        }
    return emitted


class RollbackMacroIsUnaffectedByTheEndOfRunLineTest(unittest.TestCase):
    """D-46 - the rollback set is **identical** with and without the `summary` line.

    The macro is the only way to undo an irreversible operation. The analysis says it
    reads neither `error` nor the renamed member field, and that a third value of
    `phase` crosses it without effect. This class does not take that analysis at its
    word: it runs a real batch through the state machine, collects the journal it
    produces, then compares the rollback set obtained with and without the end-of-run
    line appended.
    """

    def setUp(self):
        from acltools.pipeline import EventProcessor
        from acltools.rest import RestResponse

        from .helpers import (
            FIXTURE_MAPPING,
            FakeClock,
            FakeJournal,
            FakeRest,
            acl_body,
            make_ctx,
            make_event,
            make_params,
        )

        def path(title):
            return "/servicesNS/nobody/my_app/saved/searches/" + title

        self.journal = FakeJournal()
        rest = FakeRest(
            get_responses={
                path("written_one"): RestResponse(
                    200, acl_body(write=("legacy_role",))
                ),
                path("written_two"): RestResponse(
                    200, acl_body(write=("legacy_role",), read=())
                ),
                path("refused"): RestResponse(200, acl_body(write=("legacy_role",))),
                path("already_right"): RestResponse(
                    200, acl_body(write=("new_role_admin",))
                ),
                path("absent"): RestResponse(404, b"{}"),
            },
            post_responses={path("refused"): RestResponse(500, b"boom")},
            default_post=RestResponse(200, b"{}"),
        )
        self.processor = EventProcessor(
            params=make_params(max_objects=10),
            ctx=make_ctx(sid="1700000000.1"),
            rest=rest,
            journal=self.journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        for title in (
            "written_one", "written_two", "refused", "already_right", "absent",
        ):
            self.processor.process(make_event(title=title, write="new_role_admin"))
        self.processor.process(
            make_event(title="a_private_one", current_sharing="user")
        )

    def _journal_lines(self):
        lines = self.journal.intents + self.journal.outcomes
        return [dict(line) for line in sorted(lines, key=lambda line: line["ts"])]

    def _summary_line(self):
        return dict(self.processor.build_summary())

    # -- the demonstration -------------------------------------------------- #

    def test_the_batch_does_produce_a_rollback_set(self):
        """Guard rail: a dead instrument produces reassuring zeros."""
        restored = run_rollback_macro(self._journal_lines(), "1700000000.1")
        self.assertEqual(len(restored), 2)
        for row in restored.values():
            self.assertEqual(row["eai:acl.perms.write"], "legacy_role")
            self.assertEqual(row["eai:type"], "savedsearch")

    def test_the_rollback_set_is_identical_with_and_without_the_summary_line(self):
        without = run_rollback_macro(self._journal_lines(), "1700000000.1")
        with_summary = run_rollback_macro(
            self._journal_lines() + [self._summary_line()], "1700000000.1"
        )
        self.assertEqual(with_summary, without)

    def test_the_refused_write_stays_out_of_the_rollback_set_either_way(self):
        """The heart of the pairing: an object whose POST failed was not modified."""
        with_summary = run_rollback_macro(
            self._journal_lines() + [self._summary_line()], "1700000000.1"
        )
        self.assertNotIn(
            "/servicesNS/nobody/my_app/saved/searches/refused", with_summary
        )

    def test_the_summary_line_lands_in_a_group_of_its_own(self):
        """Section 8.5. It carries no `endpoint`, so it cannot raise the
        `max(_restorable)` of a group that holds an `intent` line."""
        lines = self._journal_lines() + [self._summary_line()]
        summary = lines[-1]
        self.assertNotIn("endpoint", summary)
        self.assertEqual(_group_key(summary), _NO_ENDPOINT)
        self.assertEqual(
            [line for line in lines if _group_key(line) is _NO_ENDPOINT], [summary]
        )

    def test_even_a_summary_line_carrying_an_empty_endpoint_would_change_nothing(self):
        """The property does not rest on the absence of the field alone.

        `_restorable` is zero on a `summary` line - `phase` is not `outcome` - so it
        can only lower a maximum, which no maximum reads; and `phase="intent"` drops it
        before the aggregation. This test makes that reasoning falsifiable rather than
        assumed.
        """
        forced = self._summary_line()
        forced["endpoint"] = ""
        self.assertEqual(
            run_rollback_macro(self._journal_lines() + [forced], "1700000000.1"),
            run_rollback_macro(self._journal_lines(), "1700000000.1"),
        )

    def test_a_summary_line_from_another_run_is_filtered_out_by_the_sid(self):
        other = self._summary_line()
        other["sid"] = "1700000000.2"
        self.assertEqual(
            run_rollback_macro(self._journal_lines() + [other], "1700000000.1"),
            run_rollback_macro(self._journal_lines(), "1700000000.1"),
        )

    def test_the_two_renamed_or_retyped_fields_are_not_read_by_the_macro(self):
        """`error` and the member field: the macro consumes neither, so neither the
        end of the `null` nor the rename can reach it."""
        definition = read_splunk_conf("default", "macros.conf")[
            "editacl_rollback(1)"
        ]["definition"]
        for absent in ("error", "host", "member"):
            self.assertNotIn(absent, definition)

    def test_the_macro_filters_on_the_phases_it_knows(self):
        """A third value of `phase` crosses it because the macro **names** the phases
        it wants, instead of excluding those it does not."""
        definition = read_splunk_conf("default", "macros.conf")[
            "editacl_rollback(1)"
        ]["definition"]
        self.assertIn('phase="outcome"', definition)
        self.assertIn('search phase="intent"', definition)
        self.assertNotIn("phase!=", definition)
        self.assertNotIn("summary", definition)


class IdIsReEmittedFromTheJournalledEndpointTest(unittest.TestCase):
    """The hole in the safety net, and the shape of its closing (section 8.6.bis).

    The macro used to re-emit `eai:type` and **no object identifier**, so the
    resolution of section 5.2 rested on that single field at replay time. An object
    whose input row carried no type - which every batch built on the native endpoints
    produces - was journaled with an empty type and rejected at rollback, its prior
    state intact in the journal and unusable.

    `endpoint` was already journaled and section 8.5 makes its shape a **contract**:
    `/servicesNS/nobody/<app>/<handler path>/<encoded title>`, identical on both
    phases. That is exactly the shape route 1 of section 5.2 parses. The macro
    therefore emits it as `id`, and the fix costs no new journaled field.

    These tests do not read the macro and conclude: they run an untyped batch through
    the real state machine, model the macro over the journal it produced, and feed the
    result back into a **second** state machine, which is where the rejection used to
    happen.
    """

    #: The untyped row rides on `data/ui/times`, the **named ambiguous handler** of
    #: the table: image of `times` and of `conf-times` at once, so the type cannot be
    #: recovered from the path and the journal line legitimately carries none. Every
    #: other native family now gets its type back by inversion, which is precisely what
    #: makes this the only shape of row that still needs `id` to come back.
    UNTYPED_ID = (
        "https://localhost:8089/servicesNS/nobody/my_app/data/ui/times/untyped_one"
    )

    def setUp(self):
        from acltools.pipeline import EventProcessor
        from acltools.rest import RestResponse

        from .helpers import (
            FIXTURE_MAPPING,
            FakeClock,
            FakeJournal,
            FakeRest,
            acl_body,
            make_ctx,
            make_event,
            make_params,
        )

        self._EventProcessor = EventProcessor
        self._make_event = make_event
        self._mapping = FIXTURE_MAPPING

        endpoint = "/servicesNS/nobody/my_app/data/ui/times/untyped_one"
        self.journal = FakeJournal()
        rest = FakeRest(
            get_responses={endpoint: RestResponse(200, acl_body(write=("legacy_role",)))},
            default_post=RestResponse(200, b"{}"),
        )
        self.processor = EventProcessor(
            params=make_params(max_objects=10),
            ctx=make_ctx(sid="1700000001.1"),
            rest=rest,
            journal=self.journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        # The untyped batch: no `eai:type` at all, resolution through `id` alone, on
        # the one handler path whose inversion is undefined. Twenty-four objects of
        # that family exist on the reference platform and their endpoint emits no
        # `eai:type`, so the case is reachable rather than contrived.
        self.outbound = self.processor.process(
            make_event(
                title="untyped_one",
                eai_type=None,
                id_value=self.UNTYPED_ID,
                write="new_role_admin",
            )
        )
        lines = self.journal.intents + self.journal.outcomes
        self.lines = [dict(line) for line in sorted(lines, key=lambda l: l["ts"])]
        self.restored = run_rollback_macro(self.lines, "1700000001.1")
        self.row = self.restored[endpoint]

    # -- the defect, stated as a fact rather than as a story ---------------- #

    def test_the_outbound_pass_writes_the_object_with_no_type_journalled(self):
        """Guard rail. If this batch were typed, the rest would prove nothing."""
        self.assertEqual(self.outbound.status, "updated")
        for line in self.lines:
            with self.subTest(phase=line["phase"]):
                self.assertEqual(line["eai_type"], "")

    def test_the_rollback_row_carries_no_type_either(self):
        self.assertEqual(self.row["eai:type"], "")

    # -- the fix ------------------------------------------------------------ #

    def test_the_macro_emits_id_from_the_endpoint(self):
        definition = read_splunk_conf("default", "macros.conf")[
            "editacl_rollback(1)"
        ]["definition"]
        self.assertIn("| eval id = endpoint", definition)
        self.assertRegex(definition, r"\|\s*fields\b[^\n]*\bid\b")

    def test_the_emitted_id_is_the_journalled_endpoint_verbatim(self):
        """Not a rebuilt string: the group key itself, so it cannot disagree with the
        pairing the macro just did."""
        self.assertEqual(
            self.row["id"], "/servicesNS/nobody/my_app/data/ui/times/untyped_one"
        )

    def test_the_untyped_rollback_row_resolves_and_is_written_back(self):
        """The end of the hole: replay the row and reach `updated`, not `rejected`."""
        from acltools.rest import RestResponse

        from .helpers import FakeClock, FakeJournal, FakeRest, acl_body, make_ctx, \
            make_params

        endpoint = "/servicesNS/nobody/my_app/data/ui/times/untyped_one"
        rest = FakeRest(
            get_responses={
                endpoint: RestResponse(200, acl_body(write=("new_role_admin",)))
            },
            default_post=RestResponse(200, b"{}"),
        )
        back = self._EventProcessor(
            params=make_params(max_objects=10),
            ctx=make_ctx(sid="1700000001.2"),
            rest=rest,
            journal=FakeJournal(),
            mapping=self._mapping,
            clock=FakeClock(),
        ).process(
            self._make_event(
                title=self.row["title"],
                app=self.row["eai:acl.app"],
                eai_type=self.row["eai:type"] or None,
                id_value=self.row["id"],
                sharing=self.row["eai:acl.sharing"],
                owner=self.row["eai:acl.owner"],
                read=self.row["eai:acl.perms.read"],
                write=self.row["eai:acl.perms.write"],
            )
        )
        self.assertEqual(back.status, "updated")
        self.assertEqual(back.endpoint, endpoint)
        self.assertEqual(back.after.perms_write, ("legacy_role",))

    def test_without_the_id_the_same_row_is_rejected(self):
        """The counter-proof, so that the test above is not green for another reason.

        Same row, `id` dropped: the row goes back to being what the macro emitted
        before this change, and the rejection is the one measured on the lab.
        """
        from .helpers import FakeClock, FakeJournal, FakeRest, make_ctx, make_params

        back = self._EventProcessor(
            params=make_params(max_objects=10),
            ctx=make_ctx(sid="1700000001.3"),
            rest=FakeRest(),
            journal=FakeJournal(),
            mapping=self._mapping,
            clock=FakeClock(),
        ).process(
            self._make_event(
                title=self.row["title"],
                app=self.row["eai:acl.app"],
                eai_type=self.row["eai:type"] or None,
                id_value=None,
                write=self.row["eai:acl.perms.write"],
            )
        )
        self.assertEqual(back.status, "rejected")
        self.assertEqual(back.error, "unresolved_endpoint:")

    # -- the nominal path must not pay for it ------------------------------- #

    def test_a_typed_row_resolves_to_the_very_same_endpoint_through_either_route(self):
        """Non-regression. `id` takes precedence over `eai:type` (section 5.2), so a
        typed rollback row now resolves through the endpoint too. It must land on the
        same URI, otherwise the fix would move the nominal path.
        """
        from acltools.endpoint import resolve_handler_path

        typed_endpoint = "/servicesNS/nobody/my_app/saved/searches/typed_one"
        by_id = resolve_handler_path(typed_endpoint, "savedsearch", self._mapping)
        by_type = resolve_handler_path(None, "savedsearch", self._mapping)
        self.assertEqual(by_id, "saved/searches")
        self.assertEqual(by_type, "saved/searches")

    def test_the_emitted_id_carries_the_fixed_context_so_it_reads_as_shared(self):
        """Section 3.5 reads the namespace of `id` to skip private objects. The
        endpoint is built in the fixed context, so a rollback row always reads as
        shared - which is right: a private object is skipped on the outbound pass and
        is never in a rollback set."""
        from acltools.endpoint import is_fixed_context, namespace_owner_from_id

        self.assertTrue(is_fixed_context(namespace_owner_from_id(self.row["id"])))

    def test_the_emitted_id_can_never_carry_the_aggregation_handler(self):
        """Route 1 discards `admin/directory`; the endpoint is built from an already
        resolved handler, so the string can never hold it."""
        for row in self.restored.values():
            with self.subTest(row=row["title"]):
                self.assertNotIn("admin/directory", row["id"])


class TableAndLookupConsistencyTest(unittest.TestCase):
    """The table is read by the Python code, the lookup by the macro. A divergence
    between the two only shows up at run time, and with no message."""

    def setUp(self):
        self.families = {
            row["eai_type"]: row["handler_path"]
            for row in read_csv_lookup("acl_object_families.csv")
        }
        self.table = endpoint_map()

    def test_the_two_files_name_the_columns_the_same_way(self):
        # One notion, one word. The override file of section 6.3 carries
        # `eai_type,handler_path`; this lookup carries the same pair and used to call
        # its first column `family`, which was a second name for the identifier the
        # operator writes in `eai:type`.
        rows = read_csv_lookup("acl_object_families.csv")
        self.assertEqual(sorted(rows[0].keys()), ["eai_type", "handler_path"])
        example = os.path.join(
            REPO_ROOT, "lookups", "acl_endpoint_map_override.csv.example"
        )
        with open(example, encoding="utf-8") as handle:
            header = handle.readline().strip()
        self.assertEqual(header.split(","), ["eai_type", "handler_path"])

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

    def test_the_lookup_is_deliberately_shorter_than_the_table_and_is_not_its_inverse(
        self,
    ):
        # THE TRAP, and renaming the column made it look more like the table, so it is
        # spelled out here. The JSON carries 28 keys, this lookup 27 rows: `times` is
        # missing, because `conf-times` already claims `data/ui/times` and inventorying
        # that endpoint twice would duplicate every object of the family.
        #
        # A reader who built an inverse table from THIS file would get
        # `data/ui/times -> conf-times` with no warning at all, where the shipped table
        # says the answer is undefined. The inverse the code uses is built from the
        # JSON, by `Mapping.type_of_handler`, and answers `None` there.
        missing = set(self.table) - set(self.families)
        self.assertEqual(missing, {"times"})
        self.assertEqual(len(self.families), 27)
        self.assertEqual(len(self.table), 28)


class SavedsearchesTest(unittest.TestCase):
    def setUp(self):
        self.conf = read_splunk_conf("default", "savedsearches.conf")

    NAMES = (
        "ACL - inventory by role",
        "ACL - references to decommissioned roles",
        "ACL - change journal",
    )

    #: The two application-level searches (v4.2 section 14.1, deliverable 8). They are a
    #: separate tuple: the controls above bear on searches built on `acl_inventory`, a
    #: macro, while these two are built on the journal of the other command and on a
    #: generating command. Folding them into `NAMES` would make three of those controls
    #: false and one of them vacuous.
    APP_NAMES = (
        "App ACL - irreversible writes",
        "App ACL - governability of the estate",
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
        # never the way it is reached (section 6.7 constraint 1). The application-level
        # pair follows the same rule for a sharper reason: one of them runs a GENERATING
        # command that reads the file system of the member, and scheduling it would put
        # that read on a timer nobody watches.
        for name in self.NAMES + (self.AUDIT,) + self.APP_NAMES:
            self.assertEqual(self.conf[name]["enableSched"], "0")

    #: The keys a shipped saved search is allowed to carry, exhaustively.
    #:
    #: R-4 of the re-audit of 2026-08-09, extended by the campaign that followed it.
    #: `enableSched` was checked; nothing checked what ELSE a stanza said, and an
    #: `action.email` pair passed the whole suite. An alert action is a side effect that
    #: no control over the SPL can see - it is not a command in the pipeline - and it
    #: would fire from a role whose whole contract is to search. The list is closed for
    #: the same reason the command list of the view is: a forbidden-key list only stops
    #: what somebody already thought of.
    ALLOWED_KEYS = frozenset((
        "description", "search", "dispatch.earliest_time", "dispatch.latest_time",
        "enableSched", "disabled", "alert.track", "request.ui_dispatch_view",
    ))

    def test_no_shipped_search_carries_a_key_outside_the_declared_set(self):
        for name, stanza in self.conf.items():
            for key in stanza:
                with self.subTest(search=name, key=key):
                    self.assertIn(key, self.ALLOWED_KEYS)

    def test_the_shipped_searches_are_exactly_the_six_declared(self):
        self.assertEqual(
            sorted(self.conf), sorted(self.NAMES + (self.AUDIT,) + self.APP_NAMES)
        )

    # -- section 12.7, blocking deliverable ---------------------------------- #

    JOURNAL = "ACL - change journal"

    def test_the_journal_search_groups_on_the_single_type_field(self):
        """One notion, one field - in the shipped searches as in the view.

        This search and the monitoring view are read side by side on the same run. It
        must group on `eai_type`, and on nothing that names a handler path: a table
        showing `savedsearch` next to another showing `saved/searches` for the same
        objects is the defect this closes.
        """
        search = self.conf[self.JOURNAL]["search"]
        self.assertRegex(search, r"BY[^|]*\beai_type\b")
        for forbidden in ("handler", "handler_path", "family"):
            self.assertNotIn(forbidden, search)

    def test_the_journal_search_labels_the_empty_type_like_the_view_does(self):
        """The literal is shared with the view on purpose: an unlabelled empty cell in
        one artefact next to a named bucket in the other is a difference the reader has
        to explain away."""
        search = self.conf[self.JOURNAL]["search"]
        self.assertIn('"(type not established)"', search)
        view = os.path.join(
            REPO_ROOT, "default", "data", "ui", "views", "editacl_runs.xml"
        )
        with open(view, encoding="utf-8") as handle:
            self.assertIn('"(type not established)"', handle.read())

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


class AppLevelMacrosTest(unittest.TestCase):
    """The five application-level macros (v4.2 sections 11.1 and 11.4).

    **This class is where the hole the previous project paid for is held shut.** The
    rollback of `editacl` re-emitted a field the journal often left empty, and 515 written
    objects out of 515 could not be restored - the defect was not that the hole existed
    but that no clause named it and no artifact made it visible. Three properties below
    are the direct answer, and each is checked on the SPL rather than on the intention:
    the selection is on **reversibility** and not on success (DV-1), the resolution rests
    on a field the journal **never leaves empty**, and what the rollback does not cover is
    listed by a macro of its own.
    """

    #: The five stanzas of deliverable 7 of section 14.1.
    NAMES = (
        "app_acl_journal_source",
        "app_acl_diag_source",
        "app_acl_rollback(1)",
        "app_acl_rollback_apply(1)",
        "app_acl_irreversible(1)",
    )

    #: Fields of the `intent` line the rollback set is built from. They are read from the
    #: journal module rather than copied, so a renamed key fails here instead of
    #: producing an empty rollback reported as a success.
    def setUp(self):
        self.conf = read_splunk_conf("default", "macros.conf")
        self.rollback = self.conf["app_acl_rollback(1)"]["definition"]
        self.applied = self.conf["app_acl_rollback_apply(1)"]["definition"]
        self.irreversible = self.conf["app_acl_irreversible(1)"]["definition"]

    def test_the_five_macros_are_declared(self):
        for name in self.NAMES:
            with self.subTest(macro=name):
                self.assertIn(name, self.conf)
                self.assertTrue(self.conf[name].get("description", "").strip())
                self.assertEqual(self.conf[name].get("iseval"), "0")

    def test_none_of_them_names_an_index_outside_the_two_sources(self):
        """D-51: the two source macros are the single place the index is written. An
        artifact that spelled it out would keep reading the old index after a
        redirection, and return an empty result without saying so - here, on the safety
        net of an irreversible operation.

        The applied form names no source at all, and that is stronger rather than
        weaker: it DELEGATES to the preview form, so it inherits whatever that one
        reads and cannot drift from it.
        """
        for name in self.NAMES[2:]:
            definition = self.conf[name]["definition"]
            with self.subTest(macro=name):
                self.assertNotRegex(definition, r"(?<![\w])index\s*=")
                self.assertTrue(
                    "app_acl_journal_source" in definition
                    or "`app_acl_rollback($sid$)`" in definition,
                    "%s reaches the journal through neither the source macro nor the "
                    "preview macro" % name,
                )

    def test_no_source_macro_uses_a_sourcetype_wildcard(self):
        """D-49: the diagnostic file auto-extracts field names that are homonyms of the
        journal's, with INVERTED meaning - they carry an SPL field name, not a value. A
        `sourcetype=editappacl:*` mixes the two sets without raising anything."""
        for name in self.NAMES[:2]:
            with self.subTest(macro=name):
                self.assertNotIn("*", self.conf[name]["definition"])

    # -- DV-1: reversibility, not success ------------------------------------ #

    def test_the_rollback_selects_on_reversibility_and_not_on_the_status(self):
        """**DV-1.** Measured: a POST answering `403 Not removable` had written all the
        same, so the premise of the previous contract - an object whose POST failed was
        not modified - is false on this path. Selecting on `status="updated"` here would
        leave a mutated stanza out of the restore set."""
        self.assertIn('reversible="true"', self.rollback)
        self.assertNotIn('status="updated"', self.rollback)

    def test_the_rollback_retains_every_target_a_post_was_sent_for(self):
        """`write_asserted` is the field that says it, and its domain is closed: `no`
        when no POST left, `yes` on a 2xx, `unknown` on anything else after a POST."""
        self.assertIn('write_asserted!="no"', self.rollback)
        self.assertIn("eventstats max(_posted) AS posted BY endpoint", self.rollback)

    def test_the_rollback_reads_no_inherited_key(self):
        """**The mechanism that closes the hole.** The effective value a creation masked
        is kept under `inherited_*`, which this macro must not read: re-injecting it would
        CREATE THE STANZA A SECOND TIME under cover of a restore."""
        for key in ("inherited_perms_read", "inherited_perms_write", "inherited_sharing"):
            with self.subTest(key=key):
                self.assertNotIn(key, self.rollback)

    def test_the_rollback_emits_the_input_contract_of_the_write_command(self):
        """The restore depends on no field the journal can leave empty, and on no
        coverage of the family table: `handler` is filled in at resolution time, and it is
        the PRIMARY resolution route of section 8.3."""
        for field in ('"eai:acl.app"', "acl_stanza_kind", "acl_handler", "acl_stanza",
                      '"eai:acl.perms.read"', '"eai:acl.perms.write"',
                      '"eai:acl.sharing"'):
            with self.subTest(field=field):
                self.assertIn(field, self.rollback)

    def test_the_emitted_names_are_the_defaults_of_the_write_command(self):
        """Read from the code, never copied: a renamed default would otherwise leave the
        macro emitting a column the command no longer reads, and a restore would
        `preserve` every attribute while reporting a success."""
        from acltools.appacl_model import DEFAULT_APP_FIELD_NAMES as names

        emitted = re.findall(r'AS\s+"?([A-Za-z:._]+)"?', self.rollback)
        for field in (names.app, names.stanza_kind, names.handler, names.stanza,
                      names.new_perms_read, names.new_perms_write, names.new_sharing):
            with self.subTest(field=field):
                self.assertIn(field, emitted)

    def test_the_rollback_consumes_only_journaled_keys(self):
        from .test_appacl_journal import APP_INTENT_KEYS

        for field in ("before_perms_read", "before_perms_write", "before_sharing",
                      "app", "stanza_kind", "handler", "stanza", "endpoint",
                      "reversible"):
            with self.subTest(field=field):
                self.assertIn(field, self.rollback)
                self.assertIn(field, APP_INTENT_KEYS)

    def test_the_rollback_materializes_the_two_permission_columns(self):
        """Defense in depth (D-32): an ABSENT column preserves the attribute where an
        EMPTY one clears it, so a permission lost along the chain would restore nothing
        while reporting a success."""
        for field in ("eai:acl.perms.read", "eai:acl.perms.write"):
            with self.subTest(field=field):
                self.assertIn("coalesce('%s'" % field, self.rollback)

    def test_it_materializes_neither_the_sharing_nor_the_stanza_name(self):
        """Two opposite reasons for the same abstention. An empty `sharing` does not
        exist platform-side and would turn a correct preservation into a rejection; an
        empty `acl_stanza` is the LEGITIMATE name of the `[]` stanza, and the kind of
        target is read from `acl_stanza_kind`, never from that field alone."""
        for field in ("eai:acl.sharing", "acl_stanza"):
            with self.subTest(field=field):
                self.assertNotIn("coalesce('%s'" % field, self.rollback)

    def test_the_rollback_is_invocable_in_generating_position(self):
        self.assertTrue(self.rollback.startswith("search `app_acl_journal_source`"))

    def test_only_the_applied_form_writes(self):
        self.assertNotIn("| editappacl ", self.rollback)
        self.assertIn("| editappacl ", self.applied)

    def test_the_applied_form_delegates_instead_of_copying(self):
        self.assertIn("`app_acl_rollback($sid$)`", self.applied)

    def test_the_applied_form_refuses_to_create(self):
        """Section 11.4: `allow_create=f` is explicit and NOT negotiable - a restore never
        creates anything. A target of the set found absent at replay time comes out
        `rejected` rather than recreated."""
        self.assertIn("allow_create=f", self.applied)

    def test_the_applied_form_raises_both_ceilings_by_value(self):
        """The VALUES are frozen, not merely the presence of the keys: `max_stanzas=5`
        put back by hand would stop a restore at the sixth stanza - on the safety net of
        an irreversible operation - and report a success. That is exactly the mutation
        class R-4 named on the previous command."""
        self.assertIn("max_stanzas=100000", self.applied)
        self.assertIn("max_impacted_objects=100000000", self.applied)
        self.assertIn("dryrun=f", self.applied)

    # -- section 9.4, dispositif 4 ------------------------------------------- #

    def test_the_irreversible_macro_lists_what_the_rollback_leaves_behind(self):
        """Without it, "what my rollback will not undo" is visible NOWHERE. That is the
        dispositif the previous project lacked."""
        self.assertIn('reversible="false"', self.irreversible)
        self.assertIn('reversible="unknown"', self.irreversible)
        self.assertNotIn('reversible="true"', self.irreversible)

    def test_the_irreversible_macro_shows_the_created_and_the_masked_value(self):
        for key in ("after_perms_read", "after_perms_write", "after_sharing",
                    "inherited_perms_read", "inherited_perms_write",
                    "inherited_sharing"):
            with self.subTest(key=key):
                self.assertIn(key, self.irreversible)

    def test_the_irreversible_macro_lists_only_targets_that_were_written(self):
        """A refused creation was never written: listing it would drown the acts that
        cannot be undone among the ones that never happened."""
        self.assertIn('write_asserted!="no"', self.irreversible)
        self.assertIn("posted=1", self.irreversible)

    def test_the_irreversible_macro_writes_nothing(self):
        self.assertNotIn("| editappacl", self.irreversible)

    def test_the_two_macro_families_never_read_each_others_journal(self):
        """DV-3 on the reading side: one journal counts objects, the other counts stanzas
        whose blast radius is several objects."""
        for name in self.NAMES[2:]:
            with self.subTest(macro=name):
                self.assertNotIn("`acl_journal_source`", self.conf[name]["definition"])
        for name in ("editacl_rollback(1)", "editacl_rollback_apply(1)"):
            with self.subTest(macro=name):
                self.assertNotIn(
                    "`app_acl_journal_source`", self.conf[name]["definition"]
                )


class AppLevelSavedSearchesTest(unittest.TestCase):
    """The two shipped searches of deliverable 8 of section 14.1.

    They cover the minimal need QO-6 left in place after ruling a dashboard extension out
    of scope: what an execution did that cannot be undone, and what the estate still lets
    us govern.
    """

    IRREVERSIBLE = "App ACL - irreversible writes"
    GOVERNABILITY = "App ACL - governability of the estate"

    def setUp(self):
        self.conf = read_splunk_conf("default", "savedsearches.conf")

    def test_both_are_shipped(self):
        for name in (self.IRREVERSIBLE, self.GOVERNABILITY):
            with self.subTest(search=name):
                self.assertIn(name, self.conf)
                self.assertTrue(self.conf[name]["description"].strip())

    def test_the_irreversible_search_names_its_source_by_the_macro(self):
        search = self.conf[self.IRREVERSIBLE]["search"]
        self.assertIn("`app_acl_journal_source`", search)
        self.assertNotRegex(search, r"(?<![\w])index\s*=")

    def test_the_irreversible_search_selects_the_creations(self):
        search = self.conf[self.IRREVERSIBLE]["search"]
        self.assertIn("reversible=false", search)
        self.assertIn("impacted_estimate", search)

    def test_the_irreversible_search_carries_the_macro_call(self):
        """The operator has nothing to type at the moment they need the detail."""
        self.assertIn("app_acl_irreversible(", self.conf[self.IRREVERSIBLE]["search"])

    def test_the_governability_search_is_built_on_the_command(self):
        """On the COMMAND and not on a macro: the provenance it ventilates has no REST
        source at all, which is the whole reason `appaclinventory` is a command."""
        search = self.conf[self.GOVERNABILITY]["search"]
        self.assertIn("| appaclinventory", search)
        self.assertNotIn("`appaclinventory`", search)

    def test_the_governability_search_groups_on_the_derived_verdict(self):
        search = self.conf[self.GOVERNABILITY]["search"]
        self.assertRegex(search, r"BY[^|]*\bacl_governable\b")
        self.assertIn("acl_member", search)

    def test_the_governability_search_keeps_the_columns_the_verdict_derives_from(self):
        """The verdict recomputes from the counters, so the counters travel with it: a
        table showing `partial` without saying how much would be an opinion."""
        search = self.conf[self.GOVERNABILITY]["search"]
        self.assertIn("acl_frozen_stanzas", search)
        self.assertIn("acl_family_headers", search)


class AppLevelRevalidationTest(unittest.TestCase):
    """Section 5.2, requirement 4: a procedure, executable, declared a prerequisite.

    O-4 of the phase 0 measurement is blunt: no measurement made on 9.4.6 transposes by
    deduction, the handler-to-stanza table least of all.
    """

    def setUp(self):
        path = os.path.join(REPO_ROOT, "tools", "revalidate_app_acl_mapping.py")
        with open(path, encoding="utf-8") as handle:
            self.source = handle.read()

    def test_the_procedure_is_shipped(self):
        self.assertTrue(self.source)

    def test_it_reuses_the_core_rather_than_rewriting_it(self):
        for symbol in ("from acltools.appacl_family import load_family_table",
                       "from acltools.appacl_target import build_family_default_path"):
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, self.source)

    def test_it_produces_the_three_required_lists(self):
        for marker in ("== A. ", "== B. ", "== C. "):
            self.assertIn(marker, self.source)

    def test_it_reads_the_files_through_the_bounded_reader(self):
        """List C can only come from the metadata files, and it comes from them through
        the SAME read-only reader the command uses - so a family this procedure reports is
        a family the command would report too."""
        self.assertIn("from acltools.appacl_provenance import", self.source)
        self.assertIn("ProvenanceReader", self.source)

    def test_it_never_writes_to_the_platform_it_validates(self):
        """The shipped table was built by POST, because writing is the only thing that
        establishes which stanza a handler writes. This procedure runs on somebody's
        production: a validation that mutated what it validates would be worth less than
        no validation at all."""
        self.assertNotIn('"POST"', self.source)
        self.assertNotIn("method=\"POST\"", self.source)
        self.assertNotIn("def post", self.source)

    def test_the_password_is_never_a_command_line_argument(self):
        self.assertIn("sys.stdin.readline()", self.source)
        self.assertNotIn("--password", self.source)

    def test_it_names_the_override_file_that_treats_list_c(self):
        self.assertIn("app_acl_family_map_override.csv", self.source)


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
