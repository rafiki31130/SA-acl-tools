"""State machine of `editappacl` (v4.1 sections 8.7, 9, 10, 11.2).

It carries the normative order of the controls, the ordering of the journal lines with
respect to the POST, the two volume ceilings and the deduplication of targets. It is the
module that holds the checkable invariants of section 11.2.

Two properties are structural rather than incidental, and both come from a measurement:

- **the file is read before any write decision**, because the modification / creation
  classification has no other source (Q0-4);
- **the `intent` line is written, flushed and synchronized to disk before the call**, and
  its failure cancels the POST - a property reconducted from v3.14 section 8.4 and made
  indispensable here by section 4.3, where a non-2xx answer does not prove that nothing
  was written.

No unexpected exception crosses this module: any unforeseen `Exception` becomes
`EventRejected("error", "internal:...")`, failing which an uncaught traceback would
interrupt the search and violate section 13.1.
"""

import json
from dataclasses import replace
from datetime import datetime

from .appacl_impact import NO_INHERITING_OBJECT
from .appacl_merge import is_noop, merge, parse_app_acl_state, validate_roles
from .appacl_model import (
    REVERSIBLE_FALSE,
    REVERSIBLE_TRUE,
    REVERSIBLE_UNKNOWN,
    AppEventResult,
)
from .appacl_target import check_designation, designation_key, resolve_target
from .errors import EventRejected
from .journal import (
    build_app_intent_record,
    build_app_outcome_record,
    build_app_summary_record,
)

MAX_ERROR_LEN = 512

#: Class of HTTP codes of a persistence refusal on the splunkd handler side (v3.14
#: section 5.6, D-16). The **whole** `5xx` class: the divergence comes from the handler
#: having mutated its in-memory state before failing to persist it, which a `502`, a
#: `503` or a `507` produce just as well as a `500`.
PERSISTENCE_FAILURE_MIN = 500
PERSISTENCE_FAILURE_MAX = 600


def is_persistence_failure(status):
    return PERSISTENCE_FAILURE_MIN <= int(status) < PERSISTENCE_FAILURE_MAX


#: Warning carried when the answer is not 2xx. **This is section 4.3 in one token**: a
#: `403` was measured **with an effective write**, so no artifact of this app treats a
#: non-2xx return code as proof of non-mutation. The operator reads that the state of the
#: target is undetermined, instead of deducing it wrongly.
WRITE_MAY_HAVE_OCCURRED = "write_may_have_occurred"

#: Warning carried on a `5xx`: the **runtime** view of splunkd may have been mutated
#: while the disk was not, and that view is the one users and access controls see.
RUNTIME_DIVERGENCE_WARNING = "runtime_divergence_possible"

RUNTIME_DIVERGENCE_MESSAGE = (
    "at least one stanza was refused with HTTP 5xx (persistence): the runtime view of "
    "splunkd may have been mutated while the disk was not, and that view is the one "
    "users, searches and access controls see until the next configuration reload. "
    "Putting that right goes through a configuration reload or a restart of the member, "
    "not through app_acl_rollback."
)


def ceiling_message(max_stanzas, skipped):
    """**Single** warning that the stanza ceiling was reached (section 10.2).

    It carries the two things the operator needs - that the ceiling bit, and **how many**
    targets were set aside - hence its emission at the end of the run, the only moment at
    which that number is known to a command receiving its input in successive chunks.

    It stays a warning: the job is not marked failed, the output of the search is
    complete, and each skipped target carries its own `acl_status`.
    """
    return (
        "max_stanzas=%d ceiling reached: %d target(s) skipped with no POST, with "
        "acl_status=skipped_ceiling. The stanzas already written are not rolled back and "
        "the output of this search is complete. To process the rest, run again with a "
        "higher max_stanzas." % (int(max_stanzas), int(skipped))
    )


def impact_ceiling_message(max_impacted_objects, skipped):
    """**Single** warning that the blast-radius ceiling was reached (section 10.2)."""
    return (
        "max_impacted_objects=%d ceiling reached: %d target(s) skipped with no POST, "
        "with acl_status=skipped_impact_ceiling. This ceiling counts the ESTIMATED "
        "objects the written stanzas move, not the number of input rows. To process the "
        "rest, state the volume you are moving with a higher max_impacted_objects."
        % (int(max_impacted_objects), int(skipped))
    )


def simulation_summary_message(planned, impacted, creations):
    """**Single** end-of-simulation message, carrying the three numbers of section 10.4.

    This is the answer to the insufficiency stated in section 10.1: the simulation of
    `editacl` shows input rows, this one shows in addition the **aggregate blast radius**
    and the **volume of irreversible acts**. The ceilings never fire in simulation, so
    the three numbers bear on the **whole** batch and never on the fraction a ceiling
    would let through.
    """
    return (
        "simulation: %d stanza(s) would be written, moving an estimated %d object(s), "
        "of which %d irreversible creation(s). The two ceilings do not fire in "
        "simulation, so these three numbers cover the whole batch."
        % (int(planned), int(impacted), int(creations))
    )


def creation_message(created):
    """**Single** end-of-run message when at least one creation happened (section 9.4).

    It is the only one of the four visibility dispositifs that reaches the operator **at
    the moment they are looking**; the three others suppose they come back and query the
    journal.
    """
    return (
        "%d generic stanza(s) were CREATED, and a creation cannot be undone: no measured "
        "REST path removes a stanza. They are EXCLUDED from app_acl_rollback(<sid>), "
        "which only restores values. To list them, use app_acl_irreversible(<sid>)."
        % int(created)
    )


def default_clock():
    """ISO 8601 timestamp with an explicit zone and **mandatory milliseconds**.

    Aligned on the `TIME_FORMAT` of `props.conf`: the milliseconds separate two mutations
    close in time, which the `earliest(...)` of the restore macro depends on.
    """
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _truncate(message):
    text = "" if message is None else str(message)
    return text[:MAX_ERROR_LEN]


class _Work(object):
    """Mutable state of the processing of one event, frozen into an `AppEventResult`."""

    __slots__ = (
        "app", "stanza_kind", "stanza", "handler", "endpoint", "reversible",
        "impacted_estimate", "http_code", "status", "error", "warnings", "before",
        "after", "inherited", "journaled", "post_attempted",
    )

    def __init__(self, event):
        self.app = str(getattr(event, "app", "") or "").strip()
        self.stanza_kind = str(getattr(event, "stanza_kind", "") or "").strip()
        self.stanza = str(getattr(event, "stanza", "") or "").strip()
        self.handler = ""
        self.endpoint = ""
        self.reversible = ""
        self.impacted_estimate = None
        self.http_code = 0
        self.status = "error"
        self.error = None
        self.warnings = []
        self.before = None
        self.after = None
        self.inherited = None
        self.journaled = False
        self.post_attempted = False

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def adopt(self, target):
        self.app = target.app
        self.stanza_kind = target.stanza_kind
        self.stanza = target.stanza
        self.handler = target.handler
        self.endpoint = target.endpoint

    def result(self):
        return AppEventResult(
            status=self.status,
            app=self.app,
            stanza_kind=self.stanza_kind,
            stanza=self.stanza,
            handler=self.handler,
            endpoint=self.endpoint,
            reversible=self.reversible,
            impacted_estimate=self.impacted_estimate,
            http_code=int(self.http_code or 0),
            error=self.error,
            warnings=tuple(self.warnings),
            before=self.before,
            after=self.after,
            inherited=self.inherited,
            journaled=self.journaled,
            post_attempted=self.post_attempted,
        )


class AppEventProcessor(object):
    """Processes one event and produces exactly one `AppEventResult`.

    The two counters are only incremented by a **POST actually sent**: statuses with no
    call do not count towards them, and neither ceiling ever fires in simulation, which
    sends none (section 10.2). That is what makes a ceiling as low as five tenable: the
    friction is on the write, never on the review.
    """

    def __init__(
        self,
        params,
        ctx,
        rest,
        journal=None,
        table=None,
        provenance=None,
        impact=None,
        roles_catalog=frozenset(),
        app_disabled_fn=None,
        self_app=None,
        clock=None,
    ):
        self._params = params
        self._ctx = ctx
        self._rest = rest
        self._journal = journal
        self._table = table
        self._provenance = provenance
        self._impact = impact
        self._roles = frozenset(roles_catalog or ())
        self._app_disabled_fn = app_disabled_fn
        self._self_app = str(self_app or "")
        self._clock = clock or default_clock

        #: Stanzas **written**, one per POST sent (section 10.2).
        self.counter = 0
        #: Sum of the estimated blast radius of the stanzas written.
        self.impacted_total = 0
        self.skipped_ceiling = 0
        self.skipped_impact_ceiling = 0
        #: What a real run **would** write, tallied in simulation only: the three
        #: numbers of the end-of-simulation message (section 10.4).
        self.planned_writes = 0
        self.planned_impact = 0
        self.planned_creations = 0
        #: Tally by `acl_status`, feeding the `summary` line. Fed from `_emit`, the exit
        #: point every event goes through without exception - the same guarantee that
        #: holds the "one outcome line per output event" invariant.
        self.counts = {}
        #: Designations and endpoints already seen in this run (**DV-2**).
        self._seen_designations = set()
        self._seen_endpoints = set()

    # -- single entry point ------------------------------------------------- #

    def process(self, event):
        work = _Work(event)
        try:
            self._run(event, work)
        except EventRejected as exc:
            work.status = exc.status
            work.error = exc.error
        except Exception as exc:                                     # pragma: no cover
            work.status = "error"
            work.error = _truncate("internal:%s: %s" % (type(exc).__name__, exc))
        return self._emit(work.result())

    # -- state machine ------------------------------------------------------ #

    def _run(self, event, work):
        check_designation(event)                                     # ranks 0 to 2

        key = designation_key(event)                                 # rank 3
        if key in self._seen_designations:
            raise EventRejected("rejected", "duplicate_target")
        self._seen_designations.add(key)

        target = resolve_target(event, self._table)                  # rank 4
        work.adopt(target)

        # Second deduplication, on the **resolved** endpoint. It is not a duplicate of
        # rank 3 and neither subsumes the other: two rows designating the same family,
        # one through `handler` and the other through `stanza`, carry different
        # designations and the same endpoint - and **DV-2** refuses the second one,
        # because a generic stanza has no natural multiplicity and the last writer would
        # win in silence over an operation section 9 establishes may be irreversible.
        if target.endpoint in self._seen_endpoints:
            raise EventRejected("rejected", "duplicate_target")
        self._seen_endpoints.add(target.endpoint)

        if self._self_app and target.app == self._self_app:
            # Section 13.4 point 5: allowed and warned, never refused. The state stays
            # recoverable outside the tool, and refusing would remove a legitimate
            # capability.
            work.warn("self_app_target")
        if self._app_disabled_fn is not None and self._app_disabled_fn(target.app):
            work.warn("app_disabled")

        before = self._read_state(work, target)                      # rank 5, 5bis, 5ter

        merged = merge(before, event, target.stanza_kind)            # ranks 6 and 7
        if merged.rejection is not None:
            raise merged.rejection
        work.before = merged.before
        work.after = merged.after
        for warning in merged.warnings:
            work.warn(warning)

        # **The file is read here, after the GET and before any write decision**: the
        # modification / creation classification has no other source (Q0-4). It is
        # re-read for every target, per the caution clause of section 13.4 point 7.
        provenance = (
            self._provenance.provenance_of_app(target.app)
            if self._provenance is not None
            else None
        )
        available = provenance is not None and provenance.available
        present = bool(available and provenance.present_local(target.stanza))

        if not available:                                            # rank 8
            work.reversible = REVERSIBLE_UNKNOWN
            if not self._params.allow_create:
                work.warn("provenance_unavailable")
                raise EventRejected("rejected", "provenance_unavailable")
            work.warn("provenance_unavailable")
        else:
            work.reversible = REVERSIBLE_TRUE if present else REVERSIBLE_FALSE

        # The state read is a **restorable prior state** only when the stanza carries it
        # in `local.meta`. Otherwise it is an inherited value: useful - it says what the
        # objects saw - but re-injecting it would create the stanza a second time under
        # cover of a restore (section 11.2).
        if work.reversible != REVERSIBLE_TRUE:
            work.inherited = merged.before

        if is_noop(merged.before, merged.after):                     # ranks 9 and 9bis
            # Rank 9 precedes rank 10: a target already compliant never triggers the
            # irreversibility refusal, since no write would take place. And it precedes
            # rank 14: `noop` and `noop_inherited` win over `dryrun`, so the `dryrun`
            # status designates only the targets a real run would have written.
            if present:
                work.status = "noop"
            else:
                # The effective value is already the right one, but it is **inherited**.
                # Materializing the stanza would change no right today and would remove
                # the family from the reach of `[]` for good, with no way back (Q0-3):
                # that is precisely the freeze this increment exists to avoid (QO-4).
                work.status = "noop_inherited"
                work.warn("not_materialized")
            return

        if not present:                                              # rank 10
            if not self._params.allow_create:
                # Rank 10 precedes rank 12: the irreversibility refusal is a property of
                # the target, the ceiling a property of the batch, and an operator must
                # see the first even when the second would bite.
                work.warn("irreversible_creation")
                raise EventRejected("rejected", "irreversible_creation")
            work.warn("irreversible_creation")

        if self._params.validate_roles:                              # rank 11
            unknown_added, stale_preserved = validate_roles(
                merged.before, merged.after, self._roles
            )
            if stale_preserved:
                work.warn("stale_role_preserved:%s" % ",".join(stale_preserved))
            if unknown_added:
                raise EventRejected(
                    "invalid_role", "invalid_role:%s" % ",".join(unknown_added)
                )

        # The estimate is computed for **every target a real run would write**,
        # simulation included (section 10.3). Making it optional would restore exactly
        # the blindness this increment exists to lift.
        estimate = self._estimate(target)
        work.impacted_estimate = estimate
        if estimate == 0:
            # Zero is not a `noop`: the write changes the default applicable to objects
            # created later (measured, Q0-2).
            work.warn(NO_INHERITING_OBJECT)

        # **Neither ceiling ever fires in simulation** (section 10.2), and that is not a
        # reordering of the control table: both counters are defined over the stanzas
        # **written**, a simulation writes none, so both conditions are false by
        # construction. Rank 12 would be false anyway - the counter stays at zero - but
        # rank 13 compares against the estimate of the current target, which a large
        # target would exceed on its own. Leaving it armed would make a `dryrun` stop
        # short of the batch it exists to show whole, and the three numbers of the
        # end-of-simulation message would then bear on a fraction.
        if not self._params.dryrun:
            if self.counter >= self._params.max_stanzas:             # rank 12
                self.skipped_ceiling += 1
                raise EventRejected(
                    "skipped_ceiling",
                    "max_stanzas_reached:%d" % self._params.max_stanzas,
                )

            if self.impacted_total + estimate > self._params.max_impacted_objects:
                self.skipped_impact_ceiling += 1                     # rank 13
                raise EventRejected(
                    "skipped_impact_ceiling",
                    "max_impacted_objects_reached:%d"
                    % self._params.max_impacted_objects,
                )

        if self._params.dryrun:                                      # rank 14
            work.status = "dryrun"
            self.planned_writes += 1
            self.planned_impact += estimate
            if work.reversible != REVERSIBLE_TRUE:
                self.planned_creations += 1
            return

        if self._journal is not None:
            record = build_app_intent_record(self._ctx, work.result(), self._clock())
            if not self._journal.write_intent(record):
                # A failure of the write + flush + fsync sequence cancels the POST for
                # this target (section 11.2). Without the write-ahead line, a write that
                # answered non-2xx while writing anyway would leave no trace at all.
                raise EventRejected("error", "journal_intent_failed")
            work.journaled = True

        work.post_attempted = True
        response = self._rest.post_app_acl(work.endpoint, merged.payload)
        self.counter += 1
        self.impacted_total += estimate
        work.http_code = response.status

        if 200 <= response.status < 300:
            # `created` covers `reversible = false` (measured creation) **and**
            # `reversible = unknown` (provenance unreadable, write authorized by
            # `allow_create`). Section 9.3 names the status for the first case and leaves
            # the second one unnamed; the two possible readings are not symmetrical.
            # `app_acl_rollback` selects on `reversible = "true"` alone, so an unknown
            # target is not restored either way: reporting it `updated` would promise a
            # reversibility the restore does not offer, while reporting it `created`
            # states exactly what `app_acl_irreversible` will list. The conservative
            # reading is therefore the coherent one, and `acl_reversible` keeps the two
            # cases distinguishable for anybody who needs the difference.
            #
            # Written as two literal assignments rather than as a conditional
            # expression, deliberately: the status extractor of the test suite classifies
            # a ternary as **opaque** and fails on it, which is the behavior that keeps a
            # status from entering the code unseen. Writing the canonical form is the
            # cheaper of the two ways out it leaves.
            if work.reversible == REVERSIBLE_TRUE:
                work.status = "updated"
            else:
                work.status = "created"
        else:
            work.status = "error"
            work.error = _truncate(
                "post_failed:%d:%s" % (response.status, response.error or response.text())
            )
            # **Section 4.3, applied literally.** A non-2xx does not prove that nothing
            # was written: a `403` was measured with an effective write. The status of
            # the target is therefore undetermined, and it is said rather than deduced.
            work.warn(WRITE_MAY_HAVE_OCCURRED)
            if is_persistence_failure(response.status):
                work.warn(RUNTIME_DIVERGENCE_WARNING)

    # -- steps -------------------------------------------------------------- #

    def _read_state(self, work, target):
        """Read the effective state (section 8.7, ranks 5, 5bis, 5ter).

        **No state is cached from one row to the next**, and that is the caution clause
        of section 13.4 point 7: the two read paths have **independent** handler caches -
        measured, one up to date while the other is stale at the same instant - and their
        consistency after a REST write has not been measured (O-3). Only the object
        enumeration, which depends on neither cache, is memoized.
        """
        response = self._rest.get_app_acl(target.endpoint)
        work.http_code = response.status
        if response.status == 404:
            raise EventRejected("not_found", "get_404")
        if response.status == 403:
            raise EventRejected("forbidden", "get_403")
        if not (200 <= response.status < 300):
            raise EventRejected(
                "error",
                _truncate(
                    "get_failed:%d:%s"
                    % (response.status, response.error or response.text())
                ),
            )
        try:
            document = json.loads(response.body.decode("utf-8", "replace"))
            acl_block = document["entry"][0]["acl"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise EventRejected("error", _truncate("get_parse_failed:%s" % (exc,)))
        return parse_app_acl_state(acl_block)

    def _estimate(self, target):
        if self._impact is None:
            return 0
        try:
            return int(self._impact.estimate(target))
        except Exception:                                            # pragma: no cover
            # The estimate is an aid to decision: losing it must not cost the write. A
            # zero estimate is visible, since it carries `no_inheriting_object`.
            return 0

    def build_summary(self):
        """End-of-run record (section 11.2), from the run's tally.

        Building it is pure and separate from writing it: the caller decides **whether**
        the run reached its normal end, and this method knows nothing about that.
        """
        return build_app_summary_record(
            self._ctx, self.counts, self.impacted_total, self._clock()
        )

    def _emit(self, result):
        """Write the `outcome` line, tally the status and return the final result.

        `write_outcome` is called on **every** exit, without exception: that is what
        holds the invariant "one `outcome` line per output event". The tally is fed here
        for the same reason - it is the one place every event goes through.
        """
        self.counts[result.status] = self.counts.get(result.status, 0) + 1
        if self._journal is not None:
            record = build_app_outcome_record(self._ctx, result, self._clock())
            if not self._journal.write_outcome(record):
                # The POST has already happened: nothing is rolled back, but the breach
                # of the invariant must be reported.
                result = replace(
                    result, warnings=result.warnings + ("journal_outcome_failed",)
                )
        return result
