"""State machine for processing one event (sections 5, 8.4, 4.3, 10.8).

It carries the ordering of the journal lines with respect to the POST, the
`max_objects` counter and the deduplication by URI. It is the module that holds the
three checkable invariants of section 8.2.

No unexpected exception crosses it: any unforeseen `Exception` is converted into
`EventRejected("error", "internal:...")`, failing which an uncaught traceback would
interrupt the search and violate section 9.
"""

import json
from dataclasses import replace
from datetime import datetime

from .derived import CarrierProbe
from .endpoint import (
    build_object_path,
    is_fixed_context,
    namespace_owner_from_id,
    resolve_handler_path,
)
from .errors import EventRejected
from .journal import (
    build_intent_record,
    build_outcome_record,
    build_summary_record,
)
from .merge import is_noop, merge, validate_roles
from .model import EventResult
from .normalize import parse_acl_state

MAX_ERROR_LEN = 512

#: Sharing scope of the objects out of scope (section 3.5, D-26). An object in
#: `sharing=user` is only visible to its owner and to the administrators: whatever
#: permissions it carried grant nothing to anybody, they are **inert**.
PRIVATE_SHARING = "user"

#: Reason for skipping a private object (section 3.5). **Identical through both
#: detection routes**: it is the same fact - the object is out of scope - and an
#: operator filtering on this reason must not have to know two of them.
PRIVATE_ERROR = "private_object_out_of_scope"

#: Warning carried by `acl_warning` when the object was skipped through the **second**
#: route of section 3.5 (D-34): a named namespace carried by `id`, with the sharing
#: scope column absent from the result set. It changes neither the status nor the
#: reason; it tells the operator that their pipeline does not emit the current sharing
#: scope and that the skip therefore rests on `id` alone. The remedy is the same as
#: everywhere else: build the pipeline on the inventory macro, which always emits both.
PRIVATE_BY_ID_WARNING = "private_detected_by_id_namespace"

#: Warning carried by `acl_warning` when **neither** of the two routes of section 3.5
#: is fed: the current sharing scope is unavailable and `id` carries no usable
#: namespace (D-38, section 3.5).
#:
#: The command then only has a name and an application. It resolves through the fixed
#: context and therefore reaches the **shared** object if one of that name exists, while
#: the input row may have designated a private object of the same name. This is not a
#: defect of the addressing: with no sharing scope designated, no information allows the
#: two to be told apart. The behavior is therefore not changed - it is **made visible**.
#:
#: **It only fires where the discrimination is genuinely impossible.** As soon as the
#: current sharing scope is usable, or `id` carries a namespace - named (the object is
#: skipped) as well as fixed (the object is shared, and `id` says so) - the scope is
#: established and the warning is not emitted. A warning that fired in the nominal case
#: would be noise, and noise gets filtered out mentally: it would be worth nothing on
#: the day it matters.
SCOPE_UNDETERMINED_WARNING = "scope_undetermined"

#: Application context out of scope (sections 1.3, 4.2). Rejection is **per event**:
#: section 9 enumerates the fatal errors exhaustively and does not list this one.
FORBIDDEN_APP = "system"

#: Class of HTTP codes of a persistence refusal on the splunkd handler side. Measured
#: in the lab: the POST is refused, the **runtime** view of splunkd is nevertheless
#: mutated, the disk stays intact.
#:
#: **The whole `5xx` class, not `500` alone** (D-16). Nothing in the observed mechanism
#: attaches the divergence to code `500` in particular: it comes from the handler having
#: mutated its in-memory state before failing to persist it, which a `502`, a `503` or a
#: `507` produce just as well. Restricting the warning to `500` would let through
#: without a signal exactly the case it must cover.
PERSISTENCE_FAILURE_MIN = 500
PERSISTENCE_FAILURE_MAX = 600


def is_persistence_failure(status):
    """True if `status` belongs to the `5xx` class (D-16)."""
    return PERSISTENCE_FAILURE_MIN <= int(status) < PERSISTENCE_FAILURE_MAX

#: Warning carried by `acl_warning` when persistence is refused. The divergence is
#: produced by the platform and the command cannot prevent it; it must make it
#: **visible**.
RUNTIME_DIVERGENCE_WARNING = "runtime_divergence_possible"

#: Text addressed to the operator at the search level, emitted once per run.
#: `acl_warning` is a set of concatenated tokens: the sentence cannot fit in it.
RUNTIME_DIVERGENCE_MESSAGE = (
    "at least one object was refused with HTTP 5xx (persistence): the runtime view of "
    "splunkd may have been mutated while the disk was not, and that view is the one "
    "users, searches and access controls see until the next configuration reload. "
    "These objects are NOT covered by editacl_rollback, which only keeps the writes "
    "that succeeded: putting them right goes through a configuration reload or a "
    "restart of the member, not through the rollback."
)


def ceiling_message(max_objects, skipped):
    """**Single** warning that the ceiling was reached (section 4.3, D-28).

    It carries the two pieces of information the operator needs: that the ceiling was
    reached, and **how many** objects were skipped - hence its emission at the end of
    the run, the only moment at which that number is known to a command that receives
    its input through successive chunks.

    It remains a warning: the job is not marked as failed, the output of the search is
    complete, and each skipped object carries its own
    `acl_status = "skipped_ceiling"`.
    """
    return (
        "max_objects=%d ceiling reached: %d object(s) skipped with no GET and no POST, "
        "with acl_status=skipped_ceiling. The objects already written are not rolled "
        "back and the output of this search is complete. To process the rest, run "
        "again with a higher max_objects." % (int(max_objects), int(skipped))
    )


def default_clock():
    """ISO 8601 timestamp with an explicit zone and **mandatory milliseconds**.

    Aligned on the `TIME_FORMAT` of `props.conf` (section 8.3): the milliseconds
    separate two mutations close in time, which the `earliest(...)` of the section 8.6
    macro depends on.
    """
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _truncate(message):
    text = "" if message is None else str(message)
    return text[:MAX_ERROR_LEN]


class _Work(object):
    """Mutable state of the processing of one event, frozen into an `EventResult`."""

    __slots__ = (
        "title", "app", "eai_type", "endpoint", "http_code", "status",
        "error", "warnings", "before", "after", "journaled", "post_attempted",
        "counted", "platform_name",
    )

    def __init__(self, event):
        self.title = str(event.title or "")
        self.app = str(event.app or "")
        self.eai_type = str(event.eai_type or "").strip()
        self.endpoint = ""
        self.http_code = 0
        self.status = "error"
        self.error = None
        self.warnings = []
        self.before = None
        self.after = None
        self.journaled = False
        self.post_attempted = False
        self.counted = False
        #: Identity returned by splunkd in the GET response (section 5.3), never the
        #: `title` of the event: section 5.3 states that the GET is authoritative, and
        #: an upstream `eval` may have forged the `title`.
        self.platform_name = None

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def result(self):
        return EventResult(
            status=self.status,
            title=self.title,
            app=self.app,
            eai_type=self.eai_type,
            endpoint=self.endpoint,
            http_code=int(self.http_code or 0),
            error=self.error,
            warnings=tuple(self.warnings),
            before=self.before,
            after=self.after,
            journaled=self.journaled,
            post_attempted=self.post_attempted,
            counted=self.counted,
        )


class _FailedPost(object):
    """Memory of a POST **sent and refused**, for the deduplication of section 10.8.

    A refused POST does not modify the object: its prior state remains the current
    state. Without this memory, a second occurrence of the same object reads the state
    again, recomputes the same merge, writes a **second `intent` line strictly
    identical** to the first and re-sends the same POST - which section 8.5
    (uniqueness of the `sid` + `endpoint` + `phase` triple) and D-6 exclude, and which
    section 10.8 explicitly saves.
    """

    __slots__ = ("before", "after", "status", "error", "http_code", "warnings")

    def __init__(self, before, after, status, error, http_code, warnings=()):
        self.before = before
        self.after = after
        self.status = status
        self.error = error
        self.http_code = http_code
        self.warnings = tuple(warnings)


class EventProcessor(object):
    """Processes one event and produces exactly one `EventResult`.

    The `counter` is incremented on each POST **sent**, whether it succeeds or fails.
    Statuses with no POST do not count towards it (section 4.3).
    """

    def __init__(
        self,
        params,
        ctx,
        rest,
        journal=None,
        mapping=None,
        roles_catalog=frozenset(),
        app_disabled_fn=None,
        clock=None,
    ):
        self._params = params
        self._ctx = ctx
        self._rest = rest
        self._journal = journal
        self._mapping = mapping
        self._roles = frozenset(roles_catalog or ())
        self._app_disabled_fn = app_disabled_fn
        self._clock = clock or default_clock
        #: Probe of rank 0 (section 3.4, D-18). It only sends a call on an object whose
        #: family and composite key already designate a carrier: on a batch with no
        #: `fvtags`, its cost is nil.
        self._carrier = CarrierProbe(rest)
        self.counter = 0
        #: Number of objects skipped for want of ceiling headroom (section 4.3, D-28).
        #: It feeds the single end-of-run warning; it is only zero if the ceiling never
        #: bit.
        self.skipped_ceiling = 0
        #: Tally of the output events by `acl_status`, feeding the `summary` line
        #: (section 8.2, D-46). It is fed from `_emit`, the exit point every event goes
        #: through without exception - the same guarantee that holds invariant 1 - so
        #: the sum of the counters is the number of output events of the run.
        #:
        #: It starts **empty** rather than pre-filled from the status enumeration: the
        #: emission of every declared status, at zero included, is the job of
        #: `build_summary_record`, which reads that enumeration at the moment it
        #: builds the line. Two derivations of the same list would be one too many.
        self.counts = {}
        #: endpoint -> state resulting from a **successful** POST.
        self._written = {}
        #: endpoint -> `_FailedPost` of a POST **sent and refused**.
        self._failed = {}
        #: endpoint -> identity returned by splunkd on the first successful GET (5.3).
        #:
        #: This memory exists only for the deduplication short circuit of section 10.8:
        #: rank 0 of section 5.4 reads `work.platform_name`, and the short circuit
        #: returns without sending a GET. Without it, deduplication and the
        #: identification of derived objects would be coupled by an **external**
        #: property - a derived object sends no POST, so it never enters `_written` /
        #: `_failed` - instead of by a local guarantee. The property is true, but it
        #: belongs to another mechanism and would break silently at the first evolution
        #: of the deduplication.
        self._platform_names = {}

    # -- single entry point ------------------------------------------------ #

    def process(self, event):
        work = _Work(event)
        try:
            self._run(event, work)
        except EventRejected as exc:
            work.status = exc.status
            work.error = exc.error
        except Exception as exc:                                     # pragma: no cover
            work.status = "error"
            work.error = _truncate(
                "internal:%s: %s" % (type(exc).__name__, exc)
            )
        return self._emit(work.result())

    # -- state machine ------------------------------------------------------ #

    def _run(self, event, work):
        self._check_required(event)

        # Ceiling (section 4.3, D-28) - **before the GET**, hence before any HTTP
        # exchange and before any `intent` journal line, which section 4.3 requires.
        # Once the write counter is at its ceiling, every following object comes out
        # here: with no GET, no POST, with its `outcome` line like any other status, and
        # the search carries on. The output stays complete - that is the whole point of
        # D-28.
        if self.counter >= self._params.max_objects:
            self.skipped_ceiling += 1
            raise EventRejected(
                "skipped_ceiling", "max_objects_reached:%d" % self._params.max_objects
            )

        # Endpoint resolution (section 5.2): a pure computation, no HTTP exchange. It
        # precedes the control table of section 5.4 - that was already its rank in v1 -
        # and gives a usable `acl_endpoint` to every status that reaches the GET.
        #
        # **It does not hold for `skipped_private`**, which erases it (see below). The
        # string computed here is that of the **shared object of the same name**: that
        # is an object *other* than the one the input row designates, and publishing it
        # in an output meant to be read back would mislead. Producing it for the private
        # object actually designated is not an option: it would require a named
        # addressing context, and `build_object_path` deliberately has **no** owner
        # parameter - that is the structural guarantee of D-25. The correct value is
        # therefore empty, as it already is for `skipped_ceiling`, the other abstention
        # with no HTTP exchange: an empty `acl_endpoint` and `acl_http_code = 0` say the
        # same thing, nothing was addressed.
        handler_path = resolve_handler_path(
            event.id_value, event.eai_type, self._mapping
        )
        work.endpoint = build_object_path(event.app, handler_path, event.title)

        # **The type of the object is settled here, once, and in a single vocabulary**
        # - that of the input contract, which is the vocabulary the operator writes in
        # `eai:type` and reads in the documentation.
        #
        # An event whose row carried a type keeps it. An event that carried none -
        # twenty-four of the twenty-seven native handlers emit no `eai:type`, measured,
        # so a batch read natively is entirely untyped - gets the type the resolved
        # handler path inverts to.
        #
        # The inversion is a **partial** function and the command does not extend it:
        # `data/ui/times` is the image of `times` **and** of `conf-times`, and the `id`
        # route resolves paths no key of the table names. `type_of_handler` answers
        # `None` on both, the type stays empty, and empty says "the type could not be
        # established" instead of naming one of two candidates.
        #
        # The handler path is **not** published as a type under any name: it belongs to
        # the other vocabulary, the one that addresses objects, and `endpoint` already
        # carries it - `/servicesNS/nobody/<app>/<handler path>/<encoded title>`.
        if not work.eai_type and self._mapping is not None:
            work.eai_type = self._mapping.type_of_handler(handler_path) or ""

        # Rank -1 (section 3.5, D-26, D-34) - private objects, skipped **with no GET
        # and no POST**.
        #
        # TWO detection routes, and the second one is not a convenience. Both rest on
        # data **emitted by the platform**: the current sharing scope the result set
        # carries, or the namespace the platform wrote into the object's `id`. Nothing
        # is reconstructed, nothing is supposed.
        #
        #  1. The current sharing scope is `user`. Main route, exact, unambiguous.
        #
        #  2. The current sharing scope is **unavailable** - column absent from the
        #     result set, or present and empty, which says no more - and `id` carries a
        #     **named** namespace. Splunkd emits `/servicesNS/nobody/` for a shared
        #     object and `/servicesNS/<owner>/` for a private one: a namespace other
        #     than the fixed context therefore designates a private object.
        #
        # Without route 2, the fallback claimed until now - "the GET through the fixed
        # context answers 404 and the object comes out as not_found" - **is false as
        # soon as a shared object of the same name exists**: fixed addressing then
        # reaches the shared one, and the command reads then would write an object
        # **other than the one designated as input**. That is the same class of defect
        # as the v1 one that section 5.2 declares closed, reintroduced by the fallback.
        #
        # Possible error and its meaning: a shared object whose `id` had been harvested
        # in a named context would come out as `skipped_private` wrongly. As at rank 0,
        # **the error is an abstention, never a faulty write**.
        #
        # If neither the sharing scope nor a usable `id` is available, the command
        # **cannot know** (D-38). It only has a name and an application, resolves
        # through the fixed context, and therefore reaches the shared object if one of
        # that name exists - the input row may have designated a private object of the
        # same name. The behavior stays that one, for want of any information allowing
        # discrimination; it is however **reported** by `SCOPE_UNDETERMINED_WARNING`.
        # The README recommends building the pipeline on the inventory macro, which
        # always emits both designations and makes this case unreachable.
        current_scope = (event.current_sharing or "").strip().lower()
        if current_scope == PRIVATE_SHARING:
            work.endpoint = ""
            raise EventRejected("skipped_private", PRIVATE_ERROR)
        if not current_scope:
            namespace_owner = namespace_owner_from_id(event.id_value)
            if namespace_owner is None:
                # Neither route is fed: the sharing scope is undetermined. The warning
                # is emitted here, and **only here** - the two following branches have
                # established the scope.
                work.warn(SCOPE_UNDETERMINED_WARNING)
            elif not is_fixed_context(namespace_owner):
                work.endpoint = ""
                work.warn(PRIVATE_BY_ID_WARNING)
                raise EventRejected("skipped_private", PRIVATE_ERROR)

        before = self._read_state(work)

        # Rank 0 (section 3.4, D-18) - it precedes ALL the other controls, including
        # `can_change_perms`. The derivation relation is discovered from the platform:
        # family from the resolved handler path, identity from the GET response,
        # existence of the carrier confirmed by a real GET. Nothing is reconstructed by
        # concatenation from a parent's name.
        #
        # The control sits here, after the GET and **before** the merge: the object is
        # not modified, so it has no target state, and its `outcome` line carries no
        # `before_*` / `after_*` - which is exactly the enumeration of section 8.2.
        carrier, carrier_warning = self._carrier.carrier_of(
            event.app, handler_path, work.platform_name
        )
        if carrier_warning:
            work.warn(carrier_warning)
        if carrier is not None:
            raise EventRejected("skipped_derived", "derived_object:%s" % carrier)

        if self._app_disabled_fn is not None and self._app_disabled_fn(event.app):
            work.warn("app_disabled")

        merged = merge(before, event)
        work.before = merged.before
        work.after = merged.after
        for warning in merged.warnings:
            work.warn(warning)

        if merged.rejection is not None:                              # ranks 1 to 4
            raise merged.rejection

        if self._params.validate_roles:                               # rank 5
            unknown_added, stale_preserved = validate_roles(
                merged.before, merged.after, self._roles
            )
            if stale_preserved:
                work.warn("stale_role_preserved:%s" % ",".join(stale_preserved))
            if unknown_added:
                raise EventRejected(
                    "invalid_role", "invalid_role:%s" % ",".join(unknown_added)
                )

        if is_noop(merged.before, merged.after):                      # rank 6
            # Rank 6 precedes rank 7: an object already compliant is a `noop` even in
            # simulation. That is what makes it possible to measure the convergence of a
            # batch without writing.
            work.status = "noop"
            return

        if self._params.dryrun:                                       # rank 7
            work.status = "dryrun"
            return

        failed = self._failed.get(work.endpoint)
        if failed is not None and failed.after == merged.after:
            # Section 10.8: the same object, already submitted with the same target
            # state within this run, is not resubmitted. The result of the first send is
            # reproduced as is - no `intent` line, no POST, no increment of the counter.
            # Hiding it would be worse: the duplicate would come out as `updated` on an
            # object the platform refused to write.
            work.status = failed.status
            work.error = failed.error
            work.http_code = failed.http_code
            for warning in failed.warnings:
                work.warn(warning)
            work.warn("duplicate_post_suppressed")
            return

        if self._journal is not None:
            record = build_intent_record(self._ctx, work.result(), self._clock())
            if not self._journal.write_intent(record):
                # A failure of the write + flush + fsync sequence cancels the POST for
                # the object concerned (section 8.4).
                raise EventRejected("error", "journal_intent_failed")
            work.journaled = True

        work.post_attempted = True
        response = self._rest.post_object_acl(work.endpoint, merged.payload)
        self.counter += 1
        work.counted = True
        work.http_code = response.status

        if 200 <= response.status < 300:
            work.status = "updated"
            self._written[work.endpoint] = merged.after
        else:
            work.status = "error"
            work.error = _truncate(
                "post_failed:%d:%s"
                % (response.status, response.error or response.text())
            )
            if is_persistence_failure(response.status):
                # A persistence refusal leaves the **runtime** view of splunkd mutated
                # while the disk is intact: the command tells the truth with respect to
                # the disk and something false with respect to what users, searches and
                # access controls see. The object is moreover excluded from the rollback
                # set - `editacl_rollback` only keeps the `outcome` lines with status
                # `updated`, a filter that is correct with respect to the disk and silent
                # with respect to the observable. The divergence is produced by the
                # platform and cannot be avoided; it must be visible.
                work.warn(RUNTIME_DIVERGENCE_WARNING)
            self._failed[work.endpoint] = _FailedPost(
                merged.before,
                merged.after,
                work.status,
                work.error,
                response.status,
                tuple(work.warnings),
            )

    # -- steps ----------------------------------------------------------- #

    def _check_required(self, event):
        """`title` and `app` are required (section 3.1). The owner no longer is.

        It no longer is because it no longer enters: addressing goes through the fixed
        context and the value sent with the POST is the one from the GET as long as
        `new_owner` is not supplied (D-25).
        """
        for name, value in (("title", event.title), ("app", event.app)):
            if not str(value or "").strip():
                raise EventRejected("rejected", "missing_field:%s" % name)
        if str(event.app).strip().lower() == FORBIDDEN_APP:
            raise EventRejected("rejected", "app_system_forbidden")

    def _read_state(self, work):
        """Read the current state (section 5.3). The result of the GET is authoritative.

        The deduplication of section 10.8 short-circuits the GET for an object already
        submitted with a POST within the current run: the memorized state stands for the
        current state. It is the target state if the POST succeeded, the prior state if
        it was refused - a refused POST does not modify the object.

        This short circuit is also what makes the processing **deterministic** on the
        case of section 5.6: an `HTTP 500` persistence refusal leaves the runtime view
        mutated, so much so that reading it again would make the duplicate come out as
        `noop` and would mask the failure. The run's memory is authoritative over that
        divergent view.

        The deduplication never changes the number of output events nor the number of
        `outcome` lines.

        **The short circuit restores the platform identity** memorized on the first GET.
        Rank 0 of section 5.4 reads it right after this call: leaving it at `None` would
        make the derivation control inoperative on a second occurrence of the same
        endpoint. The output of this method therefore carries the same `platform_name`
        through both paths - a **local** guarantee, which supposes nothing about the
        mechanism that feeds `_written` / `_failed`.
        """
        cached = self._written.get(work.endpoint)
        if cached is None:
            failed = self._failed.get(work.endpoint)
            cached = failed.before if failed is not None else None
        if cached is not None:
            work.http_code = 200
            work.platform_name = self._platform_names.get(work.endpoint)
            return cached

        response = self._rest.get_object_acl(work.endpoint)
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
            entry = document["entry"][0]
            acl_block = entry["acl"]
            # Canonical identity of the object as splunkd returns it. It feeds rank 0 of
            # section 5.4: it is the platform datum on which the identification of a
            # derived object rests, as opposed to the `title` of the event.
            work.platform_name = entry.get("name")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise EventRejected(
                "error", _truncate("get_parse_failed:%s" % (exc,))
            )
        self._platform_names[work.endpoint] = work.platform_name
        return parse_acl_state(acl_block)

    def build_summary(self):
        """End-of-run record (section 8.2, D-46), from the run's tally.

        Building it is pure and separate from writing it, like the other two records:
        the caller decides **whether** the run reached its normal end, and this method
        knows nothing about that.
        """
        return build_summary_record(self._ctx, self.counts, self._clock())

    def _emit(self, result):
        """Write the `outcome` line, tally the status and return the final result.

        `write_outcome` is called on **every** exit, without exception: that is what
        holds the invariant "one `outcome` line per output event". The tally is fed
        here for the same reason - it is the one place every event goes through, so no
        exit can escape being counted.
        """
        self.counts[result.status] = self.counts.get(result.status, 0) + 1
        if self._journal is not None:
            record = build_outcome_record(self._ctx, result, self._clock())
            if not self._journal.write_outcome(record):
                # The POST has already happened: nothing is rolled back, but the breach
                # of the invariant must be reported.
                result = replace(
                    result, warnings=result.warnings + ("journal_outcome_failed",)
                )
        return result
