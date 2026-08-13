"""Impact estimate of a generic write (v4.2 section 10.3).

**Definition.** `acl_impacted_estimate` is the number of **shared** objects of the
application whose effective rights are today determined by the target stanza - those
carrying neither their own stanza nor, for an `app_default` target, an interposed family
header.

**Calculation**, per target::

    family_default  objects of that family in that app, minus those carrying a
                    [<family>/<object>] stanza in local.meta or default.meta
    app_default     union, over the families with no header in either file, of the
                    objects with no stanza of their own

Two implementation points that are decisions rather than transcriptions, and both are
made here rather than left implicit.

**Only the stanzas that actually freeze are subtracted, and that is the correction of
A-2.** *Measured*: splunkd writes a `[<family>/<object>]` stanza for **every object it
creates or edits**, carrying `owner`, `version` and `modtime` and no `access` line - and
such an object keeps inheriting its permissions in full. Subtracting those made the
estimate collapse to zero on any application whose objects had ever been touched, that is
on any real application, while the output announced `no_inheriting_object` and the write
moved the whole family. The predicate now lives in `appacl_provenance.materializes_permissions`
and is used at both stanza levels.

**The subtraction is on counts, not on names.** Bound 3 of section 6.2 states that
`[<family>/<object>]` stanzas are *counted, never listed*: reading the file
short-circuits the capability filtering REST applies, and matching REST names against
file names would mean building the very list the bound forbids. The estimate is
therefore `max(0, objects_of_the_family - frozen_stanzas_of_the_family)`. The clamp is
not cosmetic: a frozen stanza may name an object that no longer exists, and a negative
count would be worse than an approximate one. This is consistent with the name the
contract gives the column - **estimate** - and with the arbitration of QO-2: an estimate
named as such is worth more than an exact figure that is false.

**The objects are enumerated through the native endpoints**, the same choice the
inventory macro of v3.14 section 6.7 makes and for the same measured reason:
`admin/directory` only returns 60,6 % of them. Two filters are applied to the listing,
and neither is decorative: an object belonging to **another** application is visible in
this namespace through global sharing and is not governed by this app's stanzas, and a
**private** object lives under `etc/users/`, outside the read perimeter, and whether it
inherits the generic stanzas at all is unmeasured (HY-3).

**What the estimate is worth, and what it is not worth**: a caller without
`admin_all_objects` sees a truncated population, so the estimate is then a **lower
bound** (v3.14 section 7, D-21); private objects are excluded (HY-3); families the table
does not cover cannot be enumerated at all and are excluded from the `app_default`
union. The figure is never presented as an exact count.

**Zero is not a `noop`.** A target with no inheriting object today - all frozen, or the
family empty in this app - still changes the **default applicable to objects created
later** (measured, Q0-2: a family header writes successfully into an app holding no
object of that family). The target comes out written, with
`acl_warning="no_inheriting_object"`.
"""

import json

from .appacl_model import STANZA_KIND_APP
from .appacl_target import encode_app_segment

#: Sharing scope of the objects excluded from the count (section 10.3): their metadata
#: lives under `etc/users/`, outside the read perimeter of section 6.2.
PRIVATE_SHARING = "user"

#: Warning carried when the estimate is zero for a target that is nevertheless written.
NO_INHERITING_OBJECT = "no_inheriting_object"


class ImpactEstimator(object):
    """Estimates the blast radius of a write, **memoized per (app, family)**.

    The memoization spans the run and bears **only** on the object enumeration, which
    depends on none of the handler caches of section 13.4 point 7 - that is the one thing
    the clause allows carrying from one row to the next.

    It does **not** memoize the provenance: this class asks the reader for it on every
    estimate, and `editappacl` refreshes that reader before each target. The subtraction
    below therefore always runs against the file as it stands, which matters as soon as a
    previous row of the same run has written to the same application.
    """

    def __init__(self, rest, provenance_reader, table=None):
        self._rest = rest
        self._provenance = provenance_reader
        self._table = table
        #: (app, handler) -> number of shared objects of that app in that family.
        self._counts = {}

    # -- enumeration -------------------------------------------------------- #

    def _shared_object_count(self, app, handler_path):
        """Number of **shared objects of this app** in this family. `0` on failure.

        A failed enumeration yields zero rather than an exception: the estimate is an
        aid to decision, and losing it must not cost the write. The consequence is
        visible to the operator, since an estimate of zero carries
        `no_inheriting_object`.
        """
        key = (str(app or ""), str(handler_path or ""))
        if key in self._counts:
            return self._counts[key]

        path = "/servicesNS/nobody/%s/%s" % (
            encode_app_segment(app), str(handler_path).strip("/")
        )
        response = self._rest.get_json(path, {"count": "0", "f": "title"})
        total = 0
        if response is not None and getattr(response, "ok", False):
            try:
                document = json.loads(response.body.decode("utf-8", "replace"))
                for entry in document.get("entry") or []:
                    acl = entry.get("acl") or {}
                    if str(acl.get("app") or "") != str(app or ""):
                        # Visible here through global sharing, governed by the stanzas of
                        # its own application. Counting it would attribute to this write
                        # objects it cannot move.
                        continue
                    if str(acl.get("sharing") or "").lower() == PRIVATE_SHARING:
                        continue
                    total += 1
            except (ValueError, AttributeError, TypeError):
                total = 0
        self._counts[key] = total
        return total

    # -- estimate ----------------------------------------------------------- #

    def estimate(self, target):
        """Estimated number of objects the write of `target` moves.

        Returns an integer, always: the calculation happens for every target a real run
        would write, simulation included (section 10.3). Making it optional would restore
        exactly the blindness this increment exists to lift.
        """
        provenance = self._provenance.provenance_of_app(target.app)
        if target.stanza_kind == STANZA_KIND_APP:
            return self._estimate_app_default(target.app, provenance)
        return self._estimate_family(
            target.app, target.stanza, target.handler, provenance
        )

    # -- counts published to the inventory (section 7.4) -------------------- #

    def shared_object_count(self, app, handler_path):
        """`acl_objects_total` of a family row: shared objects of this app in it.

        Public face of the enumeration the estimate is built on. The inventory needs the
        **two** figures - the population and the part of it that still inherits - because
        their difference is exactly what `acl_frozen_stanzas` says in another unit, and
        publishing only the estimate would leave the operator unable to check one against
        the other.
        """
        return self._shared_object_count(app, handler_path)

    def inheriting_count(self, app, family, handler_path):
        """`acl_objects_inheriting` of a family row: those with no stanza of their own."""
        provenance = self._provenance.provenance_of_app(app)
        return self._estimate_family(app, family, handler_path, provenance)

    def app_default_counts(self, app):
        """`(total, inheriting)` for an `app_default` row.

        The total spans every family of the table, the inheriting part only the families
        with **no header** - which is the blast radius of `[]` itself, computed by the
        very function the write command uses (section 10.3). Both are lower bounds for
        the reasons the module docstring states: the families the table does not cover
        cannot be enumerated at all.
        """
        provenance = self._provenance.provenance_of_app(app)
        total = 0
        if self._table is not None:
            for family in self._table.families():
                handler_path = self._table.resolve(family)
                if handler_path:
                    total += self._shared_object_count(app, handler_path)
        return total, self._estimate_app_default(app, provenance)

    def _estimate_family(self, app, family, handler_path, provenance):
        if not handler_path:
            return 0
        objects = self._shared_object_count(app, handler_path)
        frozen = provenance.frozen_count(family) if family else 0
        return max(0, objects - frozen)

    def _estimate_app_default(self, app, provenance):
        """Union over the families **with no header** in either file.

        A family carrying a header is out of the blast radius of `[]`: its objects read
        the header, not the application default. That is the measured inheritance chain
        `[<family>/<object>]` > `[<family>]` > `[]` (Q0-3 verdict 4).

        Only the families of the table can be enumerated, so the sum is a lower bound -
        stated here, and stated again in the operator documentation.
        """
        if self._table is None:
            return 0
        total = 0
        for family in self._table.families():
            if provenance.has_family_header(family):
                continue
            handler_path = self._table.resolve(family)
            if not handler_path:
                continue
            total += self._estimate_family(app, family, handler_path, provenance)
        return total
