"""Identification of objects derived from an `eventtype` (spec section 3.4, D-18).

An `fvtags` object is not a standalone knowledge object: it is the internal
materialization through which splunkd applies a tag set on an `eventtype`. Writing the
ACL of the carrier **propagates** that ACL to the derived object, with no POST and no
HTTP response, hence without the command being able to observe it. The command
therefore abstains from writing the derived object (section 5.4, rank 0).

The design constraint is the **third normative property of section 3.4**:

    "The derivation relation is DISCOVERED, not CONSTRUCTED. Identifying an object as
     derived must never rest on a string concatenation built from the parent's name."

What this module does NOT do
----------------------------

It never computes `"eventtype=" + <parent name>`. No function here takes an
`eventtype` name as input in order to deduce a derived object name from it. That is
exactly the forbidden operation: one day it would produce a name collision, with the
same consequences as a guessed endpoint (section 6.2).

What this module does, and on which platform data
-------------------------------------------------

The direction of travel is **reversed** - from the child towards the carrier - and
each of the three steps rests on data supplied by splunkd, never on a convention we
would have laid down:

1. **The family** comes from the resolved handler path (section 5.2), itself derived
   either from the `id` field emitted by the native endpoint, or from the mapping table
   validated by a real GET (section 6.4). Only objects of the `fvtags` family are
   candidates: an object of another family that happened to bear a name in the
   `eventtype=...` shape is not concerned.

2. **The identity of the object** is the one splunkd returns in the response of the GET
   of section 5.3 - `entry[0].name` - and not the `title` field of the input event,
   which an upstream `eval` may have forged. Section 5.3 states that the result of the
   GET is authoritative; the rule is applied here to the letter.

   That identity is the **composite key** of the `fvtags` family, whose
   `<field>=<value>` grammar is the platform's own: it is under this form that splunkd
   names the object, addresses it (`saved/fvtags/<field>%3D<value>`), creates it
   (`POST saved/fvtags name=<field>%3D<value>`) and writes it into `tags.conf`
   (`[<field>=<value>]`). Reading it is not a naming heuristic: it is reading the
   primary key of the object as the platform defines it.

3. **The existence of the carrier is confirmed by the platform**, through a real GET on
   the `saved/eventtypes` endpoint of the same namespace. That is the step that makes
   the relation an **observation** rather than a supposition: with no carrier there is
   no possible cascade, hence no abstention - an orphan `fvtags` stays modifiable.

Measurement grounding point 2
-----------------------------

The chosen grammar - splitting on the **first** equals sign - is not deduced from
documentation: it is the rule splunkd applies itself, measured on the reference
platform. An `eventtype` whose name contains an equals sign spawns a derived object
whose composite key keeps that sign in its value part, and an ACL POST on that carrier
does cascade to that derived object. The rule implemented here is therefore the
**exact converse of the observed cascade behavior**, not a supposed naming convention.

Scope
-----

Bounded to the objects derived from an `eventtype`, in line with D-18 and section
11.3: the pattern is confined to the cluster of tags over the 11 families that were
exercised; the other 16 are inferred exempt and were not observed. The rule is
deliberately not stated over "any derived object".

Nor does it extend to the `tags` family (`admin/tags`), even though its objects are
also derived from an `eventtype` and the platform even exposes the link explicitly
there (field `field_name_value`). Two reasons, in this order:

- section 3.4 names the `fvtags` object explicitly, and the measured cascade bears on
  the `[tags/<pair>]` stanza alone, which is that object's;
- an `admin/tags` object acquires a stanza of its own from its first ACL write onwards
  and stops being exposed to the cascade. Abstaining from it for good would remove it
  from the driving use case of section 1.1 - the effective disappearance of references
  to a decommissioned role - with no cascade coming to align it in return. Section 3.4
  makes the estate converge through the cascade; here there would be nothing to
  converge with.
"""

from .endpoint import build_object_path

#: Handler paths of the `fvtags` family. `saved/fvtags` is the value in the shipped
#: mapping table; `admin/fvtags` is the same handler exposed under the administration
#: tree, and an `id` field may designate it.
FVTAGS_HANDLER_PATHS = frozenset({"saved/fvtags", "admin/fvtags"})

#: Handler path of the carrier. This is the value the mapping table associates with
#: `eventtypes`, validated by a real GET (section 6.4).
EVENTTYPE_HANDLER_PATH = "saved/eventtypes"

#: Left-hand part of the composite key designating an `eventtype` as the carrier.
CARRIER_FIELD = "eventtype"

#: Separator of the `<field>=<value>` composite key of the `fvtags` family.
PAIR_SEPARATOR = "="

#: Warning emitted when the confirmation GET could neither establish nor disprove the
#: existence of the carrier. See `CarrierProbe.carrier_of`.
PROBE_INCONCLUSIVE_WARNING = "carrier_probe_inconclusive"


def split_composite_key(platform_name):
    """Split the composite key of an `fvtags` object into `(field, value)`.

    Returns `None` if the name does not conform to the platform's grammar.

    The split bears on the **first** equals sign: a field name cannot contain one, a
    value can. That is the rule measured on the reference platform.
    """
    if platform_name is None:
        return None
    name = str(platform_name)
    if PAIR_SEPARATOR not in name:
        return None
    field, _, value = name.partition(PAIR_SEPARATOR)
    if not field or not value:
        return None
    return field, value


def designated_carrier(handler_path, platform_name):
    """Name of the `eventtype` designated by the object's composite key, or `None`.

    Concludes nothing about the existence of that `eventtype`: that is the job of the
    confirmation GET in `CarrierProbe`. This function only reads the designation
    carried by the identity the platform returned.
    """
    if str(handler_path or "").strip("/") not in FVTAGS_HANDLER_PATHS:
        return None
    parts = split_composite_key(platform_name)
    if parts is None:
        return None
    field, value = parts
    if field != CARRIER_FIELD:
        return None
    return value


class CarrierProbe(object):
    """Confirms with the platform that the designated carrier exists.

    One GET per distinct `(app, carrier)` pair, memoized for the duration of the run.
    On a batch where the `fvtags` family is absent, the cost is nil: the probe is only
    queried once `designated_carrier` has already answered.

    The carrier is looked up at the **fixed context** (section 5.2, D-25), like the
    object itself: the probe receives no owner, and `build_object_path` no longer
    accepts one.
    """

    def __init__(self, rest):
        self._rest = rest
        self._cache = {}

    def _carrier_exists(self, app, carrier):
        key = (str(app), str(carrier))
        if key not in self._cache:
            path = build_object_path(app, EVENTTYPE_HANDLER_PATH, carrier)
            response = self._rest.get_json(path)
            self._cache[key] = response.status
        return self._cache[key]

    def carrier_of(self, app, handler_path, platform_name):
        """Returns `(carrier, warning)`.

        `carrier` is `None` when the object is not derived from an `eventtype` - either
        because it does not belong to the `fvtags` family, or because its composite key
        does not designate an `eventtype`, or because the platform answers that the
        designated carrier **does not exist** (HTTP 404). That last case is the orphan
        `fvtags`: no carrier can cascade onto it, so it stays modifiable.

        `warning` is non-null when the confirmation GET neither established nor
        disproved the existence of the carrier - 403, 5xx, transport failure. The
        abstention is then **conservative**: it is pronounced anyway, because writing a
        derived object whose carrier might exist silently falsifies the rollback set,
        whereas one abstention too many is traced, visible, and without effect on the
        state of the estate. The warning carries the code obtained so that the operator
        can tell the two situations apart.
        """
        carrier = designated_carrier(handler_path, platform_name)
        if carrier is None:
            return None, None

        status = self._carrier_exists(app, carrier)
        if status == 404:
            return None, None
        if 200 <= status < 300:
            return carrier, None
        return carrier, "%s:%d" % (PROBE_INCONCLUSIVE_WARNING, status)
