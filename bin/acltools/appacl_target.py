"""Target resolution and URI construction (v4.2 sections 8.3 and 11.3).

Two write paths, and they share nothing but the fact of being a path:

    app_default     POST /services/apps/local/<enc(app)>/acl
    family_default  POST /servicesNS/nobody/<enc(app)>/<handler>/_acl

**The namespace segment is the literal `nobody`, always** (section 4.1). Measured: with
`admin`, splunkd answers `200` and writes into
`etc/users/admin/<app>/metadata/local.meta` - a **private** metadata file, invisible to
everybody else, with no warning and no diagnostic field (Q0-5 verdict 2, and the trap
sheet it produced). The functions of this module therefore take **no owner argument at
all**: that is a structural guarantee, not a convention, and a signature test freezes
it - exactly as `endpoint.build_object_path` does for the previous command.
"""

from urllib.parse import quote

from .appacl_model import STANZA_KIND_APP, STANZA_KIND_FAMILY, STANZA_KINDS, AppTarget
from .errors import EventRejected
from .mapping import is_valid_handler_path

#: Namespace context of the family path. **Literal, hardcoded, never derived** from an
#: input field, from a parameter, from the running user, nor from any read datum
#: (section 4.1).
FIXED_CONTEXT = "nobody"

#: Application context out of scope (v3.14 section 1.3, reconducted by v4.2
#: section 1.2). Rejection is **per event**: section 13.1 enumerates the fatal errors
#: exhaustively and does not list this one.
FORBIDDEN_APP = "system"


def encode_app_segment(app):
    """Encode the application segment: `%`-encoding of the whole segment, `safe=''`.

    Single encoding rule of the repository (v3.14 section 5.2, measurement 3). No
    character is left literal, the forward slash included.
    """
    return quote(str(app), safe="", encoding="utf-8")


def build_app_default_path(app):
    """Write path of the `[]` stanza. **No owner argument** (section 4.1).

    It is also the read path: the GET of section 8.7 rank 5 bears on this very string,
    and so does the POST. That is a difference with the previous command, where the POST
    added an `/acl` suffix the GET did not carry - here the suffix is part of the
    endpoint itself.
    """
    return "/services/apps/local/%s/acl" % encode_app_segment(app)


def build_family_default_path(app, handler_path):
    """Write path of a family header. **No owner argument** (section 4.1).

    `handler_path` is **not** re-encoded: it is a literal coming from the shipped table,
    from the operator's override, or from the `acl_handler` field, already URL-safe and
    validated by pattern. Encoding it would turn `saved/searches` into
    `saved%2Fsearches`.
    """
    return "/servicesNS/%s/%s/%s/_acl" % (
        encode_app_segment(FIXED_CONTEXT),
        encode_app_segment(app),
        str(handler_path).strip("/"),
    )


def check_designation(event):
    """Ranks 0 to 2 of section 8.7. Returns `(app, stanza_kind)`, or raises.

    Split out of `resolve_target` because **rank 3 sits between them and rank 4**: the
    duplicate check must run once the designation is known to be well formed, and before
    the family is resolved. Two rows carrying the same unresolvable designation therefore
    come out as `duplicate_target` for the second one, not twice as `unresolved_family`.
    """
    app = str(getattr(event, "app", "") or "").strip()
    kind = str(getattr(event, "stanza_kind", "") or "").strip()

    if kind not in STANZA_KINDS:                                          # rank 0
        raise EventRejected("rejected", "invalid_stanza_kind:%s" % kind)
    if not app:                                                           # rank 1
        raise EventRejected("rejected", "app_missing")
    if app.lower() == FORBIDDEN_APP:                                      # rank 2
        raise EventRejected("rejected", "app_system_forbidden")
    return app, kind


def resolve_target(event, table):
    """Resolve one input event into an `AppTarget`, or raise `EventRejected`.

    Ranks 0 to 4 of section 8.7, in their normative order and in this order only:

    0. `stanza_kind` absent, empty or outside the domain -> `invalid_stanza_kind:<v>`;
    1. `app` absent or empty -> `app_missing`;
    2. `app` equal to `system` -> `app_system_forbidden`;
    4. handler resolution impossible -> `unresolved_family:<stanza>`.

    Rank 3 - the target already processed in this run (**DV-2**) - is held by the
    pipeline, which alone knows what the run has already seen.

    **`stanza_kind` is required and never deduced**, and that is the point of rank 0.
    Deducing `app_default` from an empty family value would write `[]` on a batch whose
    family column is merely missing - a silent, catastrophic targeting defect, of the
    same family as the one v3.14 section 5.2 documents on owner-based addressing.

    For `family_default` the two resolution routes are **complementary and disjoint**,
    never a primary and a degraded fallback:

    1. from `handler`, used as is after shape validation. This route **does not depend
       on the table**, which is what makes the restore of section 11.4 independent of
       the table's coverage;
    2. from `stanza`, through the table of section 5.2.

    For `app_default` neither is consulted: the URI is entirely determined by `app`.
    """
    app, kind = check_designation(event)                                  # ranks 0 to 2
    handler = str(getattr(event, "handler", "") or "").strip()
    stanza = str(getattr(event, "stanza", "") or "").strip()

    if kind == STANZA_KIND_APP:
        return AppTarget(
            app=app,
            stanza_kind=STANZA_KIND_APP,
            stanza="",
            handler="",
            endpoint=build_app_default_path(app),
        )

    resolved = None                                                       # rank 4
    if handler:
        if not is_valid_handler_path(handler):
            raise EventRejected("rejected", "invalid_handler:%s" % handler)
        resolved = handler
    elif stanza and table is not None:
        resolved = table.resolve(stanza)

    if not resolved:
        raise EventRejected("rejected", "unresolved_family:%s" % stanza)

    return AppTarget(
        app=app,
        stanza_kind=STANZA_KIND_FAMILY,
        stanza=stanza,
        handler=resolved,
        endpoint=build_family_default_path(app, resolved),
    )


def designation_key(event):
    """Key of the **input designation**, for rank 3 of section 8.7.

    Rank 3 precedes rank 4, so the duplicate check cannot rest on the resolved endpoint:
    two identical designations that resolve to nothing must come out as
    `duplicate_target`, not twice as `unresolved_family`. This key is therefore built
    from what the row says, before anything is resolved.

    The pipeline **also** deduplicates on the resolved endpoint, right after rank 4.
    Both are needed and neither subsumes the other: two rows designating the same family,
    one through `handler` and the other through `stanza`, have different designations and
    the same endpoint - and **DV-2** refuses the second one, because a generic stanza has
    no natural multiplicity and the last writer would win in silence over a write that
    section 9 establishes may be irreversible.
    """
    return (
        str(getattr(event, "app", "") or "").strip(),
        str(getattr(event, "stanza_kind", "") or "").strip(),
        str(getattr(event, "handler", "") or "").strip(),
        str(getattr(event, "stanza", "") or "").strip(),
    )
