"""Resolution and reconstruction of an object URI (section 5.2).

Two **complementary and disjoint** routes, not a primary one and a fallback (D-9):

- `id`, usable when it comes from a native endpoint;
- `eai:type`, resolved through the mapping table (section 6).

In both cases the URI is **rebuilt**, never reused as is: the native `id` field
double-encodes the forward slash but not the other special characters, so it is not
reusable as a URI.
"""

from urllib.parse import quote, unquote, urlsplit

from .errors import EventRejected
from .mapping import is_valid_handler_path

#: Namespace marker in a Splunk REST path.
NAMESPACE_MARKER = "/servicesNS/"

#: **Fixed addressing context** (section 5.2, D-25). It does not come from the event,
#: it is not configurable, and no signature in this module exposes an owner.
#:
#: Measured: a shared object belonging to a third party is reachable through this
#: context, for reading as well as for writing, at both sharing scopes, and the GET
#: response always carries **the real owner** - never the addressing context. The `id`
#: returned by the platform is itself in `nobody`.
#:
#: What this context fixes: v1 addressed objects through `eai:acl.owner`, and **a
#: private object masks a shared object of the same name in the namespace of its
#: holder**. The command then reached the private one and wrote its ACL - `200` on the
#: GET, POST accepted, row reported as `updated`. A silent write on the wrong target.
#:
#: The wildcard context `-` is **never** used: it refuses writes, and on two objects of
#: the same name it returns two entries on a single-object path, where a client reading
#: the first one would be choosing blindly.
FIXED_CONTEXT = "nobody"

#: Aggregation handler: it can list, it cannot write an ACL. An `id` source pointing at
#: it is discarded (section 5.2). The lab measurement establishes that 100 % of the
#: `id` values emitted by this handler are self-referential.
DIRECTORY_HANDLER = "admin/directory"

#: Encoding rule for the `title` segment, settled empirically (measurement 3): plain
#: `%`-encoding of the whole segment, `safe=''`, no character left literal.
#: The forward slash calls for **no** special treatment. Double encoding is an
#: asymmetric trap: it works for `/` alone and breaks on space, accented letter and
#: percent sign.
TITLE_ENCODING_MODE = "single"


def encode_namespace_segment(value):
    """Encode a namespace segment (`owner`, `app`)."""
    return quote(str(value), safe="", encoding="utf-8")


def encode_title_segment(title):
    """Encode the last path segment - single injection point of the rule.

    No other caller encodes a title, and no other module knows this rule.
    """
    if TITLE_ENCODING_MODE == "single":
        return quote(str(title), safe="", encoding="utf-8")
    if TITLE_ENCODING_MODE == "double_slash_only":
        return quote(str(title), safe="", encoding="utf-8").replace("%2F", "%252F")
    if TITLE_ENCODING_MODE == "double":
        return quote(
            quote(str(title), safe="", encoding="utf-8"), safe="", encoding="utf-8"
        )
    raise ValueError("unknown TITLE_ENCODING_MODE: %r" % (TITLE_ENCODING_MODE,))


def handler_path_from_id(id_value):
    """Extract the handler path carried by an `id`, or `None` if it is unusable.

    The host and port carried by `id` are **discarded**: the base is `splunkd_uri`. An
    `id` returned by one member of a search head cluster may designate a host other
    than the one running the command.

    The last segment - the object name - is **thrown away**: the name is taken from
    `title`, never from `id`.
    """
    if not id_value:
        return None
    raw = str(id_value).strip()
    if not raw:
        return None

    path = urlsplit(raw).path if "://" in raw else raw
    marker = path.find(NAMESPACE_MARKER)
    if marker < 0:
        return None

    remainder = path[marker + len(NAMESPACE_MARKER):]
    segments = [seg for seg in remainder.split("/") if seg != ""]
    # <owner> / <app> / <handler_path...> / <object name>
    if len(segments) < 4:
        return None
    handler_path = "/".join(segments[2:-1])

    if handler_path == DIRECTORY_HANDLER or handler_path.startswith(
        DIRECTORY_HANDLER + "/"
    ):
        return None
    if not is_valid_handler_path(handler_path):
        return None
    return handler_path


def namespace_owner_from_id(id_value):
    """Namespace owner carried by `id`, or `None` if `id` carries none.

    **This is data emitted by the platform, not a convention** (section 3.5, D-34, and
    property 3 of section 3.4, of which this is the literal application). Splunkd emits
    `/servicesNS/nobody/...` for a shared object and `/servicesNS/<owner>/...` for a
    private one: the segment read here is the one the platform wrote into the object's
    URI, never a reconstructed name nor a rule of our own making.

    The `id` field is also the only thing the command has when the sharing scope column
    is absent from the result set. The fallback claimed until now - the GET through the
    fixed context answers `404` and the object comes out as `not_found` - **is false as
    soon as a shared object of the same name exists**: fixed addressing then reaches
    the shared one, and the command reads then would write an object **other than the
    one designated as input**.

    The expected shape is exactly the one `handler_path_from_id` requires:
    `<owner>/<app>/<handler_path...>/<object name>`, that is at least four segments. An
    `id` of any other shape - `/services/...` without a namespace, a truncated path -
    does not carry the datum and yields `None`: the command then invents nothing.
    """
    if not id_value:
        return None
    raw = str(id_value).strip()
    if not raw:
        return None

    path = urlsplit(raw).path if "://" in raw else raw
    marker = path.find(NAMESPACE_MARKER)
    if marker < 0:
        return None

    remainder = path[marker + len(NAMESPACE_MARKER):]
    segments = [seg for seg in remainder.split("/") if seg != ""]
    if len(segments) < 4:
        return None

    owner = unquote(segments[0]).strip()
    return owner or None


def is_fixed_context(owner):
    """True if `owner` designates the fixed addressing context, hence a shared object.

    Single injection point of the comparison: it cannot drift elsewhere, and the case
    folding does not have to be decided by each caller.
    """
    return str(owner or "").strip().lower() == FIXED_CONTEXT


def resolve_handler_path(id_value, eai_type, mapping):
    """Resolve the handler path of the object. Returns the path.

    **Which of the two routes answered is not returned**, and that is deliberate. It
    was, and nothing ever read it: no output field, no journal key, no view. A datum
    carried the length of the pipeline and consumed by nobody is one more thing to keep
    in step with the code for no benefit, and the fact it stood for - the nature of the
    object - is published under one single name, `eai_type` (section 5.7).

    Errors: `EventRejected("rejected", "unresolved_endpoint:<eai:type>")` when neither
    route succeeds.
    """
    from_id = handler_path_from_id(id_value)
    if from_id:
        return from_id

    from_type = mapping.resolve(eai_type) if mapping is not None else None
    if from_type:
        return from_type

    raise EventRejected(
        "rejected", "unresolved_endpoint:%s" % ("" if not eai_type else str(eai_type))
    )


def build_object_path(app, handler_path, title):
    """Build the object path, **without** the `/acl` suffix (section 5.2).

    The context is `FIXED_CONTEXT`, always, and this function **has no owner
    parameter**: addressing therefore cannot carry one, however the callers evolve.
    That is the structural guarantee of D-25.

    The GET of section 5.3 bears on this path, the POST of section 5.6 on this path
    suffixed with `/acl`. It is also the string exposed in the output as `acl_endpoint`
    and the correlation key of the journal (section 8.5): it is computed once and never
    recomputed.

    `handler_path` is **not** re-encoded: it is a literal from the mapping table or
    from `id`, already URL-safe and validated by pattern. Encoding it would turn
    `saved/searches` into `saved%2Fsearches`.
    """
    return "%s%s/%s/%s/%s" % (
        NAMESPACE_MARKER,
        encode_namespace_segment(FIXED_CONTEXT),
        encode_namespace_segment(app),
        handler_path.strip("/"),
        encode_title_segment(title),
    )


def build_object_url(splunkd_uri, object_path):
    """Prefix the object path with the splunkd base. No hardcoded host or port."""
    return str(splunkd_uri).rstrip("/") + object_path
