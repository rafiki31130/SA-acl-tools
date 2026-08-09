#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-validation of the mapping table on the target platform (spec section 6.5).

The table shipped in `bin/acl_endpoint_map.json` was established empirically on a
single version of Splunk Enterprise. It is **not** presumed valid anywhere else:
running this procedure on the target platform is a **prerequisite to any real use**
of `editacl`.

The procedure:

  1. enumerates the distinct `eai:type` values actually present on the platform: the
     union of what the `admin/directory` aggregation handler emits and of what the
     native endpoints of the table emit;
  2. confronts them with the shipped table (override included);
  3. produces the three lists required by the specification:
       A. mappings **confirmed by a real GET** on a witness object,
       B. mappings of the table **not found on the platform**,
       C. types present on the platform and **absent from the table**.

  4. additionally checks the consistency between `bin/acl_endpoint_map.json` (read by
     the Python code) and `lookups/acl_object_families.csv` (read by the inventory
     macro, SPL being unable to read JSON). Both files carry the same information in
     two forms; a divergence would make the inventory and the resolution
     inconsistent.

List C is handled through the override file `lookups/acl_endpoint_map_override.csv`,
without any code change. List B is informative: a mapping with no witness object on
the platform is not wrong, it simply cannot be validated here.

Why a Python script and not an SPL search: building the URI of an object obeys a
single, non-obvious encoding rule, implemented exactly once in `acltools.endpoint`.
Rewriting it in SPL would create a second implementation that would diverge, which is
exactly the flaw the single injection point rule forbids. This script **reuses**
`acltools.mapping.load_mapping` (hence `Mapping.coverage()`) and
`acltools.endpoint.build_object_path`; it reimplements nothing.

The password is read from the FIRST line of stdin: never in argv, never written to
disk, never printed.

Usage, from the root of the repository or of the installed app:

    <command that supplies the password> | python3 tools/revalidate_mapping.py \\
        [--user admin] [--splunkd-uri https://127.0.0.1:8089] [--insecure]

Exit code: 0 if list C is empty, 1 otherwise (some types of the platform are not
resolved by the table: the override must be completed before any real use).
"""

import argparse
import base64
import csv
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_APP_ROOT, "bin"))

from acltools.endpoint import build_object_path  # noqa: E402
from acltools.mapping import load_mapping  # noqa: E402

JSON_PATH = os.path.join(_APP_ROOT, "bin", "acl_endpoint_map.json")
OVERRIDE_PATH = os.path.join(_APP_ROOT, "lookups", "acl_endpoint_map_override.csv")
FAMILIES_PATH = os.path.join(_APP_ROOT, "lookups", "acl_object_families.csv")

DIRECTORY = "admin/directory"


class Rest(object):
    def __init__(self, base_uri, auth_header, context):
        self._base = base_uri.rstrip("/")
        self._auth = auth_header
        self._ctx = context

    def get(self, path):
        """Returns `(http_code, document)`. `document` is `{}` on failure."""
        sep = "&" if "?" in path else "?"
        url = self._base + path + sep + "output_mode=json"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", self._auth)
        try:
            resp = urllib.request.urlopen(req, context=self._ctx, timeout=180)
            body = resp.read().decode("utf-8", "replace")
            code = resp.status
        except urllib.error.HTTPError as exc:
            return exc.code, {}
        except Exception:  # noqa: BLE001 - an unreachable platform is not an exception
            return 0, {}
        try:
            return code, json.loads(body)
        except ValueError:
            return code, {}


def entries(doc):
    return doc.get("entry", []) if isinstance(doc, dict) else []


def read_families_csv(path):
    """`lookups/acl_object_families.csv` -> {eai_type: handler_path}.

    The column carries the same name as in the override file of section 6.3, because it
    carries the same thing: the key of the mapping table, which is the one vocabulary
    this app uses for the type of an object.
    """
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            family = (row.get("eai_type") or "").strip()
            handler = (row.get("handler_path") or "").strip()
            if family and not family.startswith("#"):
                out[family] = handler
    return out


def platform_types(rest, mapping):
    """Distinct `eai:type` values really emitted by the platform.

    Two sources, unioned: the aggregation handler, and the native endpoints of the
    table. The second one is indispensable: most native endpoints emit no `eai:type`
    at all, but a few emit one that `admin/directory` does not show (data models, for
    instance, are entirely absent from it).
    """
    found = {}
    code, doc = rest.get("/servicesNS/-/-/%s?count=0" % DIRECTORY)
    for entry in entries(doc):
        value = (entry.get("content") or {}).get("eai:type")
        if value:
            found.setdefault(str(value), set()).add(DIRECTORY)

    handlers = sorted({mapping.resolve(t) for t in mapping.coverage()["types"]} - {None})
    for handler in handlers:
        code, doc = rest.get("/servicesNS/-/-/%s?count=0" % handler)
        if code != 200:
            continue
        for entry in entries(doc):
            value = (entry.get("content") or {}).get("eai:type")
            if value:
                found.setdefault(str(value), set()).add(handler)
    return found


def witness(rest, handler):
    """First object listable by this handler, with its real namespace.

    The namespace is read from the `acl` block of the entry, never assumed: an object
    with `sharing=user` is only addressable in the namespace of ITS owner.
    """
    code, doc = rest.get("/servicesNS/-/-/%s?count=1" % handler)
    if code != 200:
        return None, code
    for entry in entries(doc):
        acl = entry.get("acl") or {}
        return {
            "title": entry.get("name"),
            "owner": acl.get("owner") or "nobody",
            "app": acl.get("app") or "system",
        }, code
    return None, code


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--user", default="admin",
                        help="account used for the REST calls (default: admin)")
    parser.add_argument("--splunkd-uri", default="https://127.0.0.1:8089",
                        help="splunkd URI (default: local loopback)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify the splunkd certificate "
                             "(platform with a self-signed certificate)")
    args = parser.parse_args()

    password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        sys.stderr.write("password expected on the first line of stdin\n")
        return 2
    auth = "Basic " + base64.b64encode(
        ("%s:%s" % (args.user, password)).encode("utf-8")).decode("ascii")
    context = ssl._create_unverified_context() if args.insecure \
        else ssl.create_default_context()
    rest = Rest(args.splunkd_uri, auth, context)

    mapping = load_mapping(JSON_PATH, OVERRIDE_PATH)
    coverage = mapping.coverage()

    print("== shipped table ==")
    print("  effective entries      : %d" % coverage["total"])
    print("  coming from the JSON   : %d" % coverage["from_json"])
    print("  coming from override   : %d" % coverage["from_override"])
    if coverage["overridden"]:
        print("  overridden keys        : %s" % ", ".join(coverage["overridden"]))
    for key, value, source in coverage["rejected"]:
        print("  DISCARDED (%s) : %r -> %r" % (source, key, value))

    present = platform_types(rest, mapping)
    print("\n== platform ==")
    print("  distinct types emitted : %d" % len(present))

    confirmed, not_found = [], []
    for eai_type in coverage["types"]:
        handler = mapping.resolve(eai_type)
        obj, code = witness(rest, handler)
        if obj is None:
            not_found.append((eai_type, handler, "no listable object (HTTP %s)" % code))
            continue
        path = build_object_path(obj["owner"], obj["app"], handler, obj["title"])
        code_obj, _ = rest.get(path)
        code_acl, _ = rest.get(path + "/acl")
        if code_obj == 200 and code_acl == 200:
            confirmed.append((eai_type, handler, obj["app"], obj["title"]))
        else:
            not_found.append(
                (eai_type, handler, "GET=%s GET/acl=%s" % (code_obj, code_acl)))

    absent = sorted(t for t in present if mapping.resolve(t) is None)

    print("\n== A. mappings confirmed by a real GET (%d) ==" % len(confirmed))
    for eai_type, handler, app, title in confirmed:
        print("  %-22s -> %-32s  witness: %s / %s" % (eai_type, handler, app, title))

    print("\n== B. mappings of the table not found on the platform (%d) =="
          % len(not_found))
    for eai_type, handler, why in not_found:
        print("  %-22s -> %-32s  %s" % (eai_type, handler, why))
    if not_found:
        print("  (informational: a mapping with no witness object is not wrong,")
        print("   it simply cannot be validated on this platform)")

    print("\n== C. types present on the platform and absent from the table (%d) =="
          % len(absent))
    for eai_type in absent:
        print("  %-22s  emitted by: %s" % (eai_type, ", ".join(sorted(present[eai_type]))))
    if absent:
        print("  -> to be declared in lookups/acl_endpoint_map_override.csv BEFORE any")
        print("     real use: a type absent from the table yields acl_status=rejected.")

    families = read_families_csv(FAMILIES_PATH)
    handlers_json = {mapping.resolve(t) for t in coverage["types"]}
    handlers_csv = set(families.values())
    missing = sorted(handlers_json - handlers_csv)
    extra = sorted(handlers_csv - handlers_json)
    mismatched = sorted(f for f, h in families.items() if mapping.resolve(f) != h)

    print("\n== D. consistency of the JSON table <-> the families lookup ==")
    print("  handlers in the table  : %d" % len(handlers_json))
    print("  handlers in the lookup : %d" % len(handlers_csv))
    for handler in missing:
        print("  ABSENT FROM LOOKUP: %s (the inventory will not see this family)" % handler)
    for handler in extra:
        print("  ABSENT FROM TABLE : %s (inventoried but not resolvable)" % handler)
    for family in mismatched:
        print("  INCONSISTENT      : family %r -> %r in the lookup, %r in the table"
              % (family, families[family], mapping.resolve(family)))
    if not (missing or extra or mismatched):
        print("  consistent")

    return 1 if absent else 0


if __name__ == "__main__":
    sys.exit(main())
