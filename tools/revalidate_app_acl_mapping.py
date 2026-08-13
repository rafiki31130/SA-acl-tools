#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-validation of the FAMILY table on the target platform (v4.1 section 5.2, req. 4).

The table shipped in `bin/app_acl_family_map.json` was established empirically on a
single version of Splunk Enterprise, by a real `POST` per entry. It is **not** presumed
valid anywhere else, and O-4 of the phase 0 measurement is blunt about it: no measurement
made on 9.4.6 transposes by deduction, the handler-to-stanza table least of all. Running
this procedure on the target platform is a **prerequisite to any real use** of
`editappacl`.

The three lists the contract requires:

  A. families of the table **confirmed** by a real `GET .../<handler>/_acl`;
  B. families of the table **not found** on the platform;
  C. generic stanzas **present on the platform and absent from the table**.

List C is treated through `lookups/app_acl_family_map_override.csv` (columns `family`,
`handler_path`), with no code change. List B is informative: a family with no container
on this platform is not wrong, it simply cannot be validated here.

**A GET and never a POST.** The shipped table was built by `POST`, because writing is the
only thing that establishes which stanza a handler writes. This procedure does not
rebuild it: it checks that the handlers it names still answer, on an instance that is
somebody's production. A validation that mutated the platform it validates would be worth
less than no validation at all.

**It reuses the core rather than rewriting it**: `load_family_table` for the table,
`build_family_default_path` for the URI - the encoding rule of the application segment is
implemented exactly once - and the read-only reader of `appacl_provenance` for list C.
Rewriting any of the three here would create a second implementation, which is the very
thing the single-injection-point rule forbids.

The password is read from the FIRST line of stdin: never in argv, never written to disk,
never printed.

Usage, from the root of the repository or of the installed app:

    <command that supplies the password> | python3 tools/revalidate_app_acl_mapping.py \\
        [--user admin] [--splunkd-uri https://127.0.0.1:8089] [--insecure]

Exit code: 0 if list C is empty, 1 otherwise.
"""

import argparse
import base64
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

from acltools.appacl_family import load_family_table  # noqa: E402
from acltools.appacl_model import STANZA_KIND_FAMILY  # noqa: E402
from acltools.appacl_provenance import (  # noqa: E402
    ProvenanceReader,
    classify_stanza,
    resolve_apps_root,
)
from acltools.appacl_target import build_family_default_path  # noqa: E402
from acltools.errors import FatalProvenanceRootError  # noqa: E402

JSON_PATH = os.path.join(_APP_ROOT, "bin", "app_acl_family_map.json")
OVERRIDE_PATH = os.path.join(
    _APP_ROOT, "lookups", "app_acl_family_map_override.csv"
)


class Rest(object):
    def __init__(self, base_uri, auth_header, context):
        self._base = base_uri.rstrip("/")
        self._auth = auth_header
        self._ctx = context

    def get(self, path, params=None):
        """Returns `(http_code, document)`. `document` is `{}` on failure."""
        merged = {"output_mode": "json"}
        merged.update(params or {})
        url = self._base + path + "?" + urllib.parse.urlencode(merged)
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", self._auth)
        try:
            response = urllib.request.urlopen(request, context=self._ctx, timeout=180)
            body = response.read().decode("utf-8", "replace")
            code = response.status
        except urllib.error.HTTPError as exc:
            return exc.code, {}
        except Exception:  # noqa: BLE001 - an unreachable platform is not an exception
            return 0, {}
        try:
            return code, json.loads(body)
        except ValueError:
            return code, {}


def entries(document):
    return document.get("entry", []) if isinstance(document, dict) else []


def witness_application(rest):
    """An application to address the family containers in.

    A container is only reachable inside a namespace, so the check needs one - and it
    must be a **real** application: `system` is out of scope of the whole project
    (section 1.2), and an invented name would answer `404` for a reason that has nothing
    to do with the family.
    """
    code, document = rest.get("/services/apps/local", {"count": "0", "f": "title"})
    if code != 200:
        return None
    for entry in entries(document):
        name = str(entry.get("name") or "").strip()
        if name and name != "system":
            return name
    return None


def platform_family_stanzas(reader, applications):
    """Generic family headers really present in the metadata files (list C).

    Read through the **read-only** reader of section 6.2: the same code path the command
    uses, so a family this procedure reports is a family the command would report too.
    """
    found = {}
    for app in applications:
        provenance = reader.provenance_of_app(app)
        for meta, layer in (
            (provenance.local, "local.meta"),
            (provenance.default, "default.meta"),
        ):
            for stanza in meta.stanzas:
                if classify_stanza(stanza) != STANZA_KIND_FAMILY:
                    continue
                found.setdefault(stanza, set()).add("%s/%s" % (app, layer))
    return found


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

    table = load_family_table(JSON_PATH, OVERRIDE_PATH)
    coverage = table.coverage()

    print("== shipped table ==")
    print("  effective entries      : %d" % coverage["total"])
    print("  coming from the JSON   : %d" % coverage["from_json"])
    print("  coming from override   : %d" % coverage["from_override"])
    if coverage["overridden"]:
        print("  overridden families    : %s" % ", ".join(coverage["overridden"]))
    for key, value, source in coverage["rejected"]:
        print("  DISCARDED (%s) : %r -> %r" % (source, key, value))

    app = witness_application(rest)
    if app is None:
        sys.stderr.write("no application listed by the platform: nothing to check\n")
        return 2
    print("  namespace used         : %s" % app)

    confirmed, not_found = [], []
    for family in coverage["families"]:
        handler = table.resolve(family)
        path = build_family_default_path(app, handler)
        code, document = rest.get(path)
        name = ""
        for entry in entries(document):
            name = str(entry.get("name") or "")
            break
        if code == 200:
            confirmed.append((family, handler, name))
        else:
            not_found.append((family, handler, "GET %s -> HTTP %s" % (path, code)))

    print("\n== A. families of the table confirmed by a real GET (%d) =="
          % len(confirmed))
    for family, handler, name in confirmed:
        flag = "" if name == family else "   NAME RETURNED: %r" % name
        print("  %-18s -> %-32s%s" % (family, handler, flag))
    print("  (the returned name is the FAMILY name on this path, which is what makes")
    print("   the container a family container rather than an object; a divergence is")
    print("   reported above and deserves a look before any real use)")

    print("\n== B. families of the table not found on the platform (%d) =="
          % len(not_found))
    for family, handler, why in not_found:
        print("  %-18s -> %-32s  %s" % (family, handler, why))
    if not_found:
        print("  (informational: a family with no container on this platform is not")
        print("   wrong, it simply cannot be validated here)")

    print("\n== C. generic stanzas present on the platform and absent from the table ==")
    try:
        root = resolve_apps_root(os.environ, __file__)
    except FatalProvenanceRootError as exc:
        print("  UNAVAILABLE: %s" % exc)
        print("  Run this procedure from the INSTALLED app, or with SPLUNK_HOME set:")
        print("  list C is read from the metadata files, which is the only place a")
        print("  family the table ignores can be seen at all.")
        return 1 if not_found else 0

    code, document = rest.get("/services/apps/local", {"count": "0", "f": "title"})
    applications = [
        str(entry.get("name") or "") for entry in entries(document)
        if str(entry.get("name") or "")
    ]
    present = platform_family_stanzas(ProvenanceReader(root), applications)
    absent = sorted(family for family in present if table.resolve(family) is None)
    print("  read root              : %s" % root)
    print("  applications scanned   : %d" % len(applications))
    print("  distinct family stanzas: %d" % len(present))
    for family in absent:
        seen = sorted(present[family])
        print("  %-18s  seen in: %s%s" % (
            family,
            ", ".join(seen[:4]),
            " (+%d more)" % (len(seen) - 4) if len(seen) > 4 else "",
        ))
    if absent:
        print("  -> declare them in lookups/app_acl_family_map_override.csv BEFORE any")
        print("     real use: a family absent from the table comes out")
        print("     acl_status=rejected / acl_error=unresolved_family, and the")
        print("     inventory reports it with acl_write_path=unmapped.")
    else:
        print("  none: every family stanza seen on this platform is covered.")

    return 1 if absent else 0


if __name__ == "__main__":
    sys.exit(main())
