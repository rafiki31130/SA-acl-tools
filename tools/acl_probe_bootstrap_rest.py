# -*- coding: utf-8 -*-
"""acl_probe_bootstrap_rest.py - part 2 of the `acl_probe` throwaway app bootstrap.

Creates through the REST API what configuration files cannot declare: the
**private** objects (sharing=user, user namespace) and the objects with a
**special name** (slash, space, accented character, percent).

The admin password is read from the FIRST line of stdin: never in argv, never
written to disk, never printed.

Usage:  op read "op://<vault>/<item>/password" | python3 acl_probe_bootstrap_rest.py
        python3 acl_probe_bootstrap_rest.py --remove   (same, password on stdin)

Idempotent: an object that is already present comes back as HTTP 409, treated as a
success. Identifiers deliberately generic (public repository).
"""
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

# splunkd URI. The local loopback is the default: the script runs on the very
# instance it bootstraps. No real environment address is hard-coded here.
import os
BASE = os.environ.get("SPLUNKD_URI", "https://127.0.0.1:8089")
APP = "acl_probe"
PRIVATE_OWNER = "admin"          # owner of the sharing=user objects
_PW = sys.stdin.readline().rstrip("\r\n")
_AUTH = "Basic " + base64.b64encode(("admin:" + _PW).encode("utf-8")).decode("ascii")
_CTX = ssl._create_unverified_context()


def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, data=(body.encode("utf-8") if body is not None else None), method=method)
    req.add_header("Authorization", _AUTH)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = urllib.request.urlopen(req, context=_CTX, timeout=120)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


# Private objects (sharing=user): created in their owner's namespace.
PRIVATE_OBJECTS = [
    ("saved/searches", {"name": "probe_search_user", "search": "index=_internal | head 1"}),
    ("saved/eventtypes", {"name": "probe_eventtype_user", "search": "index=_internal"}),
    ("data/ui/views", {"name": "probe_view_user",
                       "eai:data": "<dashboard version=\"1.1\"><label>Probe view user</label>"
                                   "<row><panel><html><p>probe</p></html></panel></row></dashboard>"}),
]

# Objects with a special name: one case per character class of section 10.4 of the
# specification.
SPECIAL_NAMES = [
    u"probe space name",        # space
    u"probe/slash/name",        # slash
    u"probe_accent_eaeiou_éàü",  # accented characters
    u"probe_percent_100%",      # percent sign
]

REMOVE = "--remove" in sys.argv

if REMOVE:
    for path, params in PRIVATE_OBJECTS:
        p = "/servicesNS/%s/%s/%s/%s" % (PRIVATE_OWNER, APP, path, quote(params["name"], safe=""))
        print("DELETE %-58s HTTP %s" % (params["name"], call("DELETE", p)[0]))
    for t in SPECIAL_NAMES:
        p = "/servicesNS/nobody/%s/saved/searches/%s" % (APP, quote(t, safe=""))
        print("DELETE %-58r HTTP %s" % (t, call("DELETE", p)[0]))
    sys.exit(0)

print("== private objects (sharing=user, owner %s) ==" % PRIVATE_OWNER)
for path, params in PRIVATE_OBJECTS:
    ns = "/servicesNS/%s/%s/%s" % (PRIVATE_OWNER, APP, path)
    code, body = call("POST", ns, urlencode({k: v.encode("utf-8") for k, v in params.items()}))
    # explicit sharing scope: sharing=user (the default value, forced here to be deterministic)
    if code in (200, 201, 409):
        acl = "%s/%s/acl" % (ns, quote(params["name"], safe=""))
        code2, _ = call("POST", acl, urlencode({"owner": PRIVATE_OWNER, "sharing": "user",
                                                "perms.read": "", "perms.write": ""}))
    else:
        code2 = "-"
    print("  %-20s %-24s POST=%s  POST/acl=%s" % (path, params["name"], code, code2))

print("\n== objects with a special name (sharing=app) ==")
for t in SPECIAL_NAMES:
    ns = "/servicesNS/nobody/%s/saved/searches" % APP
    code, body = call("POST", ns, urlencode({"name": t.encode("utf-8"),
                                             "search": "index=_internal | head 1"}))
    # ENCODING RULE MEASURED ON THE 9.4.6 REFERENCE PLATFORM: plain %-encoding of the
    # whole segment, safe='' (so '/' -> %2F). Double encoding works ONLY for '/'.
    seg = quote(t, safe="")
    code2, _ = call("POST", "%s/%s/acl" % (ns, seg),
                    urlencode({"owner": "nobody", "sharing": "app",
                               "perms.read": "*", "perms.write": "admin"}))
    print("  %-42r POST=%s  seg=%-40s POST/acl=%s" % (t, code, seg, code2))

print("\n== check: app inventory ==")
code, body = call("GET", "/servicesNS/-/%s/admin/directory?count=0&output_mode=json" % APP)
try:
    n = len(json.loads(body).get("entry", []))
except Exception:
    n = "?"
print("  admin/directory (context %s): HTTP %s, %s objects" % (APP, code, n))
