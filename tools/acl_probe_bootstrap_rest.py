# -*- coding: utf-8 -*-
"""acl_probe_bootstrap_rest.py — volet 2 de l'amorcage de l'app jetable `acl_probe`.

Cree par l'API REST ce que les fichiers de configuration ne permettent pas de
declarer : les objets **prives** (sharing=user, namespace utilisateur) et les
objets a **nom special** (barre oblique, espace, caractere accentue, pourcent).

Le mot de passe admin est lu sur la PREMIERE ligne de stdin : jamais en argv,
jamais ecrit sur disque, jamais imprime.

Usage :  op read "op://<vault>/<item>/password" | python3 acl_probe_bootstrap_rest.py
         python3 acl_probe_bootstrap_rest.py --remove   (idem, mdp sur stdin)

Idempotent : un objet deja present ressort en HTTP 409, traite comme un succes.
Identifiants volontairement generiques (depot public).
"""
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

# URI de splunkd. La boucle locale est le defaut : le script s'execute sur
# l'instance qu'il amorce. Aucune adresse d'environnement reel n'est codee ici.
import os
BASE = os.environ.get("SPLUNKD_URI", "https://127.0.0.1:8089")
APP = "acl_probe"
PRIVATE_OWNER = "admin"          # proprietaire des objets sharing=user
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


# Objets prives (sharing=user) : crees dans le namespace de leur proprietaire.
PRIVES = [
    ("saved/searches", {"name": "probe_search_user", "search": "index=_internal | head 1"}),
    ("saved/eventtypes", {"name": "probe_eventtype_user", "search": "index=_internal"}),
    ("data/ui/views", {"name": "probe_view_user",
                       "eai:data": "<dashboard version=\"1.1\"><label>Probe view user</label>"
                                   "<row><panel><html><p>probe</p></html></panel></row></dashboard>"}),
]

# Objets a nom special : un cas par classe de caractere du §10.4 du cahier des charges.
NOMS_SPECIAUX = [
    u"probe space name",        # espace
    u"probe/slash/name",        # barre oblique
    u"probe_accent_eaeiou_éàü",  # caracteres accentues
    u"probe_percent_100%",      # signe pourcent
]

REMOVE = "--remove" in sys.argv

if REMOVE:
    for path, params in PRIVES:
        p = "/servicesNS/%s/%s/%s/%s" % (PRIVATE_OWNER, APP, path, quote(params["name"], safe=""))
        print("DELETE %-58s HTTP %s" % (params["name"], call("DELETE", p)[0]))
    for t in NOMS_SPECIAUX:
        p = "/servicesNS/nobody/%s/saved/searches/%s" % (APP, quote(t, safe=""))
        print("DELETE %-58r HTTP %s" % (t, call("DELETE", p)[0]))
    sys.exit(0)

print("== objets prives (sharing=user, proprietaire %s) ==" % PRIVATE_OWNER)
for path, params in PRIVES:
    ns = "/servicesNS/%s/%s/%s" % (PRIVATE_OWNER, APP, path)
    code, body = call("POST", ns, urlencode({k: v.encode("utf-8") for k, v in params.items()}))
    # portee explicite : sharing=user (valeur par defaut, on la force pour etre deterministe)
    if code in (200, 201, 409):
        acl = "%s/%s/acl" % (ns, quote(params["name"], safe=""))
        code2, _ = call("POST", acl, urlencode({"owner": PRIVATE_OWNER, "sharing": "user",
                                                "perms.read": "", "perms.write": ""}))
    else:
        code2 = "-"
    print("  %-20s %-24s POST=%s  POST/acl=%s" % (path, params["name"], code, code2))

print("\n== objets a nom special (sharing=app) ==")
for t in NOMS_SPECIAUX:
    ns = "/servicesNS/nobody/%s/saved/searches" % APP
    code, body = call("POST", ns, urlencode({"name": t.encode("utf-8"),
                                             "search": "index=_internal | head 1"}))
    # REGLE D'ENCODAGE MESUREE EN LAB 9.4.6 : simple %-encodage du segment entier,
    # safe='' (donc '/' -> %2F). Le double encodage ne fonctionne QUE pour '/'.
    seg = quote(t, safe="")
    code2, _ = call("POST", "%s/%s/acl" % (ns, seg),
                    urlencode({"owner": "nobody", "sharing": "app",
                               "perms.read": "*", "perms.write": "admin"}))
    print("  %-42r POST=%s  seg=%-40s POST/acl=%s" % (t, code, seg, code2))

print("\n== controle : inventaire de l'app ==")
code, body = call("GET", "/servicesNS/-/%s/admin/directory?count=0&output_mode=json" % APP)
try:
    n = len(json.loads(body).get("entry", []))
except Exception:
    n = "?"
print("  admin/directory (contexte %s) : HTTP %s, %s objets" % (APP, code, n))
