#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-validation de la table de correspondance sur le socle cible (§6.5).

La table livree dans `bin/acl_endpoint_map.json` a ete etablie empiriquement sur une
seule version de Splunk Enterprise. Elle n'est **pas** presumee valable ailleurs :
l'execution de cette procedure sur le socle cible est un **prerequis a tout usage
reel** de `editacl`.

La procedure :

  1. enumere les `eai:type` distincts effectivement presents sur le socle — reunion de
     ce qu'emet le handler d'agregation `admin/directory` et de ce qu'emettent les
     endpoints natifs de la table ;
  2. les confronte a la table livree (override compris) ;
  3. produit les trois listes exigees par le cahier des charges :
       A. correspondances **confirmees par un GET reel** sur un objet temoin,
       B. correspondances de la table **introuvables sur le socle**,
       C. types presents sur le socle et **absents de la table**.

  4. controle en supplement la coherence entre `bin/acl_endpoint_map.json` (lu par le
     code Python) et `lookups/acl_object_families.csv` (lu par la macro d'inventaire,
     SPL ne sachant pas lire de JSON). Les deux fichiers portent la meme information
     sous deux formes ; une divergence rendrait l'inventaire et la resolution
     incoherents.

La liste C se traite par le fichier d'override `lookups/acl_endpoint_map_override.csv`,
sans modification du code. La liste B est informative : une correspondance sans objet
temoin sur le socle n'est pas fausse, elle est seulement invalidable ici.

Pourquoi un script Python et non une recherche SPL : la construction de l'URI d'un
objet obeit a une regle d'encodage unique et non evidente, implementee une seule fois
dans `acltools.endpoint`. La reecrire en SPL creerait une seconde implementation qui
divergerait — exactement le defaut que la regle du point d'injection unique interdit.
Ce script **reutilise** `acltools.mapping.load_mapping` (donc `Mapping.coverage()`) et
`acltools.endpoint.build_object_path` ; il ne reimplemente rien.

Le mot de passe est lu sur la PREMIERE ligne de stdin : jamais en argv, jamais ecrit
sur disque, jamais imprime.

Usage, depuis la racine du depot ou de l'app installee :

    <commande qui fournit le mot de passe> | python3 tools/revalidate_mapping.py \\
        [--user admin] [--splunkd-uri https://127.0.0.1:8089] [--insecure]

Code de retour : 0 si la liste C est vide, 1 sinon (des types du socle ne sont pas
resolus par la table : l'override doit etre complete avant tout usage reel).
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
        """Renvoie `(code_http, document)`. `document` vaut `{}` sur echec."""
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
        except Exception:  # noqa: BLE001 — un socle injoignable n'est pas une exception
            return 0, {}
        try:
            return code, json.loads(body)
        except ValueError:
            return code, {}


def entries(doc):
    return doc.get("entry", []) if isinstance(doc, dict) else []


def read_families_csv(path):
    """`lookups/acl_object_families.csv` -> {famille: handler_path}."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            family = (row.get("family") or "").strip()
            handler = (row.get("handler_path") or "").strip()
            if family and not family.startswith("#"):
                out[family] = handler
    return out


def platform_types(rest, mapping):
    """`eai:type` distincts reellement emis par le socle.

    Deux sources, unionnees : le handler d'agregation, et les endpoints natifs de la
    table. La seconde est indispensable — la majorite des endpoints natifs n'emet
    aucun `eai:type`, mais quelques-uns en emettent un que `admin/directory` ne montre
    pas (les modeles de donnees, par exemple, en sont totalement absents).
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
    """Premier objet listable par ce handler, avec son namespace reel.

    Le namespace est lu dans le bloc `acl` de l'entree, jamais suppose : un objet
    `sharing=user` n'est adressable que dans le namespace de SON proprietaire.
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
                        help="compte utilise pour les appels REST (defaut : admin)")
    parser.add_argument("--splunkd-uri", default="https://127.0.0.1:8089",
                        help="URI de splunkd (defaut : boucle locale)")
    parser.add_argument("--insecure", action="store_true",
                        help="ne pas verifier le certificat de splunkd "
                             "(socle a certificat auto-signe)")
    args = parser.parse_args()

    password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        sys.stderr.write("mot de passe attendu sur la premiere ligne de stdin\n")
        return 2
    auth = "Basic " + base64.b64encode(
        ("%s:%s" % (args.user, password)).encode("utf-8")).decode("ascii")
    context = ssl._create_unverified_context() if args.insecure \
        else ssl.create_default_context()
    rest = Rest(args.splunkd_uri, auth, context)

    mapping = load_mapping(JSON_PATH, OVERRIDE_PATH)
    coverage = mapping.coverage()

    print("== table livree ==")
    print("  entrees effectives     : %d" % coverage["total"])
    print("  issues du JSON         : %d" % coverage["from_json"])
    print("  issues de l'override   : %d" % coverage["from_override"])
    if coverage["overridden"]:
        print("  cles surchargees       : %s" % ", ".join(coverage["overridden"]))
    for key, value, source in coverage["rejected"]:
        print("  ECARTEE (%s) : %r -> %r" % (source, key, value))

    present = platform_types(rest, mapping)
    print("\n== socle ==")
    print("  types distincts emis   : %d" % len(present))

    confirmees, introuvables = [], []
    for eai_type in coverage["types"]:
        handler = mapping.resolve(eai_type)
        obj, code = witness(rest, handler)
        if obj is None:
            introuvables.append((eai_type, handler, "aucun objet listable (HTTP %s)" % code))
            continue
        path = build_object_path(obj["owner"], obj["app"], handler, obj["title"])
        code_obj, _ = rest.get(path)
        code_acl, _ = rest.get(path + "/acl")
        if code_obj == 200 and code_acl == 200:
            confirmees.append((eai_type, handler, obj["app"], obj["title"]))
        else:
            introuvables.append(
                (eai_type, handler, "GET=%s GET/acl=%s" % (code_obj, code_acl)))

    absents = sorted(t for t in present if mapping.resolve(t) is None)

    print("\n== A. correspondances confirmees par un GET reel (%d) ==" % len(confirmees))
    for eai_type, handler, app, title in confirmees:
        print("  %-22s -> %-32s  temoin : %s / %s" % (eai_type, handler, app, title))

    print("\n== B. correspondances de la table introuvables sur le socle (%d) =="
          % len(introuvables))
    for eai_type, handler, why in introuvables:
        print("  %-22s -> %-32s  %s" % (eai_type, handler, why))
    if introuvables:
        print("  (informatif : une correspondance sans objet temoin n'est pas fausse,")
        print("   elle est seulement invalidable sur ce socle)")

    print("\n== C. types presents sur le socle et absents de la table (%d) =="
          % len(absents))
    for eai_type in absents:
        print("  %-22s  emis par : %s" % (eai_type, ", ".join(sorted(present[eai_type]))))
    if absents:
        print("  -> a declarer dans lookups/acl_endpoint_map_override.csv AVANT tout")
        print("     usage reel : un type absent de la table produit acl_status=rejected.")

    families = read_families_csv(FAMILIES_PATH)
    handlers_json = {mapping.resolve(t) for t in coverage["types"]}
    handlers_csv = set(families.values())
    manquants = sorted(handlers_json - handlers_csv)
    surnumeraires = sorted(handlers_csv - handlers_json)
    mal_cles = sorted(f for f, h in families.items() if mapping.resolve(f) != h)

    print("\n== D. coherence table JSON <-> lookup des familles ==")
    print("  handlers de la table   : %d" % len(handlers_json))
    print("  handlers du lookup     : %d" % len(handlers_csv))
    for handler in manquants:
        print("  ABSENT DU LOOKUP  : %s (l'inventaire ne verra pas cette famille)" % handler)
    for handler in surnumeraires:
        print("  ABSENT DE LA TABLE: %s (inventorie mais non resolvable)" % handler)
    for family in mal_cles:
        print("  INCOHERENT        : famille %r -> %r cote lookup, %r cote table"
              % (family, families[family], mapping.resolve(family)))
    if not (manquants or surnumeraires or mal_cles):
        print("  coherents")

    return 1 if absents else 0


if __name__ == "__main__":
    sys.exit(main())
