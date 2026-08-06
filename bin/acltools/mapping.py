"""Table de correspondance `eai:type` -> chemin de handler (§6).

Deux sources, dans cet ordre : `bin/acl_endpoint_map.json` (livre), puis
`lookups/acl_endpoint_map_override.csv` (cree par l'exploitant, jamais livre — D-5),
qui surcharge la premiere.

Aucune heuristique de derivation n'est admise (§6.2) : `resolve` renvoie `None` sur
un type inconnu, jamais une valeur devinee. La mesure en lab le justifie
empiriquement — `commands` se resout en `admin/commandsconf`, `conf-times` en
`data/ui/times`.
"""

import csv
import json
import os
import re

from .errors import FatalMappingError

#: Un chemin de handler est un litteral URL-sur. Le fichier d'override etant
#: editable par l'exploitant, il constitue une entree non fiable : un chemin forge
#: pourrait viser un endpoint arbitraire.
HANDLER_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)*$")


def is_valid_handler_path(path):
    return bool(path) and bool(HANDLER_PATH_RE.match(path))


class Mapping(object):
    """Table `eai:type` -> `handler_path`, immuable apres construction."""

    def __init__(self, entries, from_json=(), from_override=(), rejected=()):
        self._entries = dict(entries)
        self._from_json = tuple(sorted(from_json))
        self._from_override = tuple(sorted(from_override))
        self._rejected = tuple(rejected)

    def resolve(self, eai_type):
        """Renvoie le `handler_path` d'un `eai:type`, ou `None` s'il est inconnu."""
        if not eai_type:
            return None
        return self._entries.get(str(eai_type).strip())

    def types(self):
        return tuple(sorted(self._entries))

    def coverage(self):
        """Etat de la table, pour le README §6.4 et la re-validation §6.5."""
        return {
            "total": len(self._entries),
            "from_json": len(self._from_json),
            "from_override": len(self._from_override),
            "overridden": tuple(
                t for t in self._from_override if t in self._from_json
            ),
            "rejected": self._rejected,
            "types": self.types(),
        }

    def __len__(self):
        return len(self._entries)

    def __contains__(self, eai_type):
        return self.resolve(eai_type) is not None


def load_mapping(json_path, override_csv_path=None, diag=None):
    """Charge la table livree puis l'override eventuel.

    `diag` est un callable optionnel `(niveau, message)` pour le journal de
    diagnostic ; le paquet ne connait pas `logging` de la plateforme.

    Erreurs : `FatalMappingError` si le JSON est absent, illisible ou mal forme (§9).
    Un CSV d'override **absent est normal** ; un CSV illisible produit un
    avertissement de diagnostic, pas une erreur fatale — l'absence d'override ne doit
    pas empecher l'execution avec la table livree.
    """
    def _diag(level, message):
        if diag is not None:
            diag(level, message)

    try:
        with open(json_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (IOError, OSError) as exc:
        raise FatalMappingError(
            "table de correspondance illisible (%s) : %s" % (json_path, exc)
        )
    except ValueError as exc:
        raise FatalMappingError(
            "table de correspondance mal formee (%s) : %s" % (json_path, exc)
        )

    if not isinstance(raw, dict):
        raise FatalMappingError(
            "table de correspondance mal formee (%s) : objet JSON attendu" % json_path
        )

    entries = {}
    rejected = []
    from_json = []
    for eai_type, handler_path in raw.items():
        key = str(eai_type).strip()
        value = str(handler_path).strip()
        if not key or not is_valid_handler_path(value):
            rejected.append((key, value, "acl_endpoint_map.json"))
            _diag("WARNING", "entree de table ecartee : %r -> %r" % (key, value))
            continue
        entries[key] = value
        from_json.append(key)

    from_override = []
    if override_csv_path and os.path.exists(override_csv_path):
        try:
            with open(override_csv_path, "r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = [
                    (name or "").strip() for name in (reader.fieldnames or [])
                ]
                if "eai_type" not in fieldnames or "handler_path" not in fieldnames:
                    raise ValueError(
                        "colonnes 'eai_type' et 'handler_path' attendues, vu %r"
                        % (fieldnames,)
                    )
                for row in reader:
                    key = (row.get("eai_type") or "").strip()
                    value = (row.get("handler_path") or "").strip()
                    if not key or key.startswith("#"):
                        # Ligne de commentaire : le fichier est edite a la main par
                        # l'exploitant, il en contient necessairement.
                        continue
                    if not is_valid_handler_path(value):
                        rejected.append((key, value, "override"))
                        _diag(
                            "WARNING",
                            "entree d'override ecartee : %r -> %r" % (key, value),
                        )
                        continue
                    entries[key] = value
                    from_override.append(key)
        except (IOError, OSError, ValueError, csv.Error) as exc:
            _diag(
                "WARNING",
                "override illisible, table livree conservee (%s) : %s"
                % (override_csv_path, exc),
            )

    return Mapping(entries, from_json, from_override, rejected)
