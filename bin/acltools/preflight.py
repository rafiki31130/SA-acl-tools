"""Legitimite de l'execution, etablie une fois pour toutes avant tout evenement (§5.1).

`validate_params` est **pure** et se teste seule. Le reste consomme un `RestPort` et se
teste par substitution — aucun mock HTTP, aucune socket.
"""

import json

from .endpoint import encode_namespace_segment
from .errors import FatalCapabilityError, FatalConfigError
from .merge import parse_fields
from .model import Params
# Import relatif d'un **predicat pur** : `preflight` continue de ne consommer qu'un
# port `RestPort` et reste substituable sans socket. Voir `rest.is_tls_failure`.
from .rest import TLS_REMEDIATION, is_tls_failure

#: Capability dediee, declaree par `default/authorize.conf` (§7). Splunk n'offre pas de
#: gating natif des commandes de recherche par capability : le controle est implemente
#: dans le code et constitue une erreur fatale.
REQUIRED_CAPABILITY = "edit_acl_bulk"

#: Le role `*` est une valeur legitime du referentiel et n'est **jamais** developpe en
#: liste de roles (§10.2).
WILDCARD_ROLE = "*"

DEFAULT_MAX_OBJECTS = 500

#: Rappel emis en tete d'execution quand la simulation est active (§4.1).
#:
#: `dryrun` vaut `true` par defaut : sans ce rappel, une execution qui n'ecrit rien est
#: indiscernable d'une execution qui a tout ecrit — les deux rendent une table de
#: resultats pleine, et seule la colonne `acl_status` les distingue. C'est le parametre
#: le plus consequent de la commande, et son etat par defaut etait le seul a n'etre
#: signale nulle part.
#:
#: Le message porte les deux informations que l'operateur doit avoir : ce qui ne se
#: produira pas, et le geste exact qui le produirait.
#:
#: Il est porte par `Params.warnings`, donc emis **une seule fois par execution** par
#: l'adaptateur (§5.1) — jamais par evenement. Un lot de plusieurs centaines d'objets
#: le repeterait autant de fois, et un avertissement repete se filtre mentalement :
#: il cesserait d'etre lu exactement la ou il compte.
#:
#: C'est un avertissement (`MSG[WARN]`), jamais une erreur : il ne change ni le statut
#: du job, ni le nombre de resultats, ni le code de sortie de la commande.
DRYRUN_WARNING = (
    "simulation active (dryrun=true, valeur par defaut) : AUCUNE modification ne "
    "sera ecrite. Les objets ressortent en acl_status=dryrun. Pour appliquer "
    "reellement les changements, relancer la meme recherche avec dryrun=false."
)


def _decode(response):
    """Decode un corps de reponse JSON. Renvoie `None` si indecodable."""
    if response is None or response.status != 200 or not response.body:
        return None
    try:
        return json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return None


def _as_bool(raw, name, default=None):
    """Coerce un booleen. `None` signifie « non fourni » et retombe sur le defaut du
    §4.1 : le SDK expose une option non renseignee comme `None`, pas comme sa valeur
    par defaut."""
    if raw is None and default is not None:
        return default
    if isinstance(raw, bool):
        return raw
    token = str(raw).strip().lower()
    if token in ("1", "true", "t", "yes", "y", "on"):
        return True
    if token in ("0", "false", "f", "no", "n", "off"):
        return False
    raise FatalConfigError("parametre invalide : '%s' n'est pas un booleen (%r)" % (name, raw))


def validate_params(
    fields_raw=None,
    dryrun=True,
    validate_roles=True,
    journal=True,
    max_objects=DEFAULT_MAX_OBJECTS,
    max_objects_explicit=True,
):
    """Valide les parametres du §4.1. Fonction pure.

    Erreurs : `FatalConfigError` si `fields` contient une valeur non admise — dont
    `owner` — ou si `max_objects` n'est pas un entier strictement positif (§9).
    """
    fields = parse_fields(fields_raw)
    dryrun = _as_bool(dryrun, "dryrun", default=True)
    validate_roles = _as_bool(validate_roles, "validate_roles", default=True)
    journal = _as_bool(journal, "journal", default=True)

    if max_objects is None:
        max_objects = DEFAULT_MAX_OBJECTS
    try:
        max_objects_int = int(str(max_objects).strip())
    except (TypeError, ValueError):
        raise FatalConfigError(
            "parametre invalide : 'max_objects' doit etre un entier strictement "
            "positif (%r)" % (max_objects,)
        )
    if max_objects_int <= 0:
        raise FatalConfigError(
            "parametre invalide : 'max_objects' doit etre un entier strictement "
            "positif (%r)" % (max_objects,)
        )

    warnings = []
    if dryrun:
        warnings.append(DRYRUN_WARNING)
    if not dryrun and not max_objects_explicit:
        warnings.append(
            "dryrun=false sans max_objects explicite : plafond par defaut applique "
            "(%d)" % max_objects_int
        )

    return Params(
        fields=fields,
        dryrun=dryrun,
        validate_roles=validate_roles,
        journal=journal,
        max_objects=max_objects_int,
        warnings=tuple(warnings),
    )


def check_capability(rest):
    """Controle d'habilitation (§5.1 etape 3).

    `content.capabilities` de `current-context` est l'ensemble **effectif aplati** des
    capabilities de l'utilisateur, heritage `imported_roles` compris (mesure 6). Le
    controle se reduit donc a un test d'appartenance ; aucun parcours de la hierarchie
    de roles n'est necessaire.
    """
    response = rest.get_json("/services/authentication/current-context", None)
    document = _decode(response)
    if document is None:
        # Le premier appel REST de l'execution est aussi celui sur lequel un socle a
        # certificat auto-signe echoue. Sans designation explicite, l'operateur ne lit
        # qu'un « HTTP 0 » sur un endpoint d'authentification et cherche du cote des
        # droits, pas du certificat.
        if is_tls_failure(response):
            raise FatalCapabilityError(
                "%s (detail : %s)" % (TLS_REMEDIATION, response.error)
            )
        raise FatalCapabilityError(
            "controle d'habilitation impossible : reponse inexploitable de "
            "/services/authentication/current-context (HTTP %s%s)"
            % (
                getattr(response, "status", "?"),
                ", %s" % response.error if getattr(response, "error", None) else "",
            )
        )
    try:
        content = document["entry"][0]["content"]
    except (KeyError, IndexError, TypeError):
        raise FatalCapabilityError(
            "controle d'habilitation impossible : structure de reponse inattendue"
        )

    capabilities = content.get("capabilities") or []
    if REQUIRED_CAPABILITY not in capabilities:
        roles = content.get("roles") or []
        raise FatalCapabilityError(
            "capability '%s' absente. Roles de l'utilisateur : %s"
            % (REQUIRED_CAPABILITY, ", ".join(str(role) for role in roles) or "(aucun)")
        )


def check_realtime(rest, sid):
    """Controle du mode temps reel (§4.2, D-2).

    Renvoie `"realtime"` (jamais atteint : une exception est levee), `"batch"` si la
    recherche est confirmee non temps reel, ou `"unknown"` si la detection n'a pas
    abouti. Le garde-fou ne se transforme pas en faux positif : une detection qui
    n'aboutit pas est signalee par l'enveloppe, pas transformee en refus.

    Erreurs : `FatalCapabilityError` si le mode temps reel est detecte.
    """
    if not sid:
        return "unknown"

    response = rest.get_json(
        "/services/search/jobs/%s" % encode_namespace_segment(sid), None
    )
    document = _decode(response)
    if document is None:
        return "unknown"
    try:
        content = document["entry"][0]["content"]
    except (KeyError, IndexError, TypeError):
        return "unknown"

    flag = content.get("isRealTimeSearch")
    if flag is not None:
        if _truthy(flag):
            raise FatalCapabilityError(
                "execution en recherche temps reel refusee (§4.2)."
            )
        return "batch"

    # Repli : inspection des bornes temporelles.
    earliest = str(content.get("earliest_time") or "")
    latest = str(content.get("latest_time") or "")
    if earliest.startswith("rt") or latest.startswith("rt"):
        raise FatalCapabilityError(
            "execution en recherche temps reel refusee (§4.2)."
        )
    if earliest or latest:
        return "batch"
    return "unknown"


def _truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y", "on")


def load_roles_catalog(rest):
    """Referentiel des roles existants (§5.1 etape 5).

    Cet appel ne sert **qu'a** `validate_roles` : il est inutile au controle
    d'habilitation, que la mesure 6 reduit a un test d'appartenance.
    """
    response = rest.get_json(
        "/services/authorization/roles", {"count": "0", "f": "title"}
    )
    document = _decode(response)
    roles = {WILDCARD_ROLE}
    if document is None:
        return frozenset(roles)
    for entry in document.get("entry") or []:
        name = entry.get("name")
        if name:
            roles.add(str(name))
    return frozenset(roles)


def resolve_server_name(rest):
    """`serverName` du membre, pour le champ `host` du journal. `""` si indisponible."""
    response = rest.get_json("/services/server/info", None)
    document = _decode(response)
    if document is None:
        return ""
    try:
        return str(document["entry"][0]["content"].get("serverName") or "")
    except (KeyError, IndexError, TypeError):
        return ""


class AppStateCache(object):
    """Etat d'activation des apps, **memoise par app** (§10.5).

    L'information n'est portee ni par l'evenement ni par la reponse `/acl` : elle exige
    un appel dedie. Cout : un appel par app distincte sur l'execution.
    """

    def __init__(self, rest):
        self._rest = rest
        self._cache = {}

    def is_app_disabled(self, app):
        if app in self._cache:
            return self._cache[app]
        disabled = False
        response = self._rest.get_json(
            "/services/apps/local/%s" % encode_namespace_segment(app), None
        )
        document = _decode(response)
        if document is not None:
            try:
                content = document["entry"][0]["content"]
                disabled = _truthy(content.get("disabled"))
            except (KeyError, IndexError, TypeError):
                disabled = False
        self._cache[app] = disabled
        return disabled
