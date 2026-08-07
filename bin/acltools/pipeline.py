"""Machine a etats du traitement d'un evenement (§5, §8.4, §4.3, §10.8).

Porte l'ordre des lignes de journal vis-a-vis du POST, le compteur `max_objects` et la
deduplication par URI. C'est le module qui tient les trois invariants verifiables du
§8.2.

Aucune exception inattendue ne le traverse : toute `Exception` non prevue est
convertie en `EventRejected("error", "internal:...")`, faute de quoi une trace non
capturee interromprait la recherche et violerait le §9.
"""

import json
from dataclasses import replace
from datetime import datetime

from .derived import CarrierProbe
from .endpoint import build_object_path, resolve_handler_path
from .errors import EventRejected, MaxObjectsReached
from .journal import build_intent_record, build_outcome_record
from .merge import is_noop, merge, validate_roles
from .model import EventResult
from .normalize import parse_acl_state

MAX_ERROR_LEN = 512

#: Contexte applicatif hors perimetre (§1.3, §4.2). Refus **par evenement** : le §9
#: enumere limitativement les erreurs fatales et ne l'y fait pas figurer.
FORBIDDEN_APP = "system"

#: Classe de codes HTTP d'un refus de persistance cote handler splunkd. Mesure en lab :
#: le POST est refuse, la vue **runtime** de splunkd est neanmoins mutee, le disque
#: reste intact.
#:
#: **Toute la classe `5xx`, pas le seul `500`** (D-16). Rien dans le mecanisme observe
#: n'attache la divergence au code `500` en particulier : elle tient a ce que le
#: handler a mute son etat en memoire avant d'echouer a le persister, ce qu'un `502`,
#: un `503` ou un `507` produisent aussi bien. Restreindre l'avertissement a `500`
#: laisserait passer sans signal exactement le cas qu'il doit couvrir.
PERSISTENCE_FAILURE_MIN = 500
PERSISTENCE_FAILURE_MAX = 600


def is_persistence_failure(status):
    """Vrai si `status` releve de la classe `5xx` (D-16)."""
    return PERSISTENCE_FAILURE_MIN <= int(status) < PERSISTENCE_FAILURE_MAX

#: Avertissement porte par `acl_warning` quand la persistance est refusee. La
#: divergence est produite par la plateforme et la commande ne peut pas l'empecher ;
#: elle doit la rendre **visible**.
RUNTIME_DIVERGENCE_WARNING = "runtime_divergence_possible"

#: Texte adresse a l'operateur au niveau de la recherche, emis une fois par execution.
#: `acl_warning` est un jeu de jetons concatenes : la phrase ne peut pas y tenir.
RUNTIME_DIVERGENCE_MESSAGE = (
    "au moins un objet a ete refuse en HTTP 5xx (persistance) : la vue runtime de "
    "splunkd peut avoir ete mutee alors que le disque ne l'est pas, et c'est cette vue "
    "que voient les utilisateurs, les recherches et les controles d'acces jusqu'au "
    "prochain rechargement de configuration. Ces objets ne sont PAS couverts par "
    "editacl_rollback, qui ne retient que les ecritures abouties : la remise en etat "
    "passe par un rechargement de configuration ou un redemarrage du membre, pas par "
    "la restauration."
)


def default_clock():
    """Horodatage ISO 8601 avec fuseau explicite et **millisecondes obligatoires**.

    Aligne sur le `TIME_FORMAT` de `props.conf` (§8.3) : les millisecondes departagent
    deux mutations rapprochees, ce dont depend le `earliest(...)` de la macro §8.6.
    """
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _truncate(message):
    text = "" if message is None else str(message)
    return text[:MAX_ERROR_LEN]


class _Work(object):
    """Etat mutable du traitement d'un evenement, fige en `EventResult` a la sortie."""

    __slots__ = (
        "title", "app", "eai_type", "endpoint", "owner", "http_code", "status",
        "error", "warnings", "before", "after", "journaled", "post_attempted",
        "counted", "source", "platform_name",
    )

    def __init__(self, event):
        self.title = str(event.title or "")
        self.app = str(event.app or "")
        self.eai_type = str(event.eai_type or "")
        self.endpoint = ""
        self.owner = str(event.owner or "")
        self.http_code = 0
        self.status = "error"
        self.error = None
        self.warnings = []
        self.before = None
        self.after = None
        self.journaled = False
        self.post_attempted = False
        self.counted = False
        self.source = ""
        #: Identite renvoyee par splunkd dans la reponse du GET (§5.3), jamais le
        #: `title` de l'evenement : le §5.3 pose que le GET fait autorite, et un `eval`
        #: en amont peut avoir forge le `title`.
        self.platform_name = None

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def result(self):
        return EventResult(
            status=self.status,
            title=self.title,
            app=self.app,
            eai_type=self.eai_type,
            endpoint=self.endpoint,
            owner=self.owner,
            http_code=int(self.http_code or 0),
            error=self.error,
            warnings=tuple(self.warnings),
            before=self.before,
            after=self.after,
            journaled=self.journaled,
            post_attempted=self.post_attempted,
            counted=self.counted,
            source=self.source,
        )


class _FailedPost(object):
    """Memoire d'un POST **emis et refuse**, pour la deduplication du §10.8.

    Un POST refuse ne modifie pas l'objet : son etat anterieur reste l'etat courant.
    Sans cette memoire, une seconde occurrence du meme objet relit l'etat, recalcule la
    meme fusion, ecrit une **seconde ligne `intent` rigoureusement identique** a la
    premiere et reemet le meme POST — ce que le §8.5 (univocite du triplet
    `sid` + `endpoint` + `phase`) et D-6 excluent, et ce que le §10.8 economise
    explicitement.
    """

    __slots__ = ("before", "after", "status", "error", "http_code", "warnings")

    def __init__(self, before, after, status, error, http_code, warnings=()):
        self.before = before
        self.after = after
        self.status = status
        self.error = error
        self.http_code = http_code
        self.warnings = tuple(warnings)


class EventProcessor(object):
    """Traite un evenement et produit exactement un `EventResult`.

    Le compteur `counter` est incremente a chaque POST **emis**, qu'il aboutisse ou
    echoue. Les statuts sans POST ne le comptent pas (§4.3).
    """

    def __init__(
        self,
        params,
        ctx,
        rest,
        journal=None,
        mapping=None,
        roles_catalog=frozenset(),
        app_disabled_fn=None,
        clock=None,
    ):
        self._params = params
        self._ctx = ctx
        self._rest = rest
        self._journal = journal
        self._mapping = mapping
        self._roles = frozenset(roles_catalog or ())
        self._app_disabled_fn = app_disabled_fn
        self._clock = clock or default_clock
        #: Sonde du rang 0 (§3.4, D-18). Elle n'emet un appel que sur un objet dont la
        #: famille et la cle composite designent deja un porteur : sur un lot sans
        #: `fvtags`, son cout est nul.
        self._carrier = CarrierProbe(rest)
        self.counter = 0
        #: endpoint -> etat resultant d'un POST **abouti**.
        self._written = {}
        #: endpoint -> `_FailedPost` d'un POST **emis et refuse**.
        self._failed = {}
        #: endpoint -> identite renvoyee par splunkd au premier GET reussi (§5.3).
        #:
        #: Cette memoire n'existe que pour le court-circuit de deduplication du §10.8 :
        #: le rang 0 du §5.4 lit `work.platform_name`, or le court-circuit rend la main
        #: sans emettre de GET. Sans elle, la deduplication et l'identification des
        #: derives seraient couplees par une propriete **externe** — un derive n'emet
        #: pas de POST, il n'entre donc pas dans `_written` / `_failed` — au lieu de
        #: l'etre par une garantie locale. La propriete est vraie, mais elle appartient
        #: a un autre mecanisme et se romprait sans bruit a la premiere evolution de la
        #: deduplication.
        self._platform_names = {}

    # -- point d'entree unique --------------------------------------------- #

    def process(self, event):
        work = _Work(event)
        try:
            self._run(event, work)
        except MaxObjectsReached:
            # Sortie fatale : ni ligne `intent`, ni ligne `outcome`, ni evenement de
            # sortie. Le controle du plafond precede toute ecriture de journal
            # precisement pour ne pas bruiter la signature « intent sans outcome ».
            raise
        except EventRejected as exc:
            work.status = exc.status
            work.error = exc.error
        except Exception as exc:                                     # pragma: no cover
            work.status = "error"
            work.error = _truncate(
                "internal:%s: %s" % (type(exc).__name__, exc)
            )
        return self._emit(work.result())

    # -- machine a etats ---------------------------------------------------- #

    def _run(self, event, work):
        self._check_required(event)

        handler_path, source = resolve_handler_path(
            event.id_value, event.eai_type, self._mapping
        )
        work.source = source
        work.endpoint = build_object_path(
            event.owner, event.app, handler_path, event.title
        )

        before = self._read_state(work)
        work.owner = before.owner or work.owner

        # Rang 0 (§3.4, D-18) — il precede TOUS les autres controles, y compris
        # `can_change_perms`. La relation de derivation est decouverte aupres de la
        # plateforme : famille issue du chemin de handler resolu, identite issue de la
        # reponse du GET, existence du porteur confirmee par un GET reel. Rien n'est
        # reconstruit par concatenation a partir du nom d'un parent.
        #
        # Le controle est place ici, apres le GET et **avant** la fusion : l'objet n'est
        # pas modifie, il n'a donc pas d'etat cible, et sa ligne `outcome` ne porte pas
        # de `before_*` / `after_*` — ce qui est exactement l'enumeration du §8.2.
        carrier, carrier_warning = self._carrier.carrier_of(
            event.owner, event.app, handler_path, work.platform_name
        )
        if carrier_warning:
            work.warn(carrier_warning)
        if carrier is not None:
            raise EventRejected("skipped_derived", "derived_object:%s" % carrier)

        if self._app_disabled_fn is not None and self._app_disabled_fn(event.app):
            work.warn("app_disabled")

        merged = merge(before, event, self._params.fields)
        work.before = merged.before
        work.after = merged.after
        for warning in merged.warnings:
            work.warn(warning)

        if merged.rejection is not None:                              # rangs 1 a 4
            raise merged.rejection

        if self._params.validate_roles:                               # rang 5
            unknown_added, stale_preserved = validate_roles(
                merged.before, merged.after, self._roles
            )
            if stale_preserved:
                work.warn("stale_role_preserved:%s" % ",".join(stale_preserved))
            if unknown_added:
                raise EventRejected(
                    "invalid_role", "invalid_role:%s" % ",".join(unknown_added)
                )

        if is_noop(merged.before, merged.after):                      # rang 6
            # Le rang 6 precede le rang 7 : un objet deja conforme est un `noop` meme
            # en simulation. C'est ce qui permet de mesurer la convergence d'un lot
            # sans ecrire.
            work.status = "noop"
            return

        if self._params.dryrun:                                       # rang 7
            work.status = "dryrun"
            return

        failed = self._failed.get(work.endpoint)
        if failed is not None and failed.after == merged.after:
            # §10.8 : le meme objet, deja soumis au meme etat cible dans cette
            # execution, n'est pas resoumis. Le resultat du premier envoi est reproduit
            # tel quel — ni ligne `intent`, ni POST, ni increment du compteur. Une
            # occulation serait pire : le doublon ressortirait `updated` sur un objet
            # que la plateforme a refuse d'ecrire.
            work.status = failed.status
            work.error = failed.error
            work.http_code = failed.http_code
            for warning in failed.warnings:
                work.warn(warning)
            work.warn("duplicate_post_suppressed")
            return

        if self.counter >= self._params.max_objects:
            raise MaxObjectsReached(self._params.max_objects)

        if self._journal is not None:
            record = build_intent_record(self._ctx, work.result(), self._clock())
            if not self._journal.write_intent(record):
                # L'echec de la sequence write + flush + fsync annule le POST pour
                # l'objet concerne (§8.4).
                raise EventRejected("error", "journal_intent_failed")
            work.journaled = True

        work.post_attempted = True
        response = self._rest.post_object_acl(work.endpoint, merged.payload)
        self.counter += 1
        work.counted = True
        work.http_code = response.status

        if 200 <= response.status < 300:
            work.status = "updated"
            self._written[work.endpoint] = merged.after
        else:
            work.status = "error"
            work.error = _truncate(
                "post_failed:%d:%s"
                % (response.status, response.error or response.text())
            )
            if is_persistence_failure(response.status):
                # Un refus de persistance laisse la vue **runtime** de splunkd mutee
                # alors que le disque est intact : la commande dit vrai vis-a-vis du
                # disque et faux vis-a-vis de ce que voient les utilisateurs, les
                # recherches et les controles d'acces. L'objet est de surcroit exclu du
                # jeu de restauration — `editacl_rollback` ne retient que les `outcome`
                # de statut `updated`, filtre correct au regard du disque et muet au
                # regard de l'observable. La divergence est produite par la plateforme
                # et n'est pas evitable ; elle doit etre visible.
                work.warn(RUNTIME_DIVERGENCE_WARNING)
            self._failed[work.endpoint] = _FailedPost(
                merged.before,
                merged.after,
                work.status,
                work.error,
                response.status,
                tuple(work.warnings),
            )

    # -- etapes --------------------------------------------------------- #

    def _check_required(self, event):
        for name, value in (
            ("title", event.title),
            ("eai:acl.app", event.app),
            ("eai:acl.owner", event.owner),
        ):
            if not str(value or "").strip():
                raise EventRejected("rejected", "missing_field:%s" % name)
        if str(event.app).strip().lower() == FORBIDDEN_APP:
            raise EventRejected("rejected", "app_system_forbidden")

    def _read_state(self, work):
        """Lecture de l'etat courant (§5.3). Le resultat du GET fait autorite.

        La deduplication du §10.8 court-circuite le GET pour un objet deja soumis a un
        POST dans l'execution courante : l'etat memorise tient lieu d'etat courant. Il
        vaut l'etat cible si le POST a abouti, l'etat anterieur s'il a ete refuse — un
        POST refuse ne modifie pas l'objet.

        Ce court-circuit est aussi ce qui rend le traitement **deterministe** sur le cas
        du §5.6 : un refus `HTTP 500` de persistance laisse la vue runtime mutee, si
        bien qu'une relecture ferait ressortir le doublon en `noop` et masquerait
        l'echec. La memoire d'execution fait autorite sur cette vue divergente.

        La deduplication ne modifie jamais le nombre d'evenements de sortie ni le
        nombre de lignes `outcome`.

        **Le court-circuit restitue l'identite de plateforme** memorisee au premier GET.
        Le rang 0 du §5.4 la lit juste apres cet appel : la laisser a `None` rendrait le
        controle de derivation inoperant sur une seconde occurrence du meme endpoint.
        La sortie de cette methode porte donc le meme `platform_name` par les deux
        chemins — c'est une garantie **locale**, qui ne suppose rien du mecanisme qui
        alimente `_written` / `_failed`.
        """
        cached = self._written.get(work.endpoint)
        if cached is None:
            failed = self._failed.get(work.endpoint)
            cached = failed.before if failed is not None else None
        if cached is not None:
            work.http_code = 200
            work.platform_name = self._platform_names.get(work.endpoint)
            return cached

        response = self._rest.get_object_acl(work.endpoint)
        work.http_code = response.status
        if response.status == 404:
            raise EventRejected("not_found", "get_404")
        if response.status == 403:
            raise EventRejected("forbidden", "get_403")
        if not (200 <= response.status < 300):
            raise EventRejected(
                "error",
                _truncate(
                    "get_failed:%d:%s"
                    % (response.status, response.error or response.text())
                ),
            )
        try:
            document = json.loads(response.body.decode("utf-8", "replace"))
            entry = document["entry"][0]
            acl_block = entry["acl"]
            # Identite canonique de l'objet telle que splunkd la renvoie. Elle alimente
            # le rang 0 du §5.4 : c'est la donnee de plateforme sur laquelle repose
            # l'identification d'un derive, par opposition au `title` de l'evenement.
            work.platform_name = entry.get("name")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise EventRejected(
                "error", _truncate("get_parse_failed:%s" % (exc,))
            )
        self._platform_names[work.endpoint] = work.platform_name
        return parse_acl_state(acl_block)

    def _emit(self, result):
        """Ecrit la ligne `outcome` et renvoie le resultat definitif.

        `write_outcome` est appele sur **toutes** les sorties, sans exception : c'est ce
        qui tient l'invariant « une ligne `outcome` par evenement de sortie ».
        """
        if self._journal is not None:
            record = build_outcome_record(self._ctx, result, self._clock())
            if not self._journal.write_outcome(record):
                # Le POST a deja eu lieu : rien n'est annule, mais l'atteinte a
                # l'invariant doit etre signalee.
                result = replace(
                    result, warnings=result.warnings + ("journal_outcome_failed",)
                )
        return result
