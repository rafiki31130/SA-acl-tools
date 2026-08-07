"""Taxonomie d'erreurs — cahier des charges §9.

La frontiere entre les deux classes d'erreur est **structurelle** : elle tient au
type de l'exception, pas a une convention de nommage.

- Erreur **fatale** -> interruption de la recherche. Liste limitative du §9.
- Erreur **par evenement** -> `EventRejected`, le pipeline se poursuit.

Aucune autre exception ne doit traverser le pipeline : toute `Exception` inattendue
y est capturee et convertie en `EventRejected("error", "internal:...")`.
"""


class AclToolsError(Exception):
    """Racine de la hierarchie du paquet."""


# --------------------------------------------------------------------------- #
# Erreurs fatales (§9) — interruption de la recherche
# --------------------------------------------------------------------------- #

class FatalError(AclToolsError):
    """Base des erreurs fatales. Interrompt la recherche."""


class FatalConfigError(FatalError):
    """`fields` invalide, `max_objects` non entier positif, `splunkd_uri` ou
    `session_key` indisponibles."""


class FatalCapabilityError(FatalError):
    """Capability `edit_acl_bulk` absente, ou execution en recherche temps reel."""


class FatalMappingError(FatalError):
    """Table de correspondance illisible ou mal formee."""


class FatalJournalError(FatalError):
    """Journal non ouvrable en ecriture alors que `journal=true` ET `dryrun=false`."""


# **Le plafond `max_objects` n'est plus une erreur fatale** (D-28). Il l'etait en v1 :
# l'atteinte du plafond interrompait la recherche, la sortie etait integralement perdue,
# et l'operateur se retrouvait avec une mutation partielle **et** l'aveuglement sur ce
# qui venait de se passer. Le garde-fou produisait le pire des deux mondes a l'instant
# precis ou il se declenchait.
#
# Sa valeur reelle — borner le rayon d'action d'une ecriture lancee sans simulation —
# est integralement conservee par l'arret des ecritures. Ce qui disparait, c'est la
# cecite : le plafond ressort desormais en `acl_status = "skipped_ceiling"`, statut par
# evenement, et la sortie de la recherche reste complete. Un garde-fou doit informer,
# pas aveugler.
#
# Il n'y a donc plus de classe d'exception pour le plafond : le chercher ici est
# l'erreur qu'un lecteur de la v1 commettrait.


# --------------------------------------------------------------------------- #
# Erreur par evenement — le pipeline se poursuit
# --------------------------------------------------------------------------- #

class EventRejected(AclToolsError):
    """Refus portant sur un objet donne.

    `status` est l'un des `acl_status` du §5.7 ; `error` alimente `acl_error`.
    """

    MAX_ERROR_LEN = 512

    def __init__(self, status, error):
        error = "" if error is None else str(error)
        if len(error) > self.MAX_ERROR_LEN:
            error = error[: self.MAX_ERROR_LEN]
        super().__init__("%s: %s" % (status, error))
        self.status = status
        self.error = error
