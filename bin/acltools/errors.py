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


class MaxObjectsReached(FatalError):
    """Plafond `max_objects` atteint avant une ecriture (§4.3)."""

    def __init__(self, max_objects):
        super().__init__(
            "max_objects atteint (%s) : la recherche est interrompue, "
            "les objets deja ecrits ne sont pas annules." % max_objects
        )
        self.max_objects = max_objects


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
