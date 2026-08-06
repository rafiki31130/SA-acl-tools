"""Moteur de fusion (§3.3, §5.4) — le point le plus subtil du cahier des charges.

**Le parametre `fields` decide seul de ce qui est modifie ; le contenu de l'evenement
decide seulement de la valeur.** La presence ou l'absence d'un champ dans l'evenement
n'a aucun pouvoir de preservation.

Corollaire : cote `perms.*`, « champ absent », « champ nul » et « champ vide » sont le
**meme cas** (§3.3). C'est delibere, et c'est ce qui permet de vider `perms.write` par
un `mvmap` qui supprime toutes ses valeurs — situation nominale du cas d'usage de
decommissionnement.
"""

from .errors import EventRejected, FatalConfigError
from .model import AclState, MergeResult
from .normalize import (
    VALID_SHARING,
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    serialize_roles,
)

#: Valeurs admises de `fields` (§4.1). `owner` en est exclu : il est requis en entree
#: mais n'est jamais une valeur cible (§1.3).
ALLOWED_FIELDS = frozenset({"perms.read", "perms.write", "sharing"})

DEFAULT_FIELDS = "perms.read,perms.write"

#: Proprietaire technique : un objet partage en `user` ne peut pas lui appartenir.
NOBODY = "nobody"


def parse_fields(raw):
    """Valide et normalise le parametre `fields`.

    Erreurs : `FatalConfigError` sur toute valeur non admise — `owner` **inclus**,
    explicitement (§4.1, §9).
    """
    if raw is None:
        raw = DEFAULT_FIELDS
    if isinstance(raw, (list, tuple)):
        tokens = []
        for item in raw:
            tokens.extend(str(item).split(","))
    else:
        tokens = str(raw).split(",")

    values = [token.strip() for token in tokens if token.strip()]
    if not values:
        raise FatalConfigError(
            "parametre invalide : 'fields' est vide ; valeurs admises %s"
            % ", ".join(sorted(ALLOWED_FIELDS))
        )

    invalid = [value for value in values if value not in ALLOWED_FIELDS]
    if invalid:
        raise FatalConfigError(
            "parametre invalide : 'fields' contient %s ; valeurs admises %s"
            % (", ".join(sorted(set(invalid))), ", ".join(sorted(ALLOWED_FIELDS)))
        )
    return frozenset(values)


def merge(current, event, fields):
    """Calcule l'etat cible et les refus des rangs 1 a 4 du §5.4.

    Les rangs 5 (`validate_roles`), 6 (`noop`) et 7 (`dryrun`) sont appliques par le
    pipeline, qui seul dispose du referentiel de roles et des parametres.
    """
    perms_read = current.perms_read
    if "perms.read" in fields:
        perms_read = (
            ()
            if is_field_empty(event.raw_perms_read)
            else normalize_roles(event.raw_perms_read)
        )

    perms_write = current.perms_write
    if "perms.write" in fields:
        perms_write = (
            ()
            if is_field_empty(event.raw_perms_write)
            else normalize_roles(event.raw_perms_write)
        )

    sharing = current.sharing
    sharing_rejection = None
    if "sharing" in fields:
        if is_field_empty(event.raw_sharing):
            # `sharing=` n'est pas une portee valide : le transmettre exposerait soit a
            # un rejet HTTP opaque, soit a une substitution silencieuse — sur un
            # endpoint qui opere en remplacement integral (D-1).
            sharing_rejection = EventRejected(
                "rejected", "sharing_empty_not_allowed"
            )
        else:
            candidate = normalize_sharing(event.raw_sharing)
            if candidate not in VALID_SHARING:
                sharing_rejection = EventRejected(
                    "rejected", "invalid_sharing:%s" % candidate
                )
            else:
                sharing = candidate

    after = AclState(
        owner=current.owner,
        sharing=sharing,
        perms_read=perms_read,
        perms_write=perms_write,
        can_change_perms=current.can_change_perms,
    )

    # Ordre normatif du §5.4 : il determine quel statut l'emporte quand plusieurs
    # conditions sont reunies.
    rejection = None
    if not current.can_change_perms:                                     # rang 1
        rejection = EventRejected("skipped_immutable", "can_change_perms=0")
    elif sharing_rejection is not None:                                  # rangs 2 et 3
        rejection = sharing_rejection
    elif after.sharing == "user" and (current.owner or "").lower() == NOBODY:
        rejection = EventRejected(                                       # rang 4
            "rejected", "sharing_user_requires_named_owner"
        )

    warnings = []
    if after.sharing != current.sharing:
        # La visibilite de l'objet change pour l'ensemble des consommateurs.
        warnings.append("sharing_change")

    # Les quatre attributs sont **toujours** transmis : l'endpoint `/acl` opere en
    # remplacement integral, toute omission equivaut a un effacement (§5.4). Une valeur
    # vide est serialisee `perms.read=` — cle presente, valeur vide, jamais l'omission.
    payload = {
        "owner": current.owner,
        "sharing": after.sharing,
        "perms.read": serialize_roles(after.perms_read),
        "perms.write": serialize_roles(after.perms_write),
    }

    return MergeResult(
        before=current,
        after=after,
        payload=payload,
        warnings=tuple(warnings),
        rejection=rejection,
    )


def is_noop(current, target):
    """Egalite stricte de l'etat fusionne et de l'etat lu, apres normalisation (§5.5).

    Porte sur `sharing`, `perms_read` et `perms_write` ; `owner` n'y entre pas, il
    n'est jamais modifie. La comparaison porte sur les collections triees, pas sur les
    chaines : une permutation d'ordre des roles est un `noop`.
    """
    return (
        current.sharing == target.sharing
        and current.perms_read == target.perms_read
        and current.perms_write == target.perms_write
    )


def validate_roles(before, after, catalog):
    """Controle du §5.4 rang 5, restreint aux **roles ajoutes** (D-4).

    Renvoie `(inconnus_ajoutes, morts_conserves)`, deux tuples tries.

    Un role inconnu deja present sur l'objet et non modifie par l'operation ne bloque
    pas l'ecriture : il est seulement signale. La lecture inverse rendrait l'outil
    inutilisable sur exactement la plateforme qu'il vise — bloquer une ecriture au
    motif qu'un role mort traine dans `perms.read` alors qu'on modifie `perms.write`
    empeche le correctif sans faire disparaitre la reference morte.
    """
    before_read, before_write = set(before.perms_read), set(before.perms_write)
    after_read, after_write = set(after.perms_read), set(after.perms_write)

    added = (after_read - before_read) | (after_write - before_write)
    preserved = (after_read & before_read) | (after_write & before_write)

    unknown_added = tuple(sorted(added - set(catalog)))
    stale_preserved = tuple(sorted(preserved - set(catalog)))
    return unknown_added, stale_preserved
