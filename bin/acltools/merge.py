"""Moteur de fusion (§3.2, §3.3, §5.4) — le coeur du contrat d'entree.

**La presence de la colonne decide seule de modifier ou de preserver ; la cellule
decide seulement de la valeur.**

    colonne absente  -> attribut preserve, tel que lu par le GET
    colonne presente, cellule vide    -> attribut vide
    colonne presente, cellule valuee  -> valeur appliquee

Le predicat de presence n'est pas evalue ici : il est fige a la liaison
(`binding.field_present`) et transporte par `EventInput.present`. Ce module ne consulte
que `event.has(<attribut>)`, ce qui rend structurellement impossible d'y substituer un
test de type ou de valeur.

Deux attributs derogent a la ligne « cellule vide -> attribut vide », et pour la meme
raison : la valeur vide **n'existe pas** cote plateforme.

- `sharing` : `sharing=` n'est pas une portee valide.
- `owner`   : un proprietaire vide fait refuser le POST.

Dans les deux cas l'evenement est **rejete**, sans POST, sans incrementer le compteur
du §4.3.
"""

from .errors import EventRejected
from .model import (
    TARGET_OWNER,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    AclState,
    MergeResult,
)
from .normalize import (
    VALID_SHARING,
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    serialize_roles,
)

#: Proprietaire technique : un objet partage en `user` ne peut pas lui appartenir.
NOBODY = "nobody"


def _merged_roles(current_value, event, attribute, raw):
    """Applique la semantique de presence a une liste de roles (§3.2).

    `is_field_empty` n'est consulte **qu'apres** que la presence a tranche : il decide
    de la valeur, jamais de l'intention.
    """
    if not event.has(attribute):
        return current_value
    return () if is_field_empty(raw) else normalize_roles(raw)


def merge(current, event):
    """Calcule l'etat cible et les refus des rangs 1 a 4 du §5.4.

    Les rangs 5 (`validate_roles`), 6 (`noop`) et 7 (`dryrun`) sont appliques par le
    pipeline, qui seul dispose du referentiel de roles et des parametres. Les rangs -1
    (`skipped_private`) et 0 (`skipped_derived`) le sont aussi : ils precedent la
    fusion et n'ont pas d'etat cible.
    """
    perms_read = _merged_roles(
        current.perms_read, event, TARGET_PERMS_READ, event.new_perms_read
    )
    perms_write = _merged_roles(
        current.perms_write, event, TARGET_PERMS_WRITE, event.new_perms_write
    )

    sharing = current.sharing
    sharing_rejection = None
    if event.has(TARGET_SHARING):
        if is_field_empty(event.new_sharing):
            # Une portee vide n'existe pas. La transmettre exposerait soit a un rejet
            # HTTP opaque, soit a une substitution silencieuse — sur un endpoint qui
            # opere en remplacement integral (§3.3, D-1).
            sharing_rejection = EventRejected("rejected", "sharing_empty_not_allowed")
        else:
            candidate = normalize_sharing(event.new_sharing)
            if candidate not in VALID_SHARING:
                sharing_rejection = EventRejected(
                    "rejected", "invalid_sharing:%s" % candidate
                )
            else:
                sharing = candidate

    # Le proprietaire est transmis **dans tous les cas** — l'omettre du corps produit un
    # refus de la plateforme — mais il vient du GET tant que la colonne de `new_owner`
    # est absente (§5.4).
    owner = current.owner
    owner_rejection = None
    if event.has(TARGET_OWNER):
        if is_field_empty(event.new_owner):
            # Pendant exact de l'exception `sharing` (§3.3). Le cas se produit sur un lot
            # heterogene ou certaines lignes ne portent pas le proprietaire.
            owner_rejection = EventRejected("rejected", "owner_empty_not_allowed")
        else:
            owner = _first_token(event.new_owner)

    after = AclState(
        owner=owner,
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
    elif owner_rejection is not None:                                    # rang 3bis
        rejection = owner_rejection
    elif after.sharing == "user" and (after.owner or "").lower() == NOBODY:
        rejection = EventRejected(                                       # rang 4
            "rejected", "sharing_user_requires_named_owner"
        )

    warnings = []
    if after.sharing != current.sharing:
        # La visibilite de l'objet change pour l'ensemble des consommateurs.
        warnings.append("sharing_change")
    if after.owner != current.owner:
        # La reprise de propriete change qui detient l'objet et, sur un objet privee,
        # qui peut encore l'atteindre.
        warnings.append("owner_change")

    # Les quatre attributs sont **toujours** transmis : l'endpoint `/acl` opere en
    # remplacement integral, toute omission equivaut a un effacement (§5.4). Une valeur
    # vide est serialisee `perms.read=` — cle presente, valeur vide, jamais l'omission.
    payload = {
        "owner": after.owner,
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


def _first_token(raw):
    """Premiere valeur non vide d'un champ mono-valeur, en chaine.

    Un `owner` est mono-valeur. Un pipeline peut neanmoins le presenter en multivalue —
    c'est le cas apres certains `stats` — et la premiere valeur est alors la seule.
    """
    if isinstance(raw, (list, tuple, set, frozenset)):
        for item in raw:
            token = _first_token(item)
            if token:
                return token
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw if raw is not None else "").strip()


def is_noop(current, target):
    """Egalite stricte de l'etat fusionne et de l'etat lu, apres normalisation (§5.5).

    Porte sur `owner`, `sharing`, `perms_read` et `perms_write`.

    **`owner` y entre depuis D-22.** La v1 l'excluait au motif qu'il n'etait jamais
    modifie ; ce motif tombe avec `new_owner`. L'exclure rendrait la reprise de
    propriete inoperante : un lot ne changeant que le proprietaire ressortirait
    integralement en `noop`, sans un seul POST, et le §11.2-17bis — aller-retour sur
    `new_owner` — serait intenable.

    La comparaison porte sur les collections triees, pas sur les chaines : une
    permutation d'ordre des roles est un `noop`.
    """
    return (
        current.owner == target.owner
        and current.sharing == target.sharing
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
