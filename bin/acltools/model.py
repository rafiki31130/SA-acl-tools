"""Structures de donnees immuables partagees par le noyau.

Toutes en `dataclass(frozen=True)`, sans methode metier : elles transportent, elles
ne decident pas.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple

#: Noms logiques des quatre valeurs cibles (§3.3). Ce sont les cles employees par
#: `EventInput.present` et par le moteur de fusion — jamais des noms de champs SPL,
#: que l'operateur peut renommer.
TARGET_PERMS_READ = "perms.read"
TARGET_PERMS_WRITE = "perms.write"
TARGET_SHARING = "sharing"
TARGET_OWNER = "owner"

#: Ordre stable, employe par les tests de matrice et les messages d'erreur.
TARGET_ATTRIBUTES = (
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    TARGET_OWNER,
)


@dataclass(frozen=True)
class FieldNames:
    """Nom du champ SPL ou lire chaque information (§3.1, §3.3, §4.1).

    Chaque entree logique de la commande est un **parametre nommant un champ**, assorti
    d'un defaut qui est la nomenclature native. L'operateur qui emploie celle-ci n'ecrit
    donc aucun parametre.

    Il n'y a **aucun** champ de propriete d'adressage : l'adressage se fait par un
    contexte fixe (§5.2, D-25). `new_owner` existe, mais c'est une **valeur cible**, pas
    une adresse.
    """

    title: str = "title"
    app: str = "eai:acl.app"
    id: str = "id"
    type: str = "eai:type"
    sharing: str = "eai:acl.sharing"
    new_perms_read: str = "eai:acl.perms.read"
    new_perms_write: str = "eai:acl.perms.write"
    new_sharing: str = "eai:acl.sharing"
    new_owner: str = "eai:acl.owner"


#: Defauts du §3.1 et du §3.3, exposes pour la documentation et les tests.
DEFAULT_FIELD_NAMES = FieldNames()


@dataclass(frozen=True)
class EventInput:
    """Projection d'un evenement d'entree (§3.1, §3.2, §3.3).

    **`present` est le coeur du contrat.** Il porte le sous-ensemble de
    `TARGET_ATTRIBUTES` dont la **colonne existe dans le jeu de resultats**. C'est le
    seul discriminant entre « preserver » et « modifier » : ni le type de la valeur, ni
    la valeur elle-meme n'y entrent (§3.2).

    `current_sharing` est la portee **courante** (§3.1), utilisee pour ecarter les
    objets privees (§3.5). `None` signifie que la colonne est absente du jeu de
    resultats — cas ou la commande ne peut pas les ecarter en amont.
    """

    title: str
    app: str
    id_value: Optional[str] = None
    eai_type: Optional[str] = None
    current_sharing: Optional[str] = None
    new_perms_read: object = None
    new_perms_write: object = None
    new_sharing: object = None
    new_owner: object = None
    present: frozenset = frozenset()

    def has(self, attribute):
        """Vrai si la colonne de `attribute` existe dans le jeu de resultats.

        C'est l'unique predicat de presence du noyau : aucun autre module n'interroge
        `present` directement, ce qui garantit qu'aucun ne peut y substituer un test de
        type ou de valeur.
        """
        return attribute in self.present


@dataclass(frozen=True)
class AclState:
    """Etat ACL d'un objet, normalise (§5.5)."""

    owner: str = ""
    sharing: str = ""
    perms_read: Tuple[str, ...] = ()
    perms_write: Tuple[str, ...] = ()
    can_change_perms: bool = True


@dataclass(frozen=True)
class MergeResult:
    """Resultat de la fusion (§5.4)."""

    before: AclState
    after: AclState
    payload: dict = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()
    rejection: object = None  # EventRejected | None


@dataclass(frozen=True)
class Params:
    """Parametres valides de la commande (§4.1)."""

    names: FieldNames
    dryrun: bool
    validate_roles: bool
    journal: bool
    max_objects: int
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RunContext:
    """Constantes d'execution, identiques pour toutes les lignes de journal."""

    sid: str
    user: str
    host: str
    dryrun: bool


@dataclass(frozen=True)
class EventResult:
    """Resultat du traitement d'un evenement (§5.7 + besoins du journal §8.2)."""

    status: str
    title: str = ""
    app: str = ""
    eai_type: str = ""
    endpoint: str = ""
    http_code: int = 0
    error: Optional[str] = None
    warnings: Tuple[str, ...] = ()
    before: Optional[AclState] = None
    after: Optional[AclState] = None
    journaled: bool = False
    post_attempted: bool = False
    counted: bool = False
    source: str = ""
