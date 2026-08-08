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

#: **Enumeration normative des `acl_status` du §5.7 — source unique.**
#:
#: Elle vit ici, dans le noyau, et non dans le jeu de tests ni dans le cahier des
#: charges : une enumeration recopiee derive. Trois redactions du contrat, puis une du
#: jeu de tests, ont eu cette liste fausse — deux fois par omission, une fois par exces.
#: D-35 a supprime l'enumeration du §8.2 pour la confier au jeu de tests ; le jeu de
#: tests l'a a son tour ecrite a la main, et elle a derive de la meme facon.
#:
#: Deux tests l'arriment au code et referment la classe d'erreur :
#:
#: - `tests/test_statuses.py` extrait de l'arbre syntaxique du noyau **tout** statut
#:   litteral effectivement produit — premier argument d'un `EventRejected(...)`,
#:   affectation d'un attribut `status` — et exige l'egalite avec ce tuple. Un statut
#:   ajoute au code sans etre declare ici fait echouer la suite ;
#: - l'invariant 1 du §8.2 (`tests/test_pipeline.py`) exige d'observer **chacune** de
#:   ces valeurs sur un cas reel. Un statut declare ici sans cas de test fait donc
#:   echouer la suite lui aussi.
#:
#: L'ordre est celui du tableau du §5.7.
ACL_STATUSES = (
    "updated",
    "noop",
    "dryrun",
    "rejected",
    "not_found",
    "forbidden",
    "invalid_role",
    "skipped_immutable",
    "skipped_derived",
    "skipped_private",
    "skipped_ceiling",
    "error",
)

#: Champs de sortie portes par **tout** enregistrement, quel que soit `acl_status`
#: (§5.7). Ils entrent dans l'en-tete du flux par le premier enregistrement venu.
ACL_UNCONDITIONAL_FIELDS = (
    "acl_status",
    "acl_endpoint",
    "acl_http_code",
    "acl_error",
    "acl_warning",
    "acl_journaled",
)

#: Les huit champs d'etat du §5.7. Ils ne sont portes que par les enregistrements dont
#: la fusion a ete calculee : un `skipped_private`, un `skipped_derived`, un
#: `skipped_ceiling`, un `not_found`, un `forbidden` ou un rejet **amont** de la fusion
#: n'en porte aucun.
ACL_STATE_FIELDS = (
    "acl_before_owner",
    "acl_after_owner",
    "acl_before_perms_read",
    "acl_before_perms_write",
    "acl_before_sharing",
    "acl_after_perms_read",
    "acl_after_perms_write",
    "acl_after_sharing",
)

#: **Jeu de champs de sortie declare** (§5.7, D-33), dans l'ordre du tableau normatif.
#:
#: Le writer du SDK fige l'en-tete du flux sur les cles du **premier** enregistrement
#: emis, puis y projette tous les suivants : un champ absent de ce premier
#: enregistrement disparait de la sortie entiere, sans erreur ni avertissement. Les
#: huit champs de `ACL_STATE_FIELDS` n'etant pas portes par tous les statuts, un lot
#: commencant par un `skipped_private` — ce que la macro d'inventaire produit
#: couramment — priverait l'operateur de tout ce que la simulation existe pour montrer.
#:
#: La declaration est donc **explicite** et vit ici, hors de l'adaptateur, pour que la
#: liste declaree et la liste projetee soient la meme donnee et ne puissent pas
#: diverger. Le SDK vendorise n'est pas modifie : il expose `RecordWriter.custom_fields`
#: pour exactement cet usage.
ACL_OUTPUT_FIELDS = (
    "acl_status",
    "acl_endpoint",
    "acl_http_code",
    "acl_error",
    "acl_warning",
    "acl_before_owner",
    "acl_after_owner",
    "acl_before_perms_read",
    "acl_before_perms_write",
    "acl_before_sharing",
    "acl_after_perms_read",
    "acl_after_perms_write",
    "acl_after_sharing",
    "acl_journaled",
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
