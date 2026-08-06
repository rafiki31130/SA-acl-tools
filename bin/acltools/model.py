"""Structures de donnees immuables partagees par le noyau.

Toutes en `dataclass(frozen=True)`, sans methode metier : elles transportent, elles
ne decident pas.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class EventInput:
    """Projection d'un evenement d'entree (§3.1, §3.2).

    Il n'existe **aucun** attribut porteur d'un proprietaire cible : la reprise de
    propriete est inexprimable par construction du type (§1.3). `owner` sert
    exclusivement a l'adressage.
    """

    title: str
    app: str
    owner: str
    id_value: Optional[str] = None
    eai_type: Optional[str] = None
    raw_perms_read: object = None
    raw_perms_write: object = None
    raw_sharing: object = None


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

    fields: frozenset
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
    owner: str = ""
    http_code: int = 0
    error: Optional[str] = None
    warnings: Tuple[str, ...] = ()
    before: Optional[AclState] = None
    after: Optional[AclState] = None
    journaled: bool = False
    post_attempted: bool = False
    counted: bool = False
    source: str = ""
