"""Normalisation des listes de roles et de la portee de partage (§3.2, §5.5).

Fonctions totales : elles ne levent jamais.

Le filtrage des elements vides n'est pas cosmetique (D-8). Apres un POST portant
`perms.read=` vide, le GET suivant ne renvoie ni `[]` ni `null` mais `[""]` — une
liste contenant une chaine vide. Sans ce filtrage, l'etat lu et l'etat fusionne ne
sont jamais egaux et la detection d'idempotence du §5.5 echoue sur **tout** objet a
permission vide.
"""

from .model import AclState

VALID_SHARING = frozenset({"user", "app", "global"})


def _flatten(raw):
    """Aplatit un champ brut en une liste de jetons textuels, sans filtrage."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set, frozenset)):
        out = []
        for item in raw:
            out.extend(_flatten(item))
        return out
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return [part for part in str(raw).split(",")]


def normalize_roles(raw):
    """Normalise un champ de permissions en tuple trie, dedoublonne, sans vide.

    Accepte multivalue, chaine separee par virgules, `None`, et toute combinaison.
    `null`, `[]`, `[""]` et `["", ""]` convergent tous vers le tuple vide.
    """
    tokens = set()
    for part in _flatten(raw):
        token = part.strip()
        if token:
            tokens.add(token)
    return tuple(sorted(tokens))


def serialize_roles(roles):
    """Serialise un tuple de roles pour le corps du POST.

    Un tuple vide donne la chaine vide, jamais `*` (§3.3).
    """
    return ",".join(roles)


def normalize_sharing(raw):
    """Normalise une portee de partage. Renvoie `None` si le champ est vide."""
    for part in _flatten(raw):
        token = part.strip()
        if token:
            return token.lower()
    return None


def is_field_empty(raw):
    """Vrai pour `None`, `""`, `[]`, et toute valeur dont tous les jetons sont vides.

    Cote permissions, « champ absent », « champ nul » et « champ vide » sont le meme
    cas (§3.3) : cette fonction est le point ou cette equivalence est realisee.
    """
    for part in _flatten(raw):
        if part.strip():
            return False
    return True


def _as_bool(raw, default=True):
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    token = str(raw).strip().lower()
    if token in ("1", "true", "t", "yes", "y", "on"):
        return True
    if token in ("0", "false", "f", "no", "n", "off"):
        return False
    return default


def parse_acl_state(entry_acl):
    """Construit un `AclState` a partir du bloc `entry[0].acl` de la reponse du GET.

    Le parametre `f=eai:acl*` du §5.3 filtre `content` et laisse `acl` intact ; c'est
    `acl` qui fait autorite (§5.3). Le parsing est tolerant a `perms` absent (objet
    sans permission explicite, cas §10.1) et a `perms.read` / `perms.write` recus
    indifferemment en liste ou en chaine.
    """
    entry_acl = entry_acl or {}
    perms = entry_acl.get("perms") or {}
    if not isinstance(perms, dict):
        perms = {}
    return AclState(
        owner=str(entry_acl.get("owner") or ""),
        sharing=str(entry_acl.get("sharing") or ""),
        perms_read=normalize_roles(perms.get("read")),
        perms_write=normalize_roles(perms.get("write")),
        can_change_perms=_as_bool(entry_acl.get("can_change_perms"), default=True),
    )
