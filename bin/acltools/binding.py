"""Liaison enregistrement SPL -> `EventInput` (§3.1, §3.2, §3.3).

C'est **le** module ou se joue la semantique de presence du §3.2, et il ne fait que
cela : lire, dans un enregistrement, les champs que les parametres de nommage
designent, et consigner **quelles colonnes existent**.

    | Situation                            | Effet                        |
    |--------------------------------------|------------------------------|
    | colonne **absente** du jeu de resultats | attribut **preserve**      |
    | colonne **presente**, cellule **vide**  | attribut **vide**          |
    | colonne **presente**, cellule valuee    | valeur appliquee           |

**Le discriminant est la presence de la cle dans l'enregistrement — jamais le type,
jamais la valeur.** Mesure sur 9.4.6 : la commande recoit soit une cle absente de
l'enregistrement, soit une cle presente valant la chaine vide. Jamais `None`, jamais
une liste vide. Et un champ multivalue **reduit a une seule valeur arrive en chaine**,
pas en liste : un test de type conclurait « valeur unique » la ou il n'y a rien a
conclure, et surtout ne dirait rien de la presence.

La prudence supplementaire — `raw is not None` en plus de `key in record` — serait une
erreur, pas une precaution : elle reintroduirait par la bande la discrimination par la
valeur que le §3.2 proscrit, et transformerait un « vider cet attribut » explicite en
« preserver ». Le predicat est donc **exactement** `key in record`, sans clause.
"""

from .model import (
    TARGET_OWNER,
    TARGET_PERMS_READ,
    TARGET_PERMS_WRITE,
    TARGET_SHARING,
    EventInput,
)


def field_present(record, name):
    """Predicat de presence d'une colonne. Point d'injection unique de la regle §3.2.

    Aucun autre appelant du paquet ne teste la presence d'un champ : la regle vit ici,
    en une ligne, et ne peut pas deriver ailleurs.
    """
    if record is None or not name:
        return False
    try:
        return name in record
    except TypeError:                                                # pragma: no cover
        return False


def field_value(record, name, default=None):
    """Valeur brute d'une colonne, sans aucune interpretation ni coercition."""
    if not field_present(record, name):
        return default
    return record.get(name)


def _text(raw):
    """Reduit une valeur brute a une chaine, sans decider de sa vacuite.

    Un multivalue est reduit a sa premiere valeur non vide : c'est le cas de `title`,
    `app`, `id`, `type` et de la portee courante, qui sont mono-valeur par nature.
    """
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        for item in raw:
            token = _text(item)
            if token:
                return token
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).strip()


def build_event(record, names):
    """Construit l'`EventInput` d'un enregistrement, selon les parametres de nommage.

    Les champs de **reference** (§3.1) sont lus pour leur valeur ; leur presence en tant
    que colonne n'a d'effet que pour la portee courante, dont l'absence prive la
    commande du filtre du §3.5.

    Les quatre **valeurs cibles** (§3.3) sont lues pour leur valeur **et** pour leur
    presence, celle-ci etant consignee dans `present`.
    """
    record = record if record is not None else {}

    sharing_column = names.sharing
    current_sharing = (
        _text(field_value(record, sharing_column))
        if field_present(record, sharing_column)
        else None
    )

    present = set()
    for attribute, column in (
        (TARGET_PERMS_READ, names.new_perms_read),
        (TARGET_PERMS_WRITE, names.new_perms_write),
        (TARGET_SHARING, names.new_sharing),
        (TARGET_OWNER, names.new_owner),
    ):
        if field_present(record, column):
            present.add(attribute)

    return EventInput(
        title=_text(field_value(record, names.title)),
        app=_text(field_value(record, names.app)),
        id_value=field_value(record, names.id),
        eai_type=_text(field_value(record, names.type)) or None,
        current_sharing=current_sharing,
        new_perms_read=field_value(record, names.new_perms_read),
        new_perms_write=field_value(record, names.new_perms_write),
        new_sharing=field_value(record, names.new_sharing),
        new_owner=field_value(record, names.new_owner),
        present=frozenset(present),
    )
