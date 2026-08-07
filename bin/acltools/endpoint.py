"""Resolution et reconstruction de l'URI d'un objet (§5.2).

Deux voies **complementaires et disjointes**, pas primaire et repli (D-9) :

- `id`, exploitable lorsqu'il provient d'un endpoint natif ;
- `eai:type`, resolu par la table de correspondance (§6).

Dans les deux cas l'URI est **reconstruite**, jamais reprise telle quelle : le champ
`id` natif double-encode la barre oblique mais pas les autres caracteres speciaux, il
n'est donc pas reutilisable comme URI.
"""

from urllib.parse import quote, urlsplit

from .errors import EventRejected
from .mapping import is_valid_handler_path

#: Marqueur de namespace dans un chemin REST Splunk.
NAMESPACE_MARKER = "/servicesNS/"

#: **Contexte d'adressage fixe** (§5.2, D-25). Il ne vient pas de l'evenement, il n'est
#: pas parametrable, et aucune signature de ce module n'expose de proprietaire.
#:
#: Mesure : un objet partage appartenant a un tiers est atteignable par ce contexte, en
#: lecture comme en ecriture, aux deux portees de partage, et la reponse du GET porte
#: **toujours le proprietaire reel** — jamais le contexte d'adressage. L'`id` renvoye
#: par la plateforme est lui-meme en `nobody`.
#:
#: Ce que ce contexte corrige : la v1 adressait par `eai:acl.owner`, or **un objet prive
#: masque un objet partage homonyme dans le namespace de son detenteur**. La commande
#: atteignait alors le prive et ecrivait son ACL — `200` au GET, POST abouti, ligne
#: rapportee `updated`. Une ecriture silencieuse sur la mauvaise cible.
#:
#: Le contexte joker `-` n'est **jamais** employe : il refuse l'ecriture, et sur deux
#: objets homonymes il renvoie deux entrees sur un chemin mono-objet, ou un client
#: lisant la premiere choisirait a l'aveugle.
FIXED_CONTEXT = "nobody"

#: Handler d'agregation : il sait lister, pas ecrire une ACL. Une source `id` qui y
#: pointe est ecartee (§5.2). La mesure en lab etablit que 100 % des `id` emis par ce
#: handler sont auto-referents.
DIRECTORY_HANDLER = "admin/directory"

#: Regle d'encodage du segment `title`, tranchee empiriquement (mesure 3) : simple
#: `%`-encodage du segment entier, `safe=''`, aucun caractere laisse litteral.
#: La barre oblique n'appelle **aucun** traitement special. Le double encodage est un
#: piege asymetrique : il fonctionne pour `/` seul et casse espace, accent et pourcent.
TITLE_ENCODING_MODE = "single"


def encode_namespace_segment(value):
    """Encode un segment de namespace (`owner`, `app`)."""
    return quote(str(value), safe="", encoding="utf-8")


def encode_title_segment(title):
    """Encode le dernier segment de chemin — point d'injection unique de la regle.

    Aucun autre appelant n'encode un titre, aucun autre module ne connait cette regle.
    """
    if TITLE_ENCODING_MODE == "single":
        return quote(str(title), safe="", encoding="utf-8")
    if TITLE_ENCODING_MODE == "double_slash_only":
        return quote(str(title), safe="", encoding="utf-8").replace("%2F", "%252F")
    if TITLE_ENCODING_MODE == "double":
        return quote(
            quote(str(title), safe="", encoding="utf-8"), safe="", encoding="utf-8"
        )
    raise ValueError("TITLE_ENCODING_MODE inconnu : %r" % (TITLE_ENCODING_MODE,))


def handler_path_from_id(id_value):
    """Extrait le chemin de handler porte par un `id`, ou `None` s'il est inexploitable.

    L'hote et le port portes par `id` sont **ecartes** : la base est `splunkd_uri`. Un
    `id` renvoye par un membre de cluster de search heads peut designer un autre hote
    que celui qui execute la commande.

    Le dernier segment — le nom de l'objet — est **jete** : le nom est repris de
    `title`, jamais de `id`.
    """
    if not id_value:
        return None
    raw = str(id_value).strip()
    if not raw:
        return None

    path = urlsplit(raw).path if "://" in raw else raw
    marker = path.find(NAMESPACE_MARKER)
    if marker < 0:
        return None

    remainder = path[marker + len(NAMESPACE_MARKER):]
    segments = [seg for seg in remainder.split("/") if seg != ""]
    # <owner> / <app> / <handler_path...> / <nom d'objet>
    if len(segments) < 4:
        return None
    handler_path = "/".join(segments[2:-1])

    if handler_path == DIRECTORY_HANDLER or handler_path.startswith(
        DIRECTORY_HANDLER + "/"
    ):
        return None
    if not is_valid_handler_path(handler_path):
        return None
    return handler_path


def resolve_handler_path(id_value, eai_type, mapping):
    """Resout le chemin de handler. Renvoie `(handler_path, source)`.

    `source` vaut `"id"` ou `"eai:type"`.

    Erreurs : `EventRejected("rejected", "unresolved_endpoint:<eai:type>")` quand
    aucune voie n'aboutit.
    """
    from_id = handler_path_from_id(id_value)
    if from_id:
        return from_id, "id"

    from_type = mapping.resolve(eai_type) if mapping is not None else None
    if from_type:
        return from_type, "eai:type"

    raise EventRejected(
        "rejected", "unresolved_endpoint:%s" % ("" if not eai_type else str(eai_type))
    )


def build_object_path(app, handler_path, title):
    """Construit le chemin de l'objet, **sans** le suffixe `/acl` (§5.2).

    Le contexte est `FIXED_CONTEXT`, toujours, et cette fonction **n'a pas de parametre
    de proprietaire** : l'adressage ne peut donc pas en porter un, quelle que soit
    l'evolution des appelants. C'est la garantie structurelle de D-25.

    Le GET du §5.3 porte sur ce chemin, le POST du §5.6 sur ce chemin suffixe `/acl`.
    C'est aussi la chaine exposee en sortie via `acl_endpoint` et la cle de correlation
    du journal (§8.5) : elle est calculee une seule fois et jamais recalculee.

    `handler_path` n'est **pas** re-encode : c'est un litteral de la table ou de `id`,
    deja URL-sur et valide par motif. L'encoder transformerait `saved/searches` en
    `saved%2Fsearches`.
    """
    return "%s%s/%s/%s/%s" % (
        NAMESPACE_MARKER,
        encode_namespace_segment(FIXED_CONTEXT),
        encode_namespace_segment(app),
        handler_path.strip("/"),
        encode_title_segment(title),
    )


def build_object_url(splunkd_uri, object_path):
    """Prefixe le chemin de l'objet par la base splunkd. Aucun hote ni port en dur."""
    return str(splunkd_uri).rstrip("/") + object_path
