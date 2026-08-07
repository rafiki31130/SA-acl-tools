"""Identification des objets derives d'un `eventtype` (cahier des charges §3.4, D-18).

Un objet `fvtags` n'est pas un objet de connaissance autonome : c'est la
materialisation interne par laquelle splunkd applique un tag pose sur un `eventtype`.
Ecrire l'ACL du porteur **propage** cette ACL au derive, sans POST, sans reponse HTTP,
donc sans que la commande puisse l'observer. La commande s'abstient donc d'ecrire le
derive (§5.4 rang 0).

La contrainte de conception est la **troisieme propriete normative du §3.4** :

    « La relation de derivation est DECOUVERTE, pas CONSTRUITE. L'identification d'un
      objet comme derive ne doit jamais reposer sur une concatenation de chaines a
      partir du nom du parent. »

Ce que ce module NE fait PAS
---------------------------

Il ne calcule jamais `"eventtype=" + <nom du parent>`. Aucune fonction ici ne prend un
nom d'`eventtype` en entree pour en deduire un nom d'objet derive. C'est exactement
l'operation interdite : elle produirait un jour un homonyme, avec les memes
consequences qu'un endpoint devine (§6.2).

Ce que ce module fait, et sur quelle donnee de plateforme
---------------------------------------------------------

Le sens de parcours est **inverse** — de l'enfant vers le porteur — et chacune des
trois etapes s'appuie sur une donnee fournie par splunkd, jamais sur une convention
que nous aurions posee :

1. **La famille** vient du chemin de handler resolu (§5.2), lui-meme issu soit du champ
   `id` emis par l'endpoint natif, soit de la table de correspondance validee par GET
   reel (§6.4). Seuls les objets de la famille `fvtags` sont candidats : un objet d'une
   autre famille qui porterait par hasard un nom en `eventtype=...` n'est pas concerne.

2. **L'identite de l'objet** est celle que splunkd renvoie dans la reponse du GET du
   §5.3 — `entry[0].name` — et non le champ `title` de l'evenement d'entree, qu'un
   `eval` en amont peut avoir forge. Le §5.3 pose que le resultat du GET fait autorite ;
   la regle est appliquee ici a la lettre.

   Cette identite est la **cle composite** de la famille `fvtags`, dont la grammaire
   `<champ>=<valeur>` est celle de la plateforme : c'est sous cette forme que splunkd
   nomme l'objet, l'adresse (`saved/fvtags/<champ>%3D<valeur>`), le cree
   (`POST saved/fvtags name=<champ>%3D<valeur>`) et l'ecrit dans `tags.conf`
   (`[<champ>=<valeur>]`). La lire n'est pas une heuristique de nommage : c'est lire la
   cle primaire de l'objet telle que la plateforme la definit.

3. **L'existence du porteur est confirmee par la plateforme**, par un GET reel sur
   l'endpoint `saved/eventtypes` du meme namespace. C'est l'etape qui fait de la
   relation une **observation** et non une supposition : sans porteur, pas de cascade
   possible, donc pas d'abstention — un `fvtags` orphelin reste modifiable.

Mesure qui fonde le point 2
---------------------------

La grammaire retenue — decoupage sur le **premier** signe egal — n'est pas deduite
d'une documentation : c'est la regle que splunkd applique lui-meme, mesuree sur le
socle de reference. Un `eventtype` dont le nom contient un signe egal engendre un
objet derive dont la cle composite conserve ce signe dans sa partie valeur, et un POST
d'ACL sur ce porteur cascade bien vers ce derive. La regle implementee ici est donc
la **reciproque exacte du comportement observe de la cascade**, pas une convention de
nommage supposee.

Portee
------

Bornee aux derives d'un `eventtype`, conformement a D-18 et au §11.3 : le motif est
confine a la grappe des tags sur les 11 familles eprouvees, les 16 autres sont inferees
exemptes et non observees. La regle n'est volontairement pas formulee sur « tout objet
derive ».

Elle ne s'etend pas non plus a la famille `tags` (`admin/tags`), bien que ses objets
soient eux aussi derives d'un `eventtype` et que la plateforme y expose meme
explicitement le lien (champ `field_name_value`). Deux raisons, dans cet ordre :

- le §3.4 designe nommement l'objet `fvtags`, et la cascade mesuree porte sur la seule
  stanza `[tags/<paire>]`, celle de cet objet ;
- un objet `admin/tags` acquiert une stanza propre des sa premiere ecriture d'ACL et
  cesse alors d'etre expose a la cascade. S'en abstenir definitivement le soustrairait
  au cas d'usage moteur du §1.1 — la disparition effective des references a un role
  decommissionne — sans qu'aucune cascade ne vienne l'aligner en contrepartie. Le
  §3.4 fait converger le parc par la cascade ; ici il n'y aurait rien pour converger.
"""

from .endpoint import build_object_path

#: Chemins de handler de la famille `fvtags`. `saved/fvtags` est la valeur de la table
#: de correspondance livree ; `admin/fvtags` est le meme handler expose sous l'arbre
#: d'administration, et un champ `id` peut le designer.
FVTAGS_HANDLER_PATHS = frozenset({"saved/fvtags", "admin/fvtags"})

#: Chemin de handler du porteur. C'est la valeur que la table de correspondance associe
#: a `eventtypes`, validee par GET reel (§6.4).
EVENTTYPE_HANDLER_PATH = "saved/eventtypes"

#: Partie gauche de la cle composite designant un `eventtype` comme porteur.
CARRIER_FIELD = "eventtype"

#: Separateur de la cle composite `<champ>=<valeur>` de la famille `fvtags`.
PAIR_SEPARATOR = "="

#: Avertissement emis quand le GET de confirmation n'a pu ni etablir ni infirmer
#: l'existence du porteur. Voir `CarrierProbe.carrier_of`.
PROBE_INCONCLUSIVE_WARNING = "carrier_probe_inconclusive"


def split_composite_key(platform_name):
    """Decompose la cle composite d'un objet `fvtags` en `(champ, valeur)`.

    Renvoie `None` si le nom ne se conforme pas a la grammaire de la plateforme.

    Le decoupage porte sur le **premier** signe egal : un nom de champ ne peut pas en
    contenir, une valeur le peut. C'est la regle mesuree sur le socle de reference.
    """
    if platform_name is None:
        return None
    name = str(platform_name)
    if PAIR_SEPARATOR not in name:
        return None
    field, _, value = name.partition(PAIR_SEPARATOR)
    if not field or not value:
        return None
    return field, value


def designated_carrier(handler_path, platform_name):
    """Nom de l'`eventtype` que la cle composite de l'objet designe, ou `None`.

    Ne conclut rien sur l'existence de cet `eventtype` : c'est le role du GET de
    confirmation de `CarrierProbe`. Cette fonction ne fait que lire la designation
    portee par l'identite que la plateforme a renvoyee.
    """
    if str(handler_path or "").strip("/") not in FVTAGS_HANDLER_PATHS:
        return None
    parts = split_composite_key(platform_name)
    if parts is None:
        return None
    field, value = parts
    if field != CARRIER_FIELD:
        return None
    return value


class CarrierProbe(object):
    """Confirme aupres de la plateforme l'existence du porteur designe.

    Un GET par couple `(owner, app, porteur)` distinct, memoise sur la duree de
    l'execution. Sur un lot ou la famille `fvtags` est absente, le cout est nul : la
    sonde n'est interrogee que lorsque `designated_carrier` a deja repondu.
    """

    def __init__(self, rest):
        self._rest = rest
        self._cache = {}

    def _carrier_exists(self, owner, app, carrier):
        key = (str(owner), str(app), str(carrier))
        if key not in self._cache:
            path = build_object_path(owner, app, EVENTTYPE_HANDLER_PATH, carrier)
            response = self._rest.get_json(path)
            self._cache[key] = response.status
        return self._cache[key]

    def carrier_of(self, owner, app, handler_path, platform_name):
        """Renvoie `(porteur, avertissement)`.

        `porteur` vaut `None` quand l'objet n'est pas un derive d'`eventtype` — soit
        parce qu'il n'appartient pas a la famille `fvtags`, soit parce que sa cle
        composite ne designe pas un `eventtype`, soit parce que la plateforme repond
        que le porteur designe **n'existe pas** (HTTP 404). Ce dernier cas est le
        `fvtags` orphelin : aucun porteur ne peut cascader vers lui, il reste
        modifiable.

        `avertissement` est non nul lorsque le GET de confirmation n'a ni etabli ni
        infirme l'existence du porteur — 403, 5xx, echec de transport. L'abstention est
        alors **conservatrice** : elle est prononcee quand meme, parce que l'ecriture
        d'un derive dont le porteur pourrait exister fausse le jeu de restauration en
        silence, tandis qu'une abstention de trop est tracee, visible, et sans effet sur
        l'etat du parc. L'avertissement porte le code obtenu pour que l'operateur puisse
        distinguer les deux situations.
        """
        carrier = designated_carrier(handler_path, platform_name)
        if carrier is None:
            return None, None

        status = self._carrier_exists(owner, app, carrier)
        if status == 404:
            return None, None
        if 200 <= status < 300:
            return carrier, None
        return carrier, "%s:%d" % (PROBE_INCONCLUSIVE_WARNING, status)
