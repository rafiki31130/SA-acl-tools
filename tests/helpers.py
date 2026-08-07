"""Doublures de test : ports REST, journal et horloge.

Aucune bibliotheque de simulation HTTP, aucune socket, aucun serveur local. Le contrat
de `RestPort` est etroit (trois methodes) et un port explicite est plus lisible qu'un
correctif de bas niveau sur la pile reseau.

Les fixtures JSON sont **redigees a la main** a partir de la forme observee en lab,
jamais des captures brutes, et n'emploient que des identifiants generiques (§14).
"""

import json

from acltools.mapping import Mapping
from acltools.model import (
    DEFAULT_FIELD_NAMES,
    TARGET_ATTRIBUTES,
    AclState,
    EventInput,
    FieldNames,
    Params,
    RunContext,
)
from acltools.rest import RestResponse

#: Sentinelle de **colonne absente** pour `make_event`.
#:
#: Elle existe parce que `None` ne peut pas jouer ce role : depuis le §3.2, `None` est
#: une valeur possible d'une colonne *presente*, et confondre les deux serait
#: precisement l'erreur que la refonte corrige. Un test qui veut une colonne absente
#: l'ecrit `ABSENT` ; tout le reste est present.
ABSENT = object()

#: Table de correspondance minimale utilisee par les tests. Sous-ensemble strict de la
#: table livree ; les tests de resolution n'ont pas besoin des 28 entrees.
FIXTURE_MAPPING = Mapping(
    {
        "savedsearch": "saved/searches",
        "views": "data/ui/views",
        "eventtypes": "saved/eventtypes",
        "macros": "data/macros",
        "lookup-table-file": "data/lookup-table-files",
        "fvtags": "saved/fvtags",
    }
)


def acl_body(
    owner="nobody",
    app="mon_app",
    sharing="global",
    read=("role_a",),
    write=("ancien_role",),
    can_change_perms=True,
    name="objet_temoin",
):
    """Corps de reponse d'un `GET <objet>?output_mode=json&f=eai:acl*`.

    Seul le bloc `entry[0].acl` fait autorite (§5.3) ; `content` est volontairement
    reduit, le parametre `f` le filtre de toute facon.

    `name` est l'identite canonique renvoyee par splunkd. Elle est distincte du `title`
    de l'evenement d'entree et c'est elle qui alimente le rang 0 du §5.4 (§3.4, D-18).
    """
    document = {
        "entry": [
            {
                "name": name,
                "content": {},
                "acl": {
                    "app": app,
                    "owner": owner,
                    "sharing": sharing,
                    "can_change_perms": can_change_perms,
                    "perms": {"read": list(read), "write": list(write)},
                },
            }
        ]
    }
    return json.dumps(document).encode("utf-8")


def acl_body_raw(acl_block):
    """Corps de reponse a partir d'un bloc `acl` brut (cas limites de parsing)."""
    return json.dumps(
        {"entry": [{"name": "objet_temoin", "content": {}, "acl": acl_block}]}
    ).encode("utf-8")


class FakeRest(object):
    """Implementation en memoire de `RestPort`.

    Les reponses sont scriptees par `(methode, chemin)` ; a defaut, une reponse par
    defaut est servie. Tous les appels sont enregistres dans l'ordre.
    """

    def __init__(self, get_responses=None, post_responses=None, json_responses=None,
                 default_get=None, default_post=None, default_json=None):
        self.get_responses = dict(get_responses or {})
        self.post_responses = dict(post_responses or {})
        self.json_responses = dict(json_responses or {})
        self.default_get = default_get or RestResponse(200, acl_body())
        self.default_post = default_post or RestResponse(200, b"{}")
        self.default_json = default_json or RestResponse(200, b'{"entry":[]}')
        self.calls = []

    def get_object_acl(self, object_path):
        self.calls.append(("GET", object_path, None))
        return self.get_responses.get(object_path, self.default_get)

    def post_object_acl(self, object_path, payload):
        self.calls.append(("POST", object_path, dict(payload)))
        return self.post_responses.get(object_path, self.default_post)

    def get_json(self, path, params=None):
        self.calls.append(("JSON", path, params))
        return self.json_responses.get(path, self.default_json)

    # -- assertions de confort --------------------------------------------- #

    def count(self, method):
        return len([call for call in self.calls if call[0] == method])

    def posts(self):
        return [call for call in self.calls if call[0] == "POST"]

    def gets(self):
        return [call for call in self.calls if call[0] == "GET"]


class FakeJournal(object):
    """Implementation en memoire de `JournalPort`.

    `fail_intent` / `fail_outcome` simulent un echec de la sequence
    write + flush + fsync, qui doit annuler le POST (§8.4).
    """

    def __init__(self, fail_intent=False, fail_outcome=False):
        self.intents = []
        self.outcomes = []
        self.fail_intent = fail_intent
        self.fail_outcome = fail_outcome
        self.closed = False

    def write_intent(self, record):
        if self.fail_intent:
            return False
        self.intents.append(record)
        return True

    def write_outcome(self, record):
        if self.fail_outcome:
            return False
        self.outcomes.append(record)
        return True

    def close(self):
        self.closed = True


class FakeClock(object):
    """Horodatage deterministe, au format du §8.2 (millisecondes obligatoires)."""

    def __init__(self, start=0):
        self.tick = start

    def __call__(self):
        self.tick += 1
        return "2026-01-01T00:00:%02d.%03d+01:00" % (
            self.tick % 60,
            self.tick % 1000,
        )


def make_params(
    names=None,
    dryrun=False,
    validate_roles=False,
    journal=True,
    max_objects=500,
):
    return Params(
        names=names or FieldNames(),
        dryrun=dryrun,
        validate_roles=validate_roles,
        journal=journal,
        max_objects=max_objects,
    )


def make_ctx(sid="sid_de_test", user="operateur", host="sh01", dryrun=False):
    return RunContext(sid=sid, user=user, host=host, dryrun=dryrun)


def make_event(
    title="Ma recherche",
    app="mon_app",
    id_value=None,
    eai_type="savedsearch",
    current_sharing=None,
    read=ABSENT,
    write=ABSENT,
    sharing=ABSENT,
    owner=ABSENT,
):
    """Construit un `EventInput`, **colonnes absentes par defaut**.

    Chacun des quatre attributs cibles vaut `ABSENT` tant qu'on ne le donne pas : un
    test qui ne parle pas d'un attribut decrit donc une colonne absente, ce qui est le
    cas nominal de preservation (§3.2). Passer `read=""` decrit au contraire une
    colonne presente a cellule vide — l'ordre de vidage.
    """
    present = set()
    values = {}
    for attribute, raw in (
        ("perms.read", read),
        ("perms.write", write),
        ("sharing", sharing),
        ("owner", owner),
    ):
        if raw is ABSENT:
            values[attribute] = None
            continue
        present.add(attribute)
        values[attribute] = raw

    return EventInput(
        title=title,
        app=app,
        id_value=id_value,
        eai_type=eai_type,
        current_sharing=current_sharing,
        new_perms_read=values["perms.read"],
        new_perms_write=values["perms.write"],
        new_sharing=values["sharing"],
        new_owner=values["owner"],
        present=frozenset(present),
    )


def state(owner="nobody", sharing="global", read=(), write=(), can_change_perms=True):
    return AclState(
        owner=owner,
        sharing=sharing,
        perms_read=tuple(read),
        perms_write=tuple(write),
        can_change_perms=can_change_perms,
    )
