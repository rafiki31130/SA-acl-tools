"""Journal write-ahead (§8).

Le journal porte **deux besoins distincts** qu'une ligne unique ne peut satisfaire :
la persistance de l'etat anterieur **avant** la mutation (jeu de restauration) et la
trace du resultat **apres** la mutation (controle d'execution). Un champ `phase` les
discrimine.

La **construction** des enregistrements est pure et separee de l'**ecriture** : c'est
ce qui permet d'eprouver la conformite au §8.2 et l'alimentation de la macro §8.6 sans
toucher au disque.

**Un fichier par `sid`, sans rotation par taille** (D-3). Un handler rotatif partage
n'est pas sur entre processus : deux executions concurrentes sur le meme membre
peuvent perdre des lignes au moment d'une rotation. Le journal etant le seul filet de
securite d'une operation irreversible, une fenetre connue de perte de lignes n'est pas
acceptable quand le correctif coute un nom de fichier.
"""

import json
import os
import re

from .errors import FatalJournalError
from .normalize import serialize_roles

#: Nom de fichier du journal. La stanza de monitor du §8.3 est un glob correspondant.
JOURNAL_BASENAME = "editacl_journal_%s.log"

#: Caracteres admis dans un `sid` utilise comme composant de nom de fichier.
_SAFE_SID = re.compile(r"[^A-Za-z0-9._-]")


def journal_filename(sid):
    """Nom de fichier du journal d'une execution, `sid` assaini."""
    token = _SAFE_SID.sub("_", str(sid or "unknown"))
    return JOURNAL_BASENAME % (token or "unknown")


def journal_path(log_dir, sid):
    return os.path.join(log_dir, journal_filename(sid))


def _state_fields(prefix, state):
    """Les **quatre** attributs d'un etat, prefixes `before_` ou `after_` (§8.2).

    `owner` y figure depuis D-22 : c'est desormais une valeur cible, et la macro de
    restauration du §8.6 lit `before_owner` pour reemettre `eai:acl.owner`. Le porter
    dans le bloc d'etat plutot qu'en champ commun est ce qui donne au journal un
    `before_owner` **et** un `after_owner` distincts quand la propriete change.
    """
    return {
        prefix + "_owner": state.owner or "",
        prefix + "_perms_read": serialize_roles(state.perms_read),
        prefix + "_perms_write": serialize_roles(state.perms_write),
        prefix + "_sharing": state.sharing or "",
    }


def _common_record(ctx, result, phase):
    """Champs communs aux deux phases (§8.2).

    Contraintes de format appliquees sans exception : pas de deux-points dans un nom de
    champ, valeur vide serialisee en chaine vide et jamais `null` (`null` est reserve a
    `error`).
    """
    return {
        "ts": "",  # renseigne par le constructeur appelant
        "phase": phase,
        "sid": str(ctx.sid or ""),
        "user": str(ctx.user or ""),
        "host": str(ctx.host or ""),
        "dryrun": bool(ctx.dryrun),
        "endpoint": str(result.endpoint or ""),
        "app": str(result.app or ""),
        "title": str(result.title or ""),
        "eai_type": str(result.eai_type or ""),
    }


def build_intent_record(ctx, result, ts):
    """Ligne `phase=intent` : etat anterieur complet et charge utile prevue.

    Le champ `title` est journalise **non encode** : la restauration le reinjecte tel
    quel, et un titre deja encode serait re-encode.
    """
    record = _common_record(ctx, result, "intent")
    record["ts"] = ts
    record.update(_state_fields("before", result.before))
    record.update(_state_fields("after", result.after))
    return record


def build_outcome_record(ctx, result, ts):
    """Ligne `phase=outcome` : statut, code HTTP, erreur.

    Elle porte les six champs `before_*` / `after_*` **si et seulement si** la fusion a
    ete calculee **et** qu'aucune ligne `intent` ne les porte deja (§8.2). Les statuts
    issus d'un rejet amont ne les portent pas : ils n'ont pas ete calcules.
    """
    record = _common_record(ctx, result, "outcome")
    record["ts"] = ts
    record["status"] = str(result.status)
    record["http_code"] = int(result.http_code or 0)
    record["error"] = result.error if result.error else None

    merged = result.before is not None and result.after is not None
    if merged and not result.journaled:
        record.update(_state_fields("before", result.before))
        record.update(_state_fields("after", result.after))
    return record


def dumps(record):
    """Une ligne JSON compacte, sans retour a la ligne dans une valeur."""
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


class JournalWriter(object):
    """Implementation du port `JournalPort` sur un fichier local.

    `write_intent` garantit la **durabilite** (write + flush + fsync) : c'est la
    precondition a l'ecriture du §8.4. `write_outcome` se contente d'un flush — le POST
    a deja eu lieu, il n'y a plus rien a garantir, et un fsync par objet doublerait le
    cout d'ecriture d'une operation deja serialisee.

    Ni l'un ni l'autre ne leve : l'echec d'ecriture est un fait a consigner, pas une
    interruption. Seule l'**ouverture** peut etre fatale (§9).
    """

    def __init__(self, path):
        self.path = path
        try:
            self._handle = open(path, "a", encoding="utf-8", newline="\n")
        except (IOError, OSError) as exc:
            raise FatalJournalError(
                "journal non ouvrable en ecriture (%s) : %s" % (path, exc)
            )

    def _write(self, record, sync):
        try:
            self._handle.write(dumps(record) + "\n")
            self._handle.flush()
            if sync:
                os.fsync(self._handle.fileno())
            return True
        except (IOError, OSError, ValueError):
            return False

    def write_intent(self, record):
        return self._write(record, sync=True)

    def write_outcome(self, record):
        return self._write(record, sync=False)

    def close(self):
        try:
            self._handle.close()
        except (IOError, OSError, ValueError):
            pass
