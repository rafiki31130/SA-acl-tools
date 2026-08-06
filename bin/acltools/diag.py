"""Journal de diagnostic d'execution — `editacl.log` (§8.1).

**Ce fichier n'est pas le journal de restauration.** Le journal write-ahead
(`editacl_journal_<sid>.log`) est le seul filet de securite d'une operation
irreversible : sa perte n'est pas acceptable, et c'est pourquoi D-3 lui interdit la
rotation et lui impose un fichier par execution. Le present fichier ne porte aucun etat
restaurable ; **sa perte n'est pas critique**. Il reste donc unique et rotatif comme
l'exige le §8.1, et — consequence directe — **aucun de ses echecs n'est fatal, aucun
n'annule ni ne differe une ecriture**. Un diagnostic qui interrompt l'operation qu'il
observe serait une seconde defaillance ajoutee a la premiere.

Contenu, tel que l'enumere le §8.1 : demarrage, controle d'habilitation, parametres,
resolution de la table de correspondance, erreurs fatales.

**Aucun secret n'y entre.** La garantie est d'abord **structurelle** : ce module ne
recoit jamais la cle de session — ni le `Diagnostics`, ni aucune de ses methodes n'a de
parametre qui la porte, et `rest.py` ne lui parle pas. La redaction ci-dessous est une
seconde ligne : les messages d'erreur de la plateforme sont recopies dans le fichier, et
un fichier de diagnostic collecte vers un index est lu par bien plus de monde que le
disque d'un search head.
"""

import logging
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler

#: Nom du fichier, unique et rotatif (§8.1). La stanza de monitor du §8.3 le nomme.
DIAG_BASENAME = "editacl.log"

#: Rotation imposee par le §8.1 : 5 Mo, 5 sauvegardes.
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5

LOGGER_NAME = "editacl.diag"

REDACTED = "[redige]"

#: Motifs de redaction. Deliberement larges : un faux positif rend une ligne de
#: diagnostic moins lisible, un faux negatif publie un secret dans un index.
_SECRET_PATTERNS = (
    # En-tete d'authentification Splunk, sous toutes ses formes.
    re.compile(r"(?i)\bSplunk\s+[A-Za-z0-9+/=._-]{20,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9+/=._-]{10,}"),
    # `cle: valeur` ou `cle=valeur` pour toute cle qui nomme un secret.
    re.compile(
        r"(?i)\b(session[_-]?key|authorization|api[_-]?key|access[_-]?token|token"
        r"|password|passwd|pwd|secret|credential)\b\s*[:=]\s*\S+"
    ),
)


def redact(message):
    """Retire d'un message toute forme reconnaissable de secret.

    La troncature est proscrite : un secret tronque reste un secret partiellement
    divulgue, et il suffit souvent a reduire un espace de recherche.
    """
    text = "" if message is None else str(message)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    # Une ligne de diagnostic est une ligne : un message multiligne casserait le
    # `LINE_BREAKER` du sourcetype `editacl:diag` (§8.3).
    return text.replace("\r", " ").replace("\n", " ")


def diag_path(log_dir):
    return os.path.join(log_dir or "", DIAG_BASENAME)


class _Formatter(logging.Formatter):
    """Horodatage ISO 8601 avec fuseau et millisecondes, aligne sur le journal (§8.2)."""

    def formatTime(self, record, datefmt=None):                      # noqa: N802
        return (
            datetime.fromtimestamp(record.created)
            .astimezone()
            .isoformat(timespec="milliseconds")
        )


class NullDiagnostics(object):
    """Diagnostic inerte : meme surface, aucun effet.

    C'est la valeur par defaut de l'enveloppe. Elle garantit qu'aucun appel de
    diagnostic ne peut lever avant que le fichier ne soit ouvert, ni apres son echec
    d'ouverture — la perte du diagnostic ne doit jamais couter une execution.
    """

    path = None
    enabled = False

    def __call__(self, level, message):
        pass

    def info(self, message):
        pass

    def warning(self, message):
        pass

    def fatal(self, message):
        pass

    def startup(self, **kwargs):
        pass

    def params(self, params):
        pass

    def capability(self, granted, detail=""):
        pass

    def realtime(self, verdict):
        pass

    def mapping(self, coverage):
        pass

    def journal(self, path, opened):
        pass

    def close(self):
        pass


class Diagnostics(NullDiagnostics):
    """Ecrivain du fichier de diagnostic.

    Un `logging.Logger` est **construit directement**, jamais obtenu de
    `logging.getLogger` : le registre global est partage par tout le processus de
    recherche, et y attacher un handler exposerait a recevoir les enregistrements
    d'autres bibliotheques — dont on ne controle ni le contenu ni l'absence de secret.
    """

    enabled = True

    _LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "FATAL": logging.CRITICAL,
        "CRITICAL": logging.CRITICAL,
    }

    def __init__(self, path, sid="", handler=None):
        self.path = path
        self._sid = str(sid or "")
        self._logger = logging.Logger(LOGGER_NAME, logging.INFO)
        self._logger.propagate = False
        self._handler = handler or RotatingFileHandler(
            path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        self._handler.setFormatter(
            _Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        self._logger.addHandler(self._handler)

    # -- primitives --------------------------------------------------------- #

    def __call__(self, level, message):
        """Signature du rappel `diag` attendu par `load_mapping` : `(niveau, message)`."""
        self._emit(self._LEVELS.get(str(level).upper(), logging.INFO), message)

    def _emit(self, level, message):
        try:
            self._logger.log(
                level, "sid=%s %s", self._sid or "-", redact(message)
            )
        except Exception:                                            # noqa: BLE001
            # Un diagnostic ne peut pas faire echouer ce qu'il observe (§8.1).
            pass

    def info(self, message):
        self._emit(logging.INFO, message)

    def warning(self, message):
        self._emit(logging.WARNING, message)

    def fatal(self, message):
        self._emit(logging.CRITICAL, "erreur fatale : %s" % message)

    # -- evenements enumeres par le §8.1 ------------------------------------ #

    def startup(self, version="", user="", splunkd_uri="", verify_ssl=None):
        """Ligne de demarrage. Le membre est journalise separement : `serverName` n'est
        connu qu'apres un appel REST, et cette ligne doit preceder tout ce qui peut
        echouer."""
        self.info(
            "demarrage editacl version=%s user=%s splunkd=%s verify_ssl=%s"
            % (
                version or "?",
                user or "-",
                splunkd_uri or "-",
                "?" if verify_ssl is None else str(bool(verify_ssl)).lower(),
            )
        )

    def params(self, params):
        self.info(
            "parametres fields=%s dryrun=%s validate_roles=%s journal=%s "
            "max_objects=%s"
            % (
                ",".join(sorted(params.fields)),
                str(bool(params.dryrun)).lower(),
                str(bool(params.validate_roles)).lower(),
                str(bool(params.journal)).lower(),
                params.max_objects,
            )
        )
        for warning in params.warnings or ():
            self.warning("parametres : %s" % warning)

    def capability(self, granted, detail=""):
        if granted:
            self.info("controle d'habilitation : capability accordee")
        else:
            self.warning("controle d'habilitation : refuse (%s)" % (detail or "?"))

    def realtime(self, verdict):
        self.info("controle temps reel : %s" % verdict)

    def mapping(self, coverage):
        self.info(
            "table de correspondance : %d entrees (%d livrees, %d d'override, "
            "%d surchargees, %d ecartees)"
            % (
                coverage.get("total", 0),
                coverage.get("from_json", 0),
                coverage.get("from_override", 0),
                len(coverage.get("overridden") or ()),
                len(coverage.get("rejected") or ()),
            )
        )

    def journal(self, path, opened):
        if opened:
            self.info("journal de restauration ouvert : %s" % path)
        else:
            self.warning("journal de restauration non ouvrable : %s" % path)

    def close(self):
        try:
            self._logger.removeHandler(self._handler)
            self._handler.close()
        except Exception:                                            # noqa: BLE001
            pass


def open_diagnostics(log_dir, sid=""):
    """Ouvre le fichier de diagnostic, ou renvoie un diagnostic inerte.

    **Ne leve jamais.** L'absence de diagnostic degrade l'observabilite, elle ne remet
    en cause ni la surete de l'operation ni sa reversibilite : ces deux proprietes
    reposent entierement sur le journal de restauration, qui est un autre fichier avec
    d'autres garanties.
    """
    if not log_dir:
        return NullDiagnostics()
    try:
        return Diagnostics(diag_path(log_dir), sid=sid)
    except Exception:                                                # noqa: BLE001
        return NullDiagnostics()
