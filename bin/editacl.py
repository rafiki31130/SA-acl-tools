#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Commande de recherche `editacl` — adaptateur, **aucune regle metier ici**.

Ce fichier fait trois choses et rien d'autre :

1. il insere `bin/lib` puis `bin` en tete de `sys.path`, avant tout autre import ;
2. il declare la commande et ses parametres (§4.1) et cable le noyau `acltools` ;
3. il traduit les exceptions fatales en sortie d'erreur et projette les champs `acl_*`
   du §5.7 dans l'enregistrement de sortie.

Toute la logique — normalisation, fusion, resolution d'endpoint, journal, machine a
etats — vit dans `acltools`, qui ne depend ni du SDK ni du reseau et se teste hors
Splunk.
"""

import os
import sys

# --------------------------------------------------------------------------- #
# sys.path — AVANT tout import du projet ou du SDK (§8.3 de la spec)
# `bin/lib` en tete : la version vendorisee prime sur celle de la plateforme.
# `bin` egalement, pour que `acltools` soit importable independamment du repertoire
# de travail du processus de recherche, que la plateforme ne garantit pas.
# Le chemin derive de `__file__`, jamais d'une variable d'environnement ni d'un chemin
# absolu.
# --------------------------------------------------------------------------- #
_BIN = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_BIN, "lib"), _BIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import configparser  # noqa: E402
import socket  # noqa: E402

from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    Option,
    StreamingCommand,
    dispatch,
    validators,
)

from acltools.binding import build_event  # noqa: E402
from acltools.diag import NullDiagnostics, open_diagnostics  # noqa: E402
from acltools.errors import FatalError  # noqa: E402
from acltools.journal import JournalWriter, journal_path  # noqa: E402
from acltools.mapping import load_mapping  # noqa: E402
from acltools.model import (  # noqa: E402
    ACL_OUTPUT_FIELDS,
    DEFAULT_FIELD_NAMES,
    RunContext,
)
from acltools.normalize import serialize_roles  # noqa: E402
from acltools.pipeline import (  # noqa: E402
    RUNTIME_DIVERGENCE_MESSAGE,
    RUNTIME_DIVERGENCE_WARNING,
    EventProcessor,
    ceiling_message,
)
from acltools.preflight import (  # noqa: E402
    DEFAULT_MAX_OBJECTS,
    AppStateCache,
    check_capability,
    check_realtime,
    load_roles_catalog,
    resolve_server_name,
    validate_params,
)
from acltools.rest import RestClient  # noqa: E402

_APP_ROOT = os.path.dirname(_BIN)
_MAP_JSON = os.path.join(_BIN, "acl_endpoint_map.json")
_OVERRIDE_CSV = os.path.join(_APP_ROOT, "lookups", "acl_endpoint_map_override.csv")


def _read_app_setting(name, default):
    """Lit `default/editacl.conf` puis `local/editacl.conf`.

    Volontairement par fichier et non par l'endpoint REST `configs/conf-editacl` :
    `verify_ssl` conditionne la construction du contexte TLS, on ne peut pas le lire
    par un appel qui en depend.
    """
    parser = configparser.ConfigParser()
    for layer in ("default", "local"):
        path = os.path.join(_APP_ROOT, layer, "editacl.conf")
        if os.path.exists(path):
            try:
                parser.read(path, encoding="utf-8")
            except (configparser.Error, OSError):
                continue
    if parser.has_option("editacl", name):
        return parser.get("editacl", name)
    return default


def _app_version():
    """Version declaree par `default/app.conf`, pour la ligne de demarrage du §8.1."""
    parser = configparser.ConfigParser()
    try:
        parser.read(os.path.join(_APP_ROOT, "default", "app.conf"), encoding="utf-8")
    except (configparser.Error, OSError):
        return ""
    for section in ("launcher", "id"):
        if parser.has_option(section, "version"):
            return parser.get(section, "version")
    return ""


def _abort_process(code=1):
    """Quitte le processus **sans** derouler les `finally` ni le protocole du SDK.

    Point d'indirection unique, pour deux raisons. La premiere est de nommer ce que
    fait `os._exit` : il n'y a pas de retour, pas de nettoyage, pas de chunk final.
    La seconde est de rendre le chemin d'echec **eprouvable** — un `os._exit` en dur
    tuerait le processus de test au lieu de le faire echouer.
    """
    os._exit(code)                                                   # pragma: no cover


def _truthy(value, default=True):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y", "on")


# `type` n'est pas passe a `@Configuration` : la classe de base `StreamingCommand` le
# fige a `streaming`, et le SDK refuse toute redeclaration. Le §2.1 du cahier des
# charges enonce `@Configuration(type='streaming', ...)` ; l'effet est identique, la
# forme est imposee par le SDK. `local = true` est porte par `commands.conf`.
@Configuration(local=True)
class EditAclCommand(StreamingCommand):
    """Reecrit les ACL d'objets de connaissance decrits par le pipeline d'entree.

    ##Syntax

    .. code-block::
        editacl [title=<champ>] [app=<champ>] [id=<champ>] [type=<champ>]
                [sharing=<champ>] [new_perms_read=<champ>] [new_perms_write=<champ>]
                [new_sharing=<champ>] [new_owner=<champ>] [dryrun=<bool>]
                [validate_roles=<bool>] [journal=<bool>] [max_objects=<entier>]

    ##Description

    Chaque parametre nomme le champ SPL ou lire une information, et prend pour defaut
    la nomenclature native : l'operateur qui l'emploie n'ecrit aucun parametre.

    C'est la **presence de la colonne** dans le jeu de resultats qui decide : colonne
    absente, attribut preserve ; colonne presente et cellule vide, attribut vide ;
    colonne presente et valuee, valeur appliquee.

    ##Example

    .. code-block::
        | `acl_inventory` | search "eai:acl.perms.write"="ancien_role"
        | eval "eai:acl.perms.write" = "nouveau_role_admin"
        | editacl dryrun=f max_objects=200
    """

    # -- parametres de nommage (§3.1) : desigen l'objet ---------------------- #
    title = Option(
        doc="Champ portant le nom de l'objet. Defaut : title.",
        require=False,
        default=None,
    )
    app = Option(
        doc="Champ portant l'application du namespace. Defaut : eai:acl.app.",
        require=False,
        default=None,
    )
    id = Option(
        doc="Champ portant l'URI complete de l'objet. Defaut : id.",
        require=False,
        default=None,
    )
    type = Option(
        doc="Champ portant le type d'objet, resolu par la table. Defaut : eai:type.",
        require=False,
        default=None,
    )
    sharing = Option(
        doc="Champ portant la portee COURANTE, qui sert a ecarter les objets prives. "
            "Defaut : eai:acl.sharing.",
        require=False,
        default=None,
    )

    # -- parametres de nommage (§3.3) : valeurs cibles ----------------------- #
    new_perms_read = Option(
        doc="Champ portant la valeur cible de perms.read. "
            "Defaut : eai:acl.perms.read.",
        require=False,
        default=None,
    )
    new_perms_write = Option(
        doc="Champ portant la valeur cible de perms.write. "
            "Defaut : eai:acl.perms.write.",
        require=False,
        default=None,
    )
    new_sharing = Option(
        doc="Champ portant la valeur cible de sharing. Defaut : eai:acl.sharing.",
        require=False,
        default=None,
    )
    new_owner = Option(
        doc="Champ portant la valeur cible de owner. Defaut : eai:acl.owner.",
        require=False,
        default=None,
    )

    dryrun = Option(
        doc="Simulation : aucune ecriture. Defaut : vrai.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    validate_roles = Option(
        doc="Controle de l'existence des roles ajoutes avant ecriture. Defaut : vrai.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    journal = Option(
        doc="Consignation dans le journal indexe. Defaut : vrai.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )
    max_objects = Option(
        doc="Nombre maximal d'objets ECRITS par execution. Defaut : 10. Sans effet en "
            "simulation, qui n'emet aucun POST et porte donc sur tout le lot.",
        require=False,
        default=None,
    )

    def __init__(self):
        super(EditAclCommand, self).__init__()
        self._processor = None
        # `_journal_writer`, et surtout PAS `_journal` : le SDK range la valeur d'une
        # `Option` dans l'attribut `"_" + <nom de l'option>`
        # (`searchcommands/decorators.py`). L'option `journal` occupe donc `_journal`.
        # Y ranger le writer creait une collision bidirectionnelle — le booleen de
        # l'option se faisait fermer comme un fichier sur le chemin d'erreur fatale, et
        # l'ecriture du writer rendait la valeur de l'option illisible.
        # `tests/test_editacl_adapter.py` interdit mecaniquement le retour du defaut.
        self._journal_writer = None
        self._params = None
        self._ready = False
        # Diagnostic inerte tant que le fichier n'est pas ouvert : aucun appel de
        # diagnostic ne peut lever avant `_setup()`.
        self._diag = NullDiagnostics()
        # Le message de divergence runtime/disque (§5.6) est emis **une fois** par
        # execution : un lot dont le systeme de fichiers refuse toute ecriture le
        # produirait sinon a chaque objet, et le noierait.
        self._runtime_divergence_signaled = False
        # L'avertissement de plafond (§4.3, D-28) est emis **une fois**, en fin
        # d'execution : c'est le seul moment ou le nombre d'objets ecartes est connu
        # d'une commande qui recoit son entree par chunks successifs. Emis a la premiere
        # atteinte, il ne pourrait pas le porter ; emis par objet, il serait du bruit.
        self._ceiling_signaled = False

    # -- declaration du jeu de champs de sortie (§5.7, D-33) ---------------- #

    def _declare_output_fields(self):
        """Declare au writer l'integralite du jeu de champs du §5.7.

        Le writer du SDK construit l'en-tete du flux a partir des **cles du premier
        enregistrement emis** (`RecordWriter._write_record`), puis y projette tous les
        suivants : un champ absent de ce premier enregistrement disparait de la sortie
        entiere, **sans erreur ni avertissement**. Les huit champs `acl_before_*` /
        `acl_after_*` n'etant portes que par les enregistrements dont la fusion a ete
        calculee, un lot commencant par un `skipped_private` prive l'operateur de tout
        ce que la simulation existe pour montrer — et la macro d'inventaire, qui liste
        les objets prives au meme titre que les autres, produit couramment de tels lots.

        Le SDK expose `RecordWriter.custom_fields` pour exactement cet usage : les noms
        qui y figurent sont ajoutes a l'en-tete quel que soit le contenu du premier
        enregistrement. **Le SDK vendorise n'est donc pas modifie** ; la declaration se
        fait depuis l'app, et `custom_fields` survit au `_clear()` de fin de chunk, ce
        qui la rend valable pour tous les chunks de l'execution.

        Appelee par `prepare()` — le point d'extension prevu par le SDK, invoque avant
        toute execution — **et** par `_setup()`, qui s'execute avant le premier `yield`
        et couvre donc le cas d'un protocole ou `prepare()` ne serait pas atteint. La
        declaration est idempotente.

        Aucune defaillance de cette declaration ne doit interrompre la commande : elle
        ameliore la sortie, elle ne conditionne aucune ecriture.
        """
        writer = getattr(self, "_record_writer", None)
        declared = getattr(writer, "custom_fields", None)
        if declared is None:                                         # pragma: no cover
            return
        try:
            declared.update(ACL_OUTPUT_FIELDS)
        except AttributeError:                                       # pragma: no cover
            pass

    def prepare(self):
        super(EditAclCommand, self).prepare()
        self._declare_output_fields()

    # -- cablage ----------------------------------------------------------- #

    def _setup(self):
        self._declare_output_fields()
        info = self._metadata.searchinfo
        sid = str(getattr(info, "sid", "") or "")
        splunk_home = os.environ.get("SPLUNK_HOME")
        log_dir = (
            os.path.join(splunk_home, "var", "log", "splunk") if splunk_home else ""
        )

        # Ouvert en tout premier, pour que la ligne de demarrage et **toute** erreur
        # fatale ulterieure — y compris un parametre invalide — soient consignees. Son
        # echec d'ouverture ne coute rien : `open_diagnostics` ne leve pas et rend un
        # diagnostic inerte (§8.1, le fichier de diagnostic n'est pas le filet).
        self._diag = open_diagnostics(log_dir, sid)
        verify_ssl = _truthy(_read_app_setting("verify_ssl", "true"), default=True)
        self._diag.startup(
            version=_app_version(),
            user=str(getattr(info, "username", "") or ""),
            splunkd_uri=str(getattr(info, "splunkd_uri", "") or ""),
            verify_ssl=verify_ssl,
        )

        params = validate_params(
            names_raw={
                "title": self.title,
                "app": self.app,
                "id": self.id,
                "type": self.type,
                "sharing": self.sharing,
                "new_perms_read": self.new_perms_read,
                "new_perms_write": self.new_perms_write,
                "new_sharing": self.new_sharing,
                "new_owner": self.new_owner,
            },
            dryrun=self.dryrun,
            validate_roles=self.validate_roles,
            journal=self.journal,
            max_objects=(
                DEFAULT_MAX_OBJECTS if self.max_objects is None else self.max_objects
            ),
            max_objects_explicit=self.max_objects is not None,
        )
        self._params = params
        self._diag.params(params)
        for warning in params.warnings:
            self.write_warning(warning)

        # La cle de session ne quitte jamais cette portee vers le diagnostic : aucune
        # methode de `Diagnostics` n'a de parametre qui la porte (§8.1, R5).
        session_key = getattr(info, "session_key", None)
        splunkd_uri = getattr(info, "splunkd_uri", None)
        if not session_key or not splunkd_uri:
            from acltools.errors import FatalConfigError

            raise FatalConfigError(
                "splunkd_uri ou session_key indisponibles : la commande ne peut pas "
                "s'adresser a la plateforme."
            )

        ca_file = None
        if verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not verify_ssl:
            self._diag.warning(
                "verify_ssl=false : verification du certificat de splunkd desactivee "
                "par local/editacl.conf."
            )
            self.write_warning(
                "verify_ssl=false : la verification du certificat de splunkd est "
                "desactivee par local/editacl.conf."
            )

        rest = RestClient(splunkd_uri, session_key, verify_ssl=verify_ssl, ca_file=ca_file)

        check_capability(rest)
        self._diag.capability(True)

        verdict = check_realtime(rest, sid)
        self._diag.realtime(verdict)
        if verdict == "unknown":
            self.write_warning(
                "mode temps reel non determinable pour ce sid : le garde-fou du §4.2 "
                "n'a pas pu s'appliquer."
            )

        roles_catalog = load_roles_catalog(rest) if params.validate_roles else frozenset()
        mapping = load_mapping(_MAP_JSON, _OVERRIDE_CSV, diag=self._diag)
        self._diag.mapping(mapping.coverage())

        host = resolve_server_name(rest) or socket.gethostname()
        self._diag.info("membre : %s" % host)
        ctx = RunContext(
            sid=sid,
            user=str(getattr(info, "username", "") or ""),
            host=host,
            dryrun=params.dryrun,
        )

        if params.journal:
            path = journal_path(log_dir, sid)
            try:
                self._journal_writer = JournalWriter(path)
                self._diag.journal(path, True)
            except FatalError:
                # L'echec d'ouverture n'est fatal que si une ecriture reelle est
                # prevue (§5.1 etape 7, §9). En simulation il degrade en avertissement.
                self._diag.journal(path, False)
                if not params.dryrun:
                    raise
                self._journal_writer = None
                self.write_warning(
                    "journal non ouvrable (%s) : execution en simulation poursuivie "
                    "sans journal." % path
                )

        self._processor = EventProcessor(
            params=params,
            ctx=ctx,
            rest=rest,
            journal=self._journal_writer,
            mapping=mapping,
            roles_catalog=roles_catalog,
            app_disabled_fn=AppStateCache(rest).is_app_disabled,
        )
        self._ready = True

    # -- boucle de traitement ---------------------------------------------- #

    def stream(self, records):
        try:
            for record in records:
                if not self._ready:
                    self._setup()
                yield self._handle(record)
            self._signal_ceiling()
        except FatalError as exc:
            # Point de consignation unique des erreurs fatales du §9. `_setup()` est
            # appele depuis ce `try`, ses erreurs passent donc ici. Le plafond, lui,
            # n'y figure plus : depuis D-28 il ne leve pas, il produit un statut.
            self._diag.fatal(str(exc))
            self._cleanup()
            self._fatal_exit(exc)
        finally:
            self._cleanup()

    def _signal_ceiling(self):
        """Avertissement unique de plafond, apres le dernier enregistrement (§4.3).

        La commande recoit son entree par chunks successifs : `stream()` est reinvoquee
        a chaque chunk, et le compteur du processeur les cumule. Le nombre d'objets
        ecartes n'est donc juste qu'au **dernier** chunk — que le SDK signale par
        `self._finished`, renseigne depuis la metadonnee du chunk avant l'appel.

        Emettre plus tot sous-compterait ; emettre a chaque chunk multiplierait un
        avertissement que le §4.3 veut unique. `_ceiling_signaled` ferme le cas du
        protocole v1, ou `_finished` n'est jamais renseigne.
        """
        processor = self._processor
        if processor is None or self._ceiling_signaled:
            return
        if processor.skipped_ceiling <= 0:
            return
        if getattr(self, "_finished", None) is False:
            return
        self._ceiling_signaled = True
        message = ceiling_message(
            self._params.max_objects, processor.skipped_ceiling
        )
        self._diag.warning(message)
        self.write_warning(message)

    def _cleanup(self):
        """Referme journal et diagnostic. Idempotent, et ne leve jamais.

        Une erreur fatale ne doit pas laisser de ligne non ecrite dans le tampon. Et le
        nettoyage ne doit JAMAIS supplanter l'erreur en cours de propagation : une
        exception levee dans un `finally` remplace celle qui remontait, c'est-a-dire le
        message que l'operateur attend. Chaque `close()` est donc protege, et l'attribut
        detache avant l'appel pour qu'un second passage ne le referme pas.
        """
        writer, self._journal_writer = self._journal_writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception:                                        # noqa: BLE001
                pass
        diag, self._diag = self._diag, NullDiagnostics()
        try:
            diag.close()
        except Exception:                                            # noqa: BLE001
            pass

    def _fatal_exit(self, exc):
        """Interrompt la recherche **en marquant le job en echec** (§4.3, A-4).

        `error_exit()` du SDK ecrit le message puis leve `SystemExit`, que le SDK
        convertit en `finish()` — un chunk final `finished: true` — suivi d'une sortie 1.
        Ce chunk dit a splunkd que la commande s'est terminee normalement, et splunkd
        ignore alors le code de retour. Mesure sur Splunk 9.4.6 : le job ressort
        `dispatchState=DONE`, `isFailed=false`, `resultCount=0`. Un ordonnanceur ou une
        alerte batie sur ce pipeline ne distingue donc pas une interruption d'un lot
        vide — le `MSG[ERROR]` n'est visible que pour qui inspecte le job.

        Le message est donc emis dans un chunk **non final**, puis le processus quitte
        avec un code non nul sans jamais envoyer `finished: true`. splunkd marque alors
        `dispatchState=FAILED` / `isFailed=true` **et conserve le message** ; il ajoute
        le sien, « External search command exited unexpectedly with non-zero error
        code 1 », qui est exact.

        `os._exit` court-circuite les `finally` : le nettoyage est fait par l'appelant
        **avant** cet appel. Le journal ne perd rien pour autant — chaque ligne est
        deja `flush()`ee a l'ecriture, et la ligne `intent` `fsync()`ee (§8.4).
        """
        message = str(exc)
        try:
            self.write_error(message)
            record_writer = getattr(self, "_record_writer", None)
            write_chunk = getattr(record_writer, "write_chunk", None)
            if write_chunk is not None:
                # Chunk **non final** : le message part, la fin de flux n'est pas
                # annoncee. `_write_chunk` vide lui-meme le tampon de sortie.
                write_chunk(finished=False)
            else:                                                    # pragma: no cover
                # Protocole v1 : pas de chunk, le flush suffit a pousser l'en-tete de
                # messages.
                self.flush()
        except Exception:                                            # noqa: BLE001
            # Aucune defaillance de la sortie ne doit empecher le marquage en echec :
            # c'est la seule chose que cette methode doit garantir.
            pass
        _abort_process(1)

    def _handle(self, record):
        # `record` est l'enregistrement brut du chunk : la presence d'une cle y est
        # exactement la presence de la colonne dans le jeu de resultats (§3.2). C'est le
        # seul endroit ou l'enregistrement est lu, et il est passe tel quel a
        # `build_event` — aucun `get()` avec defaut ne vient effacer la distinction entre
        # « colonne absente » et « cellule vide » avant que la regle ne l'ait tranchee.
        event = build_event(record, self._params.names)
        result = self._processor.process(event)

        if (
            RUNTIME_DIVERGENCE_WARNING in result.warnings
            and not self._runtime_divergence_signaled
        ):
            self._runtime_divergence_signaled = True
            self.write_warning(RUNTIME_DIVERGENCE_MESSAGE)

        output = dict(record)
        output["acl_status"] = result.status
        output["acl_endpoint"] = result.endpoint
        output["acl_http_code"] = result.http_code
        output["acl_error"] = result.error or ""
        output["acl_warning"] = ";".join(result.warnings)
        output["acl_journaled"] = "true" if result.journaled else "false"
        if result.before is not None:
            output["acl_before_owner"] = result.before.owner
            output["acl_before_perms_read"] = serialize_roles(result.before.perms_read)
            output["acl_before_perms_write"] = serialize_roles(result.before.perms_write)
            output["acl_before_sharing"] = result.before.sharing
        if result.after is not None:
            output["acl_after_owner"] = result.after.owner
            output["acl_after_perms_read"] = serialize_roles(result.after.perms_read)
            output["acl_after_perms_write"] = serialize_roles(result.after.perms_write)
            output["acl_after_sharing"] = result.after.sharing
        return output


dispatch(EditAclCommand, sys.argv, sys.stdin, sys.stdout, __name__)
