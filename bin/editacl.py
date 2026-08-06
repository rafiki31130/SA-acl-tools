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

from acltools.errors import FatalError, MaxObjectsReached  # noqa: E402
from acltools.journal import JournalWriter, journal_path  # noqa: E402
from acltools.mapping import load_mapping  # noqa: E402
from acltools.model import EventInput, RunContext  # noqa: E402
from acltools.normalize import serialize_roles  # noqa: E402
from acltools.pipeline import EventProcessor  # noqa: E402
from acltools.preflight import (  # noqa: E402
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
        editacl [fields=<liste>] [dryrun=<bool>] [validate_roles=<bool>]
                [journal=<bool>] [max_objects=<entier>]

    ##Description

    Chaque evenement d'entree designe un objet (`title`, `eai:acl.app`,
    `eai:acl.owner`, plus `id` ou `eai:type`) et porte l'etat ACL cible. La commande
    lit l'etat courant par l'API REST, calcule l'etat cible en ne prenant de
    l'evenement que les attributs listes dans `fields`, et ecrit — sauf en simulation.

    ##Example

    .. code-block::
        | `acl_inventory` | search "eai:acl.perms.write"="ancien_role"
        | eval "eai:acl.perms.write" = "nouveau_role_admin"
        | editacl fields=perms.write dryrun=f max_objects=200
    """

    fields = Option(
        doc="Attributs ACL a prendre depuis l'evenement : perms.read, perms.write, "
            "sharing. Toute autre valeur, y compris owner, est une erreur fatale.",
        require=False,
        default="perms.read,perms.write",
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
        doc="Nombre maximal d'objets ecrits par execution. Defaut : 500.",
        require=False,
        default=None,
    )

    def __init__(self):
        super(EditAclCommand, self).__init__()
        self._processor = None
        self._journal = None
        self._params = None
        self._ready = False

    # -- cablage ----------------------------------------------------------- #

    def _setup(self):
        info = self._metadata.searchinfo

        params = validate_params(
            fields_raw=self.fields,
            dryrun=self.dryrun,
            validate_roles=self.validate_roles,
            journal=self.journal,
            max_objects=500 if self.max_objects is None else self.max_objects,
            max_objects_explicit=self.max_objects is not None,
        )
        self._params = params
        for warning in params.warnings:
            self.write_warning(warning)

        session_key = getattr(info, "session_key", None)
        splunkd_uri = getattr(info, "splunkd_uri", None)
        if not session_key or not splunkd_uri:
            from acltools.errors import FatalConfigError

            raise FatalConfigError(
                "splunkd_uri ou session_key indisponibles : la commande ne peut pas "
                "s'adresser a la plateforme."
            )

        verify_ssl = _truthy(_read_app_setting("verify_ssl", "true"), default=True)
        ca_file = None
        splunk_home = os.environ.get("SPLUNK_HOME")
        if verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not verify_ssl:
            self.write_warning(
                "verify_ssl=false : la verification du certificat de splunkd est "
                "desactivee par local/editacl.conf."
            )

        rest = RestClient(splunkd_uri, session_key, verify_ssl=verify_ssl, ca_file=ca_file)

        check_capability(rest)

        sid = str(getattr(info, "sid", "") or "")
        if check_realtime(rest, sid) == "unknown":
            self.write_warning(
                "mode temps reel non determinable pour ce sid : le garde-fou du §4.2 "
                "n'a pas pu s'appliquer."
            )

        roles_catalog = load_roles_catalog(rest) if params.validate_roles else frozenset()
        mapping = load_mapping(_MAP_JSON, _OVERRIDE_CSV)

        host = resolve_server_name(rest) or socket.gethostname()
        ctx = RunContext(
            sid=sid,
            user=str(getattr(info, "username", "") or ""),
            host=host,
            dryrun=params.dryrun,
        )

        if params.journal:
            log_dir = os.path.join(splunk_home or "", "var", "log", "splunk")
            path = journal_path(log_dir, sid)
            try:
                self._journal = JournalWriter(path)
            except FatalError:
                # L'echec d'ouverture n'est fatal que si une ecriture reelle est
                # prevue (§5.1 etape 7, §9). En simulation il degrade en avertissement.
                if not params.dryrun:
                    raise
                self._journal = None
                self.write_warning(
                    "journal non ouvrable (%s) : execution en simulation poursuivie "
                    "sans journal." % path
                )

        self._processor = EventProcessor(
            params=params,
            ctx=ctx,
            rest=rest,
            journal=self._journal,
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
        except MaxObjectsReached as exc:
            self.error_exit(exc, str(exc))
        except FatalError as exc:
            self.error_exit(exc, str(exc))
        finally:
            # Une erreur fatale ne doit pas laisser de ligne non ecrite dans le tampon.
            if self._journal is not None:
                self._journal.close()
                self._journal = None

    def _handle(self, record):
        event = EventInput(
            title=record.get("title") or "",
            app=record.get("eai:acl.app") or "",
            owner=record.get("eai:acl.owner") or "",
            id_value=record.get("id"),
            eai_type=record.get("eai:type"),
            raw_perms_read=record.get("eai:acl.perms.read"),
            raw_perms_write=record.get("eai:acl.perms.write"),
            raw_sharing=record.get("eai:acl.sharing"),
        )
        result = self._processor.process(event)

        output = dict(record)
        output["acl_status"] = result.status
        output["acl_endpoint"] = result.endpoint
        output["acl_http_code"] = result.http_code
        output["acl_error"] = result.error or ""
        output["acl_warning"] = ";".join(result.warnings)
        output["acl_owner"] = result.owner
        output["acl_journaled"] = "true" if result.journaled else "false"
        if result.before is not None:
            output["acl_before_perms_read"] = serialize_roles(result.before.perms_read)
            output["acl_before_perms_write"] = serialize_roles(result.before.perms_write)
            output["acl_before_sharing"] = result.before.sharing
        if result.after is not None:
            output["acl_after_perms_read"] = serialize_roles(result.after.perms_read)
            output["acl_after_perms_write"] = serialize_roles(result.after.perms_write)
            output["acl_after_sharing"] = result.after.sharing
        return output


dispatch(EditAclCommand, sys.argv, sys.stdin, sys.stdout, __name__)
