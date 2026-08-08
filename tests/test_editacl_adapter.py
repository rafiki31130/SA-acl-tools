"""Enveloppe `bin/editacl.py` — chemin d'erreur fatale et collision de noms d'attributs.

Ce module est le seul a exercer `bin/editacl.py` lui-meme. Il le charge avec un **SDK
factice** injecte dans `sys.modules`, jamais avec le SDK vendorise : `bin/lib` n'entre
donc pas dans `sys.path` de la suite, et le §11.1 reste satisfait — hors Splunk, sans
reseau.

Le faux SDK reproduit **une seule chose, mais exactement** : la regle de nommage du
champ de stockage d'une `Option`, `backing_field_name = "_" + name`
(`splunklib/searchcommands/decorators.py`). C'est cette regle qui fait qu'une option
nommee `journal` occupe l'attribut `_journal` de l'instance — le meme que celui ou
l'adaptateur rangeait son `JournalWriter`.

La collision est **bidirectionnelle** :

- avant `_setup()`, l'attribut porte le booleen de l'option, et tout `close()` sur lui
  leve `AttributeError` ;
- apres `_setup()`, l'ecriture du writer **ecrase la valeur de l'option**, qui n'est
  plus lisible.

Elle ne se manifeste que sur le chemin d'erreur fatale anterieur a l'ouverture du
journal — typiquement l'echec du controle d'habilitation — c'est-a-dire exactement au
moment ou l'operateur a besoin du message. Elle le remplace par une trace Python.
"""

import ast
import os
import sys
import types
import unittest

from . import BIN_DIR, REPO_ROOT

SDK_DIR = os.path.join(BIN_DIR, "lib", "splunk" + "lib", "searchcommands")


# --------------------------------------------------------------------------- #
# Faux SDK — strictement ce que `bin/editacl.py` importe
# --------------------------------------------------------------------------- #

class _FakeOption(object):
    """Descripteur reproduisant la regle de nommage du champ de stockage du SDK."""

    def __init__(self, doc=None, require=False, default=None, validate=None):
        self.default = default
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name
        self.backing_field_name = "_" + name           # la regle du SDK, litteralement

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return getattr(instance, self.backing_field_name, self.default)

    def __set__(self, instance, value):
        setattr(instance, self.backing_field_name, value)


class _FakeRecordWriter(object):
    """Ecrivain de chunks factice. Enregistre l'etat `finished` de chaque chunk : c'est
    lui qui decide si splunkd marque le job en echec (§4.3, A-4).

    Il reproduit par ailleurs **une seule autre chose, mais exactement** : la regle par
    laquelle `RecordWriter._write_record` construit l'en-tete du flux
    (`splunklib/searchcommands/internals.py`).

        fieldnames = self._fieldnames
        if fieldnames is None:
            self._fieldnames = fieldnames = list(record.keys())
            self._fieldnames.extend(
                [i for i in self.custom_fields if i not in self._fieldnames]
            )
        for fieldname in fieldnames:
            value = get_value(fieldname, None)

    Deux consequences, et ce sont elles que les tests exercent : l'en-tete est fige sur
    les cles du **premier** enregistrement emis, et les noms declares dans
    `custom_fields` y sont ajoutes **quel que soit** le contenu de ce premier
    enregistrement. `LeDoubleReproduitLeSdkTest` adosse cette double a la source du SDK
    vendorise, que la suite ne charge pas (§11.1).
    """

    def __init__(self):
        self.chunks = []
        self.custom_fields = set()
        self._fieldnames = None
        self.rows = []

    def write_chunk(self, finished=None):
        self.chunks.append(finished)

    def write_record(self, record):
        fieldnames = self._fieldnames
        if fieldnames is None:
            self._fieldnames = fieldnames = list(record.keys())
            self._fieldnames.extend(
                [i for i in self.custom_fields if i not in self._fieldnames]
            )
        self.rows.append(
            dict((nom, record.get(nom, None)) for nom in fieldnames)
        )

    def write_records(self, records):
        for record in records:
            self.write_record(record)

    @property
    def header(self):
        """Jeu de colonnes du flux, c'est-a-dire ce que l'operateur voit."""
        return list(self._fieldnames or [])


class _FakeSearchCommand(object):
    def __init__(self):
        self._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace())
        self._record_writer = _FakeRecordWriter()
        self.warnings = []
        self.errors = []
        self.flushes = 0
        self.finishes = 0

    def prepare(self):
        """Point d'extension du SDK, invoque avant toute execution. Inerte ici."""

    def write_warning(self, message):
        self.warnings.append(message)

    def write_error(self, message):
        self.errors.append(message)

    def flush(self):
        self.flushes += 1

    def finish(self):
        self.finishes += 1

    def error_exit(self, error, message=None):
        self.errors.append(message or str(error))
        raise SystemExit(message or str(error))


class Abandon(Exception):
    """Substitut de `os._exit` dans les tests : le vrai tuerait le processus de test."""

    def __init__(self, code):
        super(Abandon, self).__init__("abandon(%s)" % code)
        self.code = code


def _intercepter_labandon(module):
    """Remplace la sortie de processus par une exception observable."""
    def _abandon(code=1):
        raise Abandon(code)

    module._abort_process = _abandon


class _FakeBoolean(object):
    def __call__(self, value):
        return value


def _install_fake_sdk():
    """Injecte le faux SDK dans `sys.modules` et renvoie les cles ajoutees."""
    nom = "splunk" + "lib"
    ajoutees = []
    for cle in (nom, nom + ".searchcommands"):
        if cle not in sys.modules:
            ajoutees.append(cle)
    racine = types.ModuleType(nom)
    module = types.ModuleType(nom + ".searchcommands")
    module.Option = _FakeOption
    module.StreamingCommand = _FakeSearchCommand
    module.Configuration = lambda **kwargs: (lambda cls: cls)
    module.dispatch = lambda *args, **kwargs: None
    module.validators = types.SimpleNamespace(Boolean=_FakeBoolean)
    racine.searchcommands = module
    sys.modules[nom] = racine
    sys.modules[nom + ".searchcommands"] = module
    return ajoutees


def _charger_editacl():
    """Charge `bin/editacl.py` sous le faux SDK, sans polluer durablement `sys.path`."""
    import importlib.util

    chemin_lib = os.path.join(BIN_DIR, "lib")
    path_avant = list(sys.path)
    modules_ajoutes = _install_fake_sdk()
    try:
        spec = importlib.util.spec_from_file_location(
            "editacl_sous_sdk_factice", os.path.join(BIN_DIR, "editacl.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        # `bin/editacl.py` insere `bin/lib` en tete de `sys.path` : on annule, sans quoi
        # la suite cesserait de prouver que le noyau s'importe sans le SDK vendorise.
        sys.path[:] = [p for p in path_avant if p != chemin_lib]
        for cle in modules_ajoutes:
            sys.modules.pop(cle, None)


class CheminErreurFataleTest(unittest.TestCase):
    """Une erreur fatale anterieure a l'ouverture du journal doit remonter **telle
    quelle**. Le nettoyage du `finally` ne doit jamais la supplanter."""

    MESSAGE = (
        "controle d'habilitation impossible : reponse inexploitable de "
        "/services/authentication/current-context (HTTP 0)"
    )

    def setUp(self):
        self.module = _charger_editacl()
        _intercepter_labandon(self.module)
        from acltools.errors import FatalCapabilityError

        self.commande = self.module.EditAclCommand()
        self.commande.journal = True          # ce que fait le SDK sur `journal=t`
        self.commande.dryrun = True

        def _setup_qui_echoue():
            raise FatalCapabilityError(self.MESSAGE)

        self.commande._setup = _setup_qui_echoue

    def test_le_message_dorigine_nest_pas_remplace_par_une_trace_python(self):
        with self.assertRaises(Abandon):
            list(self.commande.stream([{"title": "un_objet"}]))
        self.assertEqual(self.commande.errors, [self.MESSAGE])

    def test_aucune_attributeerror_sur_le_nettoyage(self):
        try:
            list(self.commande.stream([{"title": "un_objet"}]))
        except Abandon:
            pass
        except AttributeError as exc:                            # pragma: no cover
            self.fail(
                "le nettoyage du `finally` a leve une AttributeError et masque "
                "l'erreur fatale : %s" % exc
            )

    def test_la_valeur_de_loption_journal_reste_lisible(self):
        """L'option et le writer sont deux choses distinctes : ecrire l'un ne doit pas
        rendre l'autre illisible."""
        self.assertIs(self.commande.journal, True)
        self.commande._journal_writer = object()
        self.assertIs(self.commande.journal, True)


class MarquageDuJobEnEchecTest(unittest.TestCase):
    """A-4 — une erreur fatale du §9 doit marquer le job en echec.

    Mesure sur Splunk 9.4.6 : le marquage depend d'un seul fait, le chunk final
    `finished: true`. `error_exit()` du SDK l'envoie avant de quitter, et splunkd ignore
    alors le code de retour du processus. Emettre le message dans un chunk **non final**
    puis quitter en code non nul donne `dispatchState=FAILED`, `isFailed=true`, **et**
    conserve le message.

    Le plafond `max_objects` **ne passe plus par ici** (D-28) : il n'est plus fatal. Le
    chemin est desormais exerce par la capability absente, qui reste au §9.
    """

    MESSAGE = "capability 'edit_acl_bulk' absente. Roles de l'utilisateur : (aucun)"

    def setUp(self):
        self.module = _charger_editacl()
        _intercepter_labandon(self.module)
        from acltools.errors import FatalCapabilityError

        self.commande = self.module.EditAclCommand()
        self.commande.journal = True
        self.commande.dryrun = False

        message = self.MESSAGE

        def _setup_qui_echoue():
            raise FatalCapabilityError(message)

        self.commande._setup = _setup_qui_echoue

    def _executer(self):
        with self.assertRaises(Abandon) as leve:
            list(self.commande.stream([{"title": "un_objet"}]))
        return leve.exception

    def test_le_processus_quitte_en_code_non_nul(self):
        self.assertEqual(self._executer().code, 1)

    def test_le_chunk_emis_nest_pas_final(self):
        """Le point de fond : `finished: true` ferait ignorer le code de retour."""
        self._executer()
        self.assertEqual(self.commande._record_writer.chunks, [False])
        self.assertEqual(self.commande.finishes, 0)

    def test_le_message_est_conserve(self):
        """Marquer le job en echec ne doit pas couter le message de l'operateur."""
        self._executer()
        self.assertEqual(len(self.commande.errors), 1)
        self.assertIn("edit_acl_bulk", self.commande.errors[0])

    def test_le_sdk_error_exit_nest_plus_employe(self):
        """`error_exit()` envoie `finished: true` : il ne peut pas marquer l'echec."""
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read(), filename=chemin)
        appels = {
            ast.unparse(noeud.func)
            for noeud in ast.walk(arbre)
            if isinstance(noeud, ast.Call)
        }
        self.assertNotIn("self.error_exit", appels)
        self.assertNotIn("self.finish", appels)

    def test_journal_et_diagnostic_sont_refermes_avant_labandon(self):
        """`os._exit` court-circuite les `finally` : le nettoyage doit preceder."""
        etat = {"journal": False, "diag": False}

        class _Journal(object):
            def close(self):
                etat["journal"] = True

        from acltools.diag import NullDiagnostics

        class _Diag(NullDiagnostics):
            def close(self):
                etat["diag"] = True

        self.commande._journal_writer = _Journal()
        self.commande._diag = _Diag()
        self._executer()
        self.assertEqual(etat, {"journal": True, "diag": True})


class CollisionDeNomsTest(unittest.TestCase):
    """Audit mecanique : aucun attribut prive de l'adaptateur ne doit porter le nom du
    champ de stockage d'une `Option` ou d'un reglage de `Configuration`, ni celui d'un
    attribut prive de la classe de base du SDK.

    Le SDK est lu comme un **fichier source**, jamais importe : la suite reste
    executable sans lui."""

    @classmethod
    def setUpClass(cls):
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            cls.arbre = ast.parse(handle.read(), filename=chemin)

    def _classe_commande(self):
        for noeud in ast.walk(self.arbre):
            if isinstance(noeud, ast.ClassDef) and noeud.name == "EditAclCommand":
                return noeud
        self.fail("classe EditAclCommand introuvable")

    def _attributs_prives_assignes(self):
        """Tout `self._x = ...` de la classe."""
        noms = set()
        for noeud in ast.walk(self._classe_commande()):
            cibles = []
            if isinstance(noeud, ast.Assign):
                cibles = noeud.targets
            elif isinstance(noeud, ast.AugAssign):
                cibles = [noeud.target]
            for cible in cibles:
                for element in ([cible] if not isinstance(cible, ast.Tuple)
                                else cible.elts):
                    if (isinstance(element, ast.Attribute)
                            and isinstance(element.value, ast.Name)
                            and element.value.id == "self"
                            and element.attr.startswith("_")):
                        noms.add(element.attr)
        return noms

    def _noms_doptions(self):
        """Tout `x = Option(...)` au niveau de la classe."""
        noms = set()
        for noeud in self._classe_commande().body:
            if isinstance(noeud, ast.Assign) and isinstance(noeud.value, ast.Call):
                fonction = noeud.value.func
                if isinstance(fonction, ast.Name) and fonction.id == "Option":
                    for cible in noeud.targets:
                        if isinstance(cible, ast.Name):
                            noms.add(cible.id)
        return noms

    def _reglages_de_configuration(self):
        """Mots-cles passes au decorateur `@Configuration(...)`."""
        noms = set()
        for decorateur in self._classe_commande().decorator_list:
            if (isinstance(decorateur, ast.Call)
                    and isinstance(decorateur.func, ast.Name)
                    and decorateur.func.id == "Configuration"):
                for mot in decorateur.keywords:
                    if mot.arg:
                        noms.add(mot.arg)
        return noms

    def _attributs_prives_du_sdk(self):
        """`self._x = ...` de `SearchCommand` et `StreamingCommand`, lus dans le source
        du SDK vendorise. Aucun import."""
        noms = set()
        for fichier in ("search_command.py", "streaming_command.py"):
            chemin = os.path.join(SDK_DIR, fichier)
            if not os.path.exists(chemin):                       # pragma: no cover
                continue
            with open(chemin, encoding="utf-8") as handle:
                arbre = ast.parse(handle.read(), filename=chemin)
            for noeud in ast.walk(arbre):
                if isinstance(noeud, ast.Assign):
                    for cible in noeud.targets:
                        if (isinstance(cible, ast.Attribute)
                                and isinstance(cible.value, ast.Name)
                                and cible.value.id == "self"
                                and cible.attr.startswith("_")):
                            noms.add(cible.attr)
        return noms

    def test_les_options_declarees_sont_bien_celles_du_paragraphe_4_1(self):
        self.assertEqual(
            self._noms_doptions(),
            {
                # parametres de nommage — champs de reference (§3.1)
                "title", "app", "id", "type", "sharing",
                # parametres de nommage — valeurs cibles (§3.3)
                "new_perms_read", "new_perms_write", "new_sharing", "new_owner",
                # parametres fonctionnels (§4.1)
                "dryrun", "validate_roles", "journal", "max_objects",
            },
        )

    def test_le_parametre_fields_a_disparu(self):
        """D-23 — il n'est plus declare, et sa matrice a dix-huit lignes avec lui."""
        self.assertNotIn("fields", self._noms_doptions())

    def test_aucun_attribut_prive_ne_collisionne_avec_un_champ_de_stockage(self):
        # `backing_field_name = "_" + name`, decorators.py. Une option nommee `journal`
        # occupe donc `_journal` : c'est ce qui a transforme une erreur fatale
        # exploitable en `AttributeError: 'bool' object has no attribute 'close'`.
        champs = {"_" + nom for nom in self._noms_doptions()}
        champs |= {"_" + nom for nom in self._reglages_de_configuration()}
        collisions = sorted(self._attributs_prives_assignes() & champs)
        self.assertEqual(
            collisions, [],
            "attribut(s) prive(s) de l'adaptateur en collision avec le champ de "
            "stockage d'une Option ou d'un reglage de Configuration : %s" % collisions,
        )

    def test_aucun_attribut_prive_ne_collisionne_avec_la_classe_de_base(self):
        sdk = self._attributs_prives_du_sdk()
        self.assertTrue(sdk, "le source du SDK vendorise n'a pas ete lu")
        collisions = sorted(self._attributs_prives_assignes() & sdk)
        self.assertEqual(
            collisions, [],
            "attribut(s) prive(s) de l'adaptateur en collision avec un attribut de "
            "SearchCommand / StreamingCommand : %s" % collisions,
        )

    def _methode(self, nom):
        for noeud in ast.walk(self._classe_commande()):
            if isinstance(noeud, ast.FunctionDef) and noeud.name == nom:
                return noeud
        self.fail("methode %s() introuvable" % nom)

    def test_le_finally_de_stream_delegue_au_nettoyage(self):
        essais = [n for n in ast.walk(self._methode("stream")) if isinstance(n, ast.Try)]
        finallys = [n for n in essais if n.finalbody]
        self.assertTrue(finallys, "le `stream()` n'a pas de bloc `finally`")
        appels = {
            ast.unparse(n.func)
            for bloc in finallys
            for f in bloc.finalbody
            for n in ast.walk(f)
            if isinstance(n, ast.Call)
        }
        self.assertIn("self._cleanup", appels)

    def test_le_nettoyage_ne_peut_pas_masquer_lerreur_en_cours(self):
        """Chaque `close()` du nettoyage doit etre protege : une exception levee dans
        le `finally` remplacerait l'erreur fatale en cours de propagation."""
        nettoyage = self._methode("_cleanup")
        fermetures = [
            n for n in ast.walk(nettoyage)
            if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(".close")
        ]
        self.assertTrue(fermetures, "le nettoyage ne referme rien")
        proteges = {
            n.lineno
            for essai in ast.walk(nettoyage)
            if isinstance(essai, ast.Try) and essai.handlers
            for corps in essai.body
            for n in ast.walk(corps)
            if isinstance(n, ast.Call)
        }
        for fermeture in fermetures:
            self.assertIn(
                fermeture.lineno, proteges,
                "un `close()` du nettoyage n'est pas protege : une exception y "
                "supplanterait l'erreur fatale en cours de propagation",
            )


class ConsignationDesErreursFatalesTest(unittest.TestCase):
    """A-3 — le §8.1 exige que les erreurs fatales figurent dans `editacl.log`.

    C'est le seul endroit ou une erreur fatale survit a la fin de la recherche : le
    message utilisateur est ephemere, le job disparait a l'expiration.
    """

    def setUp(self):
        from acltools.diag import NullDiagnostics
        from acltools.errors import FatalCapabilityError

        self.module = _charger_editacl()
        _intercepter_labandon(self.module)
        self.commande = self.module.EditAclCommand()
        self.commande.journal = True
        self.commande.dryrun = True
        self.consignees = []

        consignees = self.consignees

        class _FauxDiag(NullDiagnostics):
            def fatal(self, message):
                consignees.append(message)

        self.commande._diag = _FauxDiag()
        self.FatalCapabilityError = FatalCapabilityError

    def _echouer_avec(self, exception):
        def _setup_qui_echoue():
            raise exception

        self.commande._setup = _setup_qui_echoue
        try:
            list(self.commande.stream([{"title": "un_objet"}]))
        except Abandon:
            pass

    def test_une_erreur_fatale_de_preflight_est_consignee(self):
        self._echouer_avec(self.FatalCapabilityError("capability absente"))
        self.assertEqual(self.consignees, ["capability absente"])

    def test_le_plafond_nest_plus_une_erreur_fatale(self):
        """D-28 — la classe d'exception a disparu, et rien ne doit la ressusciter.

        Chercher `MaxObjectsReached` dans `acltools.errors` est l'erreur qu'un lecteur
        de la v1 commettrait ; ce test la rend impossible a commettre en silence.
        """
        import acltools.errors as errors

        self.assertFalse(hasattr(errors, "MaxObjectsReached"))

    def test_le_diagnostic_est_referme_en_fin_dexecution(self):
        fermetures = []
        from acltools.diag import NullDiagnostics

        class _DiagQuiCompte(NullDiagnostics):
            def close(self):
                fermetures.append(True)

        self.commande._diag = _DiagQuiCompte()
        self.commande._setup = lambda: setattr(self.commande, "_ready", True)
        self.commande._processor = None
        self.commande._handle = lambda record: record
        list(self.commande.stream([{"title": "un_objet"}]))
        self.assertEqual(fermetures, [True])


class AvertissementDivergenceRuntimeTest(unittest.TestCase):
    """A-2 — l'operateur doit lire, au niveau de la recherche, ce que le jeton
    `acl_warning` ne peut pas dire.

    `acl_warning` est un jeu de jetons concatenes par `;` : la phrase qui explique
    qu'un `HTTP 500` de persistance laisse une vue runtime divergente et hors de portee
    de `editacl_rollback` n'y tient pas. Elle est emise **une fois** par execution, par
    l'enveloppe.
    """

    def setUp(self):
        from acltools.model import EventResult
        from acltools.pipeline import RUNTIME_DIVERGENCE_WARNING

        from acltools.preflight import validate_params

        self.module = _charger_editacl()
        _intercepter_labandon(self.module)
        self.commande = self.module.EditAclCommand()
        self.commande._ready = True
        # `_handle` lit les parametres de nommage : la commande est cablee comme apres
        # un `_setup()` reussi, sans reseau.
        self.commande._params = validate_params()

        class _ProcesseurQuiDiverge(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(
                    status="error",
                    title="un_objet",
                    endpoint="/servicesNS/nobody/mon_app/saved/searches/un_objet",
                    http_code=500,
                    error="post_failed:500:Could not flush changes to disk",
                    warnings=(RUNTIME_DIVERGENCE_WARNING,),
                )

        class _ProcesseurNominal(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(status="updated", title="un_objet", http_code=200)

        self.divergent = _ProcesseurQuiDiverge()
        self.nominal = _ProcesseurNominal()

    def _lot(self, processeur, taille):
        self.commande._processor = processeur
        return list(
            self.commande.stream([{"title": "un_objet"} for _ in range(taille)])
        )

    def test_le_message_est_emis_et_nomme_les_deux_faits(self):
        self._lot(self.divergent, 1)
        self.assertEqual(len(self.commande.warnings), 1)
        texte = self.commande.warnings[0].lower()
        self.assertIn("runtime", texte)
        self.assertIn("disque", texte)
        self.assertIn("editacl_rollback", texte)

    def test_le_message_nest_emis_quune_fois_par_execution(self):
        self._lot(self.divergent, 5)
        self.assertEqual(len(self.commande.warnings), 1)

    def test_aucun_message_sans_divergence(self):
        self._lot(self.nominal, 3)
        self.assertEqual(self.commande.warnings, [])


class AvertissementDeSimulationTest(unittest.TestCase):
    """Le rappel de simulation est emis **une fois par execution**, pas par evenement.

    `dryrun` vaut `true` par defaut et n'etait signale nulle part : une execution qui
    n'ecrit rien rend la meme table pleine qu'une execution qui a tout ecrit.

    La justesse tient a deux proprietes, et les deux sont eprouvees ici sur un lot de
    plusieurs objets **et sur plusieurs chunks** — le SDK appelle `stream()` une fois
    par chunk, un compteur porte par la boucle ne tiendrait pas :

    1. un seul message pour tout le lot — un avertissement repete sur plusieurs
       centaines d'objets est du bruit, et le bruit se filtre mentalement ;
    2. c'est un avertissement, jamais une erreur : aucun `write_error`, aucun chunk
       d'abandon, aucun appel a la sortie de processus. Le statut du job est intact.

    Le montage substitue les collaborateurs reseau de `_setup()` — il n'y a ni socket
    ni instance Splunk dans cette suite (§11.1) — mais laisse le chemin d'emission
    reel : `validate_params`, puis la boucle sur `params.warnings`.
    """

    def setUp(self):
        from acltools.model import EventResult
        from acltools.preflight import DRYRUN_WARNING

        self.attendu = DRYRUN_WARNING
        self.module = _charger_editacl()
        _intercepter_labandon(self.module)

        class _ProcesseurNominal(object):
            skipped_ceiling = 0

            def process(self, event):
                return EventResult(status="dryrun", title="un_objet", http_code=0)

        self.module.RestClient = lambda *a, **k: object()
        self.module.check_capability = lambda rest: None
        self.module.check_realtime = lambda rest, sid: "batch"
        self.module.load_roles_catalog = lambda rest: frozenset()
        self.module.resolve_server_name = lambda rest: "sh01"
        self.module.AppStateCache = lambda rest: types.SimpleNamespace(
            is_app_disabled=lambda app: False
        )
        self.module.EventProcessor = lambda **kwargs: _ProcesseurNominal()

    def _commande(self, dryrun):
        commande = self.module.EditAclCommand()
        commande.dryrun = dryrun
        commande.validate_roles = False
        commande.journal = False              # aucun fichier ecrit par ce test
        commande.max_objects = 10
        commande._metadata = types.SimpleNamespace(
            searchinfo=types.SimpleNamespace(
                sid="1700000000.1",
                username="un_operateur",
                splunkd_uri="https://127.0.0.1:8089",
                session_key="clef-de-session-factice",
            )
        )
        return commande

    def _executer(self, commande, objets, chunks=1):
        """Deroule le lot en `chunks` appels successifs a `stream()`, comme le SDK."""
        sorties = []
        par_chunk = max(1, objets // chunks)
        restants = objets
        while restants > 0:
            taille = min(par_chunk, restants)
            sorties.extend(
                commande.stream([{"title": "objet_%d" % i} for i in range(taille)])
            )
            restants -= taille
        return sorties

    def test_le_rappel_est_emis_sur_un_lot_de_plusieurs_objets(self):
        commande = self._commande(dryrun=True)
        sorties = self._executer(commande, 250)
        self.assertEqual(len(sorties), 250)
        self.assertIn(self.attendu, commande.warnings)

    def test_le_rappel_nest_emis_quune_fois_pour_tout_le_lot(self):
        commande = self._commande(dryrun=True)
        self._executer(commande, 250)
        self.assertEqual(commande.warnings.count(self.attendu), 1)

    def test_un_seul_rappel_meme_reparti_sur_plusieurs_chunks(self):
        commande = self._commande(dryrun=True)
        self._executer(commande, 250, chunks=5)
        self.assertEqual(commande.warnings.count(self.attendu), 1)

    def test_le_rappel_nest_pas_une_erreur(self):
        commande = self._commande(dryrun=True)
        self._executer(commande, 10)
        self.assertEqual(commande.errors, [])
        self.assertEqual(commande._record_writer.chunks, [])

    def test_aucun_rappel_en_ecriture_reelle(self):
        commande = self._commande(dryrun=False)
        self._executer(commande, 10)
        self.assertNotIn(self.attendu, commande.warnings)


class JeuDeChampsDeSortieDeclareTest(unittest.TestCase):
    """§5.7, D-33 — le jeu de champs de sortie est **declare, jamais infere**.

    L'anomalie que ces tests figent n'est pas dans le code de l'app : elle est dans le
    transport. Le writer du SDK construit l'en-tete du flux a partir des cles du
    **premier** enregistrement emis, puis y projette tous les suivants. Les huit champs
    `acl_before_*` / `acl_after_*` n'etant portes que par les enregistrements dont la
    fusion a ete calculee, un lot dont la premiere ligne est un `skipped_private` prive
    l'operateur de **tout** ce que la simulation existe pour montrer — sans erreur, sans
    avertissement, et sans que le journal en porte la moindre trace.

    **Un seul degre de liberte separe les deux mesures : l'ordre du lot.** Memes objets,
    memes statuts, meme commande. Un test qui n'inverserait pas l'ordre ne prouverait
    rien.
    """

    def setUp(self):
        from acltools.model import ACL_OUTPUT_FIELDS, ACL_STATE_FIELDS, AclState, EventResult

        self.champs_declares = ACL_OUTPUT_FIELDS
        self.champs_detat = ACL_STATE_FIELDS
        self.module = _charger_editacl()
        _intercepter_labandon(self.module)

        avant = AclState(owner="nobody", sharing="app",
                         perms_read=("*",), perms_write=("ancien_role",))
        apres = AclState(owner="nobody", sharing="app",
                         perms_read=("*",), perms_write=("nouveau_role_admin",))

        #: Un statut **sans** etat — l'objet est ecarte avant la fusion — et un statut
        #: qui en porte un. C'est exactement le lot que la macro d'inventaire produit :
        #: elle liste les objets prives au meme titre que les autres.
        resultats = {
            "objet_prive": EventResult(
                status="skipped_private",
                title="objet_prive",
                error="private_object_out_of_scope",
            ),
            "objet_partage": EventResult(
                status="dryrun",
                title="objet_partage",
                http_code=200,
                before=avant,
                after=apres,
            ),
        }

        class _ProcesseurParTitre(object):
            skipped_ceiling = 0

            def process(self, event):
                return resultats[event.title]

        self.module.RestClient = lambda *a, **k: object()
        self.module.check_capability = lambda rest: None
        self.module.check_realtime = lambda rest, sid: "batch"
        self.module.load_roles_catalog = lambda rest: frozenset()
        self.module.resolve_server_name = lambda rest: "sh01"
        self.module.AppStateCache = lambda rest: types.SimpleNamespace(
            is_app_disabled=lambda app: False
        )
        self.module.EventProcessor = lambda **kwargs: _ProcesseurParTitre()

    def _flux(self, titres, declarer=True):
        """Deroule un lot et rend l'ecrivain, en-tete figee comme le ferait le SDK."""
        commande = self.module.EditAclCommand()
        commande.dryrun = True
        commande.validate_roles = False
        commande.journal = False
        commande.max_objects = 10
        commande._metadata = types.SimpleNamespace(
            searchinfo=types.SimpleNamespace(
                sid="1700000000.1",
                username="un_operateur",
                splunkd_uri="https://127.0.0.1:8089",
                session_key="clef-de-session-factice",
            )
        )
        sorties = list(commande.stream([{"title": titre} for titre in titres]))
        if not declarer:
            # Temoin : on retire la declaration juste avant l'ecriture, pour eprouver
            # que la double reproduit bien l'anomalie qu'elle est censee reproduire.
            commande._record_writer.custom_fields.clear()
        commande._record_writer.write_records(sorties)
        return commande._record_writer

    # -- la preuve, dans les deux ordres ------------------------------------ #

    def test_le_lot_commencant_par_un_statut_sans_etat_porte_tous_les_champs(self):
        writer = self._flux(["objet_prive", "objet_partage"])
        for champ in self.champs_declares:
            self.assertIn(champ, writer.header, champ)

    def test_le_lot_commencant_par_un_statut_avec_etat_porte_tous_les_champs(self):
        writer = self._flux(["objet_partage", "objet_prive"])
        for champ in self.champs_declares:
            self.assertIn(champ, writer.header, champ)

    def test_len_tete_est_la_meme_dans_les_deux_ordres(self):
        """La propriete qui compte : la sortie ne depend plus de l'ordre du lot."""
        direct = self._flux(["objet_prive", "objet_partage"]).header
        inverse = self._flux(["objet_partage", "objet_prive"]).header
        self.assertEqual(sorted(direct), sorted(inverse))

    def test_la_valeur_utile_est_bien_portee_quand_le_prive_est_en_tete(self):
        """Presence de la colonne ne suffit pas : la valeur doit y etre."""
        writer = self._flux(["objet_prive", "objet_partage"])
        self.assertEqual(writer.rows[1]["acl_before_perms_write"], "ancien_role")
        self.assertEqual(writer.rows[1]["acl_after_perms_write"], "nouveau_role_admin")

    def test_le_statut_sans_etat_ne_porte_aucune_valeur_detat(self):
        """La declaration ajoute la colonne, elle n'invente pas de contenu (§8.2)."""
        writer = self._flux(["objet_prive", "objet_partage"])
        for champ in self.champs_detat:
            self.assertIsNone(writer.rows[0][champ], champ)

    # -- temoin : sans declaration, l'anomalie est bien reproduite ---------- #

    def test_sans_declaration_les_huit_champs_disparaissent(self):
        """Ce que mesurait l'auditeur sur `191d5e8`, et ce qui ferme le controle.

        Si ce test cessait de passer, la double ne reproduirait plus l'anomalie et les
        cinq tests ci-dessus ne prouveraient plus rien.
        """
        writer = self._flux(["objet_prive", "objet_partage"], declarer=False)
        for champ in self.champs_detat:
            self.assertNotIn(champ, writer.header, champ)

    def test_sans_declaration_lordre_inverse_les_conserve(self):
        writer = self._flux(["objet_partage", "objet_prive"], declarer=False)
        for champ in self.champs_detat:
            self.assertIn(champ, writer.header, champ)

    # -- la declaration ne peut pas deriver de la projection ---------------- #

    def test_la_declaration_couvre_exactement_ce_que_ladaptateur_projette(self):
        """Deux listes qui divergeraient rendraient la correction muette.

        Les noms projetes sont releves dans la source de `_handle`, ceux declares dans
        `ACL_OUTPUT_FIELDS`. L'egalite des deux jeux est la seule chose qui garantit
        qu'aucun champ ajoute demain ne retombera dans le defaut d'aujourd'hui.
        """
        source = os.path.join(BIN_DIR, "editacl.py")
        with open(source, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read())

        projetes = set()
        for noeud in ast.walk(arbre):
            if not isinstance(noeud, ast.FunctionDef) or noeud.name != "_handle":
                continue
            for interne in ast.walk(noeud):
                if not isinstance(interne, ast.Assign):
                    continue
                for cible in interne.targets:
                    if (
                        isinstance(cible, ast.Subscript)
                        and isinstance(cible.value, ast.Name)
                        and cible.value.id == "output"
                        and isinstance(cible.slice, ast.Constant)
                    ):
                        projetes.add(cible.slice.value)

        self.assertEqual(projetes, set(self.champs_declares))

    def test_la_declaration_est_faite_des_le_point_dextension_du_sdk(self):
        """`prepare()` est invoque par le SDK avant toute execution.

        `_setup()` la refait — il s'execute avant le premier `yield` — mais s'appuyer
        sur lui seul ferait dependre la sortie d'un chemin qui n'est pas celui que le
        SDK documente.
        """
        commande = self.module.EditAclCommand()
        commande.prepare()
        self.assertEqual(
            set(self.champs_declares) - commande._record_writer.custom_fields, set()
        )


class LeDoubleReproduitLeSdkTest(unittest.TestCase):
    """Adosse `_FakeRecordWriter` a la source du SDK vendorise, sans la charger.

    La suite ne met pas `bin/lib` dans `sys.path` (§11.1) : les tests d'A-1 s'appuient
    donc sur une double. Une double qui aurait derive du SDK prouverait quelque chose
    d'autre que ce qu'elle pretend. Ces trois controles lisent la source du SDK et
    figent les trois faits sur lesquels la double — et la correction — reposent.
    """

    @classmethod
    def setUpClass(cls):
        chemin = os.path.join(SDK_DIR, "internals.py")
        with open(chemin, encoding="utf-8") as handle:
            cls.source = handle.read()
        cls.arbre = ast.parse(cls.source)

    def test_len_tete_est_figee_sur_les_cles_du_premier_enregistrement(self):
        self.assertIn(
            "self._fieldnames = fieldnames = list(record.keys())", self.source
        )

    def test_len_tete_est_etendue_par_custom_fields(self):
        self.assertIn(
            "[i for i in self.custom_fields if i not in self._fieldnames]", self.source
        )

    def test_custom_fields_survit_a_la_fin_de_chunk(self):
        """`_clear()` remet l'en-tete a zero, jamais la declaration.

        C'est ce qui rend une declaration **unique** valable pour tous les chunks d'une
        execution — sans quoi il faudrait la refaire a chaque chunk.
        """
        clears = [
            noeud
            for noeud in ast.walk(self.arbre)
            if isinstance(noeud, ast.FunctionDef) and noeud.name == "_clear"
        ]
        self.assertTrue(clears)
        for noeud in clears:
            corps = ast.dump(noeud)
            self.assertNotIn("custom_fields", corps)


if __name__ == "__main__":
    unittest.main()
