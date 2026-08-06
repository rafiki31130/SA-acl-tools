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


class _FakeSearchCommand(object):
    def __init__(self):
        self._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace())
        self.warnings = []
        self.errors = []

    def write_warning(self, message):
        self.warnings.append(message)

    def error_exit(self, error, message=None):
        self.errors.append(message or str(error))
        raise SystemExit(message or str(error))


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
        from acltools.errors import FatalCapabilityError

        self.commande = self.module.EditAclCommand()
        self.commande.journal = True          # ce que fait le SDK sur `journal=t`
        self.commande.dryrun = True

        def _setup_qui_echoue():
            raise FatalCapabilityError(self.MESSAGE)

        self.commande._setup = _setup_qui_echoue

    def test_le_message_dorigine_nest_pas_remplace_par_une_trace_python(self):
        with self.assertRaises(SystemExit) as leve:
            list(self.commande.stream([{"title": "un_objet"}]))
        self.assertEqual(str(leve.exception), self.MESSAGE)
        self.assertEqual(self.commande.errors, [self.MESSAGE])

    def test_aucune_attributeerror_sur_le_nettoyage(self):
        try:
            list(self.commande.stream([{"title": "un_objet"}]))
        except SystemExit:
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
            {"fields", "dryrun", "validate_roles", "journal", "max_objects"},
        )

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

    def test_le_nettoyage_du_finally_ne_peut_pas_masquer_lerreur_en_cours(self):
        """Le `close()` du `finally` doit etre protege : une exception levee la
        remplacerait l'erreur fatale en cours de propagation."""
        for noeud in ast.walk(self._classe_commande()):
            if isinstance(noeud, ast.FunctionDef) and noeud.name == "stream":
                essais = [n for n in ast.walk(noeud) if isinstance(n, ast.Try)]
                finallys = [n for n in essais if n.finalbody]
                self.assertTrue(finallys, "le `stream()` n'a pas de bloc `finally`")
                for bloc in finallys:
                    protege = any(
                        isinstance(n, ast.Try) and n.handlers
                        for f in bloc.finalbody for n in ast.walk(f)
                    )
                    self.assertTrue(
                        protege,
                        "le corps du `finally` n'est pas protege : une exception y "
                        "supplanterait l'erreur fatale en cours de propagation",
                    )
                return
        self.fail("methode stream() introuvable")


class ConsignationDesErreursFatalesTest(unittest.TestCase):
    """A-3 — le §8.1 exige que les erreurs fatales figurent dans `editacl.log`.

    C'est le seul endroit ou une erreur fatale survit a la fin de la recherche : le
    message utilisateur est ephemere, le job disparait a l'expiration.
    """

    def setUp(self):
        from acltools.diag import NullDiagnostics
        from acltools.errors import FatalCapabilityError, MaxObjectsReached

        self.module = _charger_editacl()
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
        self.MaxObjectsReached = MaxObjectsReached

    def _echouer_avec(self, exception):
        def _setup_qui_echoue():
            raise exception

        self.commande._setup = _setup_qui_echoue
        try:
            list(self.commande.stream([{"title": "un_objet"}]))
        except SystemExit:
            pass

    def test_une_erreur_fatale_de_preflight_est_consignee(self):
        self._echouer_avec(self.FatalCapabilityError("capability absente"))
        self.assertEqual(self.consignees, ["capability absente"])

    def test_latteinte_du_plafond_est_consignee(self):
        self._echouer_avec(self.MaxObjectsReached(2))
        self.assertEqual(len(self.consignees), 1)
        self.assertIn("max_objects atteint (2)", self.consignees[0])

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

        self.module = _charger_editacl()
        self.commande = self.module.EditAclCommand()
        self.commande._ready = True

        class _ProcesseurQuiDiverge(object):
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


if __name__ == "__main__":
    unittest.main()
