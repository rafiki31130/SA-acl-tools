"""Journal de diagnostic `editacl.log` (§8.1, A-3).

Le fichier etait annonce par le §8.1, par `inputs.conf` et par `props.conf`, et n'etait
**jamais ecrit** — aucun `import logging` dans `bin/`. Ces tests figent les trois choses
qui comptent : qu'il soit produit, qu'il porte ce que le §8.1 enumere, et qu'il ne
porte **aucun secret**.

Ils figent aussi une propriete negative : la perte du diagnostic ne coute jamais une
execution. Le fichier de diagnostic n'est pas le journal de restauration ; confondre
les deux reproduirait, cote observabilite, l'erreur de conception que D-3 a evitee.
"""

import ast
import configparser
import logging
import os
import shutil
import tempfile
import unittest
from logging.handlers import RotatingFileHandler

from acltools import diag as diag_module
from acltools.diag import (
    BACKUP_COUNT,
    DIAG_BASENAME,
    MAX_BYTES,
    Diagnostics,
    NullDiagnostics,
    diag_path,
    open_diagnostics,
    redact,
)
from acltools.mapping import load_mapping
from acltools.model import FieldNames, Params

from . import BIN_DIR, REPO_ROOT

#: Valeur factice, de la forme d'une cle de session Splunk. N'est un secret nulle part.
CLE_FACTICE = "vBkTFCbEXAMPLEnotarealkey0123456789abcdefABCDEF0123456789xyz"


class ArbreDiag(object):
    """Repertoire de logs jetable."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="acl_diag_")
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def contenu(self):
        chemin = diag_path(self.dir)
        if not os.path.exists(chemin):
            return ""
        with open(chemin, encoding="utf-8") as handle:
            return handle.read()


def params(names=None, warnings=()):
    return Params(
        names=names or FieldNames(),
        dryrun=False,
        validate_roles=True,
        journal=True,
        max_objects=10,
        warnings=tuple(warnings),
    )


class FichierProduitTest(unittest.TestCase):
    """A-3 — le fichier doit exister et ne pas etre vide."""

    def test_le_fichier_est_cree_et_ecrit(self):
        with ArbreDiag() as arbre:
            diag = open_diagnostics(arbre.dir, sid="1786033792.6")
            self.assertTrue(diag.enabled)
            diag.startup(version="1.0.0", user="operateur")
            diag.close()

            self.assertTrue(os.path.exists(diag_path(arbre.dir)))
            self.assertTrue(arbre.contenu().strip())

    def test_le_nom_du_fichier_est_celui_que_monitorent_les_conf(self):
        """`inputs.conf` declare le monitor, `props.conf` le sourcetype : le nom du
        fichier reellement ouvert doit etre celui-la, sinon rien n'est collecte."""
        parser = configparser.ConfigParser(strict=False)
        parser.read(os.path.join(REPO_ROOT, "default", "inputs.conf"), encoding="utf-8")
        stanzas = [s for s in parser.sections() if DIAG_BASENAME in s]
        self.assertEqual(
            len(stanzas), 1,
            "aucune stanza de monitor ne porte %r" % DIAG_BASENAME,
        )
        self.assertEqual(parser.get(stanzas[0], "sourcetype"), "editacl:diag")

    def test_rotation_conforme_au_paragraphe_8_1(self):
        """« `RotatingFileHandler`, 5 Mo x 5 », litteralement."""
        self.assertEqual(MAX_BYTES, 5 * 1024 * 1024)
        self.assertEqual(BACKUP_COUNT, 5)
        with ArbreDiag() as arbre:
            diag = open_diagnostics(arbre.dir)
            try:
                handler = diag._handler
                self.assertIsInstance(handler, RotatingFileHandler)
                self.assertEqual(handler.maxBytes, MAX_BYTES)
                self.assertEqual(handler.backupCount, BACKUP_COUNT)
            finally:
                diag.close()

    def test_une_ligne_par_enregistrement_et_horodatage_iso(self):
        with ArbreDiag() as arbre:
            diag = open_diagnostics(arbre.dir, sid="s1")
            diag.info("premiere ligne")
            diag.warning("message\nsur deux lignes")
            diag.close()

            lignes = [l for l in arbre.contenu().splitlines() if l.strip()]
            self.assertEqual(len(lignes), 2)
            for ligne in lignes:
                horodatage = ligne.split(" ", 1)[0]
                self.assertRegex(
                    horodatage,
                    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$",
                )
                self.assertIn("sid=s1", ligne)


class ContenuExigeParLeParagraphe81Test(unittest.TestCase):
    """« demarrage, controle d'habilitation, parametres, resolution de la table de
    correspondance, erreurs fatales » — les cinq, nommement."""

    def test_les_cinq_rubriques_sont_presentes(self):
        with ArbreDiag() as arbre:
            diag = open_diagnostics(arbre.dir, sid="1786033792.6")
            diag.startup(version="1.0.0", user="operateur", splunkd_uri="https://x:8089")
            diag.params(params(warnings=("dryrun=false sans max_objects explicite",)))
            diag.capability(True)
            diag.realtime("batch")
            diag.mapping(load_mapping(os.path.join(BIN_DIR, "acl_endpoint_map.json"))
                         .coverage())
            diag.journal("/var/log/splunk/editacl_journal_1786033792.6.log", True)
            diag.fatal("capability 'edit_acl_bulk' absente")
            diag.close()

            texte = arbre.contenu()

        for attendu in (
            "demarrage editacl",
            "version=1.0.0",
            "parametres dryrun=false",
            # Les neuf parametres de nommage sont consignes : sans eux, une execution
            # dont un nom de champ a ete redirige est illisible a posteriori.
            "nommage title=title",
            "new_owner=eai:acl.owner",
            "max_objects=10",
            "controle d'habilitation",
            "table de correspondance : 28 entrees",
            "journal de restauration ouvert",
            "erreur fatale : capability 'edit_acl_bulk' absente",
        ):
            with self.subTest(attendu=attendu):
                self.assertIn(attendu, texte)

        self.assertIn("WARNING", texte)
        self.assertIn("CRITICAL", texte)

    def test_le_rappel_de_chargement_de_table_ecrit_bien_dans_le_fichier(self):
        """§8.1 « resolution de la table » : `load_mapping` doit recevoir le diagnostic.

        C'est le point exact releve par l'audit — `load_mapping()` etait appele sans
        `diag`, donc les entrees ecartees ne laissaient aucune trace.
        """
        with ArbreDiag() as arbre:
            dossier = tempfile.mkdtemp(prefix="acl_map_")
            try:
                chemin = os.path.join(dossier, "map.json")
                with open(chemin, "w", encoding="utf-8") as handle:
                    handle.write('{"bon": "saved/searches", "mauvais": "../evasion"}')
                diag = open_diagnostics(arbre.dir)
                load_mapping(chemin, diag=diag)
                diag.close()
            finally:
                shutil.rmtree(dossier, ignore_errors=True)

            texte = arbre.contenu()
        self.assertIn("entree de table ecartee", texte)
        self.assertIn("WARNING", texte)


class AucunSecretTest(unittest.TestCase):
    """R5 — un fichier de diagnostic collecte vers un index est lu par bien plus de
    monde que le disque du search head."""

    def test_redaction_des_formes_connues(self):
        for message in (
            "Authorization: Splunk %s" % CLE_FACTICE,
            "en-tete Authorization=%s" % CLE_FACTICE,
            "session_key=%s" % CLE_FACTICE,
            "session-key: %s" % CLE_FACTICE,
            "password=motdepasse123",
            "api_key: %s" % CLE_FACTICE,
            "Bearer %s" % CLE_FACTICE,
            "token=%s" % CLE_FACTICE,
        ):
            with self.subTest(message=message):
                sortie = redact(message)
                self.assertNotIn(CLE_FACTICE, sortie)
                self.assertNotIn("motdepasse123", sortie)
                self.assertIn("[redige]", sortie)

    def test_aucune_troncature_de_secret(self):
        """Un secret tronque reste un secret partiellement divulgue."""
        sortie = redact("session_key=%s" % CLE_FACTICE)
        for longueur in (8, 12, 20):
            self.assertNotIn(CLE_FACTICE[:longueur], sortie)

    def test_le_fichier_ne_porte_pas_la_cle_meme_si_elle_est_passee_par_erreur(self):
        with ArbreDiag() as arbre:
            diag = open_diagnostics(arbre.dir, sid="s1")
            diag.info("appel refuse (Authorization: Splunk %s)" % CLE_FACTICE)
            diag.fatal("controle d'habilitation impossible, session_key=%s" % CLE_FACTICE)
            diag.close()
            texte = arbre.contenu()
        self.assertNotIn(CLE_FACTICE, texte)
        self.assertNotIn(CLE_FACTICE[:16], texte)

    def test_aucune_methode_de_diagnostic_nadmet_un_secret_en_parametre(self):
        """La garantie principale est **structurelle**, pas textuelle : le module ne
        recoit jamais la cle de session."""
        interdits = {
            "session_key", "sessionkey", "token", "password", "secret", "api_key",
            "authorization", "credential",
        }
        chemin = os.path.join(BIN_DIR, "acltools", "diag.py")
        with open(chemin, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read(), filename=chemin)
        for noeud in ast.walk(arbre):
            if isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
                noms = {a.arg.lower() for a in noeud.args.args}
                noms |= {a.arg.lower() for a in noeud.args.kwonlyargs}
                with self.subTest(fonction=noeud.name):
                    self.assertEqual(noms & interdits, set())

    def test_lenveloppe_ne_transmet_aucun_secret_au_diagnostic(self):
        """Audit mecanique de `bin/editacl.py` : aucun appel `self._diag.*` ne porte
        `session_key` ni un nom apparente."""
        interdits = ("session_key", "password", "token", "secret", "api_key")
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read(), filename=chemin)
        appels = []
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.Call) and isinstance(noeud.func, ast.Attribute):
                cible = ast.unparse(noeud.func)
                if cible.startswith("self._diag"):
                    appels.append(ast.unparse(noeud))
        self.assertTrue(appels, "l'enveloppe n'appelle aucun diagnostic")
        for appel in appels:
            with self.subTest(appel=appel):
                for interdit in interdits:
                    self.assertNotIn(interdit, appel)


class LaPerteDuDiagnosticNeCoutePasUneExecutionTest(unittest.TestCase):
    """Le fichier de diagnostic n'est **pas** le filet de securite. Aucun de ses echecs
    n'est fatal — c'est la difference de nature avec le journal de restauration (D-3)."""

    def test_repertoire_absent_donne_un_diagnostic_inerte(self):
        diag = open_diagnostics(
            os.path.join(tempfile.gettempdir(), "acl_inexistant_zz", "profond")
        )
        self.assertIsInstance(diag, NullDiagnostics)
        self.assertFalse(diag.enabled)

    def test_splunk_home_absent_donne_un_diagnostic_inerte(self):
        self.assertIsInstance(open_diagnostics(""), NullDiagnostics)
        self.assertIsInstance(open_diagnostics(None), NullDiagnostics)

    def test_le_diagnostic_inerte_absorbe_tous_les_appels(self):
        diag = NullDiagnostics()
        diag("WARNING", "x")
        diag.startup(version="1")
        diag.params(params())
        diag.capability(False, "detail")
        diag.realtime("unknown")
        diag.mapping({})
        diag.journal("/x", False)
        diag.info("x")
        diag.warning("x")
        diag.fatal("x")
        diag.close()

    def test_un_echec_decriture_ne_leve_pas(self):
        class HandlerCasse(logging.Handler):
            def emit(self, record):
                raise IOError("disque plein")

        diag = Diagnostics("/inexistant/editacl.log", sid="s", handler=HandlerCasse())
        diag.info("message")
        diag.fatal("message")
        diag.close()

    def test_le_module_nutilise_pas_le_registre_global_de_logging(self):
        """Y attacher un handler ferait entrer dans le fichier les enregistrements
        d'autres bibliotheques, dont on ne controle pas l'absence de secret."""
        chemin = os.path.join(BIN_DIR, "acltools", "diag.py")
        with open(chemin, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read(), filename=chemin)
        appels = {
            ast.unparse(noeud.func)
            for noeud in ast.walk(arbre)
            if isinstance(noeud, ast.Call)
        }
        for interdit in ("logging.getLogger", "getLogger", "logging.basicConfig"):
            with self.subTest(appel=interdit):
                self.assertNotIn(interdit, appels)

    def test_le_paquet_expose_le_module(self):
        self.assertTrue(hasattr(diag_module, "open_diagnostics"))


class EnveloppeCableLeDiagnosticTest(unittest.TestCase):
    """Audit mecanique du cablage : `bin/editacl.py` doit reellement produire le
    fichier, et le produire assez tot pour qu'un parametre invalide y figure."""

    @classmethod
    def setUpClass(cls):
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            cls.arbre = ast.parse(handle.read(), filename=chemin)

    def _fonction(self, nom):
        for noeud in ast.walk(self.arbre):
            if isinstance(noeud, ast.FunctionDef) and noeud.name == nom:
                return noeud
        self.fail("fonction %s introuvable" % nom)

    def _appels(self, noeud):
        return [
            (ast.unparse(n.func), n)
            for n in ast.walk(noeud)
            if isinstance(n, ast.Call)
        ]

    def test_le_setup_ouvre_le_diagnostic(self):
        cibles = [nom for nom, _ in self._appels(self._fonction("_setup"))]
        self.assertIn("open_diagnostics", cibles)

    def test_le_diagnostic_est_ouvert_avant_la_validation_des_parametres(self):
        """Un `fields` invalide est une erreur fatale du §9 : elle doit etre consignee."""
        ouverture = validation = None
        for nom, noeud in self._appels(self._fonction("_setup")):
            if nom == "open_diagnostics" and ouverture is None:
                ouverture = noeud.lineno
            if nom == "validate_params" and validation is None:
                validation = noeud.lineno
        self.assertIsNotNone(ouverture)
        self.assertIsNotNone(validation)
        self.assertLess(ouverture, validation)

    def test_load_mapping_recoit_le_diagnostic(self):
        """§8.1 « resolution de la table » : c'est l'omission relevee par l'audit."""
        for nom, noeud in self._appels(self._fonction("_setup")):
            if nom == "load_mapping":
                mots_cles = {kw.arg for kw in noeud.keywords}
                self.assertIn("diag", mots_cles)
                return
        self.fail("aucun appel a load_mapping dans _setup")

    def test_les_erreurs_fatales_sont_consignees_dans_stream(self):
        cibles = [nom for nom, _ in self._appels(self._fonction("stream"))]
        self.assertIn("self._diag.fatal", cibles)


if __name__ == "__main__":
    unittest.main()
