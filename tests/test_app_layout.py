"""Structure de l'app et fichiers de configuration (§2, §2.1, §7, §8.3, D-3, D-5).

Ces fichiers sont des livrables normatifs autant que le code : une cle absente de
`commands.conf` ou une stanza de monitor sans glob se voit a l'execution, jamais avant.
"""

import configparser
import os
import unittest

from . import BIN_DIR, REPO_ROOT


def read_conf(*parts):
    # `interpolation=None` : les valeurs de props.conf contiennent des `%`
    # (TIME_FORMAT), que l'interpolation de configparser refuserait.
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(os.path.join(REPO_ROOT, *parts), encoding="utf-8")
    return parser


class LayoutTest(unittest.TestCase):
    """Arborescence du §2."""

    ATTENDUS = (
        ("LICENSE",),
        ("README.md",),
        ("default", "app.conf"),
        ("default", "commands.conf"),
        ("default", "authorize.conf"),
        ("default", "inputs.conf"),
        ("default", "props.conf"),
        ("default", "data", "ui", "nav", "default.xml"),
        ("metadata", "default.meta"),
        ("bin", "editacl.py"),
        ("bin", "acl_endpoint_map.json"),
        ("bin", "acltools", "__init__.py"),
        ("lookups", "acl_endpoint_map_override.csv.example"),
        ("tools", "requirements-vendor.txt"),
        ("tools", "vendor.sh"),
        ("tools", "verify_vendor.sh"),
        ("bin", "lib", "VENDOR.md"),
        ("bin", "lib", "MANIFEST.sha256"),
    )

    def test_fichiers_attendus_presents(self):
        for parts in self.ATTENDUS:
            with self.subTest(chemin="/".join(parts)):
                self.assertTrue(
                    os.path.exists(os.path.join(REPO_ROOT, *parts)),
                    "%s absent" % "/".join(parts),
                )

    def test_modules_du_noyau(self):
        attendus = {
            "__init__.py", "errors.py", "model.py", "normalize.py", "mapping.py",
            "endpoint.py", "merge.py", "preflight.py", "journal.py", "rest.py",
            "pipeline.py",
        }
        presents = {
            f for f in os.listdir(os.path.join(BIN_DIR, "acltools"))
            if f.endswith(".py")
        }
        self.assertEqual(attendus - presents, set())


class CommandsConfTest(unittest.TestCase):
    """§2.1 — les cles sont normatives, reproduites a l'identique."""

    ATTENDU = {
        "filename": "editacl.py",
        "chunked": "true",
        "python.version": "python3",
        "local": "true",
        "run_in_preview": "false",
        "is_risky": "true",
        "maxinputs": "0",
    }

    def setUp(self):
        self.conf = read_conf("default", "commands.conf")

    def test_stanza_editacl(self):
        self.assertIn("editacl", self.conf.sections())

    def test_les_cles_normatives_sont_reproduites_a_lidentique(self):
        for cle, valeur in self.ATTENDU.items():
            with self.subTest(cle=cle):
                self.assertEqual(self.conf.get("editacl", cle), valeur)

    def test_aucune_cle_supplementaire(self):
        self.assertEqual(
            sorted(self.conf.options("editacl")), sorted(self.ATTENDU)
        )


class AuthorizeConfTest(unittest.TestCase):

    def test_capability_declaree(self):
        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::edit_acl_bulk", conf.sections())

    def test_le_nom_de_la_capability_est_celui_controle_par_le_code(self):
        from acltools.preflight import REQUIRED_CAPABILITY

        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::%s" % REQUIRED_CAPABILITY, conf.sections())


class InputsConfTest(unittest.TestCase):
    """D-3 — un fichier par `sid`, donc une stanza de monitor en **glob**."""

    def setUp(self):
        self.conf = read_conf("default", "inputs.conf")

    def test_stanza_de_journal_en_glob(self):
        attendu = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertIn(attendu, self.conf.sections())

    def test_le_glob_correspond_au_nom_de_fichier_produit_par_le_code(self):
        from acltools.journal import journal_filename

        nom = journal_filename("1754483000.1")
        self.assertTrue(nom.startswith("editacl_journal"))
        self.assertTrue(nom.endswith(".log"))

    def test_sourcetypes_dedies(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        diag = "monitor://$SPLUNK_HOME/var/log/splunk/editacl.log"
        self.assertEqual(self.conf.get(journal, "sourcetype"), "editacl:journal")
        self.assertEqual(self.conf.get(diag, "sourcetype"), "editacl:diag")

    def test_index_configurable_en_un_seul_point(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertEqual(self.conf.get(journal, "index"), "_internal")


class PropsConfTest(unittest.TestCase):

    def setUp(self):
        self.conf = read_conf("default", "props.conf")

    def test_extraction_json_du_journal(self):
        self.assertEqual(self.conf.get("editacl:journal", "KV_MODE"), "json")

    def test_format_dhorodatage_aligne_sur_le_journal(self):
        self.assertEqual(
            self.conf.get("editacl:journal", "TIME_FORMAT"),
            "%Y-%m-%dT%H:%M:%S.%3N%:z",
        )

    def test_troncature_desactivee(self):
        self.assertEqual(self.conf.get("editacl:journal", "TRUNCATE"), "0")


class MacrosEtSavedsearchesTest(unittest.TestCase):
    """Livrables de la phase suivante, volontairement absents de cet increment."""

    def test_macros_et_savedsearches_ne_sont_pas_encore_livres(self):
        for nom in ("macros.conf", "savedsearches.conf"):
            chemin = os.path.join(REPO_ROOT, "default", nom)
            if os.path.exists(chemin):
                with open(chemin, encoding="utf-8") as handle:
                    contenu = handle.read().strip()
                self.assertEqual(
                    contenu, "",
                    "%s doit rester vide tant que la macro d'inventaire et les "
                    "recherches sauvegardees ne sont pas livrees" % nom,
                )


if __name__ == "__main__":
    unittest.main()
