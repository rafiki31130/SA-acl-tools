"""Table de correspondance (§6) : chargement, override, refus d'heuristique."""

import json
import os
import shutil
import tempfile
import unittest

from acltools.errors import FatalMappingError
from acltools.mapping import is_valid_handler_path, load_mapping

from . import BIN_DIR

TABLE_LIVREE = os.path.join(BIN_DIR, "acl_endpoint_map.json")


class DeliveredTableTest(unittest.TestCase):
    """La table livree est une **donnee** etablie empiriquement, pas du code : ce test
    verifie sa forme, pas son exactitude — laquelle se re-valide sur le socle cible
    (§6.5)."""

    def test_la_table_livree_se_charge(self):
        mapping = load_mapping(TABLE_LIVREE)
        self.assertEqual(len(mapping), 28)

    def test_toutes_les_entrees_ont_un_chemin_valide(self):
        with open(TABLE_LIVREE, encoding="utf-8") as handle:
            raw = json.load(handle)
        for eai_type, handler_path in raw.items():
            with self.subTest(eai_type=eai_type):
                self.assertTrue(is_valid_handler_path(handler_path))

    def test_les_correspondances_qui_cassent_lanalogie_de_nommage(self):
        """Justification empirique de l'interdiction d'heuristique du §6.2."""
        mapping = load_mapping(TABLE_LIVREE)
        self.assertEqual(mapping.resolve("commands"), "admin/commandsconf")
        self.assertEqual(mapping.resolve("conf-times"), "data/ui/times")

    def test_aucune_derivation_par_pluralisation(self):
        mapping = load_mapping(TABLE_LIVREE)
        self.assertEqual(mapping.resolve("savedsearch"), "saved/searches")
        self.assertIsNone(mapping.resolve("savedsearches"))
        self.assertIsNone(mapping.resolve("saved-search"))

    def test_type_inconnu_donne_none_jamais_une_valeur_devinee(self):
        mapping = load_mapping(TABLE_LIVREE)
        self.assertIsNone(mapping.resolve("type_inexistant"))
        self.assertIsNone(mapping.resolve(""))
        self.assertIsNone(mapping.resolve(None))

    def test_couverture_exposee(self):
        coverage = load_mapping(TABLE_LIVREE).coverage()
        self.assertEqual(coverage["total"], 28)
        self.assertEqual(coverage["from_override"], 0)
        self.assertEqual(coverage["rejected"], ())
        self.assertIn("savedsearch", coverage["types"])


class HandlerPathValidationTest(unittest.TestCase):

    def test_chemins_valides(self):
        for path in ("saved/searches", "admin/commandsconf", "data/ui/nav",
                     "storage/collections/config", "alerts/alert_actions"):
            with self.subTest(path=path):
                self.assertTrue(is_valid_handler_path(path))

    def test_chemins_refuses(self):
        for path in ("", "/absolu", "../traverse", "saved/searches?x=1",
                     "saved//searches", "saved/searches/", "a b", "http://ailleurs"):
            with self.subTest(path=path):
                self.assertFalse(is_valid_handler_path(path))

    def test_aucun_segment_de_traversee_nest_admis(self):
        """A-5 — `..` en position ulterieure etait admis par le seul motif.

        La surete ne doit pas dependre du refus de splunkd : il repond 404 sur
        Splunk 9.4.6, mais un socle qui normaliserait le chemin ferait sortir la
        requete du namespace reconstruit.
        """
        for path in (
            "a/../../services/authentication/users",
            "saved/../admin/directory",
            "saved/searches/..",
            "saved/./searches",
            "a/.../b",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_valid_handler_path(path))

    def test_un_point_a_linterieur_dun_segment_reste_admis(self):
        """Le refus porte sur le segment de traversee, pas sur le point lui-meme."""
        for path in ("data/ui.views", "a.b/c-d_e~f", "saved/searches.v2"):
            with self.subTest(path=path):
                self.assertTrue(is_valid_handler_path(path))


class LoadMappingTest(unittest.TestCase):

    def setUp(self):
        self.dossier = tempfile.mkdtemp(prefix="editacl_map_")
        self.json_path = os.path.join(self.dossier, "acl_endpoint_map.json")
        with open(self.json_path, "w", encoding="utf-8") as handle:
            json.dump(
                {"savedsearch": "saved/searches", "views": "data/ui/views"}, handle
            )
        self.csv_path = os.path.join(self.dossier, "override.csv")

    def tearDown(self):
        shutil.rmtree(self.dossier, ignore_errors=True)

    def _write_csv(self, contenu):
        with open(self.csv_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(contenu)

    def test_json_absent_est_fatal(self):
        with self.assertRaises(FatalMappingError):
            load_mapping(os.path.join(self.dossier, "inexistant.json"))

    def test_json_mal_forme_est_fatal(self):
        chemin = os.path.join(self.dossier, "casse.json")
        with open(chemin, "w", encoding="utf-8") as handle:
            handle.write("{ pas du json")
        with self.assertRaises(FatalMappingError):
            load_mapping(chemin)

    def test_json_qui_nest_pas_un_objet_est_fatal(self):
        chemin = os.path.join(self.dossier, "liste.json")
        with open(chemin, "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        with self.assertRaises(FatalMappingError):
            load_mapping(chemin)

    def test_override_absent_est_normal(self):
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(len(mapping), 2)

    def test_override_ajoute_et_surcharge(self):
        self._write_csv(
            "eai_type,handler_path\n"
            "un-type-inedit,data/ui/inedit\n"
            "views,data/ui/autre-vue\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(mapping.resolve("un-type-inedit"), "data/ui/inedit")
        self.assertEqual(mapping.resolve("views"), "data/ui/autre-vue")
        self.assertEqual(mapping.coverage()["overridden"], ("views",))

    def test_override_a_chemin_forge_est_ecarte(self):
        """Le fichier d'override est une entree non fiable : un chemin de handler forge
        pourrait viser un endpoint arbitraire."""
        self._write_csv(
            "eai_type,handler_path\n"
            "malveillant,../../services/authentication/users\n"
            "valide,data/ui/views\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertIsNone(mapping.resolve("malveillant"))
        self.assertEqual(mapping.resolve("valide"), "data/ui/views")
        self.assertEqual(len(mapping.coverage()["rejected"]), 1)

    def test_lignes_de_commentaire_ignorees(self):
        self._write_csv(
            "eai_type,handler_path\n"
            "# un commentaire\n"
            "#autre-commentaire,data/ui/views\n"
            "valide,data/ui/views\n"
        )
        mapping = load_mapping(self.json_path, self.csv_path)
        self.assertEqual(mapping.coverage()["rejected"], ())
        self.assertEqual(mapping.resolve("valide"), "data/ui/views")

    def test_override_aux_colonnes_incorrectes_nempeche_pas_lexecution(self):
        self._write_csv("type,chemin\nx,y\n")
        diagnostics = []
        mapping = load_mapping(
            self.json_path, self.csv_path, diag=lambda l, m: diagnostics.append((l, m))
        )
        self.assertEqual(len(mapping), 2)
        self.assertTrue(diagnostics)

    def test_entree_json_invalide_ecartee_avec_trace(self):
        chemin = os.path.join(self.dossier, "partiel.json")
        with open(chemin, "w", encoding="utf-8") as handle:
            json.dump({"bon": "saved/searches", "mauvais": "../evasion"}, handle)
        diagnostics = []
        mapping = load_mapping(chemin, diag=lambda l, m: diagnostics.append((l, m)))
        self.assertEqual(len(mapping), 1)
        self.assertIsNone(mapping.resolve("mauvais"))
        self.assertEqual(len(diagnostics), 1)


class ExampleFileTest(unittest.TestCase):
    """D-5 : l'archive livre l'exemple, **jamais** le fichier reel."""

    def test_larchive_ne_contient_pas_loverride_reel(self):
        lookups = os.path.join(os.path.dirname(BIN_DIR), "lookups")
        self.assertTrue(
            os.path.exists(
                os.path.join(lookups, "acl_endpoint_map_override.csv.example")
            )
        )
        self.assertFalse(
            os.path.exists(os.path.join(lookups, "acl_endpoint_map_override.csv"))
        )


if __name__ == "__main__":
    unittest.main()
