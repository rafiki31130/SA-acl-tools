"""Resolution et reconstruction d'URI (§5.2, §10.4).

La reconstruction est obligatoire et non negociable : le champ `id` natif double-encode
la barre oblique mais pas les autres caracteres speciaux, il n'est donc pas reutilisable
tel quel comme URI.
"""

import unittest

from acltools.endpoint import (
    TITLE_ENCODING_MODE,
    build_object_path,
    build_object_url,
    encode_namespace_segment,
    encode_title_segment,
    handler_path_from_id,
    resolve_handler_path,
)
from acltools.errors import EventRejected

from .helpers import FIXTURE_MAPPING


class TitleEncodingTest(unittest.TestCase):
    """Regle unique, tranchee empiriquement : simple `%`-encodage, `safe=''`.

    Les quatre classes de caracteres du §10.4 sont couvertes une par une. Le double
    encodage est un piege asymetrique : il fonctionne pour `/` seul et casse espace,
    accent et pourcent.
    """

    def test_mode_retenu_est_le_simple_encodage(self):
        self.assertEqual(TITLE_ENCODING_MODE, "single")

    def test_classe_espace(self):
        self.assertEqual(encode_title_segment("Ma recherche"), "Ma%20recherche")

    def test_classe_barre_oblique_sans_traitement_special(self):
        self.assertEqual(
            encode_title_segment("Rapport/Mensuel"), "Rapport%2FMensuel"
        )

    def test_classe_caractere_accentue_utf8_par_octets(self):
        self.assertEqual(
            encode_title_segment("Resume ete"), "Resume%20ete"
        )
        self.assertEqual(
            encode_title_segment("éàü"), "%C3%A9%C3%A0%C3%BC"
        )

    def test_classe_pourcent(self):
        self.assertEqual(encode_title_segment("Taux 100%"), "Taux%20100%25")

    def test_autres_caracteres_reserves_encodes(self):
        self.assertEqual(encode_title_segment("a+b&c=d"), "a%2Bb%26c%3Dd")

    def test_segment_de_namespace_encode_de_la_meme_facon(self):
        self.assertEqual(encode_namespace_segment("mon app"), "mon%20app")


class BuildObjectPathTest(unittest.TestCase):

    def test_chemin_reconstruit_sans_suffixe_acl(self):
        path = build_object_path("nobody", "mon_app", "saved/searches", "Ma recherche")
        self.assertEqual(
            path, "/servicesNS/nobody/mon_app/saved/searches/Ma%20recherche"
        )
        self.assertFalse(path.endswith("/acl"))
        self.assertNotIn("/acl", path)

    def test_handler_path_nest_pas_reencode(self):
        path = build_object_path("nobody", "mon_app", "saved/searches", "objet")
        self.assertIn("saved/searches", path)
        self.assertNotIn("saved%2Fsearches", path)

    def test_namespace_construit_sur_le_proprietaire_de_lobjet(self):
        """§10.3 : un objet `sharing=user` d'un tiers s'adresse dans SON namespace."""
        path = build_object_path(
            "un_proprietaire", "mon_app", "saved/searches", "objet_prive"
        )
        self.assertTrue(path.startswith("/servicesNS/un_proprietaire/mon_app/"))

    def test_url_prefixee_par_la_base_splunkd_sans_hote_en_dur(self):
        path = build_object_path("nobody", "mon_app", "saved/searches", "objet")
        url = build_object_url("https://base.invalid:0/", path)
        self.assertEqual(url, "https://base.invalid:0" + path)


class HandlerPathFromIdTest(unittest.TestCase):

    def test_id_natif_exploitable(self):
        self.assertEqual(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/nobody/mon_app/saved/searches/"
                "Ma%20recherche"
            ),
            "saved/searches",
        )

    def test_id_pointant_sur_admin_directory_est_ecarte(self):
        self.assertIsNone(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/-/-/admin/directory/Ma%20recherche"
            )
        )

    def test_id_malforme_est_ecarte(self):
        self.assertIsNone(handler_path_from_id("pas-une-uri"))

    def test_id_sans_marqueur_servicesns_est_ecarte(self):
        self.assertIsNone(
            handler_path_from_id("https://base.invalid:0/services/saved/searches/objet")
        )

    def test_id_absent_ou_vide(self):
        self.assertIsNone(handler_path_from_id(None))
        self.assertIsNone(handler_path_from_id("   "))

    def test_dernier_segment_jete_le_nom_vient_de_title(self):
        """Le titre double-encode par `id` ne doit jamais servir de nom d'objet."""
        self.assertEqual(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/nobody/mon_app/saved/searches/"
                "Rapport%252FMensuel"
            ),
            "saved/searches",
        )

    def test_hote_et_port_de_id_sont_ecartes(self):
        path = handler_path_from_id(
            "https://autre-membre.invalid:0/servicesNS/nobody/mon_app/data/ui/views/v"
        )
        self.assertEqual(path, "data/ui/views")

    def test_id_portant_une_traversee_est_ecarte(self):
        """A-5 — un `id` forge ne doit pas sortir du namespace reconstruit.

        Sur Splunk 9.4.6 la requete aboutissait a un 404 emis par splunkd, qui traite
        `..` comme une action de handler inconnue. Le confinement est desormais porte
        par l'outil : le `handler_path` est ecarte a la source.
        """
        for id_value in (
            "https://base.invalid:0/servicesNS/nobody/mon_app/"
            "a/../../../services/authentication/users/objet",
            "https://base.invalid:0/servicesNS/nobody/mon_app/"
            "saved/../admin/directory/objet",
        ):
            with self.subTest(id_value=id_value):
                self.assertIsNone(handler_path_from_id(id_value))


class ResolveHandlerPathTest(unittest.TestCase):

    def test_voie_id_prioritaire(self):
        handler, source = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/mon_app/saved/searches/objet",
            "views",
            FIXTURE_MAPPING,
        )
        self.assertEqual((handler, source), ("saved/searches", "id"))

    def test_id_sur_admin_directory_bascule_sur_la_table(self):
        handler, source = resolve_handler_path(
            "https://base.invalid:0/servicesNS/-/-/admin/directory/objet",
            "savedsearch",
            FIXTURE_MAPPING,
        )
        self.assertEqual((handler, source), ("saved/searches", "eai:type"))

    def test_id_absent_bascule_sur_la_table(self):
        handler, source = resolve_handler_path(None, "views", FIXTURE_MAPPING)
        self.assertEqual((handler, source), ("data/ui/views", "eai:type"))

    def test_id_malforme_bascule_sur_la_table(self):
        handler, source = resolve_handler_path(
            "pas-une-uri", "views", FIXTURE_MAPPING
        )
        self.assertEqual((handler, source), ("data/ui/views", "eai:type"))

    def test_id_a_traversee_bascule_sur_la_table(self):
        """A-5 — le refus n'ouvre pas un trou fonctionnel : la table prend le relais."""
        handler, source = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/mon_app/"
            "saved/../../services/authentication/users/objet",
            "views",
            FIXTURE_MAPPING,
        )
        self.assertEqual((handler, source), ("data/ui/views", "eai:type"))

    def test_eai_type_inconnu_rejette_sans_heuristique(self):
        with self.assertRaises(EventRejected) as raised:
            resolve_handler_path(None, "type_inexistant", FIXTURE_MAPPING)
        self.assertEqual(raised.exception.status, "rejected")
        self.assertEqual(
            raised.exception.error, "unresolved_endpoint:type_inexistant"
        )

    def test_ni_id_ni_eai_type(self):
        with self.assertRaises(EventRejected) as raised:
            resolve_handler_path(None, None, FIXTURE_MAPPING)
        self.assertEqual(raised.exception.error, "unresolved_endpoint:")

    def test_famille_sans_eai_type_natif_resolue_par_id(self):
        """Les sept familles absentes de `admin/directory` n'emettent pas d'`eai:type`
        sur leur endpoint natif : `id` y est la seule voie possible."""
        handler, source = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/mon_app/data/lookup-table-files/"
            "table.csv",
            None,
            FIXTURE_MAPPING,
        )
        self.assertEqual((handler, source), ("data/lookup-table-files", "id"))


if __name__ == "__main__":
    unittest.main()
