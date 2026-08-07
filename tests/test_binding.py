"""Liaison enregistrement SPL -> `EventInput` (§3.1, §3.2, §3.3).

C'est ici que la semantique de presence est **realisee**, a partir de la seule donnee
dont la commande dispose : l'enregistrement du chunk. Le moteur de fusion, lui, ne voit
plus que le verdict (`EventInput.present`) — d'ou l'interet d'eprouver le verdict
lui-meme, sur des enregistrements bruts.

Deux modes de defaillance sont couverts ici et nulle part ailleurs :

1. **decider par le type** — un multivalue reduit a une valeur arrive en chaine, et un
   moteur qui lirait le type conclurait a tort ;
2. **decider par la valeur** — un `raw is not None` ajoute « par prudence » au predicat
   de presence transformerait un vidage explicite en preservation silencieuse.
"""

import unittest

from acltools.binding import build_event, field_present, field_value
from acltools.model import DEFAULT_FIELD_NAMES, TARGET_ATTRIBUTES, FieldNames


def record(**kwargs):
    """Enregistrement de chunk. Une cle absente du dict **est** une colonne absente."""
    return dict(kwargs)


NOMS = DEFAULT_FIELD_NAMES


class PredicatDePresenceTest(unittest.TestCase):
    """`field_present` est le point d'injection unique de la regle du §3.2.

    Sa definition tient en une ligne — `name in record` — et c'est deliberement tout ce
    qu'elle fait. Chaque clause supplementaire y serait une regression.
    """

    def test_cle_presente_valuee(self):
        self.assertTrue(field_present(record(a="x"), "a"))

    def test_cle_presente_valant_la_chaine_vide(self):
        self.assertTrue(field_present(record(a=""), "a"))

    def test_cle_presente_valant_none(self):
        """`None` est une valeur de colonne presente, pas un signal d'absence."""
        self.assertTrue(field_present(record(a=None), "a"))

    def test_cle_presente_valant_une_liste_vide(self):
        self.assertTrue(field_present(record(a=[]), "a"))

    def test_cle_absente(self):
        self.assertFalse(field_present(record(b="x"), "a"))

    def test_enregistrement_vide(self):
        self.assertFalse(field_present({}, "a"))

    def test_la_valeur_brute_nest_pas_coercee(self):
        """`field_value` transporte, elle n'interprete pas : c'est `merge` qui decide."""
        for brut in ("", None, [], ["role_a"], "role_a,role_b"):
            with self.subTest(brut=brut):
                self.assertEqual(field_value(record(a=brut), "a"), brut)

    def test_une_colonne_absente_rend_le_defaut_demande(self):
        sentinelle = object()
        self.assertIs(field_value({}, "a", default=sentinelle), sentinelle)


class PresenceDesValeursCiblesTest(unittest.TestCase):
    """Le verdict porte sur les quatre attributs cibles, un a un."""

    def test_aucune_colonne_cible_aucun_attribut_present(self):
        event = build_event(record(title="Ma recherche", **{"eai:acl.app": "mon_app"}),
                            NOMS)
        self.assertEqual(event.present, frozenset())
        for attribut in TARGET_ATTRIBUTES:
            self.assertFalse(event.has(attribut))

    def test_perms_read_presente(self):
        event = build_event(record(**{"eai:acl.perms.read": "role_a"}), NOMS)
        self.assertTrue(event.has("perms.read"))
        self.assertFalse(event.has("perms.write"))

    def test_perms_write_presente(self):
        event = build_event(record(**{"eai:acl.perms.write": ""}), NOMS)
        self.assertTrue(event.has("perms.write"))
        self.assertEqual(event.new_perms_write, "")

    def test_sharing_presente(self):
        event = build_event(record(**{"eai:acl.sharing": "global"}), NOMS)
        self.assertTrue(event.has("sharing"))

    def test_owner_presente(self):
        event = build_event(record(**{"eai:acl.owner": "un_proprietaire"}), NOMS)
        self.assertTrue(event.has("owner"))
        self.assertEqual(event.new_owner, "un_proprietaire")

    def test_les_quatre_colonnes_presentes(self):
        event = build_event(
            record(**{
                "eai:acl.perms.read": "role_a",
                "eai:acl.perms.write": "role_b",
                "eai:acl.sharing": "global",
                "eai:acl.owner": "un_proprietaire",
            }),
            NOMS,
        )
        self.assertEqual(event.present, frozenset(TARGET_ATTRIBUTES))


class PresenceNestPasLeTypeTest(unittest.TestCase):
    """**Le point sur lequel la v1 s'est trompee.**

    Mesure sur 9.4.6 : la commande recoit soit une cle absente de l'enregistrement, soit
    une cle presente valant la chaine vide. Jamais `None`, jamais une liste vide. Et un
    champ multivalue **reduit a une seule valeur arrive en chaine**, pas en liste d'un
    element.
    """

    def test_multivalue_reduit_a_une_valeur_arrive_en_chaine_et_reste_present(self):
        """Le cas nominal du decommissionnement, une fois le `mvmap` passe.

        Un moteur qui deciderait par le type — « liste, l'operateur a parle ; chaine, ce
        n'est qu'une valeur heritee » — traiterait cet enregistrement comme une absence
        et **preserverait** l'attribut, alors que le pipeline demande explicitement de
        le reduire a ce seul role.
        """
        event = build_event(record(**{"eai:acl.perms.write": "role_restant"}), NOMS)
        self.assertTrue(event.has("perms.write"))
        self.assertIsInstance(event.new_perms_write, str)
        self.assertNotIsInstance(event.new_perms_write, list)

    def test_multivalue_a_plusieurs_valeurs_arrive_en_liste_et_reste_present(self):
        event = build_event(
            record(**{"eai:acl.perms.write": ["role_a", "role_b"]}), NOMS
        )
        self.assertTrue(event.has("perms.write"))
        self.assertIsInstance(event.new_perms_write, list)

    def test_le_verdict_est_identique_quel_que_soit_le_type(self):
        """Chaine, liste d'un element, liste de deux, liste vide, chaine vide, `None` :
        toutes ces formes sont des **colonnes presentes**. Le type n'entre nulle part."""
        for brut in ("role_a", ["role_a"], ["role_a", "role_b"], [], "", None, 0):
            with self.subTest(brut=brut):
                event = build_event(record(**{"eai:acl.perms.write": brut}), NOMS)
                self.assertTrue(
                    event.has("perms.write"),
                    "la presence de la cle decide, pas le type de sa valeur",
                )

    def test_une_colonne_absente_et_une_colonne_vide_donnent_des_verdicts_opposes(self):
        """Les deux cas que la v1 tenait pour indiscernables, cote a cote sur des
        enregistrements bruts."""
        absente = build_event(record(title="x"), NOMS)
        vide = build_event(record(title="x", **{"eai:acl.perms.read": ""}), NOMS)
        self.assertFalse(absente.has("perms.read"))
        self.assertTrue(vide.has("perms.read"))

    def test_une_colonne_valant_none_est_presente_et_non_absente(self):
        """La regression la plus tentante : ajouter `and raw is not None` au predicat.

        Elle transformerait un vidage explicite en preservation silencieuse, c'est-a-dire
        exactement le defaut de la v1 reintroduit par la porte de service.
        """
        event = build_event(record(**{"eai:acl.perms.read": None}), NOMS)
        self.assertTrue(event.has("perms.read"))
        self.assertIsNone(event.new_perms_read)


class ParametresDeNommageTest(unittest.TestCase):
    """Chaque parametre redirige la lecture d'une information vers un autre nom de
    colonne. C'est ce qui permet de brancher la commande sur un pipeline amont qui a
    renomme ses champs."""

    def test_defaut_applique(self):
        event = build_event(
            record(title="Ma recherche", **{"eai:acl.app": "mon_app",
                                            "eai:type": "savedsearch"}),
            NOMS,
        )
        self.assertEqual(event.title, "Ma recherche")
        self.assertEqual(event.app, "mon_app")
        self.assertEqual(event.eai_type, "savedsearch")

    def test_champ_renomme(self):
        noms = FieldNames(type="object_type", new_perms_write="write")
        event = build_event(
            record(title="Ma recherche", **{"eai:acl.app": "mon_app",
                                            "object_type": "savedsearch",
                                            "write": "nouveau_role_admin"}),
            noms,
        )
        self.assertEqual(event.eai_type, "savedsearch")
        self.assertTrue(event.has("perms.write"))
        self.assertEqual(event.new_perms_write, "nouveau_role_admin")

    def test_le_champ_dorigine_nest_plus_lu_apres_redirection(self):
        """Rediriger, c'est bien deplacer la lecture, pas l'elargir."""
        noms = FieldNames(new_perms_write="write")
        event = build_event(
            record(**{"eai:acl.perms.write": "role_ignore"}), noms
        )
        self.assertFalse(event.has("perms.write"))

    def test_champ_designe_absent_du_jeu_de_resultats(self):
        noms = FieldNames(new_perms_write="colonne_inexistante")
        event = build_event(record(**{"eai:acl.perms.write": "role_a"}), noms)
        self.assertFalse(event.has("perms.write"))
        self.assertIsNone(event.new_perms_write)

    def test_deux_parametres_peuvent_designer_la_meme_colonne(self):
        """C'est le cas par defaut : `sharing` et `new_sharing` valent tous deux
        `eai:acl.sharing`. La portee courante sert a ecarter les prives, la valeur
        cible a decider de l'ecriture — deux usages d'une meme colonne."""
        event = build_event(record(**{"eai:acl.sharing": "global"}), NOMS)
        self.assertEqual(event.current_sharing, "global")
        self.assertTrue(event.has("sharing"))


class PorteeCouranteTest(unittest.TestCase):
    """§3.1 et §3.5 — la portee courante est facultative, et son **absence** a un effet
    observable : la commande ne peut plus ecarter les objets prives en amont."""

    def test_colonne_absente_donne_none(self):
        event = build_event(record(title="x"), NOMS)
        self.assertIsNone(event.current_sharing)

    def test_colonne_presente_vide_donne_la_chaine_vide_pas_none(self):
        """La distinction compte : `None` dit « je ne sais pas », `""` dit « la
        plateforme ne l'a pas renseigne ». Ni l'un ni l'autre n'est `user`."""
        event = build_event(record(**{"eai:acl.sharing": ""}), NOMS)
        self.assertEqual(event.current_sharing, "")
        self.assertIsNotNone(event.current_sharing)

    def test_colonne_presente_valuee(self):
        event = build_event(record(**{"eai:acl.sharing": "user"}), NOMS)
        self.assertEqual(event.current_sharing, "user")


class ChampsDeReferenceTest(unittest.TestCase):

    def test_un_multivalue_mono_valeur_est_reduit_pour_un_champ_mono_valeur(self):
        event = build_event(record(title=["Ma recherche"]), NOMS)
        self.assertEqual(event.title, "Ma recherche")

    def test_les_blancs_de_bordure_sont_retires(self):
        event = build_event(record(title="  Ma recherche  "), NOMS)
        self.assertEqual(event.title, "Ma recherche")

    def test_un_eai_type_vide_vaut_absent_pour_la_resolution(self):
        """La resolution du §5.2 n'a que faire d'une chaine vide : elle bascule sur
        `id`, ou rejette. La normaliser en `None` evite un
        `unresolved_endpoint:` trompeur."""
        event = build_event(record(**{"eai:type": "  "}), NOMS)
        self.assertIsNone(event.eai_type)

    def test_aucun_champ_de_proprietaire_dadressage_nest_lu(self):
        """D-25 — il n'y a pas de parametre `owner` de reference, seulement
        `new_owner`, qui est une valeur cible. Un enregistrement portant un
        proprietaire n'en fait donc rien d'autre qu'une valeur a appliquer."""
        self.assertFalse(hasattr(NOMS, "owner"))
        event = build_event(record(**{"eai:acl.owner": "un_tiers"}), NOMS)
        self.assertTrue(event.has("owner"))
        self.assertFalse(hasattr(event, "owner"))


if __name__ == "__main__":
    unittest.main()
