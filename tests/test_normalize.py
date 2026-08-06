"""Normalisation des listes de roles et de la portee de partage (§3.2, §5.5, D-8)."""

import unittest

from acltools.normalize import (
    is_field_empty,
    normalize_roles,
    normalize_sharing,
    parse_acl_state,
    serialize_roles,
)

from .helpers import acl_body_raw


class NormalizeRolesTest(unittest.TestCase):

    def test_chaine_separee_par_virgules(self):
        self.assertEqual(normalize_roles("role_b,role_a"), ("role_a", "role_b"))

    def test_multivalue(self):
        self.assertEqual(normalize_roles(["role_b", "role_a"]), ("role_a", "role_b"))

    def test_multivalue_dont_un_element_est_lui_meme_une_liste_csv(self):
        self.assertEqual(
            normalize_roles(["role_c,role_a", "role_b"]),
            ("role_a", "role_b", "role_c"),
        )

    def test_valeurs_dupliquees_dedoublonnees(self):
        self.assertEqual(
            normalize_roles("role_a,role_a,role_b"), ("role_a", "role_b")
        )

    def test_espaces_parasites_supprimes(self):
        self.assertEqual(
            normalize_roles("  role_b ,role_a  "), ("role_a", "role_b")
        )

    def test_chaine_vide(self):
        self.assertEqual(normalize_roles(""), ())

    def test_valeur_nulle(self):
        self.assertEqual(normalize_roles(None), ())

    def test_liste_vide(self):
        self.assertEqual(normalize_roles([]), ())

    def test_liste_contenant_une_chaine_vide_D8(self):
        """`[""]` est la forme relue apres un POST `perms.read=` vide (mesure 4).

        Sans ce filtrage, l'etat lu et l'etat fusionne ne sont jamais egaux et la
        detection d'idempotence echoue sur **tout** objet a permission vide.
        """
        self.assertEqual(normalize_roles([""]), ())

    def test_liste_de_plusieurs_chaines_vides_D8(self):
        self.assertEqual(normalize_roles(["", "", "  "]), ())

    def test_elements_vides_intercales_filtres(self):
        self.assertEqual(
            normalize_roles(["role_a", "", "role_b", "  "]), ("role_a", "role_b")
        )

    def test_virgules_seules(self):
        self.assertEqual(normalize_roles(",,,"), ())

    def test_role_etoile_est_un_role_comme_un_autre(self):
        """Le role `*` n'est jamais developpe en liste de roles (§10.2)."""
        self.assertEqual(normalize_roles("*"), ("*",))
        self.assertEqual(normalize_roles(["*", "role_a"]), ("*", "role_a"))

    def test_tri_deterministe_par_points_de_code(self):
        self.assertEqual(
            normalize_roles("Zeta,alpha,Beta"), ("Beta", "Zeta", "alpha")
        )


class SerializeRolesTest(unittest.TestCase):

    def test_tuple_vide_donne_la_chaine_vide_jamais_etoile(self):
        self.assertEqual(serialize_roles(()), "")

    def test_jointure_par_virgule(self):
        self.assertEqual(serialize_roles(("role_a", "role_b")), "role_a,role_b")


class IsFieldEmptyTest(unittest.TestCase):

    def test_cas_vides(self):
        for valeur in (None, "", [], [""], ["", "  "], "   ", ",", [None]):
            with self.subTest(valeur=valeur):
                self.assertTrue(is_field_empty(valeur))

    def test_cas_non_vides(self):
        for valeur in ("role_a", ["role_a"], ["", "role_a"], " x "):
            with self.subTest(valeur=valeur):
                self.assertFalse(is_field_empty(valeur))


class NormalizeSharingTest(unittest.TestCase):

    def test_minuscules_et_trim(self):
        self.assertEqual(normalize_sharing("  Global "), "global")

    def test_multivalue_prend_le_premier_jeton_non_vide(self):
        self.assertEqual(normalize_sharing(["", "app"]), "app")

    def test_vide_donne_none(self):
        for valeur in (None, "", [], [""]):
            with self.subTest(valeur=valeur):
                self.assertIsNone(normalize_sharing(valeur))


class ParseAclStateTest(unittest.TestCase):

    def test_bloc_acl_nominal(self):
        state = parse_acl_state(
            {
                "owner": "nobody",
                "sharing": "global",
                "can_change_perms": True,
                "perms": {"read": ["role_b", "role_a"], "write": ["ancien_role"]},
            }
        )
        self.assertEqual(state.owner, "nobody")
        self.assertEqual(state.sharing, "global")
        self.assertEqual(state.perms_read, ("role_a", "role_b"))
        self.assertEqual(state.perms_write, ("ancien_role",))
        self.assertTrue(state.can_change_perms)

    def test_perms_absent_objet_sans_permission_explicite(self):
        state = parse_acl_state({"owner": "nobody", "sharing": "app"})
        self.assertEqual(state.perms_read, ())
        self.assertEqual(state.perms_write, ())

    def test_perms_relues_en_liste_dune_chaine_vide(self):
        state = parse_acl_state(
            {"owner": "nobody", "sharing": "app", "perms": {"read": [""], "write": [""]}}
        )
        self.assertEqual(state.perms_read, ())
        self.assertEqual(state.perms_write, ())

    def test_can_change_perms_recu_en_chaine(self):
        self.assertFalse(
            parse_acl_state({"can_change_perms": "0"}).can_change_perms
        )
        self.assertTrue(parse_acl_state({"can_change_perms": "1"}).can_change_perms)

    def test_can_change_perms_absent_vaut_vrai(self):
        self.assertTrue(parse_acl_state({}).can_change_perms)

    def test_corps_de_reponse_complet(self):
        import json

        document = json.loads(
            acl_body_raw(
                {"owner": "un_proprietaire", "sharing": "user", "perms": {"read": "*"}}
            ).decode("utf-8")
        )
        state = parse_acl_state(document["entry"][0]["acl"])
        self.assertEqual(state.owner, "un_proprietaire")
        self.assertEqual(state.sharing, "user")
        self.assertEqual(state.perms_read, ("*",))


if __name__ == "__main__":
    unittest.main()
