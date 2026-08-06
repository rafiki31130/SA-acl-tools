"""Ordre des controles du §5.4, idempotence (§5.5) et `validate_roles` (D-4)."""

import unittest

from acltools.merge import DEFAULT_FIELDS, is_noop, merge, parse_fields, validate_roles
from acltools.errors import FatalConfigError

from .helpers import make_event, state

READ_WRITE = frozenset({"perms.read", "perms.write"})
SHARING = frozenset({"sharing"})
ALL_FIELDS = frozenset({"perms.read", "perms.write", "sharing"})


class ParseFieldsTest(unittest.TestCase):

    def test_defaut(self):
        self.assertEqual(
            parse_fields(DEFAULT_FIELDS), frozenset({"perms.read", "perms.write"})
        )

    def test_owner_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError) as raised:
            parse_fields("perms.read,owner")
        self.assertIn("owner", str(raised.exception))

    def test_owner_seul_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            parse_fields("owner")

    def test_valeur_non_admise_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            parse_fields("perms.read,perms.delete")

    def test_liste_vide_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            parse_fields("  ,  ")

    def test_espaces_et_multivalue_acceptes(self):
        self.assertEqual(
            parse_fields([" perms.read ", "sharing"]),
            frozenset({"perms.read", "sharing"}),
        )


class ControlOrderTest(unittest.TestCase):
    """L'ordre est normatif : il determine quel statut l'emporte quand plusieurs
    conditions sont reunies (§5.4)."""

    def test_rang_1_can_change_perms_lemporte_sur_le_rejet_de_sharing(self):
        current = state(
            owner="nobody", sharing="app", read=(), write=(), can_change_perms=False
        )
        result = merge(current, make_event(sharing=""), ALL_FIELDS)
        self.assertEqual(result.rejection.status, "skipped_immutable")

    def test_rang_1_can_change_perms_lemporte_sur_sharing_invalide(self):
        current = state(
            owner="nobody", sharing="app", read=(), write=(), can_change_perms=False
        )
        result = merge(current, make_event(sharing="galactique"), ALL_FIELDS)
        self.assertEqual(result.rejection.status, "skipped_immutable")

    def test_rang_2_sharing_vide_lemporte_sur_le_rang_4(self):
        """Un `sharing` vide est rejete avant que la regle `user`/`nobody` s'applique."""
        current = state(owner="nobody", sharing="user", read=(), write=())
        result = merge(current, make_event(sharing=None), SHARING)
        self.assertEqual(result.rejection.error, "sharing_empty_not_allowed")

    def test_rang_3_sharing_invalide_lemporte_sur_le_rang_4(self):
        current = state(owner="nobody", sharing="user", read=(), write=())
        result = merge(current, make_event(sharing="galactique"), SHARING)
        self.assertEqual(result.rejection.error, "invalid_sharing:galactique")

    def test_rang_4_sharing_user_sur_owner_nobody(self):
        current = state(owner="nobody", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="user"), SHARING)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(
            result.rejection.error, "sharing_user_requires_named_owner"
        )

    def test_rang_4_ne_se_declenche_pas_sur_un_proprietaire_nomme(self):
        current = state(owner="un_proprietaire", sharing="app", read=(), write=())
        result = merge(current, make_event(sharing="user"), SHARING)
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.sharing, "user")

    def test_skipped_immutable_calcule_quand_meme_letat_cible(self):
        """Le journal doit porter `before_*`/`after_*` pour ce statut (§8.2)."""
        current = state(
            owner="nobody",
            sharing="app",
            read=("role_a",),
            write=("ancien_role",),
            can_change_perms=False,
        )
        result = merge(current, make_event(write="nouveau_role_admin"), READ_WRITE)
        self.assertEqual(result.rejection.status, "skipped_immutable")
        self.assertEqual(result.after.perms_write, ("nouveau_role_admin",))


class IdempotenceTest(unittest.TestCase):

    def test_permutation_dordre_des_roles_est_un_noop(self):
        """La comparaison porte sur les collections triees, pas sur les chaines."""
        current = state(sharing="app", read=("role_a", "role_b"), write=("w",))
        result = merge(
            current,
            make_event(read="role_b,role_a", write="w"),
            READ_WRITE,
        )
        self.assertTrue(is_noop(result.before, result.after))

    def test_vidage_dun_attribut_liste_dans_fields_nest_pas_un_noop(self):
        current = state(sharing="app", read=("role_a",), write=("w",))
        result = merge(current, make_event(read="role_a"), READ_WRITE)
        self.assertEqual(result.after.perms_write, ())
        self.assertFalse(is_noop(result.before, result.after))

    def test_objet_a_permission_vide_relue_en_liste_dune_chaine_vide(self):
        """Le piege d'idempotence de la mesure 4, fige (D-8)."""
        from acltools.normalize import parse_acl_state

        current = parse_acl_state(
            {
                "owner": "nobody",
                "sharing": "global",
                "perms": {"read": [""], "write": ["admin"]},
            }
        )
        result = merge(
            current, make_event(read=None, write="admin"), READ_WRITE
        )
        self.assertTrue(
            is_noop(result.before, result.after),
            "un objet a permission vide doit ressortir en noop a la seconde passe",
        )

    def test_owner_nentre_pas_dans_la_comparaison(self):
        gauche = state(owner="a", sharing="app", read=("r",), write=())
        droite = state(owner="b", sharing="app", read=("r",), write=())
        self.assertTrue(is_noop(gauche, droite))

    def test_changement_de_sharing_nest_pas_un_noop(self):
        gauche = state(sharing="app")
        droite = state(sharing="global")
        self.assertFalse(is_noop(gauche, droite))


class ValidateRolesTest(unittest.TestCase):
    """D-4 : le controle ne porte que sur les **roles ajoutes**."""

    CATALOG = frozenset({"role_a", "role_b", "nouveau_role_admin", "*"})

    def test_role_mort_conserve_ne_bloque_pas(self):
        before = state(read=("role_mort", "role_a"), write=("role_a",))
        after = state(read=("role_mort", "role_a"), write=("nouveau_role_admin",))
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())
        self.assertEqual(stale, ("role_mort",))

    def test_role_mort_ajoute_bloque(self):
        before = state(read=("role_a",), write=())
        after = state(read=("role_a", "role_inexistant"), write=())
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("role_inexistant",))
        self.assertEqual(stale, ())

    def test_role_mort_ajoute_dans_perms_write_bloque(self):
        before = state(read=(), write=("role_a",))
        after = state(read=(), write=("role_a", "role_inexistant"))
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("role_inexistant",))

    def test_role_mort_conserve_en_lecture_pendant_modification_en_ecriture(self):
        """Le cas d'usage moteur : on corrige `perms.write` alors qu'un role mort
        traine dans `perms.read`. L'ecriture ne doit pas etre bloquee."""
        before = state(read=("role_mort",), write=("ancien_role",))
        after = state(read=("role_mort",), write=("nouveau_role_admin",))
        unknown, stale = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())
        self.assertIn("role_mort", stale)

    def test_role_etoile_est_dans_le_referentiel(self):
        before = state(read=(), write=())
        after = state(read=("*",), write=())
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ())

    def test_plusieurs_roles_inconnus_ajoutes_sont_tous_signales(self):
        before = state(read=(), write=())
        after = state(read=("zz_inconnu", "aa_inconnu"), write=())
        unknown, _ = validate_roles(before, after, self.CATALOG)
        self.assertEqual(unknown, ("aa_inconnu", "zz_inconnu"))


if __name__ == "__main__":
    unittest.main()
