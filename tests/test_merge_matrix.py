"""Matrice de fusion du §3.3 / spec §4.2 — **les dix-huit lignes, une par test nomme**.

3 attributs x 2 etats de `fields` x 3 etats du champ dans l'evenement. Aucune ligne
n'est omise ni renvoyee a une autre, et aucune n'est fondue dans un test parametre :
le nom du test designe la ligne qu'il couvre.

Rappel du principe : **`fields` decide seul de ce qui est modifie ; le contenu de
l'evenement decide seulement de la valeur.** La presence ou l'absence d'un champ dans
l'evenement n'a aucun pouvoir de preservation.
"""

import unittest

from acltools.merge import merge
from acltools.model import EventInput

from .helpers import state

#: Etat lu par le GET, commun a toutes les lignes de la matrice.
CURRENT = state(
    owner="nobody",
    sharing="app",
    read=("role_a", "role_b"),
    write=("ancien_role",),
)

READ = frozenset({"perms.read"})
WRITE = frozenset({"perms.write"})
SHARING = frozenset({"sharing"})
NONE_ = frozenset()


def event(**kwargs):
    """Evenement d'entree. Un champ **absent** est un champ non fourni du tout."""
    base = dict(title="Ma recherche", app="mon_app", owner="nobody",
                eai_type="savedsearch")
    base.update(kwargs)
    return EventInput(**base)


class MergeMatrixTest(unittest.TestCase):

    def assertPayload(self, result, read=None, write=None, sharing=None):
        if read is not None:
            self.assertEqual(result.payload["perms.read"], read)
        if write is not None:
            self.assertEqual(result.payload["perms.write"], write)
        if sharing is not None:
            self.assertEqual(result.payload["sharing"], sharing)
        self.assertEqual(
            sorted(result.payload),
            ["owner", "perms.read", "perms.write", "sharing"],
            "les quatre attributs sont toujours transmis (§5.4)",
        )
        self.assertEqual(result.payload["owner"], "nobody")

    # ------------------------------------------------------------------ #
    # perms.read
    # ------------------------------------------------------------------ #

    def test_ligne_01_perms_read_hors_fields_champ_absent(self):
        result = merge(CURRENT, event(), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_b")
        self.assertEqual(result.after.perms_read, ("role_a", "role_b"))

    def test_ligne_02_perms_read_hors_fields_champ_nul_ou_vide(self):
        result = merge(CURRENT, event(raw_perms_read=""), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_b")

    def test_ligne_03_perms_read_hors_fields_champ_renseigne_ignore(self):
        result = merge(CURRENT, event(raw_perms_read="role_ignore"), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_b")

    def test_ligne_04_perms_read_dans_fields_champ_absent_vide_lattribut(self):
        result = merge(CURRENT, event(), READ)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="")
        self.assertEqual(result.after.perms_read, ())

    def test_ligne_05_perms_read_dans_fields_champ_nul_ou_vide_vide_lattribut(self):
        result = merge(CURRENT, event(raw_perms_read=None), READ)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="")
        result_vide = merge(CURRENT, event(raw_perms_read=[""]), READ)
        self.assertEqual(result_vide.payload["perms.read"], "")

    def test_ligne_06_perms_read_dans_fields_champ_renseigne_applique(self):
        result = merge(
            CURRENT, event(raw_perms_read=["role_z", " role_a ", "role_z"]), READ
        )
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_z")

    # ------------------------------------------------------------------ #
    # perms.write
    # ------------------------------------------------------------------ #

    def test_ligne_07_perms_write_hors_fields_champ_absent(self):
        result = merge(CURRENT, event(), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="ancien_role")

    def test_ligne_08_perms_write_hors_fields_champ_nul_ou_vide(self):
        result = merge(CURRENT, event(raw_perms_write=[]), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="ancien_role")

    def test_ligne_09_perms_write_hors_fields_champ_renseigne_ignore(self):
        result = merge(CURRENT, event(raw_perms_write="role_ignore"), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="ancien_role")

    def test_ligne_10_perms_write_dans_fields_champ_absent_vide_lattribut(self):
        result = merge(CURRENT, event(), WRITE)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="")
        self.assertEqual(result.after.perms_write, ())

    def test_ligne_11_perms_write_dans_fields_champ_nul_ou_vide_vide_lattribut(self):
        result = merge(CURRENT, event(raw_perms_write=None), WRITE)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="")

    def test_ligne_12_perms_write_dans_fields_champ_renseigne_applique(self):
        result = merge(
            CURRENT, event(raw_perms_write="nouveau_role_admin, role_b"), WRITE
        )
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="nouveau_role_admin,role_b")

    # ------------------------------------------------------------------ #
    # sharing
    # ------------------------------------------------------------------ #

    def test_ligne_13_sharing_hors_fields_champ_absent(self):
        result = merge(CURRENT, event(), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="app")
        self.assertEqual(result.warnings, ())

    def test_ligne_14_sharing_hors_fields_champ_nul_ou_vide(self):
        result = merge(CURRENT, event(raw_sharing=""), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="app")

    def test_ligne_15_sharing_hors_fields_champ_renseigne_ignore(self):
        result = merge(CURRENT, event(raw_sharing="global"), NONE_)
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="app")
        self.assertNotIn("sharing_change", result.warnings)

    def test_ligne_16_sharing_dans_fields_champ_absent_rejette_levenement(self):
        result = merge(CURRENT, event(), SHARING)
        self.assertIsNotNone(result.rejection)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "sharing_empty_not_allowed")

    def test_ligne_17_sharing_dans_fields_champ_nul_ou_vide_rejette_levenement(self):
        for valeur in (None, "", [], [""], ["", " "]):
            with self.subTest(valeur=valeur):
                result = merge(CURRENT, event(raw_sharing=valeur), SHARING)
                self.assertIsNotNone(result.rejection)
                self.assertEqual(result.rejection.status, "rejected")
                self.assertEqual(
                    result.rejection.error, "sharing_empty_not_allowed"
                )

    def test_ligne_18_sharing_dans_fields_champ_renseigne_applique_ou_rejette(self):
        applique = merge(CURRENT, event(raw_sharing=" Global "), SHARING)
        self.assertIsNone(applique.rejection)
        self.assertPayload(applique, sharing="global")
        self.assertIn("sharing_change", applique.warnings)

        rejete = merge(CURRENT, event(raw_sharing="galactique"), SHARING)
        self.assertIsNotNone(rejete.rejection)
        self.assertEqual(rejete.rejection.status, "rejected")
        self.assertEqual(rejete.rejection.error, "invalid_sharing:galactique")

    # ------------------------------------------------------------------ #
    # owner n'a pas de ligne dans la matrice
    # ------------------------------------------------------------------ #

    def test_owner_na_pas_de_ligne_et_nest_jamais_surcharge(self):
        """`owner` est inadmissible dans `fields` (erreur fatale, teste ailleurs) et sa
        valeur transmise est toujours celle du GET."""
        result = merge(
            state(owner="un_proprietaire", sharing="app", read=(), write=()),
            event(owner="autre_proprietaire"),
            READ | WRITE,
        )
        self.assertEqual(result.payload["owner"], "un_proprietaire")
        self.assertEqual(result.after.owner, result.before.owner)


if __name__ == "__main__":
    unittest.main()
