"""Matrice de presence du §3.2 — **les douze lignes, une par test nomme**.

4 attributs cibles x 3 etats de la colonne. Aucune ligne n'est omise, aucune n'est
renvoyee a une autre, et aucune n'est fondue dans un test parametre : le nom du test
designe la ligne qu'il couvre.

    | Situation                               | Effet                |
    |-----------------------------------------|----------------------|
    | colonne **absente** du jeu de resultats  | attribut **preserve** |
    | colonne **presente**, cellule **vide**   | attribut **vide**     |
    | colonne **presente**, cellule valuee     | valeur appliquee      |

Deux attributs derogent a la deuxieme ligne, parce que leur valeur vide n'existe pas
cote plateforme : `sharing` et `owner` **rejettent** l'evenement au lieu de se vider.
Leurs lignes 08 et 11 le figent.

La matrice de la v1 — dix-huit lignes, 3 attributs x 2 etats du parametre `fields` x 3
etats du champ — n'a plus d'objet : `fields` a disparu, et c'est la presence de la
colonne, non un parametre, qui decide.
"""

import unittest

from acltools.merge import merge

from .helpers import make_event, state

#: Etat lu par le GET, commun a toutes les lignes de la matrice.
CURRENT = state(
    owner="un_proprietaire",
    sharing="app",
    read=("role_a", "role_b"),
    write=("ancien_role",),
)


class MergeMatrixTest(unittest.TestCase):

    def assertPayload(self, result, read=None, write=None, sharing=None, owner=None):
        for key, expected in (
            ("perms.read", read),
            ("perms.write", write),
            ("sharing", sharing),
            ("owner", owner),
        ):
            if expected is not None:
                self.assertEqual(result.payload[key], expected)
        self.assertEqual(
            sorted(result.payload),
            ["owner", "perms.read", "perms.write", "sharing"],
            "les quatre attributs sont toujours transmis (§5.4)",
        )

    # ------------------------------------------------------------------ #
    # perms.read
    # ------------------------------------------------------------------ #

    def test_ligne_01_perms_read_colonne_absente_preserve_lattribut(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_b")
        self.assertEqual(result.after.perms_read, ("role_a", "role_b"))

    def test_ligne_02_perms_read_colonne_presente_cellule_vide_vide_lattribut(self):
        result = merge(CURRENT, make_event(read=""))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="")
        self.assertEqual(result.after.perms_read, ())

    def test_ligne_03_perms_read_colonne_presente_cellule_valuee_applique(self):
        result = merge(CURRENT, make_event(read=["role_z", " role_a ", "role_z"]))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, read="role_a,role_z")

    # ------------------------------------------------------------------ #
    # perms.write
    # ------------------------------------------------------------------ #

    def test_ligne_04_perms_write_colonne_absente_preserve_lattribut(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="ancien_role")
        self.assertEqual(result.after.perms_write, ("ancien_role",))

    def test_ligne_05_perms_write_colonne_presente_cellule_vide_vide_lattribut(self):
        # C'est le pipeline nominal du decommissionnement : un `mvmap` qui retire la
        # derniere valeur laisse la colonne en place avec une cellule vide.
        result = merge(CURRENT, make_event(write=""))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="")
        self.assertEqual(result.after.perms_write, ())

    def test_ligne_06_perms_write_colonne_presente_cellule_valuee_applique(self):
        result = merge(CURRENT, make_event(write="nouveau_role_admin, role_b"))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, write="nouveau_role_admin,role_b")

    # ------------------------------------------------------------------ #
    # sharing
    # ------------------------------------------------------------------ #

    def test_ligne_07_sharing_colonne_absente_preserve_lattribut(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="app")
        self.assertNotIn("sharing_change", result.warnings)

    def test_ligne_08_sharing_colonne_presente_cellule_vide_rejette_levenement(self):
        # Derogation : une portee vide n'existe pas (§3.3). L'attribut ne se vide pas,
        # l'evenement est rejete.
        result = merge(CURRENT, make_event(sharing=""))
        self.assertIsNotNone(result.rejection)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "sharing_empty_not_allowed")

    def test_ligne_09_sharing_colonne_presente_cellule_valuee_applique(self):
        result = merge(CURRENT, make_event(sharing=" Global "))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, sharing="global")
        self.assertIn("sharing_change", result.warnings)

    # ------------------------------------------------------------------ #
    # owner
    # ------------------------------------------------------------------ #

    def test_ligne_10_owner_colonne_absente_preserve_le_proprietaire_du_get(self):
        result = merge(CURRENT, make_event())
        self.assertIsNone(result.rejection)
        self.assertPayload(result, owner="un_proprietaire")
        self.assertEqual(result.after.owner, result.before.owner)
        self.assertNotIn("owner_change", result.warnings)

    def test_ligne_11_owner_colonne_presente_cellule_vide_rejette_levenement(self):
        # Derogation : un proprietaire vide n'existe pas, la plateforme refuse un POST
        # dont le corps n'en porte pas (§3.3). Pendant exact de la ligne 08.
        result = merge(CURRENT, make_event(owner=""))
        self.assertIsNotNone(result.rejection)
        self.assertEqual(result.rejection.status, "rejected")
        self.assertEqual(result.rejection.error, "owner_empty_not_allowed")

    def test_ligne_12_owner_colonne_presente_cellule_valuee_applique(self):
        result = merge(CURRENT, make_event(owner="nouveau_proprietaire"))
        self.assertIsNone(result.rejection)
        self.assertPayload(result, owner="nouveau_proprietaire")
        self.assertEqual(result.after.owner, "nouveau_proprietaire")
        self.assertIn("owner_change", result.warnings)


class PresenceNestPasLeTypeTest(unittest.TestCase):
    """Le discriminant est la **presence de la cle**, jamais le type ni la valeur.

    C'est le point sur lequel la v1 s'est trompee, et le seul qu'un lecteur presse
    risque de re-implementer de travers.
    """

    def test_multivalue_reduit_a_une_valeur_arrive_en_chaine_et_reste_une_valeur(self):
        """Mesure 9.4.6 : un champ multivalue reduit a **une seule** valeur n'arrive pas
        en liste d'un element — il arrive en **chaine**.

        Un moteur qui deciderait par le type (« liste -> l'operateur a parle », « chaine
        -> ce n'est qu'une valeur heritee ») traiterait ce cas comme une absence et
        **preserverait** l'attribut, alors que le pipeline demande explicitement de le
        reduire a ce seul role. Le present test fige la lecture correcte.
        """
        result = merge(CURRENT, make_event(write="role_b"))
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.perms_write, ("role_b",))
        self.assertEqual(result.payload["perms.write"], "role_b")

    def test_meme_valeur_en_liste_dun_element_donne_le_meme_resultat(self):
        """Corollaire : le type ne change **rien**. La liste `["role_b"]` et la chaine
        `"role_b"` produisent le meme etat cible, puisque seule la presence a decide."""
        depuis_chaine = merge(CURRENT, make_event(write="role_b"))
        depuis_liste = merge(CURRENT, make_event(write=["role_b"]))
        self.assertEqual(depuis_chaine.after, depuis_liste.after)
        self.assertEqual(depuis_chaine.payload, depuis_liste.payload)

    def test_colonne_presente_valant_none_vide_lattribut_et_ne_preserve_pas(self):
        """`None` est une **valeur** de colonne presente, pas un signal d'absence.

        Un `raw is not None` ajoute « par prudence » au predicat de presence
        transformerait ce vidage explicite en preservation silencieuse — exactement le
        defaut que la refonte corrige.
        """
        result = merge(CURRENT, make_event(read=None))
        self.assertIsNone(result.rejection)
        self.assertEqual(result.after.perms_read, ())
        self.assertEqual(result.payload["perms.read"], "")

    def test_colonne_absente_et_colonne_presente_vide_ne_sont_pas_confondues(self):
        """Les deux cas que la v1 tenait pour indiscernables, cote a cote."""
        absente = merge(CURRENT, make_event())
        presente_vide = merge(CURRENT, make_event(read=""))
        self.assertEqual(absente.after.perms_read, ("role_a", "role_b"))
        self.assertEqual(presente_vide.after.perms_read, ())
        self.assertNotEqual(absente.after, presente_vide.after)

    def test_liste_vide_sur_colonne_presente_vide_lattribut(self):
        for valeur in ([], [""], ["", " "]):
            with self.subTest(valeur=valeur):
                result = merge(CURRENT, make_event(read=valeur))
                self.assertEqual(result.after.perms_read, ())


if __name__ == "__main__":
    unittest.main()
