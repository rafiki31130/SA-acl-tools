"""L'enumeration des `acl_status` est **derivee du code**, jamais recopiee (§5.7, §8.2).

Quatre redactions successives de cette liste ont ete fausses : trois dans le cahier des
charges, puis une dans le jeu de tests auquel D-35 l'avait confiee — `DOUZE_STATUTS`
annoncait douze valeurs et en portait onze, `skipped_derived` manquant. Le defaut n'est
pas l'oubli : c'est qu'une enumeration ecrite a la main n'a **aucun lien mecanique** avec
ce que le code produit, et derive donc a chaque evolution.

Ce module pose ce lien. Il extrait de l'arbre syntaxique du noyau tout statut litteral
effectivement produit, et exige l'egalite avec `acltools.model.ACL_STATUSES`. Combine a
l'invariant 1 du §8.2 — qui exige d'observer chacune de ces valeurs sur un cas reel —,
il referme la classe d'erreur au lieu de son instance :

- statut ajoute au code, absent de `ACL_STATUSES` -> ce module echoue ;
- statut ajoute a `ACL_STATUSES`, sans cas de test -> l'invariant 1 echoue.

Il n'y a pas de troisieme chemin : un statut ne peut pas entrer dans la commande sans
son cas de test.
"""

import ast
import pathlib
import unittest

from acltools.model import ACL_STATUSES

#: Racine du noyau. `bin/lib/` — SDK vendorise, non modifie — en est exclu.
CORE = pathlib.Path(__file__).resolve().parent.parent / "bin"

#: Modules balayes : le paquet metier et l'adaptateur de commande. Ce sont les seuls
#: endroits ou un `acl_status` peut naitre.
SOURCES = sorted((CORE / "acltools").glob("*.py")) + [CORE / "editacl.py"]


def _statuses_of(tree):
    """Statuts litteraux produits par un module, par les **deux** formes possibles.

    1. `EventRejected("<statut>", ...)` — premier argument positionnel. C'est la voie
       de toutes les abstentions et de tous les rejets ;
    2. affectation d'un attribut nomme `status` par une chaine litterale — c'est-a-dire
       `work.status = "<statut>"` et `self.status = "<statut>"`, la voie des statuts
       terminaux du chemin nominal.

    Une affectation depuis une variable (`work.status = exc.status`) ne porte aucun
    litteral et n'est donc pas comptee : elle propage un statut ne ailleurs, deja vu.
    """
    trouves = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            cible = node.func
            nom = getattr(cible, "id", None) or getattr(cible, "attr", None)
            if nom == "EventRejected" and node.args:
                premier = node.args[0]
                if isinstance(premier, ast.Constant) and isinstance(
                    premier.value, str
                ):
                    trouves.add(premier.value)
        elif isinstance(node, ast.Assign):
            if not (
                isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            for cible in node.targets:
                if isinstance(cible, ast.Attribute) and cible.attr == "status":
                    trouves.add(node.value.value)
    return trouves


def statuts_produits_par_le_code():
    """Union des statuts litteraux de tous les modules du noyau."""
    trouves = set()
    for chemin in SOURCES:
        trouves |= _statuses_of(ast.parse(chemin.read_text(encoding="utf-8")))
    return trouves


class EnumerationDeriveeDuCodeTest(unittest.TestCase):
    """`ACL_STATUSES` est la projection exacte de ce que le noyau produit."""

    def test_le_code_ne_produit_aucun_statut_non_declare(self):
        """Le sens fort : un statut ajoute au code fait echouer la suite ici meme."""
        inconnus = statuts_produits_par_le_code() - set(ACL_STATUSES)
        self.assertEqual(
            set(), inconnus,
            "statut(s) produits par le noyau et absents de ACL_STATUSES : %s. Un "
            "statut ne s'ajoute pas sans etre declare, ni sans son cas de test dans "
            "l'invariant 1 du §8.2." % sorted(inconnus),
        )

    def test_aucun_statut_declare_nest_mort(self):
        """Le sens inverse : une valeur declaree que le code ne produit plus est un
        residu, et un residu dans une enumeration est le debut de la derive."""
        morts = set(ACL_STATUSES) - statuts_produits_par_le_code()
        self.assertEqual(
            set(), morts,
            "statut(s) declares dans ACL_STATUSES que le noyau ne produit plus : %s"
            % sorted(morts),
        )

    def test_lextraction_nest_pas_vide(self):
        """Garde-fou contre le « zero produit par un instrument mort » : une extraction
        qui ne trouverait rien rendrait les deux tests precedents vrais par vacuite."""
        self.assertGreaterEqual(len(statuts_produits_par_le_code()), 12)

    def test_lenumeration_est_sans_doublon(self):
        self.assertEqual(len(ACL_STATUSES), len(set(ACL_STATUSES)))

    def test_lextraction_voit_les_deux_formes(self):
        """L'extracteur lui-meme est eprouve : s'il cessait de reconnaitre l'une des
        deux formes, les tests ci-dessus deviendraient muets sur toute une famille."""
        trouves = _statuses_of(
            ast.parse(
                "def f(work, exc):\n"
                "    work.status = 'par_affectation'\n"
                "    self.status = 'par_affectation_self'\n"
                "    work.status = exc.status\n"
                "    raise EventRejected('par_exception', 'motif')\n"
                "    errors.EventRejected('par_exception_qualifiee', 'motif')\n"
            )
        )
        self.assertEqual(
            trouves,
            {
                "par_affectation",
                "par_affectation_self",
                "par_exception",
                "par_exception_qualifiee",
            },
        )


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
