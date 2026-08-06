"""Manifeste d'empreintes de `bin/lib/` — `tools/hash_manifest.py` (A-6).

Le manifeste decrit **ce que `tools/vendor.sh` installe**. L'elagage de `vendor.sh`
retire deja `__pycache__` et `*.pyc` ; le parcours de verification doit appliquer la
meme exclusion. Sans cela, importer le SDK vendorise — c'est-a-dire executer un test,
un diagnostic ou la commande elle-meme — cree des `.pyc` sous `bin/lib/` et met le
verificateur en echec sur un faux positif, en orientant vers une reconstruction
complete.

Les tests operent sur une arborescence temporaire : ils n'ecrivent jamais dans le
`bin/lib/` du depot et ne dependent pas de son etat de compilation.
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

from . import REPO_ROOT

_TOOLS = os.path.join(REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import hash_manifest  # noqa: E402


def _muet(fonction):
    """Appelle `fonction()` en absorbant ses sorties : `write`/`check` rendent compte
    sur stdout/stderr, ce qui n'a rien a faire dans le rapport de tests."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
        io.StringIO()
    ):
        return fonction()


class ArbreTemporaire(object):
    """Fait pointer `hash_manifest` sur une arborescence jetable, le temps du test."""

    def __enter__(self):
        self.root = tempfile.mkdtemp(prefix="acl_manifest_")
        self._lib, self._manifest = hash_manifest.LIB, hash_manifest.MANIFEST
        hash_manifest.LIB = self.root
        hash_manifest.MANIFEST = os.path.join(self.root, "MANIFEST.sha256")
        return self

    def __exit__(self, *exc):
        hash_manifest.LIB, hash_manifest.MANIFEST = self._lib, self._manifest
        shutil.rmtree(self.root, ignore_errors=True)
        return False

    def ecrire(self, relative, contenu=b"contenu"):
        chemin = os.path.join(self.root, *relative.split("/"))
        dossier = os.path.dirname(chemin)
        if dossier and not os.path.isdir(dossier):
            os.makedirs(dossier)
        with open(chemin, "wb") as handle:
            handle.write(contenu)
        return chemin


class ManifesteIgnoreLesArtefactsDeCompilationTest(unittest.TestCase):
    """A-6 — un `__pycache__` ne doit ni entrer au manifeste ni le mettre en echec."""

    def test_le_parcours_ignore_pycache_et_pyc(self):
        with ArbreTemporaire() as arbre:
            arbre.ecrire("splunklib/__init__.py")
            arbre.ecrire("splunklib/client.py")
            arbre.ecrire("splunklib/__pycache__/__init__.cpython-312.pyc")
            arbre.ecrire("splunklib/__pycache__/client.cpython-312.pyc")
            arbre.ecrire("splunklib/client.pyo")

            releves = sorted(relative for relative, _ in hash_manifest._entries())

        self.assertEqual(releves, ["splunklib/__init__.py", "splunklib/client.py"])

    def test_check_reste_conforme_apres_apparition_dun_pycache(self):
        """Le scenario reel : `check` passe, on importe le SDK, `check` doit passer.

        C'est la formulation exacte de A-6 — le verificateur etait mis en echec par
        l'acte meme d'utiliser ce qu'il verifie.
        """
        with ArbreTemporaire() as arbre:
            arbre.ecrire("splunklib/__init__.py")
            arbre.ecrire("splunklib/searchcommands/__init__.py")
            self.assertEqual(_muet(hash_manifest.write), 0)
            self.assertEqual(_muet(hash_manifest.check), 0)

            # Un import du SDK vendorise : l'interprete depose ses artefacts.
            arbre.ecrire("splunklib/__pycache__/__init__.cpython-312.pyc")
            arbre.ecrire(
                "splunklib/searchcommands/__pycache__/__init__.cpython-312.pyc"
            )

            self.assertEqual(_muet(hash_manifest.check), 0)

    def test_une_vraie_divergence_reste_detectee(self):
        """L'exclusion ne doit pas emousser le controle : un fichier ajoute echoue."""
        with ArbreTemporaire() as arbre:
            arbre.ecrire("splunklib/__init__.py")
            self.assertEqual(_muet(hash_manifest.write), 0)

            arbre.ecrire("splunklib/porte_derobee.py")
            self.assertEqual(_muet(hash_manifest.check), 1)

            os.remove(os.path.join(arbre.root, "splunklib", "porte_derobee.py"))
            arbre.ecrire("splunklib/__init__.py", b"contenu modifie")
            self.assertEqual(_muet(hash_manifest.check), 1)


if __name__ == "__main__":
    unittest.main()
