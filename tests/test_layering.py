"""Etancheite des couches — la regle d'import du §1.2 de la spec, verifiee mecaniquement.

C'est ce test qui empeche la testabilite hors Splunk de se degrader au fil des
iterations. Sans lui, la regle n'est qu'une intention en commentaire : il suffit d'un
import ajoute a la va-vite dans `merge.py` pour que le §11.1 devienne inapplicable et
que la matrice de fusion cesse d'etre eprouvable sur une machine sans instance.
"""

import ast
import os
import unittest

from . import BIN_DIR

PACKAGE_DIR = os.path.join(BIN_DIR, "acltools")

#: Seul module autorise a parler HTTP et a ouvrir une socket.
ALLOWED_NETWORK_MODULE = "rest.py"

#: Modules interdits d'import dans le noyau, hors `rest.py`.
FORBIDDEN_IMPORTS = ("socket", "http", "urllib.request", "urllib.error", "ssl")

#: Motifs textuels interdits dans le noyau, sans exception de module : le SDK de
#: commande de recherche n'y a aucune place. Le nom est reconstitue pour que ce
#: fichier de test ne soit pas lui-meme un contre-exemple s'il etait deplace.
FORBIDDEN_TEXT = ("splunk" + "lib",)


def _python_files():
    for name in sorted(os.listdir(PACKAGE_DIR)):
        if name.endswith(".py"):
            yield name, os.path.join(PACKAGE_DIR, name)


def _imported_modules(path):
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
    return modules


class LayeringTest(unittest.TestCase):

    def test_le_paquet_existe_et_nest_pas_vide(self):
        fichiers = list(_python_files())
        self.assertGreaterEqual(len(fichiers), 10)
        self.assertIn(ALLOWED_NETWORK_MODULE, [name for name, _ in fichiers])

    def test_aucun_module_du_noyau_nimporte_le_reseau_sauf_rest(self):
        for name, path in _python_files():
            if name == ALLOWED_NETWORK_MODULE:
                continue
            with self.subTest(module=name):
                modules = _imported_modules(path)
                for interdit in FORBIDDEN_IMPORTS:
                    racine = interdit.split(".")[0]
                    fautifs = [
                        m for m in modules
                        if m == interdit or m == racine or m.startswith(interdit + ".")
                    ]
                    # `urllib.parse` est autorise : c'est du calcul de chaine, pas du
                    # reseau. Seules les branches reseau d'urllib sont proscrites.
                    fautifs = [m for m in fautifs if not m.startswith("urllib.parse")]
                    if racine == "urllib":
                        fautifs = [
                            m for m in fautifs
                            if m in ("urllib", "urllib.request", "urllib.error")
                        ]
                    self.assertEqual(
                        fautifs, [],
                        "%s importe %r : la regle d'import du §1.2 interdit le reseau "
                        "hors de acltools/rest.py" % (name, fautifs),
                    )

    def test_aucun_fichier_du_noyau_ne_mentionne_le_sdk(self):
        for name, path in _python_files():
            with self.subTest(module=name):
                with open(path, encoding="utf-8") as handle:
                    source = handle.read()
                for motif in FORBIDDEN_TEXT:
                    self.assertNotIn(
                        motif, source,
                        "%s mentionne %r : le noyau doit rester importable sans le SDK"
                        % (name, motif),
                    )

    def test_le_noyau_simporte_sans_bin_lib_sur_le_path(self):
        """Les tests n'inserent jamais `bin/lib` dans `sys.path` : le simple fait que la
        suite s'execute prouve que le noyau ne depend pas du SDK vendorise."""
        import sys

        lib = os.path.join(BIN_DIR, "lib")
        self.assertNotIn(lib, sys.path)

        import acltools.endpoint  # noqa: F401
        import acltools.journal  # noqa: F401
        import acltools.mapping  # noqa: F401
        import acltools.merge  # noqa: F401
        import acltools.normalize  # noqa: F401
        import acltools.pipeline  # noqa: F401
        import acltools.preflight  # noqa: F401

    def test_lenveloppe_se_compile_sans_le_sdk(self):
        """`bin/editacl.py` n'est pas importable sans le SDK — c'est le but — mais il
        doit au moins compiler, et son insertion de `sys.path` doit preceder le premier
        import du SDK."""
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            source = handle.read()
        compile(source, chemin, "exec")

        tree = ast.parse(source, filename=chemin)
        ligne_syspath = None
        ligne_sdk = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ligne_syspath is None:
                if ast.unparse(node.func) == "sys.path.insert":
                    ligne_syspath = node.lineno
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("splunk" + "lib") and ligne_sdk is None:
                    ligne_sdk = node.lineno
        self.assertIsNotNone(ligne_syspath, "aucune insertion dans sys.path")
        self.assertIsNotNone(ligne_sdk, "aucun import du SDK")
        self.assertLess(
            ligne_syspath, ligne_sdk,
            "bin/lib doit etre en tete de sys.path AVANT le premier import du SDK",
        )

    def test_lenveloppe_ne_porte_aucune_regle_metier(self):
        """L'adaptateur cable, il ne decide pas : aucune des fonctions de decision du
        noyau n'y est redefinie."""
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=chemin)
        definies = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        interdites = {
            "merge", "is_noop", "normalize_roles", "validate_roles", "parse_fields",
            "build_object_path", "encode_title_segment", "resolve_handler_path",
            "build_intent_record", "build_outcome_record",
        }
        self.assertEqual(definies & interdites, set())

    def test_le_noyau_nutilise_aucune_dependance_tierce(self):
        """Aucune bibliotheque hors bibliotheque standard, sur aucun module."""
        autorises = {
            "ast", "csv", "json", "logging", "logging.handlers", "os", "re", "ssl",
            "sys", "time", "typing", "dataclasses", "datetime", "urllib",
            "urllib.parse", "urllib.request", "urllib.error", "collections",
            "collections.abc",
        }
        for name, path in _python_files():
            with self.subTest(module=name):
                for module in _imported_modules(path):
                    if module.startswith("."):
                        continue
                    racine = module.split(".")[0]
                    if racine == "acltools":
                        continue
                    self.assertIn(
                        module if module in autorises else racine, autorises,
                        "%s importe %r, hors bibliotheque standard autorisee"
                        % (name, module),
                    )


if __name__ == "__main__":
    unittest.main()
