#!/usr/bin/env python3
"""Manifeste d'empreintes SHA-256 de `bin/lib/`.

`write` (re)genere `bin/lib/MANIFEST.sha256`, `check` recalcule et compare. Sortie non
nulle en cas de divergence : c'est ce qui rend detectable toute modification de
`bin/lib/` hors `tools/vendor.sh`.

Ecrit en Python plutot qu'en shell pour rester utilisable sur les postes de
developpement sans `sha256sum` (Windows, macOS ancien) — la reproductibilite de la
verification compte autant que celle de l'installation.
"""

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "bin", "lib")
MANIFEST = os.path.join(LIB, "MANIFEST.sha256")

#: Fichiers non vendorises, exclus du manifeste : ils sont ecrits a la main et
#: versionnes, pas produits par pip.
EXCLUDED = {"MANIFEST.sha256", "VENDOR.md"}

#: Repertoires d'artefacts de compilation, exclus du parcours.
EXCLUDED_DIRS = {"__pycache__"}

#: Suffixes d'artefacts de compilation, exclus du parcours.
EXCLUDED_SUFFIXES = (".pyc", ".pyo")


def _is_build_artifact(relative):
    """Vrai pour un artefact produit par l'interprete, jamais par `pip`.

    Le manifeste decrit ce que `tools/vendor.sh` installe ; l'elagage y retire deja
    `__pycache__` et `*.pyc`. Le parcours de verification doit appliquer la meme
    exclusion, faute de quoi **le simple fait d'importer le SDK vendorise met le
    verificateur en echec** — un import cree les `.pyc` sous `bin/lib/`, que le
    parcours compte alors comme des fichiers non declares. Un controle d'integrite mis
    en echec par l'usage de ce qu'il controle n'est pas exploitable, et il oriente vers
    une reconstruction complete pour un faux positif.
    """
    segments = relative.split("/")
    if any(segment in EXCLUDED_DIRS for segment in segments[:-1]):
        return True
    return segments[-1].endswith(EXCLUDED_SUFFIXES)


def _digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _entries():
    for dirpath, dirnames, filenames in os.walk(LIB):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, LIB).replace(os.sep, "/")
            if relative in EXCLUDED or _is_build_artifact(relative):
                continue
            yield relative, _digest(full)


def write():
    lignes = ["%s  %s" % (digest, relative) for relative, digest in _entries()]
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lignes) + ("\n" if lignes else ""))
    print("%d fichiers empreintes dans %s" % (len(lignes), MANIFEST))
    return 0


def check():
    if not os.path.exists(MANIFEST):
        print("ECHEC : %s absent" % MANIFEST, file=sys.stderr)
        return 2
    attendu = {}
    with open(MANIFEST, encoding="utf-8") as handle:
        for ligne in handle:
            ligne = ligne.strip()
            if not ligne:
                continue
            digest, _, relative = ligne.partition("  ")
            attendu[relative] = digest
    observe = dict(_entries())

    manquants = sorted(set(attendu) - set(observe))
    ajoutes = sorted(set(observe) - set(attendu))
    modifies = sorted(
        f for f in set(attendu) & set(observe) if attendu[f] != observe[f]
    )

    for famille, fichiers in (
        ("manquant", manquants), ("non declare", ajoutes), ("modifie", modifies)
    ):
        for fichier in fichiers:
            print("ECHEC [%s] %s" % (famille, fichier), file=sys.stderr)

    if manquants or ajoutes or modifies:
        print(
            "ECHEC : bin/lib/ diverge du manifeste. Reconstruire avec "
            "tools/vendor.sh, ne jamais editer bin/lib/ a la main.",
            file=sys.stderr,
        )
        return 1
    print("OK : %d fichiers conformes au manifeste" % len(attendu))
    return 0


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "write":
        sys.exit(write())
    if action == "check":
        sys.exit(check())
    print("usage: hash_manifest.py [write|check]", file=sys.stderr)
    sys.exit(2)
