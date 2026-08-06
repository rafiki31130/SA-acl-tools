"""Jeu de tests unitaires du §11.1 — executable hors Splunk, sans instance, sans reseau.

Commande de rejeu, depuis la racine du depot :

    python -m unittest discover -s tests -t . -v

Aucune dependance de developpement : `unittest` de la bibliotheque standard suffit.
Les tests importent `bin/acltools` directement, **sans jamais charger `bin/lib`** —
c'est la verification pratique que le noyau ne depend pas du SDK.
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN = os.path.join(_REPO_ROOT, "bin")
if _BIN not in sys.path:
    sys.path.insert(0, _BIN)

REPO_ROOT = _REPO_ROOT
BIN_DIR = _BIN
