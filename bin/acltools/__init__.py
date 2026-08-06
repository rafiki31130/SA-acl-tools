"""Noyau metier de la commande de recherche `editacl`.

Regle d'import, verifiable mecaniquement et verifiee par `tests/test_layering.py` :
**aucun fichier de ce paquet ne mentionne un SDK de commande de recherche, ni
n'importe `socket`, `http` ou `urllib.request`, a l'exception de `acltools.rest`.**

C'est cette regle qui rend la totalite de la logique metier — normalisation, fusion,
resolution d'endpoint, serialisation du journal, machine a etats — testable hors
Splunk, sans instance et sans reseau, comme l'exige le §11.1 du cahier des charges.
Elle n'est pas un confort de developpement : c'est le seul moyen d'eprouver de facon
exhaustive une operation irreversible dont la macro de restauration est le seul filet.
"""

__version__ = "1.0.0"
