#!/usr/bin/env sh
# Reconstruit `bin/lib/` a l'identique depuis `tools/requirements-vendor.txt`.
#
# Un repertoire `bin/lib/` que personne ne sait reconstruire a l'identique est un
# binaire non auditable au milieu d'un depot public. Ce script, le manifeste
# d'empreintes et `tools/verify_vendor.sh` sont ce qui rend la vendorisation
# reproductible ET verifiable.
#
# Toute montee de version passe par la modification de `requirements-vendor.txt` puis
# la reexecution de ce script et de `verify_vendor.sh`. JAMAIS par une edition directe
# dans `bin/lib/`.
#
# Usage, depuis la racine du depot :
#     sh tools/vendor.sh [chemin/vers/python]

set -eu

PYTHON="${1:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT/bin/lib"
REQ="$ROOT/tools/requirements-vendor.txt"

echo "== reconstruction de $LIB"
rm -rf "$LIB"
mkdir -p "$LIB"

# `--require-hashes` : le contenu installe est exactement celui dont l'empreinte est
# figee dans le fichier de requirements. `--no-deps` : aucune dependance transitive
# n'entre sans decision explicite. `--no-compile` : des .pyc compiles par un
# interpreteur different de celui de la plateforme cible sont au mieux du bruit de
# diff, au pire une source de comportement divergent.
"$PYTHON" -m pip install \
    --no-deps \
    --no-compile \
    --require-hashes \
    --target "$LIB" \
    -r "$REQ"

echo "== elagage"
find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$LIB" -name '*.pyc' -delete 2>/dev/null || true
find "$LIB" -name '*.pyo' -delete 2>/dev/null || true
find "$LIB" -name 'RECORD' -path '*.dist-info*' -delete 2>/dev/null || true
rm -rf "$LIB"/splunklib/tests "$LIB"/splunklib/examples 2>/dev/null || true
rm -rf "$LIB"/bin "$LIB"/tests "$LIB"/examples 2>/dev/null || true

echo "== manifeste d'empreintes"
"$PYTHON" "$ROOT/tools/hash_manifest.py" write

echo "== termine. Verifier avec : sh tools/verify_vendor.sh"
