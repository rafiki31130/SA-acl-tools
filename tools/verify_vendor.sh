#!/usr/bin/env sh
# Verifie que `bin/lib/` correspond exactement a son manifeste d'empreintes.
# Sortie non nulle en cas de divergence.
#
# Usage, depuis la racine du depot :
#     sh tools/verify_vendor.sh [chemin/vers/python]

set -eu

PYTHON="${1:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec "$PYTHON" "$ROOT/tools/hash_manifest.py" check
