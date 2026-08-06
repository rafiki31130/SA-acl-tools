# Dependances vendorisees

Ce repertoire est **genere**, jamais edite a la main. Il est neanmoins **versionne** :
l'archive de l'app doit etre deployable sans reseau.

| Element | Valeur |
|---|---|
| Paquet | `splunk-sdk` |
| Version | `2.1.1` (figee au patch) |
| Empreinte de l'archive amont | `sha256:46300d52f09e0aed7e5962ce2ba08ef54421ffb3a538c6af6164dcbf9f075faa` |
| Licence amont | Apache-2.0 |
| Date de vendorisation | 2026-08-06 |
| Interpreteur de construction | CPython 3.12 |

## Pourquoi cette version

La serie `3.x` du SDK exige Python >= 3.13 et n'est donc pas installable sur
l'interpreteur livre par Splunk Enterprise 9.x. La `2.1.1` est la derniere de la serie
compatible.

## Pourquoi une seule dependance

Le noyau `bin/acltools/` n'a **aucune** dependance tierce : les appels REST sont ecrits
en HTTP brut sur `urllib` + `ssl` de la bibliotheque standard, et les tests reposent sur
`unittest`. Le SDK ne sert qu'a l'enveloppe `bin/editacl.py`, qui implemente le
protocole de commande de recherche.

Dans un depot public, chaque paquet vendorise est une surface de licence, d'audit et de
CVE que l'app traine sans mecanisme de mise a jour. Toute dependance supplementaire est
donc un arbitrage explicite, pas une commodite.

## Reconstruction

Depuis la racine du depot :

```sh
sh tools/vendor.sh /chemin/vers/python3
sh tools/verify_vendor.sh /chemin/vers/python3
```

`vendor.sh` installe avec `--require-hashes --no-deps --no-compile`, elague les
`__pycache__`, les `.pyc`, le `RECORD` du `.dist-info` ainsi que les tests et exemples
du SDK, puis regenere `MANIFEST.sha256`.

`--no-compile` et la purge des `__pycache__` ne sont pas de la cosmetique : des `.pyc`
compiles par un interpreteur different de celui de la plateforme cible sont au mieux du
bruit de diff, au pire une source de comportement divergent.

## Montee de version

1. Modifier `tools/requirements-vendor.txt` (version **et** empreinte).
2. Reexecuter `tools/vendor.sh`.
3. Reexecuter `tools/verify_vendor.sh`.
4. Mettre a jour ce fichier.

**Jamais** par une edition directe dans `bin/lib/` : `verify_vendor.sh` la detecterait,
et l'archive cesserait d'etre reconstructible.
