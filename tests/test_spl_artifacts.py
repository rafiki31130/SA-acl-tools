"""Artefacts SPL : macros, recherches livrees, lookups (§6.5, §6.7, §8.6, §12.7).

Ces fichiers sont des livrables normatifs autant que le code, et ils ne sont
eprouvables sur une instance qu'en l'ayant sous la main. Ce module fige hors Splunk ce
qui peut l'etre : la presence des stanzas, le jeu de champs emis, la source
d'inventaire, et surtout la **coherence entre la table lue par le code Python et le
lookup lu par la macro d'inventaire** — la meme information sous deux formes, dont la
divergence rendrait l'inventaire et la resolution incoherents sans le moindre message.
"""

import csv
import json
import os
import re
import unittest

from . import BIN_DIR, REPO_ROOT
from .test_journal import ROLLBACK_FIELDS_FROM_INTENT

#: Jeu de champs exige du §6.7 contrainte 3, dans l'ordre, exactement.
CONTRAT_ENTREE = (
    "title",
    "eai:acl.app",
    "eai:acl.owner",
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    "eai:type",
    "id",
)

#: Champs produits par `editacl_rollback` (§8.6). `id` n'y figure pas : il n'est pas
#: journalise, et c'est precisement pourquoi la macro d'inventaire doit synthetiser
#: `eai:type` (§6.7 contrainte 4).
#: L'ordre est celui du §8.6, repris litteralement.
CONTRAT_ROLLBACK = (
    "eai:acl.perms.read",
    "eai:acl.perms.write",
    "eai:acl.sharing",
    "eai:acl.owner",
    "eai:acl.app",
    "title",
    "eai:type",
)


def read_splunk_conf(*parts):
    """Lecteur de `.conf` Splunk : gere la continuation de ligne par `\\` finale.

    `configparser` ne sait pas la traiter — il ne joint que les lignes indentees — et
    rendrait donc toute definition de macro multiligne illisible.
    """
    path = os.path.join(REPO_ROOT, *parts)
    stanzas = {}
    current = None
    key = None
    buffer = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if buffer is not None:
                more = line.endswith("\\")
                buffer.append(line[:-1] if more else line)
                if not more:
                    stanzas[current][key] = " ".join(
                        part.strip() for part in buffer
                    ).strip()
                    buffer = None
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                stanzas.setdefault(current, {})
                continue
            if "=" in stripped and current is not None:
                key, value = stripped.split("=", 1)
                key = key.strip()
                if line.endswith("\\"):
                    buffer = [value[: value.rindex("\\")] if "\\" in value else value]
                else:
                    stanzas[current][key] = value.strip()
    return stanzas


def read_csv_lookup(name):
    path = os.path.join(REPO_ROOT, "lookups", name)
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def endpoint_map():
    with open(os.path.join(BIN_DIR, "acl_endpoint_map.json"), encoding="utf-8") as f:
        return json.load(f)


def champs_de_table(definition):
    """Extrait la liste de champs du dernier `| table ...` d'une definition SPL."""
    segment = definition.rsplit("| table ", 1)[1]
    return [c.strip().strip('"').strip("'") for c in segment.split(",") if c.strip()]


class MacrosTest(unittest.TestCase):
    def setUp(self):
        self.conf = read_splunk_conf("default", "macros.conf")
        self.familles = read_csv_lookup("acl_object_families.csv")

    def test_les_macros_du_cahier_des_charges_sont_declarees(self):
        for stanza in ("acl_inventory", "acl_inventory(1)",
                       "editacl_rollback(1)", "editacl_rollback_apply(1)"):
            self.assertIn(stanza, self.conf)

    def test_une_stanza_par_arite_jusqu_au_nombre_de_familles(self):
        # Splunk indexe les macros par ARITE : `acl_inventory(savedsearch,views)` est un
        # appel a deux arguments. Sans stanza `[acl_inventory(2)]`, la forme parametree
        # du §13 echoue avec « macro cannot be found ».
        arites = {
            int(m.group(1))
            for m in (re.match(r"^acl_inventory\((\d+)\)$", s) for s in self.conf)
            if m
        }
        self.assertEqual(arites, set(range(1, len(self.familles) + 1)))

    def test_l_inventaire_ne_s_appuie_pas_sur_le_handler_d_agregation(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertNotIn("admin/directory", definition)
        self.assertIn("inputlookup acl_object_families", definition)

    def test_l_inventaire_emet_exactement_le_contrat_d_entree(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertEqual(tuple(champs_de_table(definition)), CONTRAT_ENTREE)

    def test_l_inventaire_synthetise_eai_type(self):
        # Sans cette synthese l'aller fonctionne — `id` est exploitable — mais le retour
        # arriere est impossible : la restauration resout par `eai:type` (§6.7-4).
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertIn("acl_family", definition)
        self.assertRegex(
            definition,
            r"eval \"eai:type\" = if\(isnull\('eai:type'\).*acl_family",
        )

    def test_la_selection_precede_les_appels_rest(self):
        # Le levier de cout du §6.7-2 : une famille non demandee ne doit couter aucun
        # appel REST. Si le `where` passait apres le `map`, tout serait enumere.
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertLess(definition.index("| where match(family"),
                        definition.index("| map "))

    def test_l_argument_de_famille_est_filtre_avant_injection_en_regex(self):
        definition = self.conf["acl_inventory_base(1)"]["definition"]
        self.assertIn('replace("$families$", "[^A-Za-z0-9_,-]", "")', definition)

    def test_le_rollback_produit_exactement_les_sept_champs_attendus(self):
        definition = self.conf["editacl_rollback(1)"]["definition"]
        emis = re.findall(r'AS\s+"?([A-Za-z:._*]+)"?', definition)
        self.assertEqual(
            tuple(c for c in emis if c != "restorable"), CONTRAT_ROLLBACK
        )

    def test_le_rollback_ne_consomme_que_des_champs_journalises(self):
        definition = self.conf["editacl_rollback(1)"]["definition"]
        for champ in ("before_perms_read", "before_perms_write", "before_sharing",
                      "owner", "app", "title", "eai_type", "endpoint", "phase",
                      "status", "sid"):
            self.assertIn(champ, definition)
            self.assertIn(champ, ROLLBACK_FIELDS_FROM_INTENT + ("status",))

    def test_le_rollback_n_apparie_que_les_ecritures_abouties(self):
        # Un objet dont le POST a echoue n'a pas ete modifie : le « restaurer »
        # l'ecrirait vers un etat qu'il n'a jamais quitte.
        definition = self.conf["editacl_rollback(1)"]["definition"]
        self.assertIn('phase="outcome" AND status="updated"', definition)
        self.assertIn("eventstats max(_restorable) AS restorable BY endpoint",
                      definition)

    def test_le_rollback_applique_delegue_au_rollback_de_previsualisation(self):
        # Deux copies du meme pipeline divergeraient au premier amendement, et la copie
        # oubliee serait celle qui ecrit.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn("`editacl_rollback($sid$)`", definition)

    def test_le_rollback_applique_porte_l_invocation_complete_et_quotee(self):
        # D-13 : la macro existe pour que la quotation ne repose pas sur la vigilance
        # de l'operateur au moment ou il restaure apres un incident.
        definition = self.conf["editacl_rollback_apply(1)"]["definition"]
        self.assertIn('| editacl fields="perms.read,perms.write,sharing"', definition)
        self.assertIn("dryrun=f", definition)

    def test_seul_le_rollback_applique_ecrit(self):
        # `editacl_rollback(1)` reste la forme de previsualisation : elle ne doit porter
        # aucune invocation de la commande (le `sourcetype=editacl:journal` n'en est
        # pas une : on cherche la commande en position de pipe).
        self.assertNotIn("| editacl ", self.conf["editacl_rollback(1)"]["definition"])

    def test_le_rollback_est_invocable_en_position_generatrice(self):
        # Invoquee par `| `editacl_rollback(...)``, la definition doit commencer par une
        # commande. Le §8.6 ecrit le SPL sans son `search` de tete.
        self.assertTrue(
            self.conf["editacl_rollback(1)"]["definition"].startswith("search index=")
        )


class CoherenceTableEtLookupTest(unittest.TestCase):
    """La table est lue par le code Python, le lookup par la macro. Une divergence
    entre les deux ne se voit qu'a l'execution, et sans message."""

    def setUp(self):
        self.familles = {
            row["family"]: row["handler_path"]
            for row in read_csv_lookup("acl_object_families.csv")
        }
        self.table = endpoint_map()

    def test_chaque_famille_est_une_cle_de_la_table(self):
        for famille, handler in self.familles.items():
            self.assertIn(famille, self.table)
            self.assertEqual(self.table[famille], handler)

    def test_chaque_handler_de_la_table_est_inventorie(self):
        self.assertEqual(set(self.familles.values()), set(self.table.values()))

    def test_un_seul_enregistrement_par_handler(self):
        # Deux cles de la table peuvent viser le meme handler ; l'inventaire ne doit
        # l'enumerer qu'une fois, sinon il produit des doublons.
        handlers = list(self.familles.values())
        self.assertEqual(len(handlers), len(set(handlers)))


class SavedsearchesTest(unittest.TestCase):
    def setUp(self):
        self.conf = read_splunk_conf("default", "savedsearches.conf")

    NOMS = (
        "ACL — inventaire par rôle",
        "ACL — références aux rôles décommissionnés",
        "ACL — journal des modifications",
    )

    def test_les_trois_recherches_du_paragraphe_12_7_sont_livrees(self):
        for nom in self.NOMS:
            self.assertIn(nom, self.conf)

    def test_les_inventaires_sont_batis_sur_la_macro_et_pas_sur_le_handler(self):
        for nom in self.NOMS[:2]:
            recherche = self.conf[nom]["search"]
            self.assertIn("`acl_inventory`", recherche)
            self.assertNotIn("admin/directory", recherche)

    def test_la_recherche_de_roles_decommissionnes_alimente_directement_editacl(self):
        recherche = self.conf[self.NOMS[1]]["search"]
        self.assertIn("lookup acl_decommissioned_roles", recherche)
        emis = champs_de_table(recherche)
        for champ in CONTRAT_ENTREE:
            self.assertIn(champ, emis)

    def test_aucune_recherche_n_est_planifiee(self):
        # L'inventaire est une macro invocable en ligne ; la planification est un usage
        # recommande, jamais la modalite d'acces (§6.7 contrainte 1).
        for nom in self.NOMS + (self.AUDIT,):
            self.assertEqual(self.conf[nom]["enableSched"], "0")

    # -- §12.7, livrable bloquant ------------------------------------------- #

    AUDIT = "ACL — divergences eventtype / objets dérivés"

    def test_la_recherche_d_audit_des_divergences_est_livree(self):
        """Livrable **bloquant** du §12.

        Elle couvre exactement l'angle mort de D-18 : un derive divergent dont le
        porteur n'entre dans aucun lot n'est atteint par aucune cascade, et la commande
        ne l'ecrira jamais. Sans cette recherche, le volume concerne n'est pas mesurable
        sur le socle cible.
        """
        self.assertIn(self.AUDIT, self.conf)

    def test_l_audit_est_bati_sur_la_macro_d_inventaire(self):
        recherche = self.conf[self.AUDIT]["search"]
        self.assertIn("`acl_inventory(eventtypes,fvtags)`", recherche)
        self.assertNotIn("admin/directory", recherche)

    def test_l_audit_compare_le_derive_a_son_porteur(self):
        recherche = self.conf[self.AUDIT]["search"]
        # Les deux cotes sont apparies, puis leurs empreintes d'ACL comparees.
        self.assertIn("acl_acl_porteur", recherche)
        self.assertIn("acl_acl_derive", recherche)
        self.assertIn("acl_acl_porteur != acl_acl_derive", recherche)

    def test_l_audit_signale_les_roles_references_par_le_derive_seul(self):
        """Le second volet du §12.7, distinct de la simple divergence d'ACL."""
        recherche = self.conf[self.AUDIT]["search"]
        self.assertIn("lookup acl_decommissioned_roles", recherche)
        self.assertIn("acl_role_non_couvert", recherche)

    def test_l_audit_apparie_par_decomposition_jamais_par_concatenation(self):
        """Meme discipline que le rang 0 du §5.4 (§3.4, propriete 3).

        L'appariement part de la cle composite de l'objet derive et la **decompose** ;
        il ne recompose jamais un nom d'objet derive a partir du nom d'un porteur. Un
        `eventtype=` suivi d'une concatenation signalerait la faute.
        """
        recherche = self.conf[self.AUDIT]["search"]
        self.assertIn("acl_pair_field", recherche)
        self.assertIn("acl_pair_value", recherche)
        self.assertNotIn('"eventtype=" .', recherche)
        self.assertNotIn('. "eventtype="', recherche)


class LookupsEtMetadataTest(unittest.TestCase):
    def test_les_definitions_de_lookup_pointent_sur_des_fichiers_livres(self):
        conf = read_splunk_conf("default", "transforms.conf")
        for stanza in ("acl_object_families", "acl_decommissioned_roles"):
            self.assertIn(stanza, conf)
            chemin = os.path.join(REPO_ROOT, "lookups", conf[stanza]["filename"])
            self.assertTrue(os.path.exists(chemin), chemin)

    def test_le_lookup_de_roles_ne_porte_que_des_identifiants_generiques(self):
        # Le depot est public : la liste livree est un gabarit, jamais des roles reels.
        roles = {row["role"] for row in read_csv_lookup("acl_decommissioned_roles.csv")}
        self.assertEqual(roles, {"ancien_role", "role_a", "role_b"})

    def test_macros_transforms_et_lookups_sont_exportes_au_systeme(self):
        # Une macro confinee au contexte de l'app n'est pas invocable en ligne depuis
        # une recherche ad hoc, et une macro exportee qui s'appuie sur un lookup non
        # exporte echoue hors de son app.
        meta = read_splunk_conf("metadata", "default.meta")
        for stanza in ("macros", "transforms", "lookups"):
            self.assertEqual(meta[stanza]["export"], "system")


class RevalidationTest(unittest.TestCase):
    """§6.5 — la procedure reutilise le noyau, elle ne le reimplemente pas."""

    def setUp(self):
        chemin = os.path.join(REPO_ROOT, "tools", "revalidate_mapping.py")
        with open(chemin, encoding="utf-8") as handle:
            self.source = handle.read()

    def test_la_procedure_est_livree(self):
        self.assertTrue(self.source)

    def test_elle_reutilise_le_noyau_plutot_que_de_le_reecrire(self):
        self.assertIn("from acltools.mapping import load_mapping", self.source)
        self.assertIn("from acltools.endpoint import build_object_path", self.source)

    def test_elle_produit_les_trois_listes_exigees(self):
        for marqueur in ("== A. ", "== B. ", "== C. "):
            self.assertIn(marqueur, self.source)

    def test_le_mot_de_passe_n_est_jamais_un_argument_de_ligne_de_commande(self):
        self.assertIn("sys.stdin.readline()", self.source)
        self.assertNotIn("--password", self.source)


class QuotationDeFieldsTest(unittest.TestCase):
    """Balayage mecanique du depot : aucune liste `fields` a plus d'une valeur ne doit
    y figurer sans guillemets — ni en SPL, ni en README, ni en commentaire de conf, ni
    en docstring, ni en contre-exemple.

    Une consigne de quotation ne se verifie pas a la relecture : la forme fautive est
    lisible, s'execute sans erreur, et ne se distingue de la forme correcte que par
    deux caracteres. La seule garantie tenable est qu'aucune ligne copiable n'existe
    dans le depot.
    """

    #: Construit par concatenation pour que ce fichier ne puisse pas etre son propre
    #: contre-exemple : le motif reconnait une liste de valeurs d'attribut ACL
    #: (`[A-Za-z._]`) separees par des virgules et NON precedee d'un guillemet. Il ne
    #: reconnait donc pas un argument nomme Python (`fields=fields,`), ou la virgule
    #: separe des arguments et non des valeurs.
    MOTIF = re.compile("fields=" + r"[A-Za-z._]+(?:,[A-Za-z._]+)+")

    #: Exclus : metadonnees git, caches d'interpretation, et le SDK vendorise, qui est
    #: du code amont non modifie (verifie : il ne contient aucune occurrence).
    EXCLUS = ("/.git/", "/__pycache__/", "/bin/lib/")

    EXTENSIONS = (".py", ".md", ".conf", ".csv", ".json", ".xml", ".sh", ".example",
                  ".txt", ".meta", ".gitattributes", ".gitignore")

    def _fichiers(self):
        for racine, dossiers, fichiers in os.walk(REPO_ROOT):
            dossiers[:] = [
                d for d in dossiers if d not in (".git", "__pycache__", "lib")
            ]
            for nom in fichiers:
                chemin = os.path.join(racine, nom)
                normalise = chemin.replace(os.sep, "/")
                if any(motif in normalise for motif in self.EXCLUS):
                    continue
                if not normalise.endswith(self.EXTENSIONS):
                    continue
                yield chemin

    def test_le_balayage_couvre_bien_les_livrables(self):
        """Un balayage qui ne lit rien passerait toujours."""
        lus = [os.path.basename(c) for c in self._fichiers()]
        for attendu in ("README.md", "macros.conf", "editacl.py", "rest.py"):
            self.assertIn(attendu, lus)

    def test_le_motif_reconnait_la_forme_fautive_et_epargne_les_formes_licites(self):
        # Assemble en deux morceaux : ce fichier est lui-meme balaye par le test
        # suivant, il ne doit pas porter la forme fautive sur une seule ligne.
        self.assertTrue(self.MOTIF.search("| editacl fields=a.b" + ",c.d dryrun=f"))
        self.assertIsNone(self.MOTIF.search('| editacl fields="a.b,c.d" dryrun=f'))
        self.assertIsNone(self.MOTIF.search("| editacl fields=perms.write dryrun=f"))
        self.assertIsNone(self.MOTIF.search("validate_params(" + "fields=fields,)"))

    def test_aucune_liste_fields_non_quotee_dans_le_depot(self):
        fautifs = []
        for chemin in self._fichiers():
            try:
                with open(chemin, encoding="utf-8") as handle:
                    lignes = handle.readlines()
            except (UnicodeDecodeError, OSError):
                continue
            for numero, ligne in enumerate(lignes, 1):
                if self.MOTIF.search(ligne):
                    fautifs.append(
                        "%s:%d" % (os.path.relpath(chemin, REPO_ROOT), numero)
                    )
        self.assertEqual(
            fautifs, [],
            "liste `fields` non quotee — SPL la tronque a sa premiere valeur, sans "
            "erreur : %s" % ", ".join(fautifs),
        )


if __name__ == "__main__":
    unittest.main()
