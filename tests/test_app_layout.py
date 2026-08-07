"""Structure de l'app et fichiers de configuration (§2, §2.1, §7, §8.3, D-3, D-5).

Ces fichiers sont des livrables normatifs autant que le code : une cle absente de
`commands.conf` ou une stanza de monitor sans glob se voit a l'execution, jamais avant.
"""

import ast
import configparser
import os
import re
import unittest

from . import BIN_DIR, REPO_ROOT


def read_conf(*parts):
    # `interpolation=None` : les valeurs de props.conf contiennent des `%`
    # (TIME_FORMAT), que l'interpolation de configparser refuserait.
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(os.path.join(REPO_ROOT, *parts), encoding="utf-8")
    return parser


class LayoutTest(unittest.TestCase):
    """Arborescence du §2."""

    ATTENDUS = (
        ("LICENSE",),
        ("README.md",),
        ("default", "app.conf"),
        ("default", "commands.conf"),
        ("default", "searchbnf.conf"),
        ("default", "authorize.conf"),
        ("default", "inputs.conf"),
        ("default", "props.conf"),
        ("default", "data", "ui", "nav", "default.xml"),
        ("metadata", "default.meta"),
        ("bin", "editacl.py"),
        ("bin", "acl_endpoint_map.json"),
        ("bin", "acltools", "__init__.py"),
        ("lookups", "acl_endpoint_map_override.csv.example"),
        ("tools", "requirements-vendor.txt"),
        ("tools", "vendor.sh"),
        ("tools", "verify_vendor.sh"),
        ("bin", "lib", "VENDOR.md"),
        ("bin", "lib", "MANIFEST.sha256"),
    )

    def test_fichiers_attendus_presents(self):
        for parts in self.ATTENDUS:
            with self.subTest(chemin="/".join(parts)):
                self.assertTrue(
                    os.path.exists(os.path.join(REPO_ROOT, *parts)),
                    "%s absent" % "/".join(parts),
                )

    def test_modules_du_noyau(self):
        attendus = {
            "__init__.py", "errors.py", "model.py", "normalize.py", "mapping.py",
            "endpoint.py", "merge.py", "preflight.py", "journal.py", "rest.py",
            "pipeline.py",
        }
        presents = {
            f for f in os.listdir(os.path.join(BIN_DIR, "acltools"))
            if f.endswith(".py")
        }
        self.assertEqual(attendus - presents, set())


class CommandsConfTest(unittest.TestCase):
    """§2.1 — les cles sont normatives, reproduites a l'identique."""

    ATTENDU = {
        "filename": "editacl.py",
        "chunked": "true",
        "python.version": "python3",
        "local": "true",
        "run_in_preview": "false",
        "is_risky": "true",
        "maxinputs": "0",
    }

    def setUp(self):
        self.conf = read_conf("default", "commands.conf")

    def test_stanza_editacl(self):
        self.assertIn("editacl", self.conf.sections())

    def test_les_cles_normatives_sont_reproduites_a_lidentique(self):
        for cle, valeur in self.ATTENDU.items():
            with self.subTest(cle=cle):
                self.assertEqual(self.conf.get("editacl", cle), valeur)

    def test_aucune_cle_supplementaire(self):
        self.assertEqual(
            sorted(self.conf.options("editacl")), sorted(self.ATTENDU)
        )


class SearchBnfConfTest(unittest.TestCase):
    """`searchbnf.conf` — coloration syntaxique, aide a la saisie, exemple d'usage.

    Sans ce fichier, `editacl` s'execute mais l'interface de recherche l'ignore
    entierement. Le manque ne produit aucune erreur : c'est ce qui l'a fait traverser
    deux audits. Les tests ci-dessous figent ce qui, autrement, ne se constate qu'en
    ouvrant un navigateur sur une instance.

    Le mode de defaillance suivant est le plus vicieux : un fichier valide, charge, et
    **sans effet** parce qu'il n'est visible que dans le contexte de son app alors que
    l'assistant lit celui de la page. Il est verrouille par `MetadataTest`.
    """

    #: Termes primitifs de la grammaire, definis par la plateforme et non par une
    #: stanza. Toute autre production referencee doit exister dans ce fichier.
    PRIMITIFS = frozenset({"bool", "int", "string", "field", "field-list"})

    def setUp(self):
        self.conf = read_conf("default", "searchbnf.conf")

    def _syntaxes(self):
        return {
            section: self.conf.get(section, "syntax")
            for section in self.conf.sections()
            if self.conf.has_option(section, "syntax")
        }

    def test_la_stanza_porte_le_nom_de_la_commande_declaree(self):
        """La convention `[<commande>-command]` est imposee par la plateforme : une
        stanza mal nommee est chargee sans erreur et ne colore rien."""
        commandes = read_conf("default", "commands.conf").sections()
        self.assertEqual(commandes, ["editacl"])
        self.assertIn("editacl-command", self.conf.sections())

    def test_usage_public(self):
        """`usage` est requis, et l'assistant de recherche n'opere que sur `public`."""
        self.assertEqual(self.conf.get("editacl-command", "usage"), "public")

    def test_la_syntaxe_commence_par_le_nom_de_la_commande(self):
        self.assertTrue(
            self.conf.get("editacl-command", "syntax").startswith("editacl"),
            "la production doit s'ouvrir sur le litteral `editacl`",
        )

    def test_toute_production_referencee_est_definie(self):
        """Une production orpheline casse l'analyse de la syntaxe cote assistant, sans
        que rien ne le signale cote serveur."""
        definies = set(self.conf.sections()) | self.PRIMITIFS
        orphelines = set()
        for syntaxe in self._syntaxes().values():
            for terme in re.findall(r"<([A-Za-z0-9._-]+)>", syntaxe):
                if terme.split(":")[0] not in definies:
                    orphelines.add(terme)
        self.assertEqual(sorted(orphelines), [])

    def test_les_options_decrites_sont_exactement_celles_du_code(self):
        """Anti-derive : l'assistant ne doit jamais proposer une option que la commande
        ne connait pas, ni taire une option qu'elle accepte.

        Les noms sont lus dans le source de `bin/editacl.py`, jamais par import : la
        suite reste executable sans le SDK.
        """
        chemin = os.path.join(BIN_DIR, "editacl.py")
        with open(chemin, encoding="utf-8") as handle:
            arbre = ast.parse(handle.read(), filename=chemin)
        options_du_code = set()
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.ClassDef) and noeud.name == "EditAclCommand":
                for element in noeud.body:
                    if (isinstance(element, ast.Assign)
                            and isinstance(element.value, ast.Call)
                            and isinstance(element.value.func, ast.Name)
                            and element.value.func.id == "Option"):
                        for cible in element.targets:
                            if isinstance(cible, ast.Name):
                                options_du_code.add(cible.id)
        self.assertTrue(options_du_code, "aucune Option lue dans bin/editacl.py")

        options_decrites = set()
        for section, syntaxe in self._syntaxes().items():
            if section == "editacl-command":
                continue
            options_decrites.add(syntaxe.split("=", 1)[0].strip())
        self.assertEqual(options_decrites, options_du_code)

    def test_chaque_option_du_code_figure_dans_la_syntaxe_de_la_commande(self):
        syntaxe = self.conf.get("editacl-command", "syntax")
        for section in self._syntaxes():
            if section == "editacl-command":
                continue
            self.assertIn("<%s>" % section, syntaxe)

    def test_description_et_resume_sont_renseignes(self):
        for cle in ("shortdesc", "description"):
            with self.subTest(cle=cle):
                self.assertTrue(self.conf.get("editacl-command", cle).strip())

    def test_au_moins_un_exemple_avec_son_commentaire(self):
        exemples = [
            o for o in self.conf.options("editacl-command")
            if re.fullmatch(r"example\d+", o)
        ]
        self.assertTrue(exemples, "l'assistant affiche un exemple : il faut en donner un")
        for exemple in exemples:
            with self.subTest(exemple=exemple):
                self.assertIn(
                    exemple.replace("example", "comment"),
                    self.conf.options("editacl-command"),
                )
                self.assertIn("editacl", self.conf.get("editacl-command", exemple))

    def test_le_defaut_de_simulation_est_dit_a_loperateur(self):
        """L'assistant est le premier endroit ou l'operateur lit la syntaxe : le fait
        que rien ne s'ecrira sans `dryrun=false` s'y trouve."""
        texte = " ".join(
            self.conf.get(section, cle)
            for section in ("editacl-command", "editacl-dryrun")
            for cle in ("description",)
        )
        self.assertIn("dryrun=false", texte)


class MetadataTest(unittest.TestCase):
    """`metadata/default.meta` — la visibilite des objets, dont depend leur effet.

    Un `searchbnf.conf` confine au contexte de son app est charge, expose sur
    `/servicesNS/nobody/SA-acl-tools/configs/conf-searchbnf`, et rigoureusement sans
    effet la ou l'operateur saisit sa recherche : l'assistant lit le namespace de la
    **page**, c'est-a-dire l'app `search`. Mesure sur Splunk 9.4.6 : sans la stanza
    ci-dessous, `/servicesNS/admin/search/configs/conf-searchbnf?search=editacl` rend
    `total=0` ; avec elle, les six stanzas. Aucune erreur dans les deux cas.
    """

    @staticmethod
    def read_meta():
        """Lecteur dedie : `configparser` refuse la stanza `[]` d'un `.meta`, qui est
        la stanza par defaut de Splunk et ne peut pas etre retiree."""
        stanzas = {}
        courante = None
        chemin = os.path.join(REPO_ROOT, "metadata", "default.meta")
        with open(chemin, encoding="utf-8") as handle:
            for ligne in handle:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#"):
                    continue
                if ligne.startswith("[") and ligne.endswith("]"):
                    courante = ligne[1:-1]
                    stanzas.setdefault(courante, {})
                elif "=" in ligne and courante is not None:
                    cle, valeur = ligne.split("=", 1)
                    stanzas[courante][cle.strip()] = valeur.strip()
        return stanzas

    def setUp(self):
        self.meta = self.read_meta()

    def test_lassistant_de_recherche_suit_la_commande(self):
        self.assertIn("searchbnf", self.meta)
        self.assertEqual(self.meta["searchbnf"].get("export"), "system")

    def test_la_commande_est_exportee(self):
        self.assertEqual(self.meta["commands"].get("export"), "system")


class AuthorizeConfTest(unittest.TestCase):

    def test_capability_declaree(self):
        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::edit_acl_bulk", conf.sections())

    def test_le_nom_de_la_capability_est_celui_controle_par_le_code(self):
        from acltools.preflight import REQUIRED_CAPABILITY

        conf = read_conf("default", "authorize.conf")
        self.assertIn("capability::%s" % REQUIRED_CAPABILITY, conf.sections())


class InputsConfTest(unittest.TestCase):
    """D-3 — un fichier par `sid`, donc une stanza de monitor en **glob**."""

    def setUp(self):
        self.conf = read_conf("default", "inputs.conf")

    def test_stanza_de_journal_en_glob(self):
        attendu = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertIn(attendu, self.conf.sections())

    def test_le_glob_correspond_au_nom_de_fichier_produit_par_le_code(self):
        from acltools.journal import journal_filename

        nom = journal_filename("1754483000.1")
        self.assertTrue(nom.startswith("editacl_journal"))
        self.assertTrue(nom.endswith(".log"))

    def test_sourcetypes_dedies(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        diag = "monitor://$SPLUNK_HOME/var/log/splunk/editacl.log"
        self.assertEqual(self.conf.get(journal, "sourcetype"), "editacl:journal")
        self.assertEqual(self.conf.get(diag, "sourcetype"), "editacl:diag")

    def test_index_configurable_en_un_seul_point(self):
        journal = "monitor://$SPLUNK_HOME/var/log/splunk/editacl_journal*.log"
        self.assertEqual(self.conf.get(journal, "index"), "_internal")


class PropsConfTest(unittest.TestCase):

    def setUp(self):
        self.conf = read_conf("default", "props.conf")

    def test_extraction_json_du_journal(self):
        self.assertEqual(self.conf.get("editacl:journal", "KV_MODE"), "json")

    def test_format_dhorodatage_aligne_sur_le_journal(self):
        self.assertEqual(
            self.conf.get("editacl:journal", "TIME_FORMAT"),
            "%Y-%m-%dT%H:%M:%S.%3N%:z",
        )

    def test_troncature_desactivee(self):
        self.assertEqual(self.conf.get("editacl:journal", "TRUNCATE"), "0")


class ArtefactsSplTest(unittest.TestCase):
    """Livrables SPL de la phase 2b. Leur contenu est eprouve par
    `tests/test_spl_artifacts.py` ; ici on ne verifie que leur presence."""

    ATTENDUS = (
        ("default", "macros.conf"),
        ("default", "savedsearches.conf"),
        ("default", "transforms.conf"),
        ("lookups", "acl_object_families.csv"),
        ("lookups", "acl_decommissioned_roles.csv"),
        ("tools", "revalidate_mapping.py"),
        ("tools", "acl_probe_bootstrap.sh"),
        ("tools", "acl_probe_bootstrap_rest.py"),
    )

    def test_les_artefacts_spl_sont_livres(self):
        for parts in self.ATTENDUS:
            chemin = os.path.join(REPO_ROOT, *parts)
            self.assertTrue(os.path.exists(chemin), chemin)
            self.assertTrue(os.path.getsize(chemin) > 0, chemin)


if __name__ == "__main__":
    unittest.main()
