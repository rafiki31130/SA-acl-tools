"""L'enumeration des `acl_status` est **derivee du code**, jamais recopiee (§5.7, §8.2).

Quatre redactions successives de cette liste ont ete fausses : trois dans le cahier des
charges, puis une dans le jeu de tests auquel D-35 l'avait confiee — `DOUZE_STATUTS`
annoncait douze valeurs et en portait onze, `skipped_derived` manquant. Le defaut n'est
pas l'oubli : c'est qu'une enumeration ecrite a la main n'a **aucun lien mecanique** avec
ce que le code produit, et derive donc a chaque evolution.

Ce module pose ce lien. Il extrait de l'arbre syntaxique du noyau tout statut litteral
effectivement produit, et exige l'egalite avec `acltools.model.ACL_STATUSES`. Combine a
l'invariant 1 du §8.2 — qui exige d'observer chacune de ces valeurs sur un cas reel —,
il attaque la classe d'erreur par les deux bouts :

- statut ajoute au code, absent de `ACL_STATUSES` -> ce module echoue ;
- statut ajoute a `ACL_STATUSES`, sans cas de test -> l'invariant 1 echoue.

**Ce que la premiere version de ce module manquait, et pourquoi la correction porte
ailleurs qu'on ne l'attend.** L'extracteur reconnaissait deux formes d'ecriture et
**ignorait tout le reste**. Un statut passe en argument nomme (`EventRejected(status=…)`)
ou par indirection (`work.status = _CONSTANTE`) entrait dans le noyau sans etre vu, et la
suite restait verte — mesure a l'audit de cloture, deux statuts furtifs, `501 passed`.
Ajouter ces deux formes a l'extracteur aurait reproduit le defaut d'un cran plus loin :
la forme suivante, non prevue, aurait echappe a son tour, en silence.

La correction est donc un **renversement de la valeur par defaut**. L'extracteur ne
classe plus « ce qu'il reconnait » contre « le reste » : il classe **toute** construction
qui touche a un statut en trois categories exhaustives —

1. **canonique** : le statut est un litteral, il est collecte
   (`EventRejected("<statut>", …)`, `<obj>.status = "<statut>"`) ;
2. **propagation reconnue** : la valeur est un statut ne ailleurs, deja collecte a sa
   naissance — un **parametre** nomme `status` de la fonction englobante, ou une
   expression `<…>.status` (`self.status = status`, `work.status = exc.status`) ;
3. **opaque** : tout le reste. **Opaque fait echouer la suite**, en nommant le module, la
   ligne, la portee et le fragment de source en cause.

Un angle mort bruyant vaut infiniment mieux qu'un angle mort silencieux. Qui introduit
une forme opaque a deux issues, toutes deux explicites : ecrire la forme canonique, ou
etendre l'extracteur — donc en connaissance de cause, jamais par inadvertance.

**Ce que ce controle ne garantit pas.** Il est **statique**, et sa portee s'arrete ou
s'arrete la lecture d'un arbre syntaxique :

- il couvre les modules de `SOURCES` — le paquet metier et l'adaptateur de commande. Un
  statut ne dans un module ajoute hors de cette liste, ou dans `bin/lib/` (SDK
  vendorise), n'est pas vu ; `tests/test_layering.py` borne les dependances du noyau,
  il ne borne pas l'endroit ou un statut peut naitre ;
- il ne suit aucune valeur a l'execution : un statut fabrique par `exec`, par
  `importlib`, par une metaclasse ou par un decorateur qui reecrit un attribut echappe a
  toute lecture de source ;
- les categories 1 et 2 reposent sur des **noms** (`status`, `acl_status`,
  `EventRejected`). Un statut ecrit dans un attribut portant un autre nom, puis recopie
  vers `status` par un chemin non textuel, n'est pas vu ;
- une propagation `<expr>.status` est acceptee **sans remonter a l'origine** de la
  valeur. Si cette origine n'est pas elle-meme un site canonique du noyau — un objet
  construit ailleurs, une constante de module portant un attribut `status` —, le statut
  qu'elle porte n'est pas collecte. La propagation depuis un **nom** est plus etroite :
  seul un parametre de la fonction englobante est admis, une variable locale nommee
  `status` est refusee ;
- les **exemptions declarees** (`EXEMPTIONS`) sont des trous ouverts a la main. Chacune
  porte sa justification, aucune n'est implicite, et une exemption qui ne correspond plus
  a rien fait echouer la suite — mais tant qu'elle vaut, elle vaut.

Ces limites sont la raison d'etre du garde-fou `test_lextraction_nest_pas_vide` et des
auto-tests de l'extracteur : un instrument mort produit des zeros rassurants.
"""

import ast
import os
import re
import unittest

from acltools.model import ACL_STATUSES

from . import BIN_DIR, REPO_ROOT

#: Modules balayes : le paquet metier et l'adaptateur de commande. `bin/lib/` — SDK
#: vendorise, non modifie — en est exclu. C'est une **frontiere declaree**, pas une
#: preuve : voir les limites en tete de module.
_PAQUET = os.path.join(BIN_DIR, "acltools")
SOURCES = tuple(
    sorted(
        os.path.join(_PAQUET, nom)
        for nom in os.listdir(_PAQUET)
        if nom.endswith(".py")
    )
) + (os.path.join(BIN_DIR, "editacl.py"),)

#: Noms d'attribut qui portent un `acl_status`. Une ecriture sur l'un d'eux est un
#: **site de statut** : elle est canonique, propagee, ou opaque — jamais ignoree.
ATTRIBUTS_DE_STATUT = ("status",)

#: Memes noms, cote cle de dictionnaire (`output["acl_status"] = …`, le puits du §5.7).
CLES_DE_STATUT = ("status", "acl_status")

#: Memes noms, cote argument nomme (`EventResult(status=…)`).
ARGUMENTS_DE_STATUT = ("status", "acl_status")

#: Exception par evenement : son premier argument positionnel **est** le statut.
CONSTRUCTEURS_DE_REJET = ("EventRejected",)

#: Enveloppes qui ne peuvent pas changer la valeur d'un statut deja etabli. Elles sont
#: **deballees** avant classification, jamais acceptees en bloc : `str(<expr>)` renvoie
#: la classification a `<expr>`, qui reste canonique, propagee, ou opaque.
ENVELOPPES_TRANSPARENTES = ("str",)


# --------------------------------------------------------------------------- #
# Exemptions declarees
# --------------------------------------------------------------------------- #

#: Sites qui portent le nom `status` **sans** porter un `acl_status`. Chaque entree est
#: un trou ouvert a la main dans le controle : elle est nommee, justifiee, et verifiee
#: vivante (`test_les_exemptions_declarees_correspondent_toutes_a_une_construction`).
#: Cle : `(module, portee, source normalisee)` — deplacer ou reecrire le site fait
#: tomber l'exemption, donc echouer la suite, donc redecider.
EXEMPTIONS = (
    (
        "rest.py",
        "RestResponse.__init__",
        "self.status = int(status)",
        "Code HTTP de la reponse de transport, pas un `acl_status` : `RestResponse` "
        "porte `status = 0` pour un echec de transport et `2xx`/`4xx`/`5xx` sinon "
        "(§10.4). L'homonymie est dans le domaine, pas dans le controle.",
    ),
)


# --------------------------------------------------------------------------- #
# Balayage
# --------------------------------------------------------------------------- #

class SiteOpaque(object):
    """Construction touchant un statut que l'extracteur ne sait pas interpreter."""

    __slots__ = ("module", "ligne", "portee", "source", "motif")

    def __init__(self, module, ligne, portee, source, motif):
        self.module = module
        self.ligne = ligne
        self.portee = portee
        self.source = source
        self.motif = motif

    def cle(self):
        """Identite stable d'un site, insensible au numero de ligne."""
        return (self.module, self.portee, self.source)

    def __repr__(self):
        return "%s:%d dans %s -- %s\n        source : %s" % (
            self.module, self.ligne, self.portee, self.motif, self.source,
        )


class _Balayeur(ast.NodeVisitor):
    """Classe chaque site de statut d'un module en canonique / propage / opaque."""

    def __init__(self, module, texte):
        self.module = module
        self._lignes = texte.splitlines()
        self._pile = []
        self._parametres = []
        self.statuts = set()
        self.opaques = []

    # -- outillage ---------------------------------------------------------- #

    def _portee(self):
        return ".".join(self._pile) or "<module>"

    def _source(self, node):
        debut = max(node.lineno - 1, 0)
        fin = getattr(node, "end_lineno", None) or node.lineno
        brut = " ".join(ligne.strip() for ligne in self._lignes[debut:fin])
        return re.sub(r"\s+", " ", brut).strip()

    def _opaque(self, node, motif):
        self.opaques.append(
            SiteOpaque(
                self.module, node.lineno, self._portee(), self._source(node), motif
            )
        )

    # -- pile des portees --------------------------------------------------- #

    @staticmethod
    def _noms_de_parametres(node):
        args = getattr(node, "args", None)
        if args is None or not isinstance(args, ast.arguments):
            return frozenset()                     # ClassDef : pas de parametres
        noms = set()
        for groupe in (
            getattr(args, "posonlyargs", []), args.args, args.kwonlyargs,
        ):
            noms.update(arg.arg for arg in groupe)
        for solitaire in (args.vararg, args.kwarg):
            if solitaire is not None:
                noms.add(solitaire.arg)
        return frozenset(noms)

    def _descendre(self, node):
        self._pile.append(getattr(node, "name", "<lambda>"))
        self._parametres.append(self._noms_de_parametres(node))
        self.generic_visit(node)
        self._parametres.pop()
        self._pile.pop()

    visit_ClassDef = _descendre
    visit_FunctionDef = _descendre
    visit_AsyncFunctionDef = _descendre
    visit_Lambda = _descendre

    def _est_un_parametre(self, nom):
        """Une variable **locale** nommee `status` n'est pas une propagation : c'est
        une indirection, et l'indirection est precisement ce que C-1 refuse."""
        return bool(self._parametres) and nom in self._parametres[-1]

    # -- classification d'une valeur affectee a un statut -------------------- #

    @classmethod
    def _deballer(cls, valeur):
        """Retire les enveloppes **transparentes** : `str(<valeur>)`.

        Ce n'est pas une forme reconnue de plus, c'est une reecriture : ce qui est
        dedans redescend dans les trois memes categories. `str(_TABLE["cle"])` reste
        donc opaque, `str(result.status)` reste une propagation.
        """
        if (
            isinstance(valeur, ast.Call)
            and getattr(valeur.func, "id", None) in ENVELOPPES_TRANSPARENTES
            and len(valeur.args) == 1
            and not valeur.keywords
            and not isinstance(valeur.args[0], ast.Starred)
        ):
            return cls._deballer(valeur.args[0])
        return valeur

    def _classer_valeur(self, stmt, valeur, motif):
        valeur = self._deballer(valeur)
        if isinstance(valeur, ast.Constant):
            if isinstance(valeur.value, str):
                self.statuts.add(valeur.value)     # (1) canonique
            return                                 # constante non textuelle : hors sujet
        if (
            isinstance(valeur, ast.Name)
            and valeur.id in ATTRIBUTS_DE_STATUT
            and self._est_un_parametre(valeur.id)
        ):
            return                                 # (2) `self.status = status`
        if isinstance(valeur, ast.Attribute) and valeur.attr in ATTRIBUTS_DE_STATUT:
            return                                 # (2) `work.status = exc.status`
        self._opaque(stmt, motif)                  # (3) opaque

    # -- reconnaissance des cibles ------------------------------------------ #

    @staticmethod
    def _cle_de_souscription(cible):
        cle = cible.slice
        if cle.__class__.__name__ == "Index":      # Python < 3.9
            cle = cle.value                        # pragma: no cover
        return cle

    @classmethod
    def _designe_un_statut(cls, cible):
        if isinstance(cible, ast.Starred):
            cible = cible.value
        if isinstance(cible, ast.Attribute):
            return cible.attr in ATTRIBUTS_DE_STATUT
        if isinstance(cible, ast.Subscript):
            cle = cls._cle_de_souscription(cible)
            return (
                isinstance(cle, ast.Constant)
                and isinstance(cle.value, str)
                and cle.value in CLES_DE_STATUT
            )
        if isinstance(cible, (ast.Tuple, ast.List)):
            return any(cls._designe_un_statut(sous) for sous in cible.elts)
        return False

    def _cible_assignee(self, stmt, cible, valeur):
        if isinstance(cible, (ast.Tuple, ast.List, ast.Starred)):
            if self._designe_un_statut(cible):
                self._opaque(
                    stmt,
                    "affectation deballee : la valeur qui atterrit dans le statut n'est "
                    "pas isolable. Forme canonique attendue : une affectation simple.",
                )
            return
        if not self._designe_un_statut(cible):
            return
        self._classer_valeur(
            stmt,
            valeur,
            "ecriture d'un statut par une expression non litterale et non reconnue "
            "comme propagation. Formes canoniques : `<obj>.status = \"<statut>\"`, ou "
            "propagation depuis `status` / `<expr>.status`.",
        )

    # -- visites ------------------------------------------------------------ #

    def visit_Assign(self, node):
        for cible in node.targets:
            self._cible_assignee(node, cible, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._cible_assignee(node, node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self._designe_un_statut(node.target):
            self._opaque(
                node,
                "affectation augmentee sur un statut : la valeur resultante ne se lit "
                "pas dans la source.",
            )
        self.generic_visit(node)

    def visit_For(self, node):
        if self._designe_un_statut(node.target):
            self._opaque(
                node,
                "statut affecte par une boucle : la valeur ne se lit pas dans la source.",
            )
        self.generic_visit(node)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None and self._designe_un_statut(
                item.optional_vars
            ):
                self._opaque(
                    node,
                    "statut affecte par un gestionnaire de contexte : la valeur ne se "
                    "lit pas dans la source.",
                )
        self.generic_visit(node)

    def visit_Call(self, node):
        nom = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if nom in CONSTRUCTEURS_DE_REJET:
            self._classer_rejet(node)
        else:
            if nom == "setattr":
                self._classer_setattr(node)
            for kw in node.keywords:
                if kw.arg in ARGUMENTS_DE_STATUT:
                    self._classer_valeur(
                        node,
                        kw.value,
                        "statut passe en argument nomme par une expression non "
                        "litterale et non reconnue comme propagation.",
                    )
        self.generic_visit(node)

    # -- formes particulieres ----------------------------------------------- #

    def _classer_rejet(self, node):
        """`EventRejected(...)` : le statut est le **premier argument positionnel**.

        Toute autre forme est refusee — y compris l'argument nomme, qui serait pourtant
        lisible. C'est deliberé : une seule forme canonique laisse un seul chemin a
        surveiller, la ou deux formes tolerees en appellent une troisieme.
        """
        for kw in node.keywords:
            if kw.arg is None:
                self._opaque(
                    node,
                    "expansion `**` : les arguments d'EventRejected ne sont pas "
                    "lisibles dans la source.",
                )
                return
            if kw.arg in ARGUMENTS_DE_STATUT:
                self._opaque(
                    node,
                    "statut porte en argument nomme. Forme canonique attendue : "
                    "EventRejected(\"<statut>\", <erreur>).",
                )
                return
        if not node.args:
            self._opaque(
                node,
                "EventRejected sans argument positionnel : le statut n'est pas "
                "localisable.",
            )
            return
        premier = node.args[0]
        if isinstance(premier, ast.Starred):
            self._opaque(
                node,
                "expansion `*` en premier argument : le statut n'est pas lisible dans "
                "la source.",
            )
            return
        if isinstance(premier, ast.Constant) and isinstance(premier.value, str):
            self.statuts.add(premier.value)
            return
        self._opaque(
            node,
            "premier argument d'EventRejected non litteral (indirection). Forme "
            "canonique attendue : EventRejected(\"<statut>\", <erreur>).",
        )

    def _classer_setattr(self, node):
        """`setattr` est une ecriture d'attribut que le nom seul ne trahit pas."""
        if node.keywords or len(node.args) != 3:
            self._opaque(
                node,
                "`setattr` de forme inattendue : impossible d'etablir s'il vise un "
                "statut.",
            )
            return
        nom = node.args[1]
        if not (isinstance(nom, ast.Constant) and isinstance(nom.value, str)):
            self._opaque(
                node,
                "`setattr` dont le nom d'attribut n'est pas litteral : il peut viser "
                "`status`.",
            )
            return
        if nom.value in ATTRIBUTS_DE_STATUT:
            self._classer_valeur(
                node,
                node.args[2],
                "statut ecrit par `setattr` avec une valeur non litterale.",
            )


def balayer_source(texte, module="<extrait>"):
    """Balaye un fragment de source. Renvoie `(statuts, sites opaques)`."""
    balayeur = _Balayeur(module, texte)
    balayeur.visit(ast.parse(texte))
    return balayeur.statuts, balayeur.opaques


def balayer_le_noyau():
    """Balaye `SOURCES`. Renvoie `(statuts, sites opaques)`."""
    statuts = set()
    opaques = []
    for chemin in SOURCES:
        with open(chemin, encoding="utf-8") as flux:
            texte = flux.read()
        vus, muets = balayer_source(texte, os.path.basename(chemin))
        statuts |= vus
        opaques.extend(muets)
    return statuts, opaques


def statuts_produits_par_le_code():
    """Union des statuts litteraux de tous les modules du noyau."""
    return balayer_le_noyau()[0]


def _appliquer_exemptions(opaques):
    """Renvoie `(sites non exemptes, index des exemptions effectivement utilisees)`."""
    index = {(mod, portee, src): rang
             for rang, (mod, portee, src, _) in enumerate(EXEMPTIONS)}
    restants = []
    utilisees = set()
    for site in opaques:
        rang = index.get(site.cle())
        if rang is None:
            restants.append(site)
        else:
            utilisees.add(rang)
    return restants, utilisees


# --------------------------------------------------------------------------- #
# L'enumeration du code
# --------------------------------------------------------------------------- #

class EnumerationDeriveeDuCodeTest(unittest.TestCase):
    """`ACL_STATUSES` est la projection exacte de ce que le noyau produit."""

    def test_le_code_ne_produit_aucun_statut_non_declare(self):
        """Le sens fort : un statut ajoute au code fait echouer la suite ici meme."""
        inconnus = statuts_produits_par_le_code() - set(ACL_STATUSES)
        self.assertEqual(
            set(), inconnus,
            "statut(s) produits par le noyau et absents de ACL_STATUSES : %s. Un "
            "statut ne s'ajoute pas sans etre declare, ni sans son cas de test dans "
            "l'invariant 1 du §8.2." % sorted(inconnus),
        )

    def test_aucun_statut_declare_nest_mort(self):
        """Le sens inverse : une valeur declaree que le code ne produit plus est un
        residu, et un residu dans une enumeration est le debut de la derive."""
        morts = set(ACL_STATUSES) - statuts_produits_par_le_code()
        self.assertEqual(
            set(), morts,
            "statut(s) declares dans ACL_STATUSES que le noyau ne produit plus : %s"
            % sorted(morts),
        )

    def test_lextraction_nest_pas_vide(self):
        """Garde-fou contre le « zero produit par un instrument mort » : une extraction
        qui ne trouverait rien rendrait les deux tests precedents vrais par vacuite."""
        self.assertGreaterEqual(len(statuts_produits_par_le_code()), 12)

    def test_lenumeration_est_sans_doublon(self):
        self.assertEqual(len(ACL_STATUSES), len(set(ACL_STATUSES)))


# --------------------------------------------------------------------------- #
# L'inconnu echoue
# --------------------------------------------------------------------------- #

class AucunAngleMortSilencieuxTest(unittest.TestCase):
    """Le controle central : ce que l'extracteur ne sait pas lire, il le refuse."""

    def test_aucune_construction_de_statut_nechappe_a_lextracteur(self):
        _, opaques = balayer_le_noyau()
        restants, _ = _appliquer_exemptions(opaques)
        self.assertEqual(
            [], restants,
            "construction(s) touchant un `acl_status` que l'extracteur ne sait pas "
            "interpreter avec certitude. Chacune doit etre reecrite sous forme "
            "canonique, ou couverte par une entree justifiee de EXEMPTIONS, ou "
            "l'extracteur doit etre etendu — jamais ignoree :\n    - %s"
            % "\n    - ".join(repr(site) for site in restants),
        )

    def test_les_exemptions_declarees_correspondent_toutes_a_une_construction(self):
        """Une exemption morte est un trou qui a survecu a son motif."""
        _, opaques = balayer_le_noyau()
        _, utilisees = _appliquer_exemptions(opaques)
        mortes = [EXEMPTIONS[rang][:3]
                  for rang in range(len(EXEMPTIONS)) if rang not in utilisees]
        self.assertEqual(
            [], mortes,
            "exemption(s) declaree(s) ne correspondant plus a aucune construction du "
            "noyau : %s. Une exemption survit rarement au code qui l'a motivee ; la "
            "retirer, ou la reajuster en connaissance de cause." % (mortes,),
        )


class ExtracteurEprouveTest(unittest.TestCase):
    """L'extracteur lui-meme est mis a l'epreuve, sur des fragments construits.

    Sans cela, les tests ci-dessus mesureraient un instrument dont rien n'etablit qu'il
    voit encore quoi que ce soit.
    """

    #: Les deux formes canoniques, sous leurs quatre ecritures.
    FORMES_CANONIQUES = (
        ('raise EventRejected("par_exception", "motif")', "par_exception"),
        ('errors.EventRejected("par_exception_qualifiee", "m")',
         "par_exception_qualifiee"),
        ('work.status = "par_affectation"', "par_affectation"),
        ('self.status = "par_affectation_self"', "par_affectation_self"),
        ('output["acl_status"] = "par_souscription"', "par_souscription"),
        ('EventResult(status="par_argument_nomme")', "par_argument_nomme"),
    )

    #: Les propagations : un statut ne ailleurs, deja collecte a sa naissance. Elles
    #: sont donnees dans leur fonction englobante — la propagation depuis un nom exige
    #: que ce nom soit un **parametre**.
    FORMES_PROPAGEES = (
        "def f(work, exc):\n    work.status = exc.status\n",
        "def __init__(self, status, error):\n    self.status = status\n",
        "def result(self):\n    return EventResult(status=self.status)\n",
        'def ecrire(record, result):\n    record["status"] = str(result.status)\n',
    )

    #: Les formes que l'extracteur ne sait pas interpreter. Chacune **doit** echouer.
    #: Les deux premieres sont exactement celles que l'audit de cloture a injectees dans
    #: le noyau et qui ont laisse la suite entiere au vert.
    FORMES_REFUSEES = (
        'raise EventRejected(status="statut_furtif_kw", error="sonde")',
        'work.status = _STATUT_FURTIF_INDIRECT',
        'raise EventRejected(_STATUT, "sonde")',
        'raise EventRejected(*args)',
        'raise EventRejected(**charge)',
        'raise EventRejected()',
        'work.status = choisir_le_statut()',
        'work.status = "a" if condition else "b"',
        'work.status = _TABLE["cle"]',
        # l'enveloppe transparente ne blanchit pas ce qu'elle enveloppe
        'work.status = str(_TABLE["cle"])',
        'work.status = str(a, b)',
        'work.status, work.error = _paire()',
        'work.status += "_suffixe"',
        'setattr(work, "status", _STATUT_FURTIF_INDIRECT)',
        'setattr(work, nom_calcule, "statut_furtif")',
        'output["acl_status"] = _STATUT_FURTIF_INDIRECT',
        'EventResult(status=calculer())',
        'for work.status in _STATUTS: pass',
        # variable **locale** nommee `status` : ce n'est pas une propagation, c'est
        # l'indirection par constante deguisee en propagation.
        'def f(work):\n    status = "statut_furtif_local"\n    work.status = status\n',
    )

    def test_les_formes_canoniques_sont_reconnues_et_collectees(self):
        for source, attendu in self.FORMES_CANONIQUES:
            with self.subTest(source=source):
                statuts, opaques = balayer_source(source)
                self.assertEqual([], opaques, "forme canonique jugee opaque")
                self.assertEqual({attendu}, statuts)

    def test_les_propagations_sont_reconnues_et_ne_collectent_rien(self):
        for source in self.FORMES_PROPAGEES:
            with self.subTest(source=source):
                statuts, opaques = balayer_source(source)
                self.assertEqual([], opaques, "propagation jugee opaque")
                self.assertEqual(set(), statuts)

    def test_toute_forme_non_reconnue_est_refusee(self):
        """Le coeur de C-1 : l'inconnu echoue, et il se nomme."""
        for source in self.FORMES_REFUSEES:
            with self.subTest(source=source):
                _, opaques = balayer_source(source, "extrait.py")
                self.assertEqual(
                    1, len(opaques),
                    "forme non reconnue passee en silence : %s" % source,
                )
                site = opaques[0]
                self.assertEqual("extrait.py", site.module)
                self.assertTrue(site.motif, "un refus sans motif n'aide personne")
                self.assertGreaterEqual(site.ligne, 1)
                self.assertIn(site.source, re.sub(r"[ \t]+", " ", source))

    def test_le_noyau_reel_ne_declenche_aucun_refus(self):
        """Le troisieme cas : sur le code livre, le controle est muet."""
        statuts, opaques = balayer_le_noyau()
        restants, _ = _appliquer_exemptions(opaques)
        self.assertEqual([], restants)
        self.assertEqual(set(ACL_STATUSES), statuts)


# --------------------------------------------------------------------------- #
# L'enumeration du README
# --------------------------------------------------------------------------- #

#: `Les etats terminaux … sont les douze `acl_status`.` — la seule tournure du README
#: qui chiffre l'enumeration en toutes lettres.
_COMPTE_README = re.compile(r"\bles\s+([a-zéèêë]+)\s+`acl_status`", re.IGNORECASE)

#: Assez de cardinaux pour encadrer une evolution ; **un mot absent de la table fait
#: echouer**, plutot que de laisser passer un compte non verifie.
_CARDINAUX = {
    "dix": 10, "onze": 11, "douze": 12, "treize": 13, "quatorze": 14,
    "quinze": 15, "seize": 16,
}


class ReadmeArrimeALaSourceUniqueTest(unittest.TestCase):
    """C-2 — l'enumeration du README livre est derivee de `ACL_STATUSES`.

    Le README recopiait les douze valeurs a la main : exactes le jour de l'audit, et
    sans aucun lien avec la source. C'est la classe d'erreur de D-35, du cote de la
    documentation livree. Ces tests posent le lien manquant.

    Portee : ils arriment **l'enumeration**, le **compte** et la **machine a etats** du
    `README.md`. Ils ne disent rien de la justesse des libelles qui decrivent chaque
    statut ailleurs dans le document, ni du cahier des charges, qu'aucun test du depot
    ne peut atteindre.
    """

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as flux:
            cls.readme = flux.read()

    def _ligne_du_tableau(self):
        lignes = [
            ligne for ligne in self.readme.splitlines()
            if ligne.startswith("| `acl_status` |")
        ]
        self.assertEqual(
            1, len(lignes),
            "le README doit porter exactement une ligne de tableau enumerant les "
            "`acl_status` ; %d trouvee(s)." % len(lignes),
        )
        return lignes[0]

    def test_lenumeration_du_readme_egale_ACL_STATUSES(self):
        """Un statut ajoute sans mise a jour du README fait echouer la suite ici."""
        cellule = self._ligne_du_tableau().split("|")[2]
        enumeres = re.findall(r"`([^`]+)`", cellule)
        self.assertEqual(
            list(ACL_STATUSES), enumeres,
            "le tableau des champs de sortie du README diverge de ACL_STATUSES "
            "(ordre compris). Manquants : %s ; en trop : %s."
            % (sorted(set(ACL_STATUSES) - set(enumeres)),
               sorted(set(enumeres) - set(ACL_STATUSES))),
        )

    def test_le_compte_annonce_par_le_readme_est_juste(self):
        """« les douze `acl_status` » est une enumeration deguisee en nombre."""
        mots = _COMPTE_README.findall(self.readme)
        self.assertTrue(
            mots, "le README n'annonce plus le nombre d'`acl_status` en toutes lettres ; "
                  "si la tournure a change, ce controle doit etre reajuste, pas retire.",
        )
        for mot in mots:
            with self.subTest(mot=mot):
                self.assertIn(
                    mot.lower(), _CARDINAUX,
                    "cardinal « %s » absent de la table : compte invérifiable, donc "
                    "refuse." % mot,
                )
                self.assertEqual(
                    len(ACL_STATUSES), _CARDINAUX[mot.lower()],
                    "le README annonce « %s » `acl_status`, ACL_STATUSES en porte %d."
                    % (mot, len(ACL_STATUSES)),
                )

    def test_la_machine_a_etats_du_readme_couvre_tous_les_statuts(self):
        """Le diagramme est la troisieme copie de l'enumeration dans le document."""
        blocs = [
            bloc for bloc in re.findall(r"```mermaid\n(.*?)```", self.readme, re.S)
            if "stateDiagram" in bloc
        ]
        self.assertEqual(1, len(blocs), "un seul diagramme d'etats attendu")
        cibles = set(re.findall(r"-->\s*([A-Za-z_][A-Za-z0-9_]*)", blocs[0]))
        manquants = sorted(set(ACL_STATUSES) - cibles)
        self.assertEqual(
            [], manquants,
            "statut(s) declares dans ACL_STATUSES et absents de la machine a etats du "
            "README : %s." % manquants,
        )


if __name__ == "__main__":                                       # pragma: no cover
    unittest.main()
