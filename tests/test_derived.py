"""Abstention sur les objets derives d'un `eventtype` (§3.4, §5.4 rang 0, D-18).

Deux niveaux :

- l'identification elle-meme (`acltools.derived`), et surtout la preuve qu'elle est
  **decouverte** et non construite — c'est la troisieme propriete normative du §3.4 ;
- son insertion au rang 0 de l'ordre du §5.4, avec les invariants qui l'accompagnent :
  aucun POST, compteur non incremente, ligne `outcome` presente.
"""

import unittest

from acltools.derived import (
    CarrierProbe,
    designated_carrier,
    split_composite_key,
)
from acltools.pipeline import EventProcessor, _Work
from acltools.rest import RestResponse

from .helpers import (
    FIXTURE_MAPPING,
    FakeJournal,
    FakeRest,
    acl_body,
    make_ctx,
    make_event,
    make_params,
)

#: Chemin du derive temoin, tel que `build_object_path` le produit.
DERIVE_PATH = "/servicesNS/nobody/mon_app/saved/fvtags/eventtype%3Dmon_eventtype"

#: Chemin du GET de confirmation du porteur. C'est l'appel qui rend la relation
#: **observee** : sans lui, elle serait supposee.
PORTEUR_PATH = "/servicesNS/nobody/mon_app/saved/eventtypes/mon_eventtype"


def derive_rest(carrier_status=200, **kwargs):
    """`FakeRest` servant un objet `fvtags` dont splunkd nomme l'identite."""
    return FakeRest(
        default_get=RestResponse(200, acl_body(name="eventtype=mon_eventtype")),
        json_responses={PORTEUR_PATH: RestResponse(carrier_status, b'{"entry":[]}')},
        default_json=RestResponse(404, b"{}"),
        **kwargs
    )


def derive_event(**kwargs):
    kwargs.setdefault("title", "eventtype=mon_eventtype")
    kwargs.setdefault("eai_type", "fvtags")
    kwargs.setdefault("write", "nouveau_role_admin")
    return make_event(**kwargs)


def run(rest, event, params=None, journal=None):
    processor = EventProcessor(
        params or make_params(),
        make_ctx(),
        rest,
        journal=journal,
        mapping=FIXTURE_MAPPING,
    )
    return processor.process(event), processor


class TestCleComposite(unittest.TestCase):
    """Grammaire `<champ>=<valeur>` de la famille `fvtags`."""

    def test_decoupage_sur_le_premier_signe_egal(self):
        self.assertEqual(
            split_composite_key("eventtype=mon_eventtype"),
            ("eventtype", "mon_eventtype"),
        )

    def test_une_valeur_peut_contenir_un_signe_egal(self):
        """Mesure sur le socle de reference : la cascade suit cette lecture.

        Un `eventtype` nomme `a=b` engendre un derive nomme `eventtype=a=b`, et le POST
        d'ACL sur le porteur cascade bien vers lui. Un decoupage sur le **dernier**
        signe egal, ou un rejet des noms a plusieurs signes egal, manquerait ce cas.
        """
        self.assertEqual(split_composite_key("eventtype=a=b"), ("eventtype", "a=b"))

    def test_formes_hors_grammaire(self):
        for nom in (None, "", "sans_signe_egal", "=valeur_sans_champ", "champ_sans_valeur="):
            with self.subTest(nom=nom):
                self.assertIsNone(split_composite_key(nom))


class TestDesignationDuPorteur(unittest.TestCase):
    """`designated_carrier` lit une designation, elle ne conclut pas a l'existence."""

    def test_derive_d_eventtype_designe_son_porteur(self):
        self.assertEqual(
            designated_carrier("saved/fvtags", "eventtype=mon_eventtype"),
            "mon_eventtype",
        )

    def test_le_handler_d_administration_est_reconnu(self):
        self.assertEqual(
            designated_carrier("admin/fvtags", "eventtype=mon_eventtype"),
            "mon_eventtype",
        )

    def test_un_tag_champ_valeur_ordinaire_ne_designe_aucun_eventtype(self):
        """`mon_champ=ma_valeur` est un tag de champ, pas un derive d'`eventtype`."""
        self.assertIsNone(
            designated_carrier("saved/fvtags", "mon_champ=ma_valeur")
        )

    def test_la_famille_est_un_prealable(self):
        """Un objet d'une autre famille nomme `eventtype=...` n'est pas un derive.

        Sans ce garde-fou, une recherche sauvegardee dont l'operateur aurait choisi ce
        nom serait ecartee de toute modification. La famille vient du chemin de handler
        resolu (§5.2), donnee de plateforme et non du nom.
        """
        for handler in ("saved/searches", "data/ui/views", "admin/tags"):
            with self.subTest(handler=handler):
                self.assertIsNone(
                    designated_carrier(handler, "eventtype=mon_eventtype")
                )


class TestSondeDuPorteur(unittest.TestCase):
    """La relation est **confirmee par la plateforme**, jamais supposee."""

    def test_le_porteur_est_confirme_par_un_get_reel(self):
        rest = derive_rest()
        porteur, avertissement = CarrierProbe(rest).carrier_of(
            "mon_app", "saved/fvtags", "eventtype=mon_eventtype"
        )
        self.assertEqual(porteur, "mon_eventtype")
        self.assertIsNone(avertissement)
        self.assertIn(
            ("JSON", PORTEUR_PATH, None),
            rest.calls,
            "l'existence du porteur doit etre demandee a la plateforme",
        )

    def test_derive_orphelin_le_porteur_n_existe_pas(self):
        """HTTP 404 : aucun porteur ne peut cascader, l'objet reste modifiable.

        C'est la contrepartie qui fait de l'identification une decouverte : une
        heuristique de nommage repondrait « derive » ici aussi.
        """
        rest = derive_rest(carrier_status=404)
        porteur, avertissement = CarrierProbe(rest).carrier_of(
            "mon_app", "saved/fvtags", "eventtype=mon_eventtype"
        )
        self.assertIsNone(porteur)
        self.assertIsNone(avertissement)

    def test_reponse_non_concluante_abstention_conservatrice_et_tracee(self):
        for code in (403, 500, 503, 0):
            with self.subTest(code=code):
                rest = derive_rest(carrier_status=code)
                porteur, avertissement = CarrierProbe(rest).carrier_of(
                    "mon_app", "saved/fvtags", "eventtype=mon_eventtype"
                )
                self.assertEqual(porteur, "mon_eventtype")
                self.assertEqual(
                    avertissement, "carrier_probe_inconclusive:%d" % code
                )

    def test_un_seul_appel_par_porteur_distinct(self):
        rest = derive_rest()
        sonde = CarrierProbe(rest)
        for _ in range(3):
            sonde.carrier_of(
                "mon_app", "saved/fvtags", "eventtype=mon_eventtype"
            )
        self.assertEqual(rest.count("JSON"), 1)

    def test_aucun_appel_hors_de_la_famille_fvtags(self):
        rest = derive_rest()
        CarrierProbe(rest).carrier_of(
            "mon_app", "saved/searches", "eventtype=mon_eventtype"
        )
        self.assertEqual(rest.count("JSON"), 0)


class TestRang0(unittest.TestCase):
    """Insertion du controle au rang 0 de l'ordre normatif du §5.4."""

    def test_statut_et_erreur(self):
        resultat, _ = run(derive_rest(), derive_event())
        self.assertEqual(resultat.status, "skipped_derived")
        self.assertEqual(resultat.error, "derived_object:mon_eventtype")

    def test_aucun_post_et_compteur_non_incremente(self):
        rest = derive_rest()
        _, processor = run(rest, derive_event())
        self.assertEqual(rest.posts(), [])
        self.assertEqual(processor.counter, 0)
        self.assertFalse(processor._written)

    def test_ligne_outcome_presente_et_aucune_ligne_intent(self):
        journal = FakeJournal()
        resultat, _ = run(derive_rest(), derive_event(), journal=journal)
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.intents, [])
        self.assertEqual(journal.outcomes[0]["status"], "skipped_derived")
        self.assertEqual(journal.outcomes[0]["endpoint"], DERIVE_PATH)
        self.assertFalse(resultat.journaled)

    def test_la_ligne_outcome_ne_porte_pas_d_etat(self):
        """La fusion n'a pas ete calculee : le §8.2 exclut donc `before_*` / `after_*`."""
        journal = FakeJournal()
        run(derive_rest(), derive_event(), journal=journal)
        for cle in journal.outcomes[0]:
            self.assertFalse(
                cle.startswith("before_") or cle.startswith("after_"), cle
            )

    def test_le_rang_0_precede_can_change_perms(self):
        rest = derive_rest()
        rest.default_get = RestResponse(
            200, acl_body(name="eventtype=mon_eventtype", can_change_perms=False)
        )
        resultat, _ = run(rest, derive_event())
        self.assertEqual(resultat.status, "skipped_derived")

    def test_le_rang_0_precede_le_refus_de_sharing_vide(self):
        resultat, _ = run(
            derive_rest(),
            derive_event(sharing=""),
            params=make_params(),
        )
        self.assertEqual(resultat.status, "skipped_derived")

    def test_le_rang_0_precede_dryrun(self):
        resultat, _ = run(
            derive_rest(), derive_event(), params=make_params(dryrun=True)
        )
        self.assertEqual(resultat.status, "skipped_derived")

    def test_le_rang_0_precede_noop(self):
        """Un derive deja conforme sort en `skipped_derived`, pas en `noop`.

        L'information utile est que l'objet n'entre pas dans le perimetre d'ecriture.
        """
        resultat, _ = run(derive_rest(), derive_event(write="ancien_role"))
        self.assertEqual(resultat.status, "skipped_derived")

    def test_un_derive_orphelin_est_traite_normalement(self):
        rest = derive_rest(carrier_status=404)
        resultat, _ = run(rest, derive_event())
        self.assertEqual(resultat.status, "updated")
        self.assertEqual(len(rest.posts()), 1)

    def test_l_identite_vient_du_get_pas_du_titre(self):
        """Le §5.3 pose que le GET fait autorite.

        Le `title` de l'evenement designe un `eventtype`, mais splunkd renvoie une autre
        identite : l'objet n'est pas un derive. Se fier au `title` rendrait le rang 0
        contournable — et surtout declenchable — par un `eval` en amont.
        """
        rest = derive_rest()
        rest.default_get = RestResponse(200, acl_body(name="mon_champ=ma_valeur"))
        resultat, _ = run(rest, derive_event())
        self.assertEqual(resultat.status, "updated")

    def test_avertissement_de_sonde_non_concluante_expose_en_sortie(self):
        rest = derive_rest(carrier_status=503)
        resultat, _ = run(rest, derive_event())
        self.assertEqual(resultat.status, "skipped_derived")
        self.assertIn("carrier_probe_inconclusive:503", resultat.warnings)

    def test_aucun_cout_sur_un_lot_sans_derive(self):
        """Le rang 0 n'emet aucun appel sur les familles qui ne sont pas concernees."""
        rest = derive_rest()
        run(rest, make_event(eai_type="savedsearch", write="nouveau_role_admin"))
        self.assertEqual(rest.count("JSON"), 0)


class RangZeroEtDeduplicationTest(unittest.TestCase):
    """A-11 — le rang 0 ne doit pas dependre d'une propriete du §10.8.

    Le court-circuit de deduplication rend la main sans emettre de GET. Il doit donc
    restituer lui-meme l'identite de plateforme, faute de quoi `designated_carrier`
    recevrait `None` et le rang 0 serait inoperant sur une seconde occurrence du meme
    endpoint.

    Le chemin **n'est pas atteignable** dans l'etat livre : un derive est ecarte au
    rang 0, il n'emet pas de POST, il n'entre donc ni dans `_written` ni dans
    `_failed`. La coherence tient, mais elle tient par une propriete d'un **autre**
    mecanisme. Ces deux tests atteignent le chemin deliberement, en injectant la
    memoire d'execution qu'une evolution de la deduplication produirait, et figent la
    garantie **locale** qui la remplace.
    """

    def _processeur(self, rest):
        return EventProcessor(
            make_params(), make_ctx(), rest, mapping=FIXTURE_MAPPING
        )

    def test_le_court_circuit_restitue_lidentite_renvoyee_par_splunkd(self):
        """Invariant de `_read_state` : meme `platform_name` par les deux chemins."""
        rest = derive_rest()
        processeur = self._processeur(rest)

        premier = _Work(derive_event())
        premier.endpoint = DERIVE_PATH
        etat = processeur._read_state(premier)
        self.assertEqual(premier.platform_name, "eventtype=mon_eventtype")

        # Memoire que laisserait un POST abouti sur cet endpoint.
        processeur._written[DERIVE_PATH] = etat

        second = _Work(derive_event())
        second.endpoint = DERIVE_PATH
        processeur._read_state(second)
        self.assertEqual(len(rest.gets()), 1)                # le court-circuit a joue
        self.assertEqual(second.platform_name, premier.platform_name)

    def test_un_derive_deja_memorise_reste_ecarte_au_rang_0(self):
        """La consequence : l'abstention survit a la deduplication.

        Sans la restitution, ce second passage ressortirait `updated` avec un POST.
        """
        rest = derive_rest()
        processeur = self._processeur(rest)

        amorce = _Work(derive_event())
        amorce.endpoint = DERIVE_PATH
        processeur._written[DERIVE_PATH] = processeur._read_state(amorce)

        resultat = processeur.process(derive_event(write="encore_un_autre_role"))
        self.assertEqual(resultat.status, "skipped_derived")
        self.assertEqual(resultat.error, "derived_object:mon_eventtype")
        self.assertEqual(len(rest.posts()), 0)


if __name__ == "__main__":                                   # pragma: no cover
    unittest.main()
