"""Machine a etats, invariants de journal (§8.2), plafond (§4.3) et deduplication (§10.8)."""

import unittest

from acltools.pipeline import (
    PRIVATE_BY_ID_WARNING,
    RUNTIME_DIVERGENCE_MESSAGE,
    RUNTIME_DIVERGENCE_WARNING,
    EventProcessor,
    ceiling_message,
)
from acltools.rest import RestResponse

from .helpers import (
    FIXTURE_MAPPING,
    FakeClock,
    FakeJournal,
    FakeRest,
    acl_body,
    make_ctx,
    make_event,
    make_params,
)

ENDPOINT = "/servicesNS/nobody/mon_app/saved/searches/Ma%20recherche"


def processor(rest=None, journal=None, params=None, roles=frozenset({"*"})):
    return EventProcessor(
        params=params or make_params(),
        ctx=make_ctx(),
        rest=rest or FakeRest(),
        journal=journal,
        mapping=FIXTURE_MAPPING,
        roles_catalog=roles,
        clock=FakeClock(),
    )


class StatusTest(unittest.TestCase):

    def test_updated(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("ancien_role",)))
        )
        result = processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertEqual(result.endpoint, ENDPOINT)
        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(rest.posts()[0][1], ENDPOINT)

    def test_le_post_porte_toujours_les_quatre_attributs(self):
        rest = FakeRest()
        processor(rest).process(make_event(write="nouveau_role_admin"))
        payload = rest.posts()[0][2]
        self.assertEqual(
            sorted(payload), ["owner", "perms.read", "perms.write", "sharing"]
        )

    def test_noop(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(read=("role_a",), write=("w",)))
        )
        result = processor(rest).process(make_event(read="role_a", write="w"))
        self.assertEqual(result.status, "noop")
        self.assertEqual(rest.posts(), [])

    def test_noop_lemporte_sur_dryrun(self):
        """Rang 6 avant rang 7 : un objet deja conforme est un `noop` meme en simulation."""
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(read=("role_a",), write=("w",)))
        )
        proc = processor(rest, params=make_params(dryrun=True))
        result = proc.process(make_event(read="role_a", write="w"))
        self.assertEqual(result.status, "noop")

    def test_dryrun_nemet_aucune_ecriture(self):
        rest = FakeRest()
        proc = processor(rest, params=make_params(dryrun=True))
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "dryrun")
        self.assertEqual(rest.posts(), [])

    def test_not_found(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "not_found")
        self.assertEqual(result.http_code, 404)

    def test_forbidden(self):
        rest = FakeRest(default_get=RestResponse(403, b"{}"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "forbidden")

    def test_error_sur_get_5xx(self):
        rest = FakeRest(default_get=RestResponse(503, b"indisponible"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 503)

    def test_error_sur_echec_de_transport(self):
        rest = FakeRest(default_get=RestResponse(0, b"", "transport:TimeoutError: x"))
        result = processor(rest).process(make_event())
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 0)

    def test_error_sur_post_non_2xx(self):
        rest = FakeRest(default_post=RestResponse(409, b"conflit"))
        result = processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.http_code, 409)
        self.assertTrue(result.post_attempted)
        self.assertTrue(result.counted)

    def test_rejected_champ_obligatoire_absent(self):
        for champ in ("title", "app"):
            with self.subTest(champ=champ):
                result = processor().process(make_event(**{champ: ""}))
                self.assertEqual(result.status, "rejected")
                self.assertTrue(result.error.startswith("missing_field:"))

    def test_le_proprietaire_nest_plus_un_champ_obligatoire(self):
        """D-25 : l'adressage se fait par contexte fixe, il n'y a plus rien a exiger.

        Un pipeline qui ne porte aucun proprietaire doit fonctionner de bout en bout :
        c'est le cas nominal depuis la refonte.
        """
        rest = FakeRest(
            default_get=RestResponse(
                200, acl_body(owner="un_tiers", write=("ancien_role",))
            )
        )
        result = processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertEqual(rest.posts()[0][2]["owner"], "un_tiers")

    def test_rejected_app_system(self):
        result = processor().process(make_event(app="system"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "app_system_forbidden")
        self.assertEqual(result.http_code, 0)

    def test_rejected_endpoint_non_resolu(self):
        result = processor().process(make_event(eai_type="type_inexistant"))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "unresolved_endpoint:type_inexistant")

    def test_rejected_sharing_vide(self):
        result = processor().process(make_event(sharing=""))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "sharing_empty_not_allowed")

    def test_rejected_owner_vide(self):
        """§3.3 — pendant exact du refus sur `sharing`, statut par evenement."""
        rest = FakeRest()
        result = processor(rest).process(make_event(owner=""))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "owner_empty_not_allowed")
        self.assertEqual(rest.posts(), [])

    def test_skipped_immutable(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(can_change_perms=False))
        )
        result = processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "skipped_immutable")
        self.assertEqual(rest.posts(), [])

    def test_invalid_role(self):
        proc = processor(
            params=make_params(validate_roles=True), roles=frozenset({"*", "role_a"})
        )
        result = proc.process(make_event(write="role_inexistant"))
        self.assertEqual(result.status, "invalid_role")
        self.assertEqual(result.error, "invalid_role:role_inexistant")

    def test_role_mort_conserve_ne_bloque_pas_mais_avertit(self):
        rest = FakeRest(
            default_get=RestResponse(
                200, acl_body(read=("role_mort",), write=("ancien_role",))
            )
        )
        proc = processor(
            rest,
            params=make_params(validate_roles=True),
            roles=frozenset({"*", "role_mort_absent", "nouveau_role_admin"}),
        )
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("stale_role_preserved:role_mort", result.warnings)


class SkippedPrivateTest(unittest.TestCase):
    """§3.5, D-26 — les objets prives sortent du perimetre.

    Un objet en `sharing=user` n'est visible que de son proprietaire et des
    administrateurs : les permissions qu'il porterait n'accordent rien a personne.
    """

    def test_objet_prive_ecarte_sans_get_ni_post(self):
        rest = FakeRest()
        result = processor(rest).process(
            make_event(current_sharing="user", write="nouveau_role_admin")
        )
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.error, "private_object_out_of_scope")
        self.assertEqual(rest.gets(), [])
        self.assertEqual(rest.posts(), [])

    def test_objet_prive_nincremente_pas_le_plafond(self):
        proc = processor(params=make_params(max_objects=1))
        proc.process(make_event(current_sharing="user"))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_objet_prive_porte_sa_ligne_de_journal(self):
        journal = FakeJournal()
        proc = processor(journal=journal)
        proc.process(make_event(current_sharing="user"))
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.outcomes[0]["status"], "skipped_private")
        self.assertEqual(journal.intents, [])

    def test_la_portee_courante_est_lue_insensiblement_a_la_casse(self):
        result = processor().process(make_event(current_sharing=" User "))
        self.assertEqual(result.status, "skipped_private")

    def test_ni_portee_ni_id_exploitable_repli_en_not_found(self):
        """§3.5 — ni portee courante, ni `id` : l'objet ressort en `not_found`.

        C'est le seul cas ou le repli annonce tient, et il tient **parce qu'aucune
        designation ne permet de faire mieux**. Des qu'un `id` est disponible, la
        seconde voie du §3.5 s'applique et ce chemin n'est plus emprunte — d'ou la
        recommandation de batir le pipeline sur la macro d'inventaire, qui emet
        toujours les deux.
        """
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        result = processor(rest).process(
            make_event(current_sharing=None, id_value=None)
        )
        self.assertEqual(result.status, "not_found")
        self.assertEqual(len(rest.gets()), 1)

    def test_un_objet_partage_nest_pas_ecarte(self):
        for portee in ("app", "global"):
            with self.subTest(portee=portee):
                result = processor().process(
                    make_event(current_sharing=portee, write="nouveau_role_admin")
                )
                self.assertEqual(result.status, "updated")


class PriveDetecteParLeNamespaceDeIdTest(unittest.TestCase):
    """§3.5, D-34 — seconde voie de detection, et elle est **necessaire**.

    Le repli annonce jusqu'a la v2.4 — « colonne de portee absente, le GET par contexte
    fixe repond 404, l'objet ressort en `not_found` » — **est faux des qu'un homonyme
    partage existe**. L'adressage par contexte fixe atteint alors le partage : la
    commande lit, et en ecriture reelle ecrirait, **un objet autre que celui designe en
    entree**. C'est la classe de defaut que le §5.2 declare close, reintroduite par le
    repli.

    Le montage reproduit exactement cette configuration : la ligne d'entree designe le
    prive par son `id` (`/servicesNS/un_operateur/…`), l'homonyme partage existe et
    repond `200` sur le chemin en contexte fixe — c'est le defaut de `FakeRest`. La
    seule chose qui doit se produire est **rien** : ni GET, ni POST.
    """

    ID_PRIVE = (
        "https://base.invalid:0/servicesNS/un_operateur/mon_app/saved/searches/"
        "Ma%2520recherche"
    )
    ID_PARTAGE = (
        "https://base.invalid:0/servicesNS/nobody/mon_app/saved/searches/"
        "Ma%2520recherche"
    )

    def _evenement(self, id_value, current_sharing=None):
        return make_event(
            id_value=id_value,
            current_sharing=current_sharing,
            write="nouveau_role_admin",
        )

    def test_le_prive_designe_par_son_id_ressort_skipped_private(self):
        result = processor().process(self._evenement(self.ID_PRIVE))
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(result.error, "private_object_out_of_scope")

    def test_lhomonyme_partage_nest_pas_touche(self):
        """Le critere qui compte : **aucun** echange HTTP, donc aucune lecture et
        aucune ecriture sur l'objet partage que l'adressage fixe aurait atteint."""
        rest = FakeRest()
        result = processor(rest).process(self._evenement(self.ID_PRIVE))
        self.assertEqual(result.status, "skipped_private")
        self.assertEqual(rest.calls, [])
        self.assertEqual(result.http_code, 0)

    def test_le_meme_lot_sans_la_correction_atteindrait_le_partage(self):
        """Temoin explicite du defaut : l'endpoint que la commande aurait cible est
        bien celui du partage, pas celui du prive. C'est ce que l'auditeur a mesure."""
        result = processor().process(self._evenement(self.ID_PRIVE))
        self.assertEqual(
            result.endpoint, "/servicesNS/nobody/mon_app/saved/searches/Ma%20recherche"
        )

    def test_lecartement_est_signale_a_loperateur(self):
        """Le statut ne dit pas par quelle voie l'objet a ete ecarte ; l'avertissement
        le dit, et nomme du meme coup ce qui manque au pipeline."""
        result = processor().process(self._evenement(self.ID_PRIVE))
        self.assertIn(PRIVATE_BY_ID_WARNING, result.warnings)

    def test_un_id_en_contexte_fixe_nest_pas_ecarte(self):
        """La detection porte sur un namespace **nominatif**, pas sur la presence d'un
        `id`. Un objet partage garde son traitement nominal."""
        result = processor().process(self._evenement(self.ID_PARTAGE))
        self.assertEqual(result.status, "updated")

    def test_la_portee_courante_prime_sur_le_namespace(self):
        """La voie 2 est un **complement**, pas une surcharge : quand le jeu de
        resultats porte la portee, c'est elle qui tranche."""
        result = processor().process(
            self._evenement(self.ID_PRIVE, current_sharing="app")
        )
        self.assertEqual(result.status, "updated")
        self.assertNotIn(PRIVATE_BY_ID_WARNING, result.warnings)

    def test_une_portee_presente_mais_vide_ne_renseigne_pas_davantage(self):
        """Une cellule vide ne dit pas que l'objet est partage : elle ne dit rien. La
        seconde voie s'applique donc, comme si la colonne etait absente."""
        result = processor().process(
            self._evenement(self.ID_PRIVE, current_sharing="  ")
        )
        self.assertEqual(result.status, "skipped_private")

    def test_lecartement_precede_le_plafond_dans_ses_effets(self):
        proc = processor(params=make_params(max_objects=1))
        proc.process(self._evenement(self.ID_PRIVE))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_lobjet_ecarte_porte_sa_ligne_de_journal(self):
        journal = FakeJournal()
        proc = processor(journal=journal)
        proc.process(self._evenement(self.ID_PRIVE))
        self.assertEqual(len(journal.outcomes), 1)
        self.assertEqual(journal.outcomes[0]["status"], "skipped_private")
        self.assertEqual(journal.intents, [])


class AdressageSansProprietaireTest(unittest.TestCase):
    """§5.2, D-25 — l'URI construite ne porte jamais de proprietaire.

    C'est le defaut de ciblage de la v1 : un objet prive **masque** un objet partage
    homonyme dans le namespace de son detenteur. La commande atteignait alors le prive
    et ecrivait son ACL, en rapportant `updated`.
    """

    def test_luri_du_get_porte_le_contexte_fixe(self):
        rest = FakeRest()
        processor(rest).process(make_event(title="Ma recherche", app="mon_app"))
        self.assertEqual(
            rest.gets()[0][1],
            "/servicesNS/nobody/mon_app/saved/searches/Ma%20recherche",
        )

    def test_luri_du_post_porte_le_contexte_fixe(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="un_tiers")))
        processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertTrue(rest.posts()[0][1].startswith("/servicesNS/nobody/"))

    def test_le_proprietaire_reel_du_get_ne_fuit_pas_dans_ladresse(self):
        """Le GET renvoie **toujours** le proprietaire reel, jamais le contexte
        d'adressage. Le reinjecter dans l'URI reintroduirait le defaut de la v1."""
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="un_tiers")))
        processor(rest).process(make_event(write="nouveau_role_admin"))
        for _, path, _ in rest.calls:
            self.assertNotIn("un_tiers", path)

    def test_le_contexte_joker_nest_jamais_employe(self):
        rest = FakeRest()
        processor(rest).process(make_event(write="nouveau_role_admin"))
        for _, path, _ in rest.calls:
            self.assertNotIn("/servicesNS/-/", path)

    def test_une_reprise_de_propriete_nechange_pas_ladresse(self):
        """`new_owner` est une **valeur cible**, pas une adresse : l'URI reste identique
        avec et sans lui."""
        sans = FakeRest()
        processor(sans).process(make_event(write="nouveau_role_admin"))
        avec = FakeRest()
        processor(avec).process(
            make_event(write="nouveau_role_admin", owner="autre_proprietaire")
        )
        self.assertEqual(sans.posts()[0][1], avec.posts()[0][1])


class WarningTest(unittest.TestCase):

    def test_sharing_change(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(sharing="app")))
        result = processor(rest).process(make_event(sharing="global"))
        self.assertIn("sharing_change", result.warnings)

    def test_owner_change(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="un_proprietaire")))
        result = processor(rest).process(make_event(owner="autre_proprietaire"))
        self.assertIn("owner_change", result.warnings)

    def test_app_disabled(self):
        proc = EventProcessor(
            params=make_params(),
            ctx=make_ctx(),
            rest=FakeRest(),
            mapping=FIXTURE_MAPPING,
            app_disabled_fn=lambda app: True,
            clock=FakeClock(),
        )
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertIn("app_disabled", result.warnings)


class JournalInvariantTest(unittest.TestCase):
    """Les trois invariants verifiables du §8.2."""

    DOUZE_STATUTS = (
        "updated", "noop", "dryrun", "rejected", "not_found", "forbidden",
        "invalid_role", "skipped_immutable", "skipped_private", "skipped_ceiling",
        "error",
    )

    def test_invariant_1_une_ligne_outcome_par_evenement_de_sortie_tous_statuts(self):
        journal = FakeJournal()
        vus = []

        def chemin(titre):
            return (
                "/servicesNS/nobody/mon_app/saved/searches/"
                + titre.replace(" ", "%20")
            )

        rest = FakeRest(
            get_responses={
                chemin("obj_updated"): RestResponse(200, acl_body(write=("ancien_role",))),
                chemin("obj_noop"): RestResponse(200, acl_body(read=(), write=("w",))),
                chemin("obj_notfound"): RestResponse(404, b"{}"),
                chemin("obj_forbidden"): RestResponse(403, b"{}"),
                chemin("obj_error"): RestResponse(500, b"boum"),
                chemin("obj_immutable"): RestResponse(
                    200, acl_body(can_change_perms=False)
                ),
                chemin("obj_invalidrole"): RestResponse(200, acl_body(write=("ancien_role",))),
            }
        )
        proc = EventProcessor(
            params=make_params(validate_roles=True),
            ctx=make_ctx(),
            rest=rest,
            journal=journal,
            mapping=FIXTURE_MAPPING,
            roles_catalog=frozenset({"*", "w", "role_a", "nouveau_role_admin",
                                     "ancien_role"}),
            clock=FakeClock(),
        )
        vus.append(proc.process(make_event(title="obj_updated", write="nouveau_role_admin")).status)
        vus.append(proc.process(make_event(title="obj_noop", write="w")).status)
        vus.append(proc.process(make_event(title="obj_notfound", write="w")).status)
        vus.append(proc.process(make_event(title="obj_forbidden", write="w")).status)
        vus.append(proc.process(make_event(title="obj_error", write="w")).status)
        vus.append(proc.process(make_event(title="obj_immutable", write="w")).status)
        vus.append(
            proc.process(make_event(title="obj_invalidrole", write="role_inexistant")).status
        )
        vus.append(proc.process(make_event(title="obj_rejected", app="system")).status)
        vus.append(
            proc.process(make_event(title="obj_prive", current_sharing="user")).status
        )
        # Plafond a 1, sur un processeur dedie : le premier objet est ecrit, le second
        # est ecarte. Partager le journal fait entrer ses lignes dans le meme decompte.
        proc_plafond = EventProcessor(
            params=make_params(max_objects=1),
            ctx=make_ctx(),
            rest=FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",)))),
            journal=journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        vus.append(
            proc_plafond.process(
                make_event(title="obj_ecrit", write="nouveau_role_admin")
            ).status
        )
        vus.append(
            proc_plafond.process(
                make_event(title="obj_plafond", write="nouveau_role_admin")
            ).status
        )

        proc_dryrun = EventProcessor(
            params=make_params(dryrun=True),
            ctx=make_ctx(dryrun=True),
            rest=FakeRest(),
            journal=journal,
            mapping=FIXTURE_MAPPING,
            clock=FakeClock(),
        )
        vus.append(
            proc_dryrun.process(
                make_event(title="obj_dryrun", write="nouveau_role_admin")
            ).status
        )

        self.assertEqual(sorted(set(vus)), sorted(self.DOUZE_STATUTS))
        self.assertEqual(
            len(journal.outcomes), len(vus),
            "une ligne outcome par evenement de sortie, sans exception",
        )
        self.assertEqual(
            [o["phase"] for o in journal.outcomes], ["outcome"] * len(vus)
        )

    def test_invariant_2_une_ligne_intent_par_post_tente(self):
        journal = FakeJournal()
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("ancien_role",))),
            default_post=RestResponse(200, b"{}"),
        )
        proc = processor(rest, journal=journal)
        for index in range(4):
            proc.process(
                make_event(title="objet_%d" % index, write="nouveau_role_admin")
            )
        self.assertEqual(len(journal.intents), len(rest.posts()))
        self.assertEqual(len(journal.intents), 4)

    def test_invariant_2_aucune_intent_sans_post(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(read=(), write=("w",))))
        proc = processor(rest, journal=journal)
        proc.process(make_event(write="w"))                        # noop
        self.assertEqual(journal.intents, [])
        self.assertEqual(rest.posts(), [])
        self.assertEqual(len(journal.outcomes), 1)

    def test_invariant_3_intent_sans_outcome_signale_une_interruption(self):
        """Une interruption entre la synchronisation sur disque et la reponse du POST
        laisse exactement une `intent` sans `outcome`."""

        class RestInterrompu(FakeRest):
            def post_object_acl(self, object_path, payload):
                raise KeyboardInterrupt("interruption entre fsync et reponse")

        journal = FakeJournal()
        proc = processor(RestInterrompu(), journal=journal)
        with self.assertRaises(KeyboardInterrupt):
            proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(journal.outcomes, [])

    def test_invariant_3_le_plafond_ne_bruite_pas_le_signal(self):
        """Un objet ecarte par le plafond produit un `outcome` et **aucune** `intent` :
        le controle du plafond precede toute ecriture de journal."""
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, journal=journal, params=make_params(max_objects=2))
        for index in range(4):
            proc.process(make_event(title="objet_%d" % index, write="nouveau_role_admin"))
        self.assertEqual(len(journal.intents), 2)
        self.assertEqual(len(journal.outcomes), 4)

    def test_echec_decriture_de_outcome_est_signale_sans_rien_annuler(self):
        journal = FakeJournal(fail_outcome=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal)
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("journal_outcome_failed", result.warnings)
        self.assertEqual(len(rest.posts()), 1)

    def test_le_journal_porte_before_owner_et_after_owner(self):
        """§8.2, D-22 — le journal reprend le proprietaire, sur les deux phases."""
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(owner="un_proprietaire")))
        proc = processor(rest, journal=journal)
        proc.process(make_event(owner="autre_proprietaire"))
        intent = journal.intents[0]
        self.assertEqual(intent["before_owner"], "un_proprietaire")
        self.assertEqual(intent["after_owner"], "autre_proprietaire")


class IntentFailureTest(unittest.TestCase):

    def test_echec_de_fsync_annule_le_post(self):
        journal = FakeJournal(fail_intent=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal)
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error, "journal_intent_failed")
        self.assertFalse(result.journaled)
        self.assertEqual(rest.posts(), [])
        self.assertEqual(len(journal.outcomes), 1)
        self.assertIn("before_perms_read", journal.outcomes[0])


class PlafondNonFatalTest(unittest.TestCase):
    """§4.3, D-28 — a l'atteinte du plafond la commande cesse d'ecrire **sans**
    interrompre le pipeline.

    Dans sa forme anterieure, l'atteinte du plafond levait une erreur fatale : la
    recherche s'interrompait, la sortie etait integralement perdue, et l'operateur se
    retrouvait avec une mutation partielle **et** l'aveuglement sur ce qui venait de se
    passer. Un garde-fou doit informer, pas aveugler.
    """

    def _lot(self, taille, max_objects, dryrun=False):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        journal = FakeJournal()
        proc = processor(
            rest, journal=journal,
            params=make_params(max_objects=max_objects, dryrun=dryrun),
        )
        resultats = [
            proc.process(make_event(title="objet_%02d" % i, write="nouveau_role_admin"))
            for i in range(taille)
        ]
        return proc, rest, journal, resultats

    def test_le_nombre_decritures_vaut_exactement_max_objects(self):
        proc, rest, _, _ = self._lot(taille=7, max_objects=3)
        self.assertEqual(len(rest.posts()), 3)
        self.assertEqual(proc.counter, 3)

    def test_la_sortie_reste_complete(self):
        """Un evenement de sortie par evenement d'entree, plafond ou non (§5.7)."""
        _, _, _, resultats = self._lot(taille=7, max_objects=3)
        self.assertEqual(len(resultats), 7)

    def test_les_objets_ecartes_ressortent_en_skipped_ceiling(self):
        _, _, _, resultats = self._lot(taille=7, max_objects=3)
        statuts = [r.status for r in resultats]
        self.assertEqual(statuts, ["updated"] * 3 + ["skipped_ceiling"] * 4)

    def test_un_objet_ecarte_ne_produit_ni_get_ni_post(self):
        _, rest, _, _ = self._lot(taille=7, max_objects=3)
        self.assertEqual(len(rest.gets()), 3)
        self.assertEqual(len(rest.posts()), 3)

    def test_le_compteur_dobjets_ecartes_est_tenu(self):
        proc, _, _, _ = self._lot(taille=7, max_objects=3)
        self.assertEqual(proc.skipped_ceiling, 4)

    def test_chaque_objet_ecarte_porte_sa_ligne_de_journal(self):
        _, _, journal, _ = self._lot(taille=7, max_objects=3)
        self.assertEqual(len(journal.outcomes), 7)
        ecartes = [o for o in journal.outcomes if o["status"] == "skipped_ceiling"]
        self.assertEqual(len(ecartes), 4)

    def test_lerreur_nomme_le_plafond_atteint(self):
        _, _, _, resultats = self._lot(taille=7, max_objects=3)
        self.assertEqual(resultats[-1].error, "max_objects_reached:3")

    def test_un_lot_exactement_egal_au_plafond_necarte_rien(self):
        proc, _, _, resultats = self._lot(taille=2, max_objects=2)
        self.assertEqual(proc.counter, 2)
        self.assertEqual(proc.skipped_ceiling, 0)
        self.assertEqual([r.status for r in resultats], ["updated", "updated"])

    def test_les_statuts_sans_post_ne_comptent_pas(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest, params=make_params(max_objects=1))
        for index in range(5):
            proc.process(make_event(title="objet_%d" % index, write="w"))
        self.assertEqual(proc.counter, 0)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_le_plafond_ne_se_declenche_jamais_en_simulation(self):
        """§4.3 (D-30) — la simulation n'emet aucun POST, le compteur reste a zero.

        C'est cette propriete qui rend tenable un plafond par defaut aussi bas que dix :
        elle place la friction sur l'ecriture reelle, jamais sur l'examen. Un `dryrun`
        sur cent objets qui en ecarterait quatre-vingt-dix serait un defaut.
        """
        proc, rest, _, resultats = self._lot(taille=40, max_objects=10, dryrun=True)
        self.assertEqual(len(resultats), 40)
        self.assertEqual([r.status for r in resultats], ["dryrun"] * 40)
        self.assertEqual(proc.skipped_ceiling, 0)
        self.assertEqual(proc.counter, 0)
        self.assertEqual(rest.posts(), [])

    def test_la_reprise_apres_plafond_ne_reecrit_pas_les_premiers(self):
        """§4.3 (D-30) — un lot interrompu se termine en relancant la meme recherche.

        Les objets deja ecrits ressortent `noop` par idempotence ; seuls les ecartes
        sont traites. La simulation ici porte sur le fait que la seconde passe lit
        l'etat **deja converge** des trois premiers.
        """
        deja_ecrits = {
            "/servicesNS/nobody/mon_app/saved/searches/objet_%02d" % i: RestResponse(
                200, acl_body(write=("nouveau_role_admin",))
            )
            for i in range(3)
        }
        rest = FakeRest(
            get_responses=deja_ecrits,
            default_get=RestResponse(200, acl_body(write=("ancien_role",))),
        )
        proc = processor(rest, params=make_params(max_objects=10))
        resultats = [
            proc.process(make_event(title="objet_%02d" % i, write="nouveau_role_admin"))
            for i in range(7)
        ]
        statuts = [r.status for r in resultats]
        self.assertEqual(statuts, ["noop"] * 3 + ["updated"] * 4)
        self.assertEqual(len(rest.posts()), 4)
        self.assertEqual(proc.skipped_ceiling, 0)

    def test_le_message_dit_le_plafond_et_le_nombre_decartes(self):
        message = ceiling_message(10, 32)
        self.assertIn("10", message)
        self.assertIn("32", message)
        self.assertIn("skipped_ceiling", message)


class DeduplicationTest(unittest.TestCase):
    """§10.8 : la deduplication economise le GET et le POST, jamais un evenement de
    sortie ni une ligne `outcome`."""

    def test_deux_evenements_identiques(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, journal=journal)
        premier = proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(premier.status, "updated")
        self.assertEqual(second.status, "noop")
        self.assertEqual(len(rest.gets()), 1)
        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(len(journal.outcomes), 2)

    def test_un_doublon_demandant_une_valeur_differente_produit_une_seconde_ecriture(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest)
        proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="encore_un_autre_role"))
        self.assertEqual(second.status, "updated")
        self.assertEqual(len(rest.posts()), 2)
        self.assertEqual(len(rest.gets()), 1)

    def test_un_objet_dont_le_traitement_a_echoue_nest_pas_memorise(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest)
        proc.process(make_event(write="w"))
        proc.process(make_event(write="w"))
        self.assertEqual(len(rest.gets()), 2)


class DivergenceRuntimeDisqueTest(unittest.TestCase):
    """A-2 — un `HTTP 500` de persistance ne signifie pas « rien n'a change ».

    Il signifie « rien n'a ete **persiste** ». La vue runtime de splunkd peut avoir ete
    mutee — mesure en lab — et c'est elle que voient les utilisateurs, les recherches et
    les controles d'acces jusqu'au prochain rechargement de configuration. L'objet est
    par ailleurs exclu du jeu de restauration, `editacl_rollback` ne retenant que les
    `outcome` de statut `updated`.

    La commande ne peut pas empecher la divergence : elle est produite par la
    plateforme. Elle doit la rendre visible.
    """

    def _resultat(self, code, corps=b'{"messages":[{"type":"ERROR","text":"x"}]}'):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("ancien_role",))),
            default_post=RestResponse(code, corps),
        )
        return processor(rest).process(make_event(write="nouveau_role_admin"))

    def test_un_refus_de_persistance_porte_lavertissement(self):
        resultat = self._resultat(
            500,
            b'{"messages":[{"type":"ERROR","text":"Could not flush changes to '
            b'disk"}]}',
        )
        self.assertEqual(resultat.status, "error")
        self.assertEqual(resultat.http_code, 500)
        self.assertIn(RUNTIME_DIVERGENCE_WARNING, resultat.warnings)

    def test_toute_la_classe_5xx_porte_lavertissement(self):
        """D-16 : l'avertissement porte sur tout `5xx`, pas sur le seul `500`."""
        for code in (500, 501, 502, 503, 504, 507, 599):
            with self.subTest(code=code):
                resultat = self._resultat(code)
                self.assertEqual(resultat.status, "error")
                self.assertEqual(resultat.http_code, code)
                self.assertIn(RUNTIME_DIVERGENCE_WARNING, resultat.warnings)

    def test_un_refus_qui_nest_pas_de_persistance_ne_le_porte_pas(self):
        for code in (400, 403, 404, 409):
            with self.subTest(code=code):
                resultat = self._resultat(code)
                self.assertEqual(resultat.status, "error")
                self.assertNotIn(RUNTIME_DIVERGENCE_WARNING, resultat.warnings)

    def test_une_ecriture_aboutie_ne_le_porte_pas(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        resultat = processor(rest).process(make_event(write="nouveau_role_admin"))
        self.assertEqual(resultat.status, "updated")
        self.assertNotIn(RUNTIME_DIVERGENCE_WARNING, resultat.warnings)

    def test_le_message_operateur_nomme_les_deux_faits(self):
        texte = RUNTIME_DIVERGENCE_MESSAGE.lower()
        self.assertIn("runtime", texte)
        self.assertIn("disque", texte)
        self.assertIn("editacl_rollback", texte)
        self.assertIn("rechargement de configuration", texte)

    def test_le_doublon_dun_objet_diverge_conserve_lavertissement(self):
        rest = FakeRest(
            default_get=RestResponse(200, acl_body(write=("ancien_role",))),
            default_post=RestResponse(500, b'{"messages":[]}'),
        )
        proc = processor(rest)
        proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="nouveau_role_admin"))
        self.assertIn(RUNTIME_DIVERGENCE_WARNING, second.warnings)


def rest_post_refuse():
    """Socle refusant l'ecriture, l'etat lu restant celui d'avant tentative."""
    return FakeRest(
        default_get=RestResponse(200, acl_body(write=("ancien_role",))),
        default_post=RestResponse(
            500,
            b'{"messages":[{"type":"ERROR","text":"Could not flush changes to '
            b'disk"}]}',
        ),
    )


class DeduplicationApresPostRefuseTest(unittest.TestCase):
    """A-7 — le cache n'etait peuple qu'apres un POST **abouti**."""

    def _proc(self, rest, journal, max_objects=500):
        return processor(
            rest, journal=journal, params=make_params(max_objects=max_objects)
        )

    def test_un_seul_intent_un_seul_post_apres_un_refus(self):
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="nouveau_role_admin"))
        proc.process(make_event(write="nouveau_role_admin"))

        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(len(rest.gets()), 1)
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(proc.counter, 1)

    def test_le_triplet_sid_endpoint_phase_reste_univoque(self):
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="nouveau_role_admin"))
        proc.process(make_event(write="nouveau_role_admin"))

        cles = [
            (record["sid"], record["endpoint"], record["phase"])
            for record in journal.intents
        ]
        self.assertEqual(len(set(cles)), len(cles))

    def test_le_doublon_produit_un_evenement_et_une_ligne_outcome(self):
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal)
        premier = proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="nouveau_role_admin"))

        self.assertEqual(len(journal.outcomes), 2)
        self.assertEqual(second.status, premier.status)
        self.assertEqual(second.error, premier.error)
        self.assertEqual(second.http_code, 500)
        self.assertIn("duplicate_post_suppressed", second.warnings)
        self.assertFalse(second.counted)

    def test_le_doublon_ne_ressort_jamais_updated_ni_noop(self):
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="nouveau_role_admin"))
        self.assertNotIn(second.status, ("updated", "noop"))

    def test_une_cible_differente_apres_un_refus_est_bien_retentee(self):
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal)
        proc.process(make_event(write="nouveau_role_admin"))
        proc.process(make_event(write="nouveau_role_lecture"))
        self.assertEqual(len(rest.posts()), 2)
        self.assertEqual(len(journal.intents), 2)

    def test_un_refus_ne_consomme_le_plafond_quune_fois(self):
        """Trois occurrences d'un objet refuse n'epuisent pas `max_objects=2`."""
        rest, journal = rest_post_refuse(), FakeJournal()
        proc = self._proc(rest, journal, max_objects=2)
        for _ in range(3):
            proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(proc.counter, 1)


class InternalErrorTest(unittest.TestCase):

    def test_une_exception_inattendue_devient_une_erreur_par_evenement(self):
        class RestCasse(FakeRest):
            def get_object_acl(self, object_path):
                raise RuntimeError("panne interne")

        journal = FakeJournal()
        proc = processor(RestCasse(), journal=journal)
        result = proc.process(make_event())
        self.assertEqual(result.status, "error")
        self.assertTrue(result.error.startswith("internal:RuntimeError"))
        self.assertEqual(len(journal.outcomes), 1)


if __name__ == "__main__":
    unittest.main()
