"""Machine a etats, invariants de journal (§8.2), plafond (§4.3) et deduplication (§10.8)."""

import unittest

from acltools.errors import MaxObjectsReached
from acltools.pipeline import EventProcessor
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
        for champ in ("title", "app", "owner"):
            with self.subTest(champ=champ):
                result = processor().process(make_event(**{champ: ""}))
                self.assertEqual(result.status, "rejected")
                self.assertTrue(result.error.startswith("missing_field:"))

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
        proc = processor(params=make_params(fields=("sharing",)))
        result = proc.process(make_event(sharing=None))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.error, "sharing_empty_not_allowed")

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
            params=make_params(fields=("perms.write",), validate_roles=True),
            roles=frozenset({"*", "role_mort_absent", "nouveau_role_admin"}),
        )
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("stale_role_preserved:role_mort", result.warnings)


class WarningTest(unittest.TestCase):

    def test_sharing_change(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(sharing="app")))
        proc = processor(rest, params=make_params(fields=("sharing",)))
        result = proc.process(make_event(sharing="global"))
        self.assertIn("sharing_change", result.warnings)

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

    NEUF_STATUTS = (
        "updated", "noop", "dryrun", "rejected", "not_found", "forbidden",
        "invalid_role", "skipped_immutable", "error",
    )

    def test_invariant_1_une_ligne_outcome_par_evenement_de_sortie_neuf_statuts(self):
        journal = FakeJournal()
        vus = []

        chemin = lambda titre: (
            "/servicesNS/nobody/mon_app/saved/searches/" + titre.replace(" ", "%20")
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
            params=make_params(fields=("perms.write",), validate_roles=True),
            ctx=make_ctx(),
            rest=rest,
            journal=journal,
            mapping=FIXTURE_MAPPING,
            roles_catalog=frozenset({"*", "w", "nouveau_role_admin", "ancien_role"}),
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

        proc_dryrun = EventProcessor(
            params=make_params(fields=("perms.write",), dryrun=True),
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

        self.assertEqual(sorted(set(vus)), sorted(self.NEUF_STATUTS))
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
        proc = processor(rest, journal=journal, params=make_params(fields=("perms.write",)))
        for index in range(4):
            proc.process(
                make_event(title="objet_%d" % index, write="nouveau_role_admin")
            )
        self.assertEqual(len(journal.intents), len(rest.posts()))
        self.assertEqual(len(journal.intents), 4)

    def test_invariant_2_aucune_intent_sans_post(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(read=(), write=("w",))))
        proc = processor(rest, journal=journal, params=make_params(fields=("perms.write",)))
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
        proc = processor(
            RestInterrompu(), journal=journal, params=make_params(fields=("perms.write",))
        )
        with self.assertRaises(KeyboardInterrupt):
            proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(len(journal.intents), 1)
        self.assertEqual(journal.outcomes, [])

    def test_invariant_3_le_cas_nominal_du_plafond_ne_bruite_pas_le_signal(self):
        """L'evenement qui declenche `max_objects` ne produit **ni** `intent` **ni**
        `outcome` : le controle du plafond precede l'ecriture du journal."""
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(
            rest, journal=journal,
            params=make_params(fields=("perms.write",), max_objects=2),
        )
        for index in range(2):
            proc.process(make_event(title="objet_%d" % index, write="nouveau_role_admin"))
        with self.assertRaises(MaxObjectsReached):
            proc.process(make_event(title="objet_2", write="nouveau_role_admin"))
        self.assertEqual(len(journal.intents), 2)
        self.assertEqual(len(journal.outcomes), 2)

    def test_echec_decriture_de_outcome_est_signale_sans_rien_annuler(self):
        journal = FakeJournal(fail_outcome=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal, params=make_params(fields=("perms.write",)))
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "updated")
        self.assertIn("journal_outcome_failed", result.warnings)
        self.assertEqual(len(rest.posts()), 1)


class IntentFailureTest(unittest.TestCase):

    def test_echec_de_fsync_annule_le_post(self):
        journal = FakeJournal(fail_intent=True)
        rest = FakeRest()
        proc = processor(rest, journal=journal, params=make_params(fields=("perms.write",)))
        result = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error, "journal_intent_failed")
        self.assertFalse(result.journaled)
        self.assertEqual(rest.posts(), [])
        self.assertEqual(len(journal.outcomes), 1)
        self.assertIn("before_perms_read", journal.outcomes[0])


class MaxObjectsTest(unittest.TestCase):
    """§4.3 : portillon avant ecriture, pas de pre-condition sur le lot."""

    def test_le_nombre_decritures_vaut_exactement_max_objects(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, params=make_params(fields=("perms.write",), max_objects=3))
        for index in range(3):
            proc.process(make_event(title="objet_%d" % index, write="nouveau_role_admin"))
        with self.assertRaises(MaxObjectsReached):
            proc.process(make_event(title="objet_3", write="nouveau_role_admin"))
        self.assertEqual(len(rest.posts()), 3)
        self.assertEqual(proc.counter, 3)

    def test_un_lot_exactement_egal_au_plafond_ne_leve_pas(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, params=make_params(fields=("perms.write",), max_objects=2))
        for index in range(2):
            proc.process(make_event(title="objet_%d" % index, write="nouveau_role_admin"))
        self.assertEqual(proc.counter, 2)

    def test_les_statuts_sans_post_ne_comptent_pas(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest, params=make_params(fields=("perms.write",), max_objects=1))
        for index in range(5):
            proc.process(make_event(title="objet_%d" % index, write="w"))
        self.assertEqual(proc.counter, 0)


class DeduplicationTest(unittest.TestCase):
    """§10.8 : la deduplication economise le GET et le POST, jamais un evenement de
    sortie ni une ligne `outcome`."""

    def test_deux_evenements_identiques(self):
        journal = FakeJournal()
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, journal=journal, params=make_params(fields=("perms.write",)))
        premier = proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="nouveau_role_admin"))
        self.assertEqual(premier.status, "updated")
        self.assertEqual(second.status, "noop")
        self.assertEqual(len(rest.gets()), 1)
        self.assertEqual(len(rest.posts()), 1)
        self.assertEqual(len(journal.outcomes), 2)

    def test_un_doublon_demandant_une_valeur_differente_produit_une_seconde_ecriture(self):
        rest = FakeRest(default_get=RestResponse(200, acl_body(write=("ancien_role",))))
        proc = processor(rest, params=make_params(fields=("perms.write",)))
        proc.process(make_event(write="nouveau_role_admin"))
        second = proc.process(make_event(write="encore_un_autre_role"))
        self.assertEqual(second.status, "updated")
        self.assertEqual(len(rest.posts()), 2)
        self.assertEqual(len(rest.gets()), 1)

    def test_un_objet_dont_le_traitement_a_echoue_nest_pas_memorise(self):
        rest = FakeRest(default_get=RestResponse(404, b"{}"))
        proc = processor(rest, params=make_params(fields=("perms.write",)))
        proc.process(make_event(write="w"))
        proc.process(make_event(write="w"))
        self.assertEqual(len(rest.gets()), 2)


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
