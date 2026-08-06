"""Format du journal (§8.2) et contrat d'alimentation de la macro de restauration (§8.6)."""

import json
import os
import shutil
import tempfile
import unittest

from acltools.errors import FatalJournalError
from acltools.journal import (
    JournalWriter,
    build_intent_record,
    build_outcome_record,
    dumps,
    journal_filename,
)
from acltools.merge import merge
from acltools.model import EventResult

from .helpers import FakeClock, make_ctx, make_event, state

#: Champs consommes par `editacl_rollback` (§8.6). La liste est **portee en dur** :
#: toute evolution du schema du journal ou de la macro casse ce test, ce qui est le but.
ROLLBACK_FIELDS_FROM_INTENT = (
    "sid",
    "phase",
    "endpoint",
    "before_perms_read",
    "before_perms_write",
    "before_sharing",
    "owner",
    "app",
    "title",
    "eai_type",
    "ts",
)

CTX = make_ctx(sid="1754483000.1", user="operateur", host="sh01", dryrun=False)


def result(status="updated", **kwargs):
    base = dict(
        title="Ma recherche",
        app="mon_app",
        eai_type="savedsearch",
        endpoint="/servicesNS/nobody/mon_app/saved/searches/Ma%20recherche",
        owner="nobody",
        http_code=200,
        before=state(sharing="global", read=("role_a",), write=("ancien_role",)),
        after=state(sharing="global", read=("role_a",), write=("nouveau_role_admin",)),
    )
    base.update(kwargs)
    return EventResult(status=status, **base)


class IntentRecordTest(unittest.TestCase):

    def test_champs_communs_et_specifiques(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        for field in (
            "ts", "phase", "sid", "user", "host", "dryrun", "endpoint", "app",
            "owner", "title", "eai_type",
        ):
            self.assertIn(field, record)
        for field in (
            "before_perms_read", "before_perms_write", "before_sharing",
            "after_perms_read", "after_perms_write", "after_sharing",
        ):
            self.assertIn(field, record)
        self.assertEqual(record["phase"], "intent")

    def test_intent_ne_porte_pas_status(self):
        """L'absence de `status` sur `intent` est **requise** : sinon une ligne `intent`
        pourrait valoir 1 dans le `max(_restorable)` de la macro."""
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        self.assertNotIn("status", record)

    def test_titre_journalise_non_encode(self):
        record = build_intent_record(
            CTX, result(title="Rapport/Mensuel"), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(record["title"], "Rapport/Mensuel")
        self.assertNotIn("%2F", record["title"])

    def test_aucun_nom_de_champ_ne_contient_deux_points(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        for field in record:
            self.assertNotIn(":", field)

    def test_valeurs_vides_serialisees_en_chaine_vide(self):
        record = build_intent_record(
            CTX,
            result(before=state(sharing="global", read=(), write=())),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertEqual(record["before_perms_read"], "")
        self.assertIsNot(record["before_perms_read"], None)

    def test_endpoint_sans_schema_ni_hote_ni_suffixe_acl(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        self.assertTrue(record["endpoint"].startswith("/servicesNS/"))
        self.assertNotIn("://", record["endpoint"])
        self.assertFalse(record["endpoint"].endswith("/acl"))


class OutcomeRecordTest(unittest.TestCase):

    def test_champs_propres(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(record["phase"], "outcome")
        self.assertEqual(record["status"], "updated")
        self.assertEqual(record["http_code"], 200)
        self.assertIsNone(record["error"])

    def test_updated_ne_reporte_pas_before_after_deja_portes_par_intent(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertNotIn("before_perms_read", record)

    def test_noop_dryrun_invalid_role_skipped_immutable_portent_before_after(self):
        for status in ("noop", "dryrun", "invalid_role", "skipped_immutable"):
            with self.subTest(status=status):
                record = build_outcome_record(
                    CTX,
                    result(status=status, journaled=False),
                    "2026-01-01T00:00:00.000+01:00",
                )
                self.assertIn("before_perms_read", record)
                self.assertIn("after_sharing", record)

    def test_rejet_amont_ne_porte_pas_before_after(self):
        for status in ("rejected", "not_found", "forbidden"):
            with self.subTest(status=status):
                record = build_outcome_record(
                    CTX,
                    result(status=status, before=None, after=None, http_code=404),
                    "2026-01-01T00:00:00.000+01:00",
                )
                self.assertNotIn("before_perms_read", record)

    def test_echec_de_journalisation_intent_reporte_letat_anterieur(self):
        """Sans cela l'etat anterieur serait definitivement perdu."""
        record = build_outcome_record(
            CTX,
            result(status="error", journaled=False, error="journal_intent_failed"),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertIn("before_perms_read", record)

    def test_http_code_sentinelle_zero_en_labsence_dechange(self):
        record = build_outcome_record(
            CTX,
            result(status="rejected", before=None, after=None, http_code=0),
            "2026-01-01T00:00:00.000+01:00",
        )
        self.assertEqual(record["http_code"], 0)
        self.assertIsInstance(record["http_code"], int)

    def test_error_est_le_seul_champ_pouvant_valoir_null(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        nuls = [field for field, value in record.items() if value is None]
        self.assertEqual(nuls, ["error"])


class RollbackContractTest(unittest.TestCase):
    """La macro §8.6 est le seul moyen d'annuler une operation irreversible : un champ
    manquant la rend inoperante sans erreur visible."""

    def test_intent_porte_tous_les_champs_consommes_par_la_macro(self):
        record = build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00")
        manquants = [f for f in ROLLBACK_FIELDS_FROM_INTENT if f not in record]
        self.assertEqual(manquants, [])

    def test_outcome_porte_status_et_endpoint_pour_lappariement(self):
        record = build_outcome_record(
            CTX, result(journaled=True), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertIn("status", record)
        self.assertIn("endpoint", record)
        self.assertIn("phase", record)

    def test_endpoint_identique_sur_intent_et_outcome(self):
        res = result(journaled=True)
        intent = build_intent_record(CTX, res, "2026-01-01T00:00:00.000+01:00")
        outcome = build_outcome_record(CTX, res, "2026-01-01T00:00:00.001+01:00")
        self.assertEqual(intent["endpoint"], outcome["endpoint"])

    def test_restauration_dune_permission_vide_revide_bien_lattribut(self):
        """Aller-retour complet en memoire.

        Etat initial `perms.read` vide -> ligne `intent` -> perte du champ vide a
        l'extraction JSON de l'indexation -> reinjection -> la fusion revide bien
        `perms.read` (ligne 4 de la matrice).
        """
        before = state(sharing="global", read=(), write=("ancien_role",))
        after = state(sharing="global", read=(), write=("nouveau_role_admin",))
        intent = build_intent_record(
            CTX, result(before=before, after=after), "2026-01-01T00:00:00.000+01:00"
        )
        self.assertEqual(intent["before_perms_read"], "")

        # Simulation de l'indexation : un champ JSON de valeur vide n'est pas
        # materialise, la sortie de la macro ne porte donc pas `eai:acl.perms.read`.
        sortie_macro = {
            "title": intent["title"],
            "eai:acl.app": intent["app"],
            "eai:acl.owner": intent["owner"],
            "eai:type": intent["eai_type"],
        }
        if intent["before_perms_read"]:
            sortie_macro["eai:acl.perms.read"] = intent["before_perms_read"]
        if intent["before_perms_write"]:
            sortie_macro["eai:acl.perms.write"] = intent["before_perms_write"]
        if intent["before_sharing"]:
            sortie_macro["eai:acl.sharing"] = intent["before_sharing"]
        self.assertNotIn("eai:acl.perms.read", sortie_macro)

        # Reinjection : `| editacl fields="perms.read,perms.write,sharing"`
        etat_courant = state(sharing="global", read=("role_ajoute",),
                             write=("nouveau_role_admin",))
        reinjection = merge(
            etat_courant,
            make_event(
                read=sortie_macro.get("eai:acl.perms.read"),
                write=sortie_macro.get("eai:acl.perms.write"),
                sharing=sortie_macro.get("eai:acl.sharing"),
            ),
            frozenset({"perms.read", "perms.write", "sharing"}),
        )
        self.assertIsNone(reinjection.rejection)
        self.assertEqual(reinjection.payload["perms.read"], "")
        self.assertEqual(reinjection.payload["perms.write"], "ancien_role")
        self.assertEqual(reinjection.payload["sharing"], "global")


class SerializationTest(unittest.TestCase):

    def test_ligne_json_compacte_sans_retour_a_la_ligne(self):
        line = dumps(build_intent_record(CTX, result(), "2026-01-01T00:00:00.000+01:00"))
        self.assertNotIn("\n", line)
        self.assertNotIn(", ", line)
        json.loads(line)

    def test_caracteres_non_ascii_conserves(self):
        line = dumps({"title": "Résumé"})
        self.assertIn("Résumé", line)

    def test_horodatage_avec_millisecondes_et_fuseau(self):
        from acltools.pipeline import default_clock

        stamp = default_clock()
        self.assertRegex(
            stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$"
        )


class JournalWriterTest(unittest.TestCase):
    """Un fichier par `sid`, sans rotation par taille (D-3)."""

    def setUp(self):
        self.dossier = tempfile.mkdtemp(prefix="editacl_test_")

    def tearDown(self):
        shutil.rmtree(self.dossier, ignore_errors=True)

    def test_nom_de_fichier_par_sid(self):
        self.assertEqual(
            journal_filename("1754483000.1"), "editacl_journal_1754483000.1.log"
        )

    def test_sid_assaini_pour_ne_pas_traverser_larborescence(self):
        nom = journal_filename("../../etc/passwd")
        self.assertNotIn("/", nom)
        self.assertNotIn("\\", nom)
        self.assertEqual(os.path.basename(nom), nom)
        self.assertTrue(nom.startswith("editacl_journal_"))
        self.assertTrue(nom.endswith(".log"))

    def test_sid_vide_donne_un_nom_exploitable(self):
        self.assertEqual(journal_filename(""), "editacl_journal_unknown.log")

    def test_ecriture_et_relecture(self):
        chemin = os.path.join(self.dossier, journal_filename("sid_de_test"))
        writer = JournalWriter(chemin)
        self.assertTrue(writer.write_intent({"phase": "intent", "a": 1}))
        self.assertTrue(writer.write_outcome({"phase": "outcome", "b": 2}))
        writer.close()
        with open(chemin, encoding="utf-8") as handle:
            lignes = [json.loads(l) for l in handle if l.strip()]
        self.assertEqual([l["phase"] for l in lignes], ["intent", "outcome"])

    def test_ouverture_impossible_est_fatale(self):
        chemin = os.path.join(self.dossier, "sous-dossier-inexistant", "j.log")
        with self.assertRaises(FatalJournalError):
            JournalWriter(chemin)

    def test_horloge_de_test_deterministe(self):
        clock = FakeClock()
        self.assertNotEqual(clock(), clock())


if __name__ == "__main__":
    unittest.main()
