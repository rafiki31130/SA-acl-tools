"""Preflight (§5.1, §4.2) : parametres, habilitation, temps reel, referentiel de roles."""

import json
import unittest

from acltools.errors import FatalCapabilityError, FatalConfigError
from acltools.model import DEFAULT_FIELD_NAMES
from acltools.preflight import (
    DEFAULT_MAX_OBJECTS,
    DRYRUN_WARNING,
    AppStateCache,
    check_capability,
    check_realtime,
    load_roles_catalog,
    resolve_server_name,
    validate_params,
)
from acltools.rest import RestResponse

from .helpers import FakeRest


def body(content):
    return json.dumps({"entry": [{"name": "context", "content": content}]}).encode(
        "utf-8"
    )


class ValidateParamsTest(unittest.TestCase):

    def test_defauts_du_cahier_des_charges(self):
        params = validate_params()
        self.assertEqual(params.names, DEFAULT_FIELD_NAMES)
        self.assertTrue(params.dryrun)
        self.assertTrue(params.validate_roles)
        self.assertTrue(params.journal)
        self.assertEqual(params.max_objects, 10)

    def test_le_plafond_par_defaut_vaut_dix(self):
        """D-30 — et non cinq cents.

        Un plafond de cinq cents laissait passer sans un mot des operations de plusieurs
        centaines d'objets. Dix laisse passer la correction ponctuelle et fait de la
        levee du plafond un acte conscient.
        """
        self.assertEqual(DEFAULT_MAX_OBJECTS, 10)
        self.assertEqual(validate_params().max_objects, 10)

    def test_defauts_de_nommage_conformes_au_cahier_des_charges(self):
        """§3.1 et §3.3 : les defauts sont la nomenclature native, ce qui rend le cas
        nominal implicite — l'operateur qui l'emploie n'ecrit aucun parametre."""
        names = validate_params().names
        self.assertEqual(names.title, "title")
        self.assertEqual(names.app, "eai:acl.app")
        self.assertEqual(names.id, "id")
        self.assertEqual(names.type, "eai:type")
        self.assertEqual(names.sharing, "eai:acl.sharing")
        self.assertEqual(names.new_perms_read, "eai:acl.perms.read")
        self.assertEqual(names.new_perms_write, "eai:acl.perms.write")
        self.assertEqual(names.new_sharing, "eai:acl.sharing")
        self.assertEqual(names.new_owner, "eai:acl.owner")

    def test_un_nom_de_champ_renomme_est_repris(self):
        params = validate_params(
            names_raw={"type": "object_type", "new_perms_write": " write "}
        )
        self.assertEqual(params.names.type, "object_type")
        self.assertEqual(params.names.new_perms_write, "write")
        self.assertEqual(params.names.title, "title")

    def test_un_nom_de_champ_vide_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            validate_params(names_raw={"title": "   "})

    def test_une_liste_de_champs_est_une_erreur_fatale(self):
        """Le parametre `fields` de la v1 n'existe plus : chaque parametre nomme UN
        champ. Refuser la virgule attrape l'operateur qui raisonne encore en v1 et
        supprime par construction le piege de quotation du §4.4."""
        with self.assertRaises(FatalConfigError) as leve:
            validate_params(names_raw={"new_perms_read": "perms.read,perms.write"})
        self.assertIn("fields", str(leve.exception))

    def test_le_parametre_fields_nexiste_plus(self):
        """`validate_params` ne l'accepte plus, meme sous son ancien nom d'appel."""
        with self.assertRaises(TypeError):
            validate_params(fields_raw="perms.read,perms.write")

    def test_max_objects_non_entier_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            validate_params(max_objects="beaucoup")

    def test_max_objects_nul_ou_negatif_est_une_erreur_fatale(self):
        for valeur in (0, -1, "0", "-5"):
            with self.subTest(valeur=valeur):
                with self.assertRaises(FatalConfigError):
                    validate_params(max_objects=valeur)

    def test_booleen_invalide_est_une_erreur_fatale(self):
        with self.assertRaises(FatalConfigError):
            validate_params(dryrun="peut-etre")

    def test_avertissement_si_ecriture_reelle_sans_max_objects_explicite(self):
        params = validate_params(dryrun=False, max_objects_explicit=False)
        self.assertTrue(params.warnings)
        self.assertIn("max_objects", params.warnings[0])

    def test_pas_davertissement_si_max_objects_explicite(self):
        params = validate_params(dryrun=False, max_objects=10, max_objects_explicit=True)
        self.assertEqual(params.warnings, ())

    def test_le_plafond_par_defaut_nest_pas_signale_en_simulation(self):
        """La simulation n'ecrit pas : le rappel du plafond n'a pas d'objet.

        Ce test disait auparavant qu'une execution en simulation n'emettait AUCUN
        avertissement. C'etait exact, et c'etait le defaut : le parametre le plus
        consequent de la commande etait le seul dont l'etat par defaut ne se signalait
        nulle part. Ce qui reste vrai, et que ce test continue de tenir, c'est que le
        rappel du plafond ne se declenche pas la ou aucune ecriture n'est prevue.
        """
        params = validate_params(dryrun=True, max_objects_explicit=False)
        self.assertEqual(
            [w for w in params.warnings if "max_objects" in w], []
        )


class AvertissementDeSimulationTest(unittest.TestCase):
    """La simulation est l'etat par defaut, et elle etait muette.

    Une execution en simulation rend une table de resultats pleine, exactement comme
    une execution qui a tout ecrit ; seule la colonne `acl_status` les distingue. Sans
    rappel en tete d'execution, l'operateur qui croit avoir applique ses modifications
    n'a aucun signal contraire.

    L'avertissement est porte par `Params.warnings`, donc emis **une fois par
    execution** par l'adaptateur, jamais par evenement — cf.
    `tests/test_editacl_adapter.py`.
    """

    def test_la_simulation_est_signalee(self):
        params = validate_params(dryrun=True)
        self.assertIn(DRYRUN_WARNING, params.warnings)

    def test_la_simulation_par_defaut_est_signalee(self):
        """Le cas reel : l'operateur n'a pas ecrit `dryrun` du tout."""
        params = validate_params()
        self.assertIn(DRYRUN_WARNING, params.warnings)

    def test_le_message_dit_quaucune_ecriture_naura_lieu(self):
        self.assertIn("AUCUNE", DRYRUN_WARNING)
        self.assertIn("ecrite", DRYRUN_WARNING)

    def test_le_message_dit_comment_pousser_reellement(self):
        self.assertIn("dryrun=false", DRYRUN_WARNING)

    def test_le_message_est_en_tete_des_avertissements(self):
        """Il precede les autres : c'est le cadre de lecture de tout ce qui suit."""
        params = validate_params(dryrun=True)
        self.assertEqual(params.warnings[0], DRYRUN_WARNING)

    def test_aucun_avertissement_de_simulation_en_ecriture_reelle(self):
        for explicite in (True, False):
            with self.subTest(max_objects_explicit=explicite):
                params = validate_params(
                    dryrun=False, max_objects=10, max_objects_explicit=explicite
                )
                self.assertNotIn(DRYRUN_WARNING, params.warnings)

    def test_le_message_napparait_quune_fois_dans_le_jeu(self):
        params = validate_params(dryrun=True)
        self.assertEqual(list(params.warnings).count(DRYRUN_WARNING), 1)

    def test_option_non_renseignee_retombe_sur_le_defaut(self):
        """Le SDK expose une option absente de la ligne de commande comme `None`, pas
        comme sa valeur par defaut : la retombee est portee ici, pas dans l'enveloppe."""
        params = validate_params(
            names_raw=None, dryrun=None, validate_roles=None, journal=None,
            max_objects=None,
        )
        self.assertEqual(params.names, DEFAULT_FIELD_NAMES)
        self.assertTrue(params.dryrun)
        self.assertTrue(params.validate_roles)
        self.assertTrue(params.journal)
        self.assertEqual(params.max_objects, 10)

    def test_booleens_acceptes_sous_forme_de_chaine(self):
        params = validate_params(dryrun="f", journal="t", validate_roles="false")
        self.assertFalse(params.dryrun)
        self.assertTrue(params.journal)
        self.assertFalse(params.validate_roles)


class CapabilityTest(unittest.TestCase):
    """La mesure 6 reduit le controle a un test d'appartenance : `capabilities` est
    l'ensemble effectif aplati, heritage `imported_roles` compris."""

    PATH = "/services/authentication/current-context"

    def test_capability_presente(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    200,
                    body(
                        {
                            "username": "operateur",
                            "roles": ["un_role"],
                            "capabilities": ["search", "edit_acl_bulk"],
                        }
                    ),
                )
            }
        )
        check_capability(rest)

    def test_capability_absente_est_fatale(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    200,
                    body({"roles": ["un_role"], "capabilities": ["search"]}),
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        self.assertIn("edit_acl_bulk", str(raised.exception))
        self.assertIn("un_role", str(raised.exception))

    def test_reponse_inexploitable_est_fatale(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(500, b"boum")})
        with self.assertRaises(FatalCapabilityError):
            check_capability(rest)

    def test_structure_inattendue_est_fatale(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(200, b'{"entry":[]}')})
        with self.assertRaises(FatalCapabilityError):
            check_capability(rest)

    def test_un_echec_tls_designe_TLS_et_le_parametre_verify_ssl(self):
        """`verify_ssl=true` sur un socle a certificat auto-signe echoue **ici**, sur le
        premier appel REST de l'execution. Le message doit nommer la cause et le
        parametre : sans cela l'operateur lit « HTTP 0 » sur un endpoint
        d'authentification et cherche du cote des droits."""
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    0,
                    b"",
                    "transport:SSLCertVerificationError: [SSL: "
                    "CERTIFICATE_VERIFY_FAILED] certificate verify failed: self "
                    "signed certificate in certificate chain (_ssl.c:1006)",
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        message = str(raised.exception)
        self.assertIn("TLS", message)
        self.assertIn("verify_ssl", message)
        self.assertIn("local/editacl.conf", message)

    def test_un_echec_de_transport_non_tls_ne_parle_pas_de_certificat(self):
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(
                    0, b"", "transport:ConnectionRefusedError: Connection refused"
                )
            }
        )
        with self.assertRaises(FatalCapabilityError) as raised:
            check_capability(rest)
        message = str(raised.exception)
        self.assertNotIn("verify_ssl", message)
        self.assertIn("Connection refused", message)

    def test_aucun_parcours_de_la_hierarchie_de_roles(self):
        """Un seul appel REST : `authorization/roles` n'est pas sollicite."""
        rest = FakeRest(
            json_responses={
                self.PATH: RestResponse(200, body({"capabilities": ["edit_acl_bulk"]}))
            }
        )
        check_capability(rest)
        self.assertEqual(len(rest.calls), 1)


class RealtimeTest(unittest.TestCase):

    PATH = "/services/search/jobs/sid_de_test"

    def _rest(self, content):
        return FakeRest(json_responses={self.PATH: RestResponse(200, body(content))})

    def test_temps_reel_detecte_est_fatal(self):
        with self.assertRaises(FatalCapabilityError):
            check_realtime(self._rest({"isRealTimeSearch": True}), "sid_de_test")

    def test_recherche_historique(self):
        self.assertEqual(
            check_realtime(self._rest({"isRealTimeSearch": False}), "sid_de_test"),
            "batch",
        )

    def test_repli_sur_les_bornes_temporelles(self):
        with self.assertRaises(FatalCapabilityError):
            check_realtime(
                self._rest({"earliest_time": "rt-5m", "latest_time": "rt"}),
                "sid_de_test",
            )

    def test_bornes_temporelles_historiques(self):
        self.assertEqual(
            check_realtime(
                self._rest({"earliest_time": "-24h", "latest_time": "now"}),
                "sid_de_test",
            ),
            "batch",
        )

    def test_detection_impossible_ne_leve_pas(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(404, b"{}")})
        self.assertEqual(check_realtime(rest, "sid_de_test"), "unknown")

    def test_sid_absent(self):
        self.assertEqual(check_realtime(FakeRest(), ""), "unknown")


class RolesCatalogTest(unittest.TestCase):

    PATH = "/services/authorization/roles"

    def test_referentiel_charge_avec_letoile(self):
        document = json.dumps(
            {"entry": [{"name": "role_a"}, {"name": "role_b"}]}
        ).encode("utf-8")
        rest = FakeRest(json_responses={self.PATH: RestResponse(200, document)})
        catalog = load_roles_catalog(rest)
        self.assertEqual(catalog, frozenset({"role_a", "role_b", "*"}))

    def test_letoile_est_presente_meme_si_lappel_echoue(self):
        rest = FakeRest(json_responses={self.PATH: RestResponse(500, b"")})
        self.assertIn("*", load_roles_catalog(rest))


class ServerNameTest(unittest.TestCase):

    def test_server_name_lu(self):
        document = json.dumps(
            {"entry": [{"name": "server-info", "content": {"serverName": "sh01"}}]}
        ).encode("utf-8")
        rest = FakeRest(
            json_responses={"/services/server/info": RestResponse(200, document)}
        )
        self.assertEqual(resolve_server_name(rest), "sh01")

    def test_indisponible_donne_une_chaine_vide(self):
        rest = FakeRest(
            json_responses={"/services/server/info": RestResponse(503, b"")}
        )
        self.assertEqual(resolve_server_name(rest), "")


class AppStateCacheTest(unittest.TestCase):
    """§10.5 : un appel par app **distincte** sur l'execution."""

    def _rest(self, disabled):
        document = json.dumps(
            {"entry": [{"name": "mon_app", "content": {"disabled": disabled}}]}
        ).encode("utf-8")
        return FakeRest(
            json_responses={"/services/apps/local/mon_app": RestResponse(200, document)}
        )

    def test_app_desactivee(self):
        cache = AppStateCache(self._rest(True))
        self.assertTrue(cache.is_app_disabled("mon_app"))

    def test_app_active(self):
        cache = AppStateCache(self._rest(False))
        self.assertFalse(cache.is_app_disabled("mon_app"))

    def test_memoisation_par_app(self):
        rest = self._rest(True)
        cache = AppStateCache(rest)
        for _ in range(5):
            cache.is_app_disabled("mon_app")
        self.assertEqual(len(rest.calls), 1)


if __name__ == "__main__":
    unittest.main()
