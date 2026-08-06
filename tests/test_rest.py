"""Client REST — reprises et non-fuite de la cle de session.

Aucune socket n'est ouverte : la methode de transport est substituee. Ce fichier
verifie la **politique** de reprise, pas la pile reseau, qui releve du lab.
"""

import unittest

from acltools import rest as rest_module
from acltools.rest import (
    TLS_REMEDIATION,
    RestClient,
    RestResponse,
    build_ssl_context,
    is_tls_failure,
)

CLE_DE_SESSION = "cle-de-session-factice-0123456789"


class RecordingClient(RestClient):
    """Client dont le transport est remplace par une file de reponses scriptees."""

    def __init__(self, reponses, **kwargs):
        super(RecordingClient, self).__init__(
            "https://base.invalid:0", CLE_DE_SESSION, **kwargs
        )
        self.reponses = list(reponses)
        self.appels = []

    def _request(self, method, path, params=None, payload=None):
        self.appels.append((method, path, params, payload))
        if self.reponses:
            return self.reponses.pop(0)
        return RestResponse(200, b"{}")


class RetryPolicyTest(unittest.TestCase):

    def setUp(self):
        self._sleep = rest_module.time.sleep
        rest_module.time.sleep = lambda _seconds: None

    def tearDown(self):
        rest_module.time.sleep = self._sleep

    def test_une_seule_reprise_sur_get_5xx(self):
        client = RecordingClient(
            [RestResponse(503, b"indisponible"), RestResponse(200, b"{}")]
        )
        response = client.get_object_acl("/servicesNS/nobody/mon_app/saved/searches/o")
        self.assertEqual(response.status, 200)
        self.assertEqual(len(client.appels), 2)

    def test_pas_de_troisieme_tentative_sur_get(self):
        client = RecordingClient(
            [RestResponse(503, b"x"), RestResponse(503, b"x"), RestResponse(200, b"{}")]
        )
        response = client.get_object_acl("/servicesNS/nobody/mon_app/saved/searches/o")
        self.assertEqual(response.status, 503)
        self.assertEqual(len(client.appels), 2)

    def test_pas_de_reprise_sur_get_4xx(self):
        client = RecordingClient([RestResponse(404, b"{}")])
        client.get_object_acl("/servicesNS/nobody/mon_app/saved/searches/o")
        self.assertEqual(len(client.appels), 1)

    def test_aucune_reprise_sur_le_post(self):
        """Une reprise ne distinguerait pas « le POST n'est pas parti » de « le POST a
        abouti et la reponse s'est perdue » — le §8.7 traite ce cas par controle
        croise, ce qui suppose de ne pas multiplier les tentatives."""
        client = RecordingClient([RestResponse(503, b"indisponible")])
        response = client.post_object_acl(
            "/servicesNS/nobody/mon_app/saved/searches/o", {"owner": "nobody"}
        )
        self.assertEqual(response.status, 503)
        self.assertEqual(len(client.appels), 1)

    def test_le_post_cible_le_suffixe_acl(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.post_object_acl("/servicesNS/nobody/mon_app/saved/searches/o", {})
        methode, chemin, _params, _payload = client.appels[0]
        self.assertEqual(methode, "POST")
        self.assertEqual(chemin, "/servicesNS/nobody/mon_app/saved/searches/o/acl")

    def test_le_get_ne_porte_pas_le_suffixe_acl(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.get_object_acl("/servicesNS/nobody/mon_app/saved/searches/o")
        _methode, chemin, params, _payload = client.appels[0]
        self.assertFalse(chemin.endswith("/acl"))
        self.assertEqual(params["f"], "eai:acl*")
        self.assertEqual(params["output_mode"], "json")


class SessionKeyTest(unittest.TestCase):
    """La cle de session ne figure ni dans un log, ni dans un message d'erreur, ni dans
    une URL : elle n'est portee que par l'en-tete `Authorization`."""

    def test_la_cle_napparait_pas_dans_les_parametres_de_requete(self):
        client = RecordingClient([RestResponse(200, b"{}")])
        client.get_object_acl("/servicesNS/nobody/mon_app/saved/searches/o")
        _methode, chemin, params, payload = client.appels[0]
        self.assertNotIn(CLE_DE_SESSION, chemin)
        self.assertNotIn(CLE_DE_SESSION, repr(params))
        self.assertNotIn(CLE_DE_SESSION, repr(payload))

    def test_la_cle_napparait_pas_dans_la_representation_dune_reponse(self):
        response = RestResponse(0, b"", "transport:TimeoutError: expire")
        self.assertNotIn(CLE_DE_SESSION, repr(response))
        self.assertNotIn(CLE_DE_SESSION, response.text())

    def test_la_cle_napparait_pas_dans_la_representation_du_client(self):
        client = RecordingClient([])
        self.assertNotIn(CLE_DE_SESSION, repr(client))


class ResponseTest(unittest.TestCase):

    def test_sentinelle_zero_pour_un_echec_de_transport(self):
        response = RestResponse(0, b"", "transport:URLError: injoignable")
        self.assertEqual(response.status, 0)
        self.assertFalse(response.ok)

    def test_corps_tronque_a_512_caracteres(self):
        response = RestResponse(500, b"x" * 2000)
        self.assertEqual(len(response.text()), 512)


class SslContextTest(unittest.TestCase):

    def test_verification_activee_par_defaut(self):
        import ssl

        context = build_ssl_context(verify_ssl=True)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_verification_desactivable_pour_certificat_auto_signe(self):
        import ssl

        context = build_ssl_context(verify_ssl=False)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)


class TlsFailureTest(unittest.TestCase):
    """Un echec TLS arrive au noyau comme n'importe quel echec de transport — un
    `status = 0` indifferencie. Ce classement est ce qui permet a `preflight` d'en
    faire un message qui designe la cause et le parametre."""

    def test_le_message_reellement_produit_par_le_transport_est_classe(self):
        # Message construit exactement comme `RestClient._request` le construit sur une
        # levee de `ssl.SSLCertVerificationError`, exception reelle d'un socle a
        # certificat auto-signe.
        import ssl

        exc = ssl.SSLCertVerificationError(
            1,
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed "
            "certificate in certificate chain (_ssl.c:1006)",
        )
        response = RestResponse(
            0, b"", "transport:%s: %s" % (type(exc).__name__, exc)
        )
        self.assertTrue(is_tls_failure(response))

    def test_un_echec_de_transport_non_tls_nest_pas_classe_tls(self):
        response = RestResponse(
            0, b"", "transport:ConnectionRefusedError: [Errno 111] Connection refused"
        )
        self.assertFalse(is_tls_failure(response))

    def test_une_reponse_http_nest_jamais_un_echec_tls(self):
        # Un 403 n'est pas un echec de transport : le tunnel a bien ete etabli.
        self.assertFalse(is_tls_failure(RestResponse(403, b"forbidden")))
        self.assertFalse(is_tls_failure(RestResponse(200, b"{}")))
        self.assertFalse(is_tls_failure(None))

    def test_la_remediation_designe_le_parametre_et_son_fichier(self):
        # C'est tout l'objet de la correction : un message qui ne nomme pas
        # `verify_ssl` ni `local/editacl.conf` laisse l'operateur chercher du cote des
        # droits, sur un endpoint d'authentification.
        self.assertIn("verify_ssl", TLS_REMEDIATION)
        self.assertIn("local/editacl.conf", TLS_REMEDIATION)
        self.assertIn("TLS", TLS_REMEDIATION)


if __name__ == "__main__":
    unittest.main()
