"""Client REST vers splunkd. **Seul module du paquet autorise a ouvrir une socket.**

Bibliotheque standard uniquement : aucune dependance a `requests`, ni a la version
du SDK de commande de recherche livree par la plateforme.

Aucune exception reseau ne remonte : un echec de transport devient une reponse de
statut `0`. Le noyau n'a ainsi qu'un seul chemin de traitement.
"""

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

#: Constantes de module, **pas** des parametres de commande : le §4.1 fige la surface
#: parametrique de `editacl`.
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60

#: Une seule reprise, apres temporisation, sur `5xx` **au GET** (§5.3).
#: **Aucune reprise sur le POST** : elle ne distinguerait pas « le premier POST n'est
#: pas parti » de « le premier POST a abouti et la reponse s'est perdue ». Le §8.7
#: traite ce cas par controle croise avec le journal d'acces de splunkd, ce qui suppose
#: de ne pas multiplier les tentatives.
RETRY_DELAY_SECONDS = 2

#: Marqueurs d'un echec de transport imputable a TLS, cherches en minuscules dans le
#: message normalise de `RestResponse.error`.
#:
#: Le classement vit ici, avec le code qui **produit** ce message : separer les deux
#: garantirait leur divergence au premier changement de format.
TLS_FAILURE_MARKERS = (
    "sslcertverificationerror",
    "sslerror",
    "certificate_verify_failed",
    "certificate verify failed",
    "self signed certificate",
    "self-signed certificate",
    "unable to get local issuer certificate",
    "certificate has expired",
    "hostname mismatch",
    "doesn't match either of",
)

#: Message de remediation d'un echec TLS. Il **designe le parametre** : sans cela,
#: l'operateur ne voit qu'un `HTTP 0` sur un appel de preflight et n'a aucune raison de
#: soupconner le certificat. Le cas nominal est un socle a certificat auto-signe, sur
#: lequel `verify_ssl` vaut `true` par defaut (§2.2).
TLS_REMEDIATION = (
    "echec de la verification TLS du certificat de splunkd. Socle a certificat "
    "auto-signe : creer le fichier local/editacl.conf de l'app SA-acl-tools avec "
    "[editacl] puis verify_ssl = false, ou installer le CA de la plateforme dans "
    "$SPLUNK_HOME/etc/auth/cacert.pem."
)


def is_tls_failure(response):
    """Vrai si `response` est un echec de **transport** imputable a TLS.

    Un echec TLS se presente au noyau comme n'importe quel autre echec de transport —
    `status = 0` — donc comme un `HTTP 0` indifferencie. C'est ce que cette fonction
    permet de lever.
    """
    if response is None or getattr(response, "status", None) != 0:
        return False
    marker = str(getattr(response, "error", "") or "").lower()
    return any(motif in marker for motif in TLS_FAILURE_MARKERS)


class RestResponse(object):
    """`(status, body, error)`. `status = 0` signale un echec de transport."""

    __slots__ = ("status", "body", "error")

    def __init__(self, status, body=b"", error=None):
        self.status = int(status)
        self.body = body or b""
        self.error = error

    @property
    def ok(self):
        return 200 <= self.status < 300

    def text(self, limit=512):
        try:
            decoded = self.body.decode("utf-8", "replace")
        except Exception:                                    # pragma: no cover
            decoded = repr(self.body)
        return decoded[:limit]

    def __repr__(self):                                      # pragma: no cover
        return "RestResponse(status=%d, error=%r)" % (self.status, self.error)


def build_ssl_context(verify_ssl=True, ca_file=None):
    """Contexte TLS. Verification activee par defaut, avec le CA bundle de la plateforme."""
    if not verify_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


class RestClient(object):
    """Client HTTP minimal vers `splunkd_uri`.

    La cle de session ne figure ni dans un log, ni dans un message d'erreur, ni dans
    une URL : elle n'est portee que par l'en-tete `Authorization`.
    """

    def __init__(self, base_uri, session_key, verify_ssl=True, ca_file=None):
        self._base = str(base_uri).rstrip("/")
        self._session_key = session_key
        self._context = build_ssl_context(verify_ssl, ca_file)

    # -- transport --------------------------------------------------------- #

    def _request(self, method, path, params=None, payload=None):
        url = self._base + path
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        data = None
        headers = {"Authorization": "Splunk %s" % self._session_key}
        if payload is not None:
            data = urllib.parse.urlencode(payload).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(
                request, context=self._context, timeout=READ_TIMEOUT
            ) as response:
                return RestResponse(response.status, response.read())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:                                # pragma: no cover
                body = b""
            return RestResponse(exc.code, body)
        except Exception as exc:
            # Echec de transport : jamais d'exception vers le noyau. Le message est
            # normalise et ne peut pas contenir la cle de session, qui n'apparait que
            # dans un en-tete.
            return RestResponse(0, b"", "transport:%s: %s" % (type(exc).__name__, exc))

    # -- port REST --------------------------------------------------------- #

    def get_object_acl(self, object_path):
        """`GET <object_path>?output_mode=json&f=eai:acl*` — une reprise sur `5xx`."""
        params = {"output_mode": "json", "f": "eai:acl*"}
        response = self._request("GET", object_path, params=params)
        if 500 <= response.status < 600:
            time.sleep(RETRY_DELAY_SECONDS)
            response = self._request("GET", object_path, params=params)
        return response

    def post_object_acl(self, object_path, payload):
        """`POST <object_path>/acl`, corps `application/x-www-form-urlencoded`.

        Aucune reprise, volontairement.
        """
        body = dict(payload)
        body["output_mode"] = "json"
        return self._request("POST", object_path + "/acl", payload=body)

    def get_json(self, path, params=None):
        """Appel de preflight (contexte, roles, apps, tache de recherche)."""
        merged = {"output_mode": "json"}
        if params:
            merged.update(params)
        return self._request("GET", path, params=merged)
