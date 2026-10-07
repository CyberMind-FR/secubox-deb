# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: client de l'API Freebox OS
CyberMind — https://cybermind.fr

Autorisation unique (le propriétaire valide SUR la Freebox), puis session par défi HMAC-SHA1 (jeton d'application + défi). Le transport
est injecté : les tests ne touchent aucun réseau. Les erreurs sont traduites en messages clairs, sans écho des détails techniques ni
du jeton.
"""
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request

APP_ID = "fr.cybermind.secubox"
APP_NOM = "SecuBox"
HOTE_DEFAUT = "http://mafreebox.freebox.fr"
DELAI_S = 10

_CHEMIN_OK = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,120}$")   # « : » et majuscules : identifiants de bail DHCP (adresse MAC)
_ETATS = {"pending": "attente", "granted": "accordee", "denied": "refusee", "timeout": "expiree", "unknown": "inconnue"}


class ErreurFreebox(Exception):
    """Erreur lisible par l'utilisateur."""


class Injoignable(ErreurFreebox):
    pass


class NonAutorise(ErreurFreebox):
    pass


class DroitManquant(ErreurFreebox):
    pass


def transport_http(methode, url, entetes, corps, delai=DELAI_S):
    """Transport réel : (statut, document JSON). Une réponse HTTP d'erreur est rendue, pas levée ; le réseau en panne lève OSError."""
    req = urllib.request.Request(url, data=corps.encode("utf-8") if corps else None, method=methode, headers=entetes or {})
    try:
        with urllib.request.urlopen(req, timeout=delai) as r:   # nosec - réseau local, hôte configuré
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except ValueError:
            return e.code, {}


class Client:
    def __init__(self, transport, magasin, hote=HOTE_DEFAUT):
        self.transport = transport
        self.magasin = magasin
        self.hote = hote.rstrip("/")
        self.base = None
        self.info = {}
        self.session = None
        self.droits = {}

    # ── découverte ───────────────────────────────────────────────────────────
    def _envoyer(self, methode, url, entetes=None, corps=None):
        try:
            return self.transport(methode, url, entetes or {}, json.dumps(corps) if corps is not None else None)
        except OSError:
            raise Injoignable("La Freebox ne répond pas : vérifiez qu'elle est allumée et sur le même réseau.") from None

    def decouvrir(self):
        statut, d = self._envoyer("GET", self.hote + "/api_version")
        if statut != 200 or "api_version" not in d:
            raise ErreurFreebox("Réponse inattendue de la Freebox.")
        majeur = int(str(d["api_version"]).split(".")[0])
        racine = d.get("api_base_url") or "/api/"
        self.base = f"{self.hote}{racine}v{majeur}/"
        self.info = {"version": str(d["api_version"]), "modele": d.get("box_model_name") or d.get("box_model") or "",
                     "nom": d.get("device_name") or ""}
        return dict(self.info)

    def _pret(self):
        if self.base is None:
            self.decouvrir()

    # ── autorisation ─────────────────────────────────────────────────────────
    def demander_autorisation(self, nom_appareil):
        self._pret()
        statut, d = self._envoyer("POST", self.base + "login/authorize/", {"Content-Type": "application/json"},
                                  {"app_id": APP_ID, "app_name": APP_NOM, "app_version": "1.0", "device_name": nom_appareil or "SecuBox"})
        if not d.get("success"):
            raise ErreurFreebox("La Freebox a refusé la demande d'autorisation.")
        r = d["result"]
        self.magasin.ecrire({"app_id": APP_ID, "app_token": r["app_token"], "track_id": r["track_id"], "autorise": False})
        return {"track_id": r["track_id"]}

    def etat_autorisation(self):
        mem = self.magasin.lire()
        if not mem.get("app_token") or mem.get("track_id") is None:
            return {"etat": "aucune"}
        self._pret()
        statut, d = self._envoyer("GET", f"{self.base}login/authorize/{int(mem['track_id'])}")
        if not d.get("success"):
            return {"etat": "inconnue"}
        etat = _ETATS.get(d["result"].get("status"), "inconnue")
        if etat == "accordee" and not mem.get("autorise"):
            self.magasin.ecrire({"autorise": True})
        elif etat != "accordee" and mem.get("autorise") and etat in ("refusee", "expiree"):
            self.magasin.ecrire({"autorise": False})
        return {"etat": etat}

    # ── session ──────────────────────────────────────────────────────────────
    def ouvrir_session(self):
        mem = self.magasin.lire()
        if not (mem.get("app_token") and mem.get("autorise")):
            raise NonAutorise("La Freebox n'a pas encore autorisé SecuBox : validez la demande sur la Freebox.")
        self._pret()
        statut, d = self._envoyer("GET", self.base + "login/")
        defi = (d.get("result") or {}).get("challenge")
        if not defi:
            raise ErreurFreebox("La Freebox n'a pas rendu de défi de connexion.")
        mot = hmac.new(mem["app_token"].encode(), defi.encode(), hashlib.sha1).hexdigest()
        statut, d = self._envoyer("POST", self.base + "login/session/", {"Content-Type": "application/json"},
                                  {"app_id": APP_ID, "password": mot})
        if not d.get("success"):
            raise NonAutorise("La Freebox a refusé la connexion : l'autorisation a peut-être été retirée.")
        self.session = d["result"]["session_token"]
        self.droits = d["result"].get("permissions") or {}
        return dict(self.droits)

    # ── appels ───────────────────────────────────────────────────────────────
    def _verifier_chemin(self, chemin):
        if not isinstance(chemin, str) or not _CHEMIN_OK.match(chemin) or ".." in chemin or "//" in chemin:
            raise ValueError("chemin d'API invalide")

    def _appel(self, methode, chemin, corps=None, _deuxieme=False):
        self._verifier_chemin(chemin)
        if self.session is None:
            self.ouvrir_session()
        entetes = {"X-Fbx-App-Auth": self.session}
        if corps is not None:
            entetes["Content-Type"] = "application/json"
        statut, d = self._envoyer(methode, self.base + chemin, entetes, corps)
        code = d.get("error_code")
        if not d.get("success"):
            if code in ("auth_required", "invalid_token") and not _deuxieme:
                self.session = None
                return self._appel(methode, chemin, corps, _deuxieme=True)
            if code == "insufficient_rights":
                raise DroitManquant("Cette action demande un droit que la Freebox n'a pas accordé à SecuBox : "
                                    "réglez-le dans Paramètres → Gestion des accès → Applications.")
            raise ErreurFreebox("La Freebox a refusé cette demande.")
        return d.get("result")

    def lire(self, chemin):
        return self._appel("GET", chemin)

    def ecrire(self, methode, chemin, corps=None):
        if methode not in ("POST", "PUT", "DELETE"):
            raise ValueError("méthode invalide")
        return self._appel(methode, chemin, corps)
