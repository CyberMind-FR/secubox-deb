# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2193 : BANC DE BOUT EN BOUT, sans matériel. Le vrai moteur de l'agent, le vrai client HTTP, le vrai service d'enrôlement (application publique ET application
du tunnel), de vrais jetons, un vrai fichier de réponses signé avec un vrai gpg et de vraies clés WireGuard ; seuls apt, systemctl et wg-quick sont des faux
(ils enregistrent leurs commandes). Chaque scénario part d'une box vierge et d'un jeton émis par l'administrateur."""
import io
import json
import os
import subprocess
import urllib.error
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, tunnel as T
from api import main as A
from autoload_agent import client as C, moteur as M, tunnel as TA, validation as VA
from premier_pas import provision as V

T0 = 1_800_000_000
HUB_PUB = "H" * 43 + "="
ARGON = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
SIMULATION = "Inst secubox-core (1)\nInst secubox-ad-guard (1.8.0)\nInst secubox-lite (1.0.42)\n"


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


class Rep:
    def __init__(self, status, corps):
        self.status, self._c = status, corps

    def read(self, n=-1):
        return self._c

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Systeme:
    """apt, systemctl, premier-pasctl, profilectl : des faux qui enregistrent. wg et gpg sont les VRAIS (genkey, pubkey, gpgv)."""
    def __init__(self):
        self.cmds = []

    def __call__(self, argv, **kw):
        if argv[0] == "wg":
            return subprocess.run(argv, **{k: v for k, v in kw.items() if k in ("capture_output", "text", "timeout", "input")})
        self.cmds.append(list(argv))

        class R:
            returncode, stdout, stderr = 0, "", ""
        r = R()
        if argv[:2] == ["apt-get", "-s"]:
            r.stdout = SIMULATION
        return r

    def installs(self):
        return [c for c in self.cmds if c[0] == "apt-get" and "install" in c and "-s" not in c]


class Banc:
    def __init__(self, tmp_path, monkeypatch):
        self.tmp, self.h = tmp_path, Horloge()
        # ── infrastructure ──
        self.reg = J.Registre(tmp_path / "infra" / "jetons.db", tmp_path / "infra" / "audit.log", horloge=self.h)
        self.pairs = T.Pairs(tmp_path / "infra" / "jetons.db", horloge=self.h)
        self.syncs = 0
        self.infra_en_panne = False
        self.publique = A.creer_app(self.reg, self.pairs, HUB_PUB, self._appliquer, horloge=self.h, portee="public")
        self.publique.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
        self.admin = TestClient(self.publique)
        self.tunnel_app = A.creer_app(self.reg, self.pairs, HUB_PUB, self._appliquer, horloge=self.h, portee="tunnel")
        self.adresse = None
        # ── box ──
        self.secrets = tmp_path / "box" / "secrets"
        self.secrets.mkdir(parents=True, mode=0o700)
        self.sys = Systeme()
        self.cfg = M.Config(reponses=tmp_path / "box" / "reponses.toml", signature=tmp_path / "box" / "reponses.toml.sig", trousseau=tmp_path / "box" / "trousseau.gpg",
                            racine_secrets=self.secrets, etat=tmp_path / "box" / "etat.json", cle_wg=self.secrets / "autoload-wg.key",
                            conf_wg=tmp_path / "box" / "wg-autoload.conf", rapport=tmp_path / "box" / "rapport.json")
        self.infra = C.ClientInfra(ouvrir=self._reseau)
        self._signe_les_reponses()

    # ── ponts ──
    def _appliquer(self):
        if self.infra_en_panne:
            raise T.TunnelErreur("hub indisponible")
        self.syncs += 1

    def _reseau(self, requete, timeout=None, context=None):
        """Le « réseau » : HTTPS public → application publique ; HTTP vers le hub → application du tunnel, avec l'adresse source de WireGuard."""
        url = requete.full_url
        if self.infra_en_panne and url.startswith("https://"):
            raise urllib.error.URLError("hôte injoignable")
        if url.startswith("https://"):
            client = TestClient(self.publique)
            chemin = url.split("/api/v1/autoload", 1)[1]
            r = client.request(requete.get_method(), chemin, content=requete.data, headers={"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.50, 127.0.0.1"})
        else:
            assert url.startswith("http://10.64.0.1:8470/"), url                         # le client ne parle qu'au hub
            if not self.adresse:
                raise urllib.error.URLError("hub injoignable : le tunnel n'est pas encore monté")     # comme sur une vraie box avant la poignée de main
            client = TestClient(self.tunnel_app, client=(self.adresse, 51000))
            r = client.request(requete.get_method(), url.split("8470", 1)[1], content=requete.data, headers={"Content-Type": "application/json"})
        if r.status_code >= 400:
            raise urllib.error.HTTPError(url, r.status_code, "x", {}, io.BytesIO(r.content))
        return Rep(r.status_code, r.content)

    def _signe_les_reponses(self, profil="lite", mode="auto", grace=15):
        home = self.tmp / "gnupg"
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        gpg = lambda *a: subprocess.run(["gpg", "--batch", "--yes", "--no-tty", *a], env=env, capture_output=True, check=True)       # noqa: E731
        gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Provisioning <p@test.invalid>", "ed25519", "sign", "never")
        self.cfg.trousseau.write_bytes(gpg("--export").stdout)
        self.gpg, self.home = gpg, home
        self.ecrit_reponses(profil, mode, grace)

    def ecrit_reponses(self, profil="lite", mode="auto", grace=15):
        self.cfg.reponses.write_text(f"""
[box]
nom = "client-042"
langue = "fr"
clavier = "fr"
fuseau = "Europe/Paris"
ntp = true
[admin]
mot_de_passe = "{ARGON}"
totp = "enroler"
[reseau]
mode = "routeur"
domaine = "client042.secubox.in"
[services]
profil = "{profil}"
[maillage]
mode = "plus_tard"
[apt]
auto = true
heure = "03:00"
[provision]
mode = "{mode}"
jeton = "ref:/etc/secubox/secrets/autoload-jeton"
grace_min = {grace}
""", encoding="utf-8")
        self.cfg.signature.unlink(missing_ok=True)
        self.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--output", str(self.cfg.signature), "--detach-sign", str(self.cfg.reponses))

    def pose_le_jeton(self, valeur):
        p = self.secrets / "autoload-jeton"
        p.write_text(valeur + "\n")
        p.chmod(0o600)

    def emet(self, client="client-042", profil="lite", mois=12):
        j = self.admin.post("/jetons", json={"client": client, "profil": profil, "lot": "lot-banc"}).json()
        self.admin.post(f"/clients/{client}/abonnement", json={"statut": "actif", "mois": mois, "formule": f"pme_{mois}m"})
        self.pose_le_jeton(j["valeur"])
        return j

    def moteur(self, valideur=None):
        def fabrique(rep):
            return VA.pour_mode(rep["provision"]["mode"], rep, dossier=self.tmp / "box", publier=self.infra.publier, refuse=self.infra.refuse,
                                lire_confirmation=lambda: None, horloge=self.h, dormir=self._dormir)
        return M.Moteur(self.cfg, executeur=self.sys, enroleur=self._enroler, valideur=valideur, fabrique_valideur=fabrique, rapporteur=self.infra.progression,
                        diffuseur=self.infra.rapport, horloge=self.h)

    def _enroler(self, jeton, serie, cle_pub, infra):
        rep = self.infra.enroler(jeton, serie, cle_pub, infra)
        self.adresse = rep["tunnel"]["adresse"].split("/")[0]
        return rep

    def _dormir(self, s):
        self.h.dormir(s)
        if self.refus_a is not None and self.h.t >= self.refus_a and self.pre_empreinte() and not self._deja_refuse:
            self.admin.post(f"/prerapports/{self.pre_empreinte()}/refuser", json={"motif": "pas ce profil"})
            self._deja_refuse = True

    refus_a, _deja_refuse = None, False

    def pre_empreinte(self):
        liste = self.admin.get("/prerapports").json()
        return liste[0]["empreinte"] if liste else None

    def etat_box(self):
        return self.admin.get("/boxes").json()


@pytest.fixture
def banc(tmp_path, monkeypatch):
    b = Banc(tmp_path, monkeypatch)
    # clé WireGuard de la box : la vraie (wg genkey) ; le tunnel est « monté » par une commande enregistrée
    monkeypatch.setattr(TA, "monter", lambda reponse, cle=None, conf=None, infra=TA.INFRA, executeur=None: (TA.valider(reponse, infra), b.sys(["systemctl", "enable", "--now", "wg-quick@wg-autoload"], timeout=1)))
    return b


def test_A_parcours_complet_zero_touch(banc):
    banc.emet()
    r = banc.moteur().run()
    assert r.ok, r
    # côté box : une seule installation, du méta-paquet du profil, et l'application des profils
    assert [c[-1] for c in banc.sys.installs()] == ["secubox-lite"]
    assert any(c[0] == "premier-pasctl" for c in banc.sys.cmds) and any("apply" in c for c in banc.sys.cmds)
    # le délai de grâce de 15 minutes a été attendu avant l'installation
    assert banc.h.t - T0 >= 15 * 60
    # côté infrastructure : un pair, la box « terminée » à 100 %, un pré-rapport reçu, l'audit complet et sans valeur de jeton
    b = banc.etat_box()[0]
    assert (b["statut"], b["progression"], b["client"], b["profil"]) == ("terminé", 100, "client-042", "lite")
    assert len(banc.pairs.actifs()) == 1 and banc.syncs == 1
    assert banc.admin.get("/prerapports").json()[0]["paquets"] == 3
    audit = (banc.tmp / "infra" / "audit.log").read_text()
    assert {"jeton-emis", "jeton-reclame", "prerapport-recu"} <= {json.loads(l)["action"] for l in audit.splitlines()}
    assert banc.reg.lister()[0]["etat"] == "reclame" and "gk2_" not in audit
    assert banc.reg.livraison_autorisee(banc.pairs.actifs()[0]["cle_pub"]) is True
    # le rapport final est arrivé à l'infrastructure, sans secret, avec les mêmes champs que sur la box
    rapports = banc.admin.get("/rapports").json()
    assert len(rapports) == 1 and rapports[0]["client"] == "client-042" and rapports[0]["paquets"] == 3
    rap = banc.admin.get(f"/rapports/{rapports[0]['id']}").json()
    assert rap == json.loads(banc.cfg.rapport.read_text()) and "gk2_" not in json.dumps(rap) and "argon2" not in json.dumps(rap)
    # un second passage ne refait rien, et le jeton consommé ne rouvre rien
    n = len(banc.sys.cmds)
    assert banc.moteur().run().ok and len(banc.sys.cmds) == n


def test_B_l_operateur_refuse_pendant_le_delai_de_grace_et_rien_n_est_installe(banc):
    banc.emet()
    banc.refus_a = T0 + 5 * 60
    r = banc.moteur().run()
    assert not r.ok and r.etape == "validation"
    assert banc.sys.installs() == []                                         # rien n'a été installé
    assert banc.admin.get("/prerapports").json()[0]["refuse"] is True
    assert banc.etat_box()[0]["statut"] == "en cours"                        # elle a avancé jusqu'à la validation, pas plus


def test_C_infrastructure_injoignable_puis_retour_le_parcours_reprend_sans_rejouer(banc):
    banc.emet()
    banc.infra_en_panne = True
    r = banc.moteur().run()
    assert not r.ok and r.etape == "enrolement" and banc.reg.lister()[0]["etat"] == "emis"      # le jeton n'a pas été consommé
    banc.infra_en_panne = False
    assert banc.moteur().run().ok
    assert banc.etat_box()[0]["statut"] == "terminé"


def test_D_jeton_revoque_avant_l_enrolement(banc):
    j = banc.emet()
    banc.admin.post(f"/jetons/{j['id']}/revoquer", json={"motif": "client parti"})
    r = banc.moteur().run()
    assert not r.ok and r.etape == "enrolement" and "refus" in r.detail
    assert banc.pairs.actifs() == [] and banc.sys.installs() == []


def test_E_abonnement_suspendu_refuse_l_enrolement_sans_rien_dire_de_plus(banc):
    banc.emet()
    banc.admin.post("/clients/client-042/abonnement", json={"statut": "suspendu"})
    r = banc.moteur().run()
    assert not r.ok and r.etape == "enrolement" and banc.pairs.actifs() == []
    banc.admin.post("/clients/client-042/abonnement", json={"statut": "actif", "mois": 12})
    assert banc.moteur().run().ok                                            # réactivé : la même box passe


def test_F_un_fichier_de_reponses_modifie_apres_signature_ne_demarre_rien(banc):
    banc.emet()
    banc.cfg.reponses.write_text(banc.cfg.reponses.read_text().replace('profil = "lite"', 'profil = "full"'))
    r = banc.moteur().run()
    assert not r.ok and r.etape == "reponses"
    assert banc.reg.lister()[0]["etat"] == "emis" and banc.sys.cmds == []


def test_G_le_profil_isp_installe_le_meta_paquet_isp(banc):
    banc.ecrit_reponses(profil="isp")
    banc.emet(profil="isp")
    assert banc.moteur(valideur=lambda p: True).run().ok
    assert [c[-1] for c in banc.sys.installs()] == ["secubox-isp"]


def test_H_une_box_revoquee_apres_coup_perd_son_pair_et_ses_livraisons(banc):
    j = banc.emet()
    assert banc.moteur(valideur=lambda p: True).run().ok
    cle = banc.pairs.actifs()[0]["cle_pub"]
    n = banc.syncs
    banc.admin.post(f"/jetons/{j['id']}/revoquer", json={"motif": "box volée"})
    assert banc.pairs.actifs() == [] and banc.syncs == n + 1 and banc.reg.livraison_autorisee(cle) is False
