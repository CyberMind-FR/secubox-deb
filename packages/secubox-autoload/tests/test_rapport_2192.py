# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2192 (infrastructure) : rapport final — réception bornée, contact du client, courrier sans injection d'en-tête, sans secret."""
import json
import sys
from email import message_from_string as _mfs, policy


def message_from_string(texte):
    return _mfs(texte, policy=policy.default)
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, rapport as R, tunnel as T
from api import main as A

CLE_A = "A" * 43 + "="
HUB = "H" * 43 + "="
T0 = 1_800_000_000
RAP = {"client": "client-042", "profil": "lite", "paquets": ["secubox-core", "secubox-ad-guard", "secubox-lite"], "domaine": "client042.secubox.in",
       "comptes": ["admin"], "tunnel_adresse": "10.64.0.2/32", "debut": T0, "fin": T0 + 1500,
       "etapes": ["reponses", "cle", "enrolement", "tunnel", "plan", "validation", "installation", "application"]}


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t


@pytest.fixture
def reg(tmp_path):
    r = J.Registre(tmp_path / "j.db", tmp_path / "a.log", horloge=Horloge())
    r.reclamer(r.emettre("client-042", "lite").valeur, CLE_A)
    return r


# ── registre ─────────────────────────────────────────────────────────────────────────────────────────────
def test_un_rapport_est_recu_conserve_et_liste(reg):
    reg.recevoir_rapport(CLE_A, RAP)
    liste = reg.rapports()
    assert len(liste) == 1 and liste[0]["client"] == "client-042" and liste[0]["paquets"] == 3 and liste[0]["envoye"] is False
    assert reg.rapport(liste[0]["id"])["domaine"] == "client042.secubox.in"


def test_un_rapport_rejoue_ne_double_pas(reg):
    reg.recevoir_rapport(CLE_A, RAP)
    reg.recevoir_rapport(CLE_A, RAP)
    assert len(reg.rapports()) == 1


@pytest.mark.parametrize("mut", [
    {"secret": "x"},                                                 # clé inconnue
    {"paquets": ["ok", "mal forme; rm -rf /"]}, {"paquets": ["p"] * 3000}, {"paquets": "pas une liste"},
    {"domaine": "pas un domaine"}, {"comptes": ["a;b"]}, {"tunnel_adresse": "192.168.1.5/32"}, {"profil": "../x"},
    {"debut": "hier"}, {"fin": -1}, {"client": "Mal Forme"}, {"etapes": ["x" * 100]},
])
def test_rapport_hostile_refuse(reg, mut):
    with pytest.raises(ValueError):
        reg.recevoir_rapport(CLE_A, {**RAP, **mut})


def test_rapport_d_une_cle_inconnue_ou_trop_gros_refuse(reg):
    with pytest.raises(ValueError):
        reg.recevoir_rapport("B" * 43 + "=", RAP)
    with pytest.raises(ValueError):
        reg.recevoir_rapport(CLE_A, {**RAP, "paquets": [f"paquet-{i:05d}-" + "a" * 60 for i in range(2000)]})


# ── contact du client ───────────────────────────────────────────────────────────────────────────────────
def test_contact_valide_et_lisible(reg):
    reg.fixer_contact("client-042", "gerant@boulangerie.example")
    assert reg.contact("client-042") == "gerant@boulangerie.example"
    reg.fixer_contact("client-042", None)
    assert reg.contact("client-042") is None


@pytest.mark.parametrize("mauvais", ["", "sans-arobase", "a@b", "a b@c.example", "a@b.example\nBcc: evil@x.example", "a@b.example\r\nSubject: x", "<a@b.example>",
                                     "a@b.example, c@d.example", "x" * 300 + "@b.example", "a@@b.example", "a@b..example"])
def test_contact_hostile_refuse(reg, mauvais):
    with pytest.raises(ValueError):
        reg.fixer_contact("client-042", mauvais)


# ── courrier ─────────────────────────────────────────────────────────────────────────────────────────────
class FauxSMTP:
    vus = []

    def __init__(self, hote, port, timeout=None):
        FauxSMTP.vus.append(("connexion", hote, port, timeout))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_message(self, msg, from_addr=None, to_addrs=None):
        FauxSMTP.vus.append(("envoi", msg.as_string(), from_addr, to_addrs))


def test_le_courrier_est_sobre_sans_secret_et_sans_injection(monkeypatch):
    FauxSMTP.vus = []
    R.envoyer(RAP, "gerant@boulangerie.example", "10.100.0.1", 25, "autoload@secubox.in", ouvrir=FauxSMTP)
    msg = [v for v in FauxSMTP.vus if v[0] == "envoi"][0]
    m = message_from_string(msg[1])
    assert m["To"] == "gerant@boulangerie.example" and m["From"] == "autoload@secubox.in" and m["Subject"] == "Votre SecuBox est prête"
    corps = m.get_content()
    assert "client042.secubox.in" in corps and "Lite" in corps and "secubox-ad-guard" in corps and "10.64.0.2" not in corps           # pas d'adresse de tunnel
    assert msg[3] == ["gerant@boulangerie.example"] and FauxSMTP.vus[0][3] and FauxSMTP.vus[0][3] <= 30                                # délai borné


def test_le_courrier_refuse_un_destinataire_hostile_avant_toute_connexion():
    FauxSMTP.vus = []
    with pytest.raises(ValueError):
        R.envoyer(RAP, "a@b.example\nBcc: evil@x.example", "10.100.0.1", 25, "autoload@secubox.in", ouvrir=FauxSMTP)
    assert FauxSMTP.vus == []


def test_la_liste_de_paquets_du_courrier_est_bornee():
    FauxSMTP.vus = []
    R.envoyer({**RAP, "paquets": [f"secubox-p{i}" for i in range(500)]}, "g@b.example", "10.100.0.1", 25, "a@secubox.in", ouvrir=FauxSMTP)
    corps = message_from_string([v for v in FauxSMTP.vus if v[0] == "envoi"][0][1]).get_content()
    assert corps.count("secubox-p") <= 40 and "500 paquets" in corps


# ── API ──────────────────────────────────────────────────────────────────────────────────────────────────
class Monde:
    def __init__(self, tmp_path, courrier=None):
        self.h = Horloge()
        self.reg = J.Registre(tmp_path / "j.db", tmp_path / "a.log", horloge=self.h)
        self.pairs = T.Pairs(tmp_path / "j.db", horloge=self.h)
        self.courrier = courrier
        self.pub = A.creer_app(self.reg, self.pairs, HUB, lambda: None, horloge=self.h, courrier=courrier)
        self.pub.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
        self.c = TestClient(self.pub)
        self.tun_app = A.creer_app(self.reg, self.pairs, HUB, lambda: None, horloge=self.h, portee="tunnel", courrier=courrier)
        e = self.reg.emettre("client-042", "lite")
        self.reg.reclamer(e.valeur, CLE_A)
        self.adresse = self.pairs.attribuer(CLE_A)
        self.t = TestClient(self.tun_app, client=(self.adresse, 51000))


def test_la_box_poste_son_rapport_par_le_tunnel_et_l_admin_le_lit(tmp_path):
    m = Monde(tmp_path)
    assert m.t.post("/rapport", json=RAP).status_code == 200
    liste = m.c.get("/rapports").json()
    assert liste[0]["client"] == "client-042"
    assert m.c.get(f"/rapports/{liste[0]['id']}").json()["paquets"][0] == "secubox-core"
    assert m.c.get("/rapports/999").status_code == 404
    assert m.c.post("/rapport", json=RAP).status_code in (404, 405)              # pas dans l'application publique


def test_le_rapport_est_envoye_par_courrier_quand_le_client_a_un_contact(tmp_path):
    envois = []
    m = Monde(tmp_path, courrier=lambda rap, email: envois.append((rap["client"], email)))
    m.c.post("/clients/client-042/contact", json={"email": "gerant@boulangerie.example"})
    assert m.t.post("/rapport", json=RAP).json() == {"ok": True, "envoye": True}
    assert envois == [("client-042", "gerant@boulangerie.example")]
    assert m.c.get("/rapports").json()[0]["envoye"] is True


def test_sans_contact_ou_courrier_en_panne_le_rapport_est_quand_meme_enregistre(tmp_path):
    m = Monde(tmp_path, courrier=lambda rap, email: (_ for _ in ()).throw(OSError("smtp")))
    assert m.t.post("/rapport", json=RAP).json() == {"ok": True, "envoye": False}              # pas de contact : rien à envoyer
    m2 = Monde(tmp_path / "bis", courrier=lambda rap, email: (_ for _ in ()).throw(OSError("smtp")))
    m2.c.post("/clients/client-042/contact", json={"email": "gerant@boulangerie.example"})
    assert m2.t.post("/rapport", json=RAP).json() == {"ok": True, "envoye": False}              # panne SMTP : la box n'est pas touchée
    assert any("rapport-mail-echec" in l for l in (tmp_path / "bis" / "a.log").read_text().splitlines())


def test_routes_d_administration_du_rapport_exigent_un_administrateur(tmp_path):
    m = Monde(tmp_path)
    m.pub.dependency_overrides.clear()
    for methode, chemin, corps in (("get", "/rapports", None), ("get", "/rapports/1", None), ("post", "/clients/client-042/contact", {"email": "a@b.example"})):
        r = getattr(m.c, methode)(chemin, **({"json": corps} if corps else {}))
        assert r.status_code in (401, 403), chemin


def test_contact_invalide_refuse_par_l_api(tmp_path):
    m = Monde(tmp_path)
    assert m.c.post("/clients/client-042/contact", json={"email": "a@b.example\nBcc: x@y.example"}).status_code == 422
    assert m.c.post("/clients/client-042/contact", json={"email": None}).status_code == 200
