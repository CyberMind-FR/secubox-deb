# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2728 — gk2 (le maître) repère les box neuves, les liste, puis leur pousse le profil en prenant la session distante au lieu du code.

Demande du mainteneur : « gk2 repère les box neuves, les liste, puis pousse le profil en prenant la session distante au lieu du code » (le code à 8×4 caractères
affiché sur l'écran est « relou »). Ce qui reste à la main du maître : choisir le profil. L'automatique est DÉSACTIVÉ par défaut, limité à `remplir`/`proposer` (jamais `forcer`),
à un profil complet, et ne tente qu'UNE fois par box : une box qui répond « je suis neuve » à l'adresse d'un voisin n'est pas forcément la vôtre."""
import importlib
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import decouverte as D, maitre as MA, remplir as R  # noqa: E402

MDP = "une-phrase-longue-et-sure"
PROFIL = {"box": {"fuseau": "Europe/Paris", "langue": "fr", "clavier": "fr"}, "admin": {"mot_de_passe": MDP, "confirmation": MDP},
          "reseau": {"mode": "routeur", "domaine": "gk3.secubox.in"}, "services": {"profil": "full"}, "maillage": {"mode": "plus_tard"},
          "apt": {"auto": True, "heure": "03:00"}}
MAINTENANT = 1_800_000_000


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    return tmp_path


# ---------- un faux réseau ----------

class Rep:
    def __init__(self, code=200, corps=None):
        self.status_code, self._c = code, corps
        self.text = json.dumps(corps) if corps is not None else ""

    def json(self):
        if self._c is None:
            raise ValueError("pas du JSON")
        return self._c


def etat(fait=False, nom=None):
    d = {"fait": fait, "complet": False, "reprendre": "bienvenue", "etapes": [{"id": "bienvenue"}], "profil": {}}
    if nom:
        d["profil"] = {"box": {"nom": nom}}
    return d


class FauxReseau:
    """ip -> JSON d'état, un code HTTP, ou une exception."""
    def __init__(self, boites):
        self.boites, self.appels = boites, []

    def get(self, url, **k):
        ip = url.split("//")[1].split("/")[0]
        self.appels.append(ip)
        b = self.boites.get(ip, OSError("injoignable"))
        if isinstance(b, Exception):
            raise b
        return Rep(b) if isinstance(b, int) else Rep(200, b)


def analyse(reseau, voisins, maintenant=MAINTENANT):
    return D.analyse(client=reseau, voisins_fn=lambda: voisins, maintenant=lambda: maintenant)


# ---------- les voisins ----------

NEIGH = json.dumps([
    {"dst": "192.168.1.60", "dev": "end0", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["REACHABLE"]},
    {"dst": "192.168.1.61", "dev": "end0", "state": ["STALE"]},
    {"dst": "192.168.1.62", "dev": "end0", "state": ["FAILED"]},
    {"dst": "192.168.1.63", "dev": "end0", "state": ["INCOMPLETE"]},
    {"dst": "8.8.8.8", "dev": "end0", "state": ["REACHABLE"]},
    {"dst": "127.0.0.1", "dev": "lo", "state": ["REACHABLE"]},
    {"dst": "192.168.1.200", "dev": "end0", "state": ["REACHABLE"]},
    {"dst": "fe80::1", "dev": "end0", "state": ["REACHABLE"]},
])
WG = "PUBKEY1=\t10.10.0.2/32\nPUBKEY2=\t10.10.0.3/32 10.99.0.0/24\n"


def test_voisins_garde_les_adresses_privees_vues_et_rien_d_autre():
    sortie = {"neigh": NEIGH, "wg": WG}
    v = D.voisins(lancer=lambda cmd: sortie["neigh" if "neigh" in cmd else "wg"], mes_adresses=["192.168.1.200"])
    assert set(v) == {"192.168.1.60", "192.168.1.61", "10.10.0.2", "10.10.0.3"}, v


def test_voisins_ne_plante_pas_si_ip_ou_wg_sont_absents():
    def casse(cmd):
        raise OSError("absent")
    assert D.voisins(lancer=casse, mes_adresses=[]) == []
    assert D.voisins(lancer=lambda cmd: "pas du json", mes_adresses=[]) == []


# ---------- la sonde ----------

def test_sonde_reconnait_une_box_secubox_par_son_etat_public():
    r = D.sonde("192.168.1.60", FauxReseau({"192.168.1.60": etat(False, "gk3")}))
    assert r == {"fait": False, "complet": False, "nom": "gk3"}


@pytest.mark.parametrize("reponse", [{"hello": "world"}, {"fait": "oui", "etapes": []}, {"fait": True}, ["liste"], 404, 500, OSError("x"), TimeoutError()])
def test_sonde_ignore_tout_ce_qui_n_est_pas_une_box_secubox(reponse):
    assert D.sonde("192.168.1.60", FauxReseau({"192.168.1.60": reponse})) is None


def test_sonde_refuse_une_adresse_publique_sans_rien_envoyer():
    reseau = FauxReseau({"8.8.8.8": etat()})
    assert D.sonde("8.8.8.8", reseau) is None and reseau.appels == []


# ---------- le registre ----------

def test_une_box_neuve_est_listee_une_box_configuree_aussi_mais_distinctement(maitre):
    r = analyse(FauxReseau({"192.168.1.60": etat(False, "gk3"), "192.168.1.61": etat(True, "gk1")}), ["192.168.1.60", "192.168.1.61", "192.168.1.62"])
    par = {b["adresse"]: b for b in r["boxes"]}
    assert par["192.168.1.60"]["etat"] == "nouvelle" and par["192.168.1.60"]["nom"] == "gk3"
    assert par["192.168.1.61"]["etat"] == "configuree"
    assert "192.168.1.62" not in par and r["sondees"] == 3 and r["trouvees"] == 2


def test_les_nouvelles_sont_en_tete(maitre):
    r = analyse(FauxReseau({"192.168.1.61": etat(True), "192.168.1.60": etat(False)}), ["192.168.1.61", "192.168.1.60"])
    assert [b["etat"] for b in r["boxes"]] == ["nouvelle", "configuree"]


def test_un_second_passage_garde_la_premiere_vue_et_rafraichit_la_derniere(maitre):
    reseau = FauxReseau({"192.168.1.60": etat(False)})
    analyse(reseau, ["192.168.1.60"], MAINTENANT)
    r = analyse(reseau, ["192.168.1.60"], MAINTENANT + 120)
    b = r["boxes"][0]
    assert b["premiere_vue"] == MAINTENANT and b["derniere_vue"] == MAINTENANT + 120


def test_une_box_preparee_qui_devient_configuree_change_d_etat(maitre):
    reseau = FauxReseau({"192.168.1.60": etat(False)})
    analyse(reseau, ["192.168.1.60"])
    D._ecrit_box("192.168.1.60", {"etat": "preparee"})
    reseau.boites["192.168.1.60"] = etat(True, "gk3")
    assert analyse(reseau, ["192.168.1.60"])["boxes"][0]["etat"] == "configuree"


def test_une_box_configuree_rejouee_redevient_nouvelle(maitre):
    reseau = FauxReseau({"192.168.1.60": etat(True)})
    analyse(reseau, ["192.168.1.60"])
    reseau.boites["192.168.1.60"] = etat(False)
    assert analyse(reseau, ["192.168.1.60"])["boxes"][0]["etat"] == "nouvelle"


def test_une_box_absente_depuis_plus_d_une_heure_disparait(maitre):
    reseau = FauxReseau({"192.168.1.60": etat(False)})
    analyse(reseau, ["192.168.1.60"], MAINTENANT)
    assert analyse(FauxReseau({}), [], MAINTENANT + 1800)["boxes"]
    assert analyse(FauxReseau({}), [], MAINTENANT + 3700)["boxes"] == []


def test_oublier_une_box(maitre):
    analyse(FauxReseau({"192.168.1.60": etat(False)}), ["192.168.1.60"])
    D.oublie("192.168.1.60")
    assert D.liste() == []


def test_un_registre_illisible_est_un_registre_vide(maitre):
    (maitre / "maitre").mkdir()
    (maitre / "maitre" / "decouverte.json").write_text("{pas du json")
    assert D.liste() == []
    assert analyse(FauxReseau({"192.168.1.60": etat(False)}), ["192.168.1.60"])["trouvees"] == 1


def test_beaucoup_de_voisins_sont_sondes_en_parallele_sans_en_perdre(maitre):
    ips = [f"192.168.1.{i}" for i in range(10, 70)]
    r = analyse(FauxReseau({ip: etat(False) for ip in ips}), ips)
    assert r["sondees"] == 60 and r["trouvees"] == 60


# ---------- les réglages ----------

def test_reglages_par_defaut_automatique_desactive(maitre):
    assert D.reglages() == {"auto": False, "profil": "", "mode": "remplir"}


def test_l_automatique_refuse_forcer_un_profil_inconnu_ou_incomplet(maitre):
    MA.enregistre("gk3", PROFIL)
    MA.enregistre("brouillon", {"box": {"nom": "x"}})
    for mauvais in ({"auto": True, "profil": "gk3", "mode": "forcer"}, {"auto": True, "profil": "inconnu", "mode": "remplir"},
                    {"auto": True, "profil": "brouillon", "mode": "remplir"}, {"auto": True, "profil": "", "mode": "remplir"}, {"auto": True, "profil": "gk3", "mode": "n'importe"}):
        with pytest.raises(R.Refus):
            D.regle(mauvais)
    assert D.regle({"auto": True, "profil": "gk3", "mode": "proposer"})["auto"] is True


def test_desactiver_l_automatique_ne_demande_pas_de_profil(maitre):
    assert D.regle({"auto": False, "profil": "", "mode": "remplir"})["auto"] is False


# ---------- préparer : la session distante à la place du code ----------

class _Distant:
    def __init__(self, tc):
        self.tc = tc
        self.appels = []

    def _p(self, url):
        return url.split("/api/v1/premier-pas", 1)[1]

    def put(self, url, **k):
        self.appels.append(("PUT", self._p(url), (k.get("headers") or {}).get("X-Premier-Pas")))
        return self.tc.put(self._p(url), **k)

    def get(self, url, **k):
        self.appels.append(("GET", self._p(url), None))
        return self.tc.get(self._p(url), **k)

    def post(self, url, **k):
        self.appels.append(("POST", self._p(url), (k.get("headers") or {}).get("X-Premier-Pas")))
        return self.tc.post(self._p(url), **k)


@pytest.fixture
def box_neuve(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "neuve"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    monkeypatch.setenv("PREMIER_PAS_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_USERS_JSON", str(tmp_path / "users.json"))
    (tmp_path / "jeton").write_text("code-ecran\n")
    (tmp_path / "jeton-local").write_text("local\n")
    from api import main
    importlib.reload(R)
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(main.M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(main.P, "PROFILS_DIR", tmp_path / "profils")
    monkeypatch.setattr(main, "_maintenant", lambda: 120)            # la box vient de démarrer : la fenêtre de 15 minutes est ouverte
    monkeypatch.setattr(main, "_boot_id", lambda: "boot-1")
    (tmp_path / "profils").mkdir()
    (tmp_path / "profils" / "full.toml").write_text('on = ["a"]\n')
    from fastapi.testclient import TestClient
    return _Distant(TestClient(main.app)), tmp_path


def test_le_maitre_pousse_sans_code_en_prenant_une_session_distante(maitre, box_neuve):
    distant, t = box_neuve
    MA.enregistre("gk3", PROFIL)
    r = MA.pousse("gk3", "192.168.1.9", "", "remplir", client=distant, par="gk2")
    assert r["ok"] and r["complet"], r
    assert distant.appels[0][:2] == ("POST", "/session")
    secrets = {a[2] for a in distant.appels if a[0] == "PUT"}
    assert len(secrets) == 1 and None not in secrets and "code-ecran" not in secrets, "les écritures portent le secret de SESSION, pas le code"
    prof = (t / "neuve" / "profil.toml").read_text()
    assert "$argon2" in prof and MDP not in prof and 'nom = "gk3"' in prof


def test_forcer_sans_code_applique_et_proposer_laisse_l_utilisateur_decider(maitre, box_neuve):
    distant, t = box_neuve
    MA.enregistre("gk3", PROFIL)
    r = MA.pousse("gk3", "192.168.1.9", "", "proposer", client=distant, par="gk2")
    assert r["proposition"]["statut"] == "en_attente" and not (t / "neuve" / "demande").exists()


def test_avec_un_code_le_comportement_d_avant_est_inchange(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    assert MA.pousse("gk3", "192.168.1.9", "code-ecran", "remplir", client=distant)["ok"]
    assert not any(a[1] == "/session" for a in distant.appels), "avec un code on ne prend pas de session"


@pytest.mark.parametrize("mise_en_place,attendu", [("occupee", "autre poste"), ("close", "fenêtre"), ("en_service", "en service")])
def test_la_session_refusee_arrete_tout_et_dit_pourquoi(maitre, box_neuve, monkeypatch, mise_en_place, attendu):
    distant, t = box_neuve
    from api import main
    MA.enregistre("gk3", PROFIL)
    if mise_en_place == "occupee":
        distant.tc.post("/session")                       # un autre poste a déjà la session
    elif mise_en_place == "close":
        monkeypatch.setattr(main, "_maintenant", lambda: 20 * 60)
    else:
        (t / "users.json").write_text(json.dumps({"users": [{"username": "admin", "password_hash": "$argon2id$x", "must_change_password": False}]}))
    r = MA.pousse("gk3", "192.168.1.9", "", "remplir", client=distant)
    assert r["ok"] is False and attendu in str(r["detail"]).lower() and r["faites"] == []
    assert not any(a[0] == "PUT" for a in distant.appels), "aucune écriture après un refus de session"


# ---------- préparer depuis le registre ----------

def test_on_ne_prepare_que_ce_qui_a_ete_detecte_et_qui_est_neuf(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    with pytest.raises(R.Refus, match="détectée"):
        D.prepare("192.168.1.9", "gk3", "remplir", client=distant)
    analyse(FauxReseau({"192.168.1.9": etat(True, "gk1")}), ["192.168.1.9"])
    with pytest.raises(R.Refus, match="déjà configurée"):
        D.prepare("192.168.1.9", "gk3", "remplir", client=distant)


def test_preparer_marque_la_box_et_garde_le_resultat(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    analyse(FauxReseau({"192.168.1.9": etat(False)}), ["192.168.1.9"])
    r = D.prepare("192.168.1.9", "gk3", "remplir", client=distant, maintenant=lambda: MAINTENANT)
    assert r["ok"]
    b = D.liste()[0]
    assert b["etat"] == "preparee" and b["dernier"] == {"le": MAINTENANT, "profil": "gk3", "mode": "remplir", "ok": True, "auto": False, "arret": None}


def test_une_preparation_qui_echoue_laisse_la_box_nouvelle_avec_la_raison(maitre, box_neuve, monkeypatch):
    distant, _ = box_neuve
    from api import main
    monkeypatch.setattr(main, "_maintenant", lambda: 20 * 60)
    MA.enregistre("gk3", PROFIL)
    analyse(FauxReseau({"192.168.1.9": etat(False)}), ["192.168.1.9"])
    r = D.prepare("192.168.1.9", "gk3", "remplir", client=distant, maintenant=lambda: MAINTENANT)
    assert not r["ok"]
    b = D.liste()[0]
    assert b["etat"] == "nouvelle" and b["dernier"]["ok"] is False and "fenêtre" in b["dernier"]["arret"].lower()


# ---------- l'automatique ----------

def automatique(maitre, mode="remplir"):
    MA.enregistre("gk3", PROFIL)
    D.regle({"auto": True, "profil": "gk3", "mode": mode})


def test_automatique_desactive_par_defaut_rien_n_est_pousse(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    D.analyse(client=_Rouleur(distant, {"192.168.1.9": etat(False)}), voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT)
    assert not any(a[0] == "PUT" for a in distant.appels) and D.liste()[0]["etat"] == "nouvelle"


class _Rouleur:
    """Les sondes (/etat) vont au faux réseau, les écritures vers la vraie API de la box neuve."""
    def __init__(self, distant, boites):
        self.distant, self.reseau = distant, FauxReseau(boites)

    def get(self, url, **k):
        return self.reseau.get(url, **k) if url.endswith("/etat") and not self.distant.appels else self.distant.get(url, **k)

    def put(self, url, **k):
        return self.distant.put(url, **k)

    def post(self, url, **k):
        return self.distant.post(url, **k)


def test_automatique_active_prepare_une_box_neuve_une_seule_fois(maitre, box_neuve):
    distant, _ = box_neuve
    automatique(maitre)
    cl = _Rouleur(distant, {"192.168.1.9": etat(False)})
    D.analyse(client=cl, voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT)
    b = D.liste()[0]
    assert b["etat"] == "preparee" and b["dernier"]["auto"] is True and b["dernier"]["mode"] == "remplir"
    n = len([a for a in distant.appels if a[0] == "PUT"])
    cl.reseau.boites["192.168.1.9"] = etat(False)
    D.analyse(client=cl, voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT + 60)
    assert len([a for a in distant.appels if a[0] == "PUT"]) == n, "une seule tentative automatique par box"


def test_automatique_ne_retente_pas_apres_un_echec(maitre, box_neuve, monkeypatch):
    distant, _ = box_neuve
    from api import main
    monkeypatch.setattr(main, "_maintenant", lambda: 20 * 60)       # fenêtre close : la tentative échoue
    automatique(maitre)
    cl = _Rouleur(distant, {"192.168.1.9": etat(False)})
    D.analyse(client=cl, voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT)
    assert D.liste()[0]["dernier"]["ok"] is False
    monkeypatch.setattr(main, "_maintenant", lambda: 120)             # la fenêtre se rouvre (redémarrage)
    D.analyse(client=cl, voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT + 60)
    assert D.liste()[0]["dernier"]["ok"] is False, "l'automatique n'insiste pas : c'est à l'administrateur de relancer"


def test_automatique_ne_touche_pas_une_box_deja_configuree(maitre, box_neuve):
    distant, _ = box_neuve
    automatique(maitre)
    D.analyse(client=_Rouleur(distant, {"192.168.1.9": etat(True, "gk1")}), voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT)
    assert not any(a[0] == "PUT" for a in distant.appels)


def test_une_panne_de_l_automatique_ne_fait_pas_tomber_l_analyse(maitre):
    automatique(maitre)

    class Casse(FauxReseau):
        def put(self, *a, **k):
            raise OSError("coupure")

        def post(self, *a, **k):
            raise OSError("coupure")
    r = D.analyse(client=Casse({"192.168.1.9": etat(False)}), voisins_fn=lambda: ["192.168.1.9"], maintenant=lambda: MAINTENANT)
    assert r["trouvees"] == 1 and D.liste()[0]["dernier"]["ok"] is False


# ---------- la trace ----------

def test_le_registre_n_a_aucun_secret_ni_mot_de_passe(maitre, box_neuve):
    distant, t = box_neuve
    MA.enregistre("gk3", PROFIL)
    analyse(FauxReseau({"192.168.1.9": etat(False)}), ["192.168.1.9"])
    D.prepare("192.168.1.9", "gk3", "remplir", client=distant)
    texte = (maitre / "maitre" / "decouverte.json").read_text()
    for interdit in (MDP, "argon2", "code-ecran", "local", "X-Premier-Pas"):
        assert interdit not in texte, interdit
    assert time.time() > 0


# ---------- la ligne de commande et la minuterie du maître ----------

def test_cli_resume_et_code_zero_meme_sans_rien_trouver(maitre):
    sorties = []
    r = analyse(FauxReseau({}), [])
    assert D.cli(False, analyse_fn=lambda: r, imprime=sorties.append) == 0
    assert "0 voisin(s) sondé(s), 0 box SecuBox, 0 nouvelle(s)" in sorties[0]


def test_cli_liste_les_box_et_compte_les_nouvelles(maitre):
    r = analyse(FauxReseau({"192.168.1.60": etat(False, "gk3"), "192.168.1.61": etat(True, "gk1")}), ["192.168.1.60", "192.168.1.61"])
    sorties = []
    D.cli(False, analyse_fn=lambda: r, imprime=sorties.append)
    assert "2 box SecuBox, 1 nouvelle(s)" in sorties[0]
    assert any("192.168.1.60" in s and "nouvelle" in s and "gk3" in s for s in sorties[1:])


def test_cli_json(maitre):
    sorties = []
    r = analyse(FauxReseau({"192.168.1.60": etat(False)}), ["192.168.1.60"])
    D.cli(True, analyse_fn=lambda: r, imprime=sorties.append)
    assert json.loads(sorties[0])["boxes"][0]["adresse"] == "192.168.1.60"


PKG = Path(__file__).resolve().parents[1]


def test_premier_pasctl_connait_decouvrir():
    t = (PKG / "sbin" / "premier-pasctl").read_text()
    assert '"decouvrir"' in t and "DE.cli(a.json)" in t


def test_l_unite_est_confinee_et_ne_parle_qu_aux_reseaux_prives():
    u = (PKG / "systemd" / "secubox-premier-pas-decouverte.service").read_text()
    for ligne in ("User=secubox", "NoNewPrivileges=yes", "ProtectSystem=strict", "IPAddressDeny=any", "ExecStart=/usr/sbin/premier-pasctl decouvrir", "Type=oneshot"):
        assert ligne in u, ligne
    assert "User=root" not in u and "IPAddressAllow=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8" in u


def test_la_minuterie_existe_mais_n_est_pas_activee_par_le_paquet():
    """Seule la box maître l'active : une box ordinaire ne doit pas sonder son voisinage toutes les 2 minutes."""
    assert "OnUnitActiveSec=5min" in (PKG / "systemd" / "secubox-premier-pas-decouverte.timer").read_text()
    assert "decouverte" not in (PKG / "debian" / "postinst").read_text(), "le postinst n'active pas la minuterie"
    assert "systemd/*.timer" in (PKG / "debian" / "rules").read_text()
