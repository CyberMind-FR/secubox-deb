# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3467 : activation et retrait de la clé : DNS unique, origine rendue, jamais d'écrasement ni de DNS mort."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

CHEMIN = Path(__file__).resolve().parents[1] / "sbin/secubox-mobilectl"
_l = importlib.machinery.SourceFileLoader("mobilectl", str(CHEMIN))
_s = importlib.util.spec_from_loader("mobilectl", _l)
C = importlib.util.module_from_spec(_s)
_l.exec_module(C)


class Faux:
    def __init__(self, dns=("192.168.1.254",), ip="192.168.1.50", gw="192.168.1.254", dev="eth0"):
        self.dns, self.ip, self.gw, self.dev = list(dns), ip, gw, dev
        self.autorise = self.droit = self.nft_ok = self.dig_ok = self.check_ok = True
        self.dns6, self.perso6, self.ip6 = ["2001:db8::1"], False, "2001:db8::50"
        self.bail, self.regles, self.appels, self.echec = "", 0, [], None

    def __call__(self, cmd):
        self.appels.append(cmd)
        if cmd[:2] == ["ip", "-j"] and "route" in cmd:
            return 0, json.dumps([{"prefsrc": self.ip, "dev": self.dev, "gateway": self.gw}])
        if cmd[:3] == ["ip", "-j", "-4"]:
            return 0, json.dumps([{"addr_info": [{"local": self.ip, "prefixlen": 24}]}])
        if cmd[:3] == ["ip", "-j", "-6"]:
            infos = [{"local": "2001:db8::dead", "prefixlen": 64, "temporary": True}]
            if self.ip6:
                infos.append({"local": self.ip6, "prefixlen": 64})
            return 0, json.dumps([{"addr_info": infos}])
        if cmd[0] == "timeout":
            return self.fb(cmd[cmd.index("/usr/sbin/freeboxctl") + 1:])
        if cmd[:3] == ["nft", "-a", "list"]:
            return 0, "\n".join(f'accept comment "secubox-mobile" # handle {i}' for i in range(self.regles))
        if cmd[:2] == ["nft", "-f"]:
            if not self.nft_ok:
                return 1, "syntaxe"
            self.regles = Path(cmd[2]).read_text().count("\n")
            return 0, ""
        if cmd[0] == "dig":
            return (0 if self.dig_ok else 9), ""
        if cmd[0] == "unbound-checkconf":
            return (0 if self.check_ok else 1), "erreur"
        return 0, ""

    def fb(self, v):
        if not self.autorise:
            return 1, json.dumps({"erreur": "non autorisé"})
        if v[0] == "dns-lire":
            return 0, json.dumps({"dns": self.dns})
        if v[0] == "dns6-lire":
            return 0, json.dumps({"dns": self.dns6, "use_custom_dns": self.perso6})
        if v[0] == "ip-fixe-lire":
            return 0, json.dumps({"mac": "AA:BB:CC:DD:EE:FF", "ip": self.bail})
        if not self.droit:
            return 1, json.dumps({"erreur": "droit"})
        if v[0] == "dns-regler":
            self.dns = [x for x in v[1].split(",") if x]
        if v[0] == "dns6-regler":
            self.perso6, self.dns6 = v[1] == "1", [x for x in (v[2] if len(v) > 2 else "").split(",") if x]
        if v[0] == "ip-fixe-poser":
            self.bail = v[1]
        if v[0] == "bail-poser":
            self.bail = v[2]
            self.echec = None
        if self.echec and v[0] == self.echec:
            return 1, json.dumps({"erreur": "panne"})
        if v[0] == "ip-fixe-retirer":
            self.bail = ""
        return 0, json.dumps({"mac": "AA:BB:CC:DD:EE:FF"})


@pytest.fixture
def k(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "AUDIT", tmp_path / "audit.log")
    monkeypatch.setattr(C, "durable", lambda: True)
    src = tmp_path / "src"
    src.write_text("x")
    return dict(etat_f=tmp_path / "m/e.json", retire=tmp_path / "r", conf=tmp_path / "u.conf", nft=tmp_path / "z.nft"), src


def act(f, k):
    return C.activer(f, source=k[1], **k[0])


def ret(f, k, **a):
    return C.retirer(f, **k[0], **a)


def etat(k):
    return json.loads(k[0]["etat_f"].read_text())


def test_activation_un_seul_dns_origine_gardee(k):
    f = Faux()
    assert act(f, k)["etat"] == "actif" and f.dns == ["192.168.1.50"]
    assert etat(k)["dns_origine"] == ["192.168.1.254"]


def test_retrait_rend_tout(k):
    f = Faux()
    act(f, k)
    r = ret(f, k)
    assert r["detail"] == "rendu" and f.dns == ["192.168.1.254"] and f.dns6 == ["2001:db8::1"] and not f.perso6
    assert f.bail == "" and not k[0]["conf"].exists() and not k[0]["nft"].exists() and not k[0]["etat_f"].exists()


def test_dns_muet_jamais_de_bascule(k):
    f = Faux()
    f.dig_ok = False
    assert act(f, k)["etat"] == "erreur_dns" and f.dns == ["192.168.1.254"]


def test_nft_refuse_jamais_de_bascule(k):
    f = Faux()
    f.nft_ok = False
    assert act(f, k)["etat"] == "erreur_dns" and f.dns == ["192.168.1.254"]


def test_unbound_invalide_defait_et_pas_de_bascule(k):
    f = Faux()
    f.check_ok = False
    assert act(f, k)["etat"] == "erreur_dns" and not k[0]["conf"].exists() and f.dns == ["192.168.1.254"]


def test_etat_perdu_jamais_notre_adresse_comme_origine(k):
    f = Faux(dns=["192.168.1.50"])
    assert act(f, k)["freebox"] == "origine_inconnue"
    assert "dns_origine" not in C.lire_etat(k[0]["etat_f"])


def test_origine_ecrite_avant_le_changement_de_dns(k):
    f = Faux()
    vu = {}
    fb = f.fb

    def espion(v):
        if v[0] == "dns-regler":
            vu["origine"] = etat(k).get("dns_origine")
        return fb(v)
    f.fb = espion
    act(f, k)
    assert vu["origine"] == ["192.168.1.254"]


def test_echec_freebox_ne_fausse_pas_l_adresse_posee(k):
    f = Faux()
    act(f, k)
    f.droit = False
    f.ip = "192.168.1.77"
    assert act(f, k)["freebox"] == "droit_requis" and "192.168.1.50" in etat(k)["ips_posees"]
    f.droit = True
    assert ret(f, k)["detail"] == "rendu" and f.dns == ["192.168.1.254"]


def test_autre_pc_suit_l_adresse(k):
    f = Faux()
    act(f, k)
    f.ip = "192.168.1.77"
    act(f, k)
    assert f.dns == ["192.168.1.77"] and etat(k)["dns_origine"] == ["192.168.1.254"]


def test_reglage_de_l_utilisateur_ni_reecrit_ni_ecrase(k):
    f = Faux()
    act(f, k)
    f.dns = ["9.9.9.9"]
    assert act(f, k)["freebox"] == "repris" and f.dns == ["9.9.9.9"]
    assert ret(f, k)["detail"] == "laisse" and f.dns == ["9.9.9.9"]


def test_autre_freebox_rien_touche(k):
    f = Faux()
    act(f, k)
    f.dns, f.gw, f.ip = ["10.0.0.1"], "192.168.1.1", "192.168.1.60"
    assert act(f, k)["freebox"] == "autre_reseau" and f.dns == ["10.0.0.1"]


def test_retrait_echoue_garde_tout_le_dns_de_la_cle_reste_ouvert(k):
    f = Faux()
    act(f, k)
    f.autorise = False
    assert ret(f, k)["etat"] == "dns_non_rendu"
    assert k[0]["etat_f"].exists() and k[0]["conf"].exists() and k[0]["nft"].exists()


def test_retrait_manuel_en_attente_est_retente_par_le_suivi(k):
    f = Faux()
    act(f, k)
    f.autorise = False
    ret(f, k, manuel=True)
    f.autorise = True
    assert act(f, k)["etat"] == "retiree" and f.dns == ["192.168.1.254"]
    assert act(f, k)["etat"] == "retiree"


def test_bail_de_l_utilisateur_rendu(k):
    f = Faux()
    f.bail = "192.168.1.9"
    act(f, k)
    ret(f, k)
    assert f.bail == "192.168.1.9"


def test_reponse_anormale_n_est_pas_aucun_dns(k):
    f = Faux()
    f.fb = lambda v: (0, json.dumps({"dns": None}))
    assert act(f, k)["freebox"] == "autorisation_requise" and "dns_origine" not in C.lire_etat(k[0]["etat_f"])


@pytest.mark.parametrize("ip,gw,dev", [("82.67.100.75", "82.67.100.1", "eth0"), ("169.254.1.2", "169.254.1.1", "eth0"),
                                       ("10.8.0.2", "10.8.0.1", "wg0"), ("192.168.1.5", "192.168.9.1", "eth0")])
def test_jamais_hors_du_reseau_local(k, ip, gw, dev):
    assert act(Faux(ip=ip, gw=gw, dev=dev), k)["etat"] == "pas_de_reseau" and not k[0]["conf"].exists()


def test_ipv6_couvert_sans_adresse_temporaire(k):
    f = Faux()
    act(f, k)
    assert f.dns6 == ["2001:db8::50"] and f.perso6 and etat(k)["ipv6"] == "actif"
    assert "2001:db8::dead" not in k[0]["conf"].read_text()


def test_sans_ipv6_le_contournement_est_signale(k):
    f = Faux()
    f.ip6 = ""
    act(f, k)
    assert etat(k)["ipv6"] == "contournement_possible" and f.dns6 == ["2001:db8::1"]


def test_regles_inchangees_rien_ne_bouge(k):
    f = Faux()
    act(f, k)
    f.appels.clear()
    act(f, k)
    assert not [c for c in f.appels if c[:2] == ["nft", "-f"] or c[:2] == ["nft", "delete"]]
    assert ["systemctl", "restart", "unbound"] not in f.appels


def test_nft_limite_a_l_interface_et_au_reseau():
    t = C.rendu_nft({"dev": "eth0", "reseau": "192.168.1.0/24"})
    assert t.count("add rule") == 2 and 'iifname "eth0" ip saddr 192.168.1.0/24' in t


def test_etat_ne_livre_ni_origine_ni_mac(k, tmp_path):
    f = Faux()
    act(f, k)
    r = C.etat_complet(f, k[0]["etat_f"], k[0]["retire"], k[1], tmp_path / "absent")
    assert r["freebox"] == "actif" and "dns_origine" not in r and "mac" not in r


def test_routes_gardees():
    api = (CHEMIN.parents[1] / "api/main.py").read_text()
    assert '@app.post("/retirer", dependencies=[Depends(require_jwt)])' in api
    assert '@app.post("/reactiver", dependencies=[Depends(require_jwt)])' in api
    assert '@app.get("/etat", dependencies=[Depends(require_lecture)])' in api


def test_page_guide_le_retrait_et_la_freebox():
    page = (CHEMIN.parents[1] / "www/mobile/index.html").read_text(encoding="utf-8")
    for t in ("Retirer la clé", "Modification des réglages", "Clé arrachée", "sbx_token", "contournement_possible"):
        assert t in page


def test_exception_root_documentee_et_unite_confinee():
    racine = CHEMIN.parents[3]
    assert "`secubox-mobile.service`" in (racine / ".claude/RULES-CODE.md").read_text(encoding="utf-8")
    u = (CHEMIN.parents[1] / "systemd/secubox-mobile.service").read_text()
    for d in ("ProtectSystem=strict", "UMask=0027", "ReadWritePaths="):
        assert d in u


def test_api_a_son_profil_apparmor():
    u = (CHEMIN.parents[1] / "systemd/secubox-mobile-api.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-mobile-api" in u
    assert "/usr/sbin/secubox-mobile-api flags=(attach_disconnected) {" in (CHEMIN.parents[1] / "apparmor/secubox-mobile-api").read_text()


def test_dns6_change_par_l_utilisateur_ni_reecrit_ni_ecrase(k):
    f = Faux()
    act(f, k)
    f.dns6 = ["2001:db8::9"]
    act(f, k)
    assert f.dns6 == ["2001:db8::9"] and etat(k)["ipv6"] == "repris"
    ret(f, k)
    assert f.dns6 == ["2001:db8::9"]


def test_echec_ipv6_au_retrait_garde_l_etat_et_retente(k):
    f = Faux()
    act(f, k)
    f.echec = "dns6-regler"
    assert ret(f, k)["etat"] == "dns_non_rendu" and etat(k)["dns6_origine"]
    assert f.dns == ["192.168.1.254"]
    f.echec = None
    assert ret(f, k)["etat"] == "retiree" and f.dns6 == ["2001:db8::1"]


def test_echec_bail_au_retrait_retente(k):
    f = Faux()
    act(f, k)
    f.echec = "ip-fixe-retirer"
    assert ret(f, k)["etat"] == "dns_non_rendu"
    f.echec = None
    assert ret(f, k)["etat"] == "retiree" and f.bail == ""


def test_expiration_apres_ecriture_reconnue_au_retrait(k):
    f = Faux()
    fb = f.fb

    def applique_puis_expire(v):
        r = fb(v)
        return (1, "") if v[0] == "dns-regler" else r
    f.fb = applique_puis_expire
    act(f, k)
    assert f.dns == ["192.168.1.50"]
    f.fb = fb
    assert ret(f, k)["detail"] == "rendu" and f.dns == ["192.168.1.254"]


def test_retrait_sur_une_autre_freebox_ne_touche_rien(k):
    f = Faux()
    act(f, k)
    f.dns, f.gw, f.ip = ["10.0.0.1"], "192.168.1.1", "192.168.1.60"
    assert ret(f, k)["detail"] == "autre_reseau" and f.dns == ["10.0.0.1"] and etat(k)["dns_origine"]


def test_ancienne_adresse_de_la_liste_jamais_origine(k):
    assert act(Faux(dns=["192.168.1.50", "9.9.9.9"]), k)["freebox"] == "origine_inconnue"


def test_origine_mal_formee_n_est_pas_rendue(k):
    k[0]["etat_f"].parent.mkdir()
    k[0]["etat_f"].write_text(json.dumps({"dns_origine": "pas une liste", "reseau": "192.168.1.254"}))
    assert "dns_origine" not in C.lire_etat(k[0]["etat_f"])


def test_dns_muet_apres_bascule_rend_le_reseau(k):
    f = Faux()
    act(f, k)
    f.dig_ok = False
    assert act(f, k)["etat"] == "erreur_dns" and f.dns == ["192.168.1.254"]
    assert ["systemctl", "restart", "unbound"] in f.appels


def test_sans_persistance_le_reseau_n_est_pas_touche(k, monkeypatch):
    monkeypatch.setattr(C, "durable", lambda: False)
    f = Faux()
    assert act(f, k)["freebox"] == "non_durable" and f.dns == ["192.168.1.254"]


def test_freebox_jointe_par_son_adresse(k):
    f = Faux()
    act(f, k)
    assert "SECUBOX_FREEBOX_HOTE=http://192.168.1.254" in [c for c in f.appels if c[0] == "timeout"][0]


def test_fifo_jamais_lue(tmp_path, k):
    import os
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    r = C.etat_complet(Faux(), k[0]["etat_f"], k[0]["retire"], k[1], fifo)
    assert r["bloques"] == 0


def test_marqueur_de_persistance_hors_de_la_branche_slipstream():
    b = (CHEMIN.parents[3] / "image/build-live-usb.sh").read_text(encoding="utf-8")
    assert b.index('touch "${ROOTFS}/var/lib/secubox/.persistent"') < b.index('log "Creating build metadata..."')
    assert b.index('touch "${ROOTFS}/var/lib/secubox/.persistent"') > b.index('rm -rf "${ROOTFS}/tmp/secubox-debs"')


def test_listes_compilees_par_leur_unite(tmp_path, k):
    f = Faux()
    C.activer(f, source=tmp_path / "absent", **k[0])
    assert ["systemctl", "start", "secubox-adblock-sync.service"] in f.appels


def test_socket_de_l_api_fermee_apres_le_demarrage():
    u = (CHEMIN.parents[1] / "systemd/secubox-mobile-api.service").read_text()
    assert "chmod 660 /run/secubox/mobile.sock" in u
