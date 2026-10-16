# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2788 — actions rapides de /system/ : réelles quand elles peuvent l'être, honnêtes quand elles échouent.

CONSTAT (gk2) : l'API tourne en User=secubox, NoNewPrivileges : `systemctl reload nftables` et `timedatectl set-ntp` répondaient « Interactive authentication
required » ; l'API rendait `{"success": false}` en HTTP 200 SANS raison (« Échec : HTTP 200 »). « Redémarrer les services » ignorait le code retour,
« Éteindre » / « Redémarrer la machine » répondaient « programmé » sans contrôle, « Vider les caches » écrivait /proc sans droit.
Parade : des unités root `secubox-systeme-*.service` démarrées par `systemctl start`, autorisées par la règle polkit existante (sujet secubox-system.service, unités secubox-*)."""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

PAQUETS = Path(__file__).resolve().parents[2]
SYSTEM = PAQUETS / "secubox-system"
sys.path.insert(0, str(PAQUETS.parent / "common"))

UNITES = {
    "reload_firewall": "secubox-systeme-pare-feu-verif.service",
    "sync_time": "secubox-systeme-heure.service",
    "clear_cache": "secubox-systeme-caches.service",
    "reboot": "secubox-systeme-redemarrer.service",
    "shutdown": "secubox-systeme-eteindre.service",
}


def charge_api():
    spec = importlib.util.spec_from_file_location("api_systeme_2788", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Res:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.stderr, self.returncode = out, err, rc


@pytest.fixture(scope="module")
def api():
    return charge_api()


def faux_systemctl(appels, rc=0, err="", journal=""):
    def run(argv, *a, **k):
        appels.append(list(argv))
        if argv[0] == "journalctl":
            return Res(journal)
        return Res("", rc, err)
    return run


# ---------- les unités ----------

@pytest.mark.parametrize("unite", UNITES.values())
def test_chaque_unite_est_livree_et_root_oneshot(unite):
    u = (SYSTEM / "systemd" / unite).read_text()
    assert "Type=oneshot" in u and "User=" not in u.replace("# User=", ""), "root : c'est tout l'intérêt"
    assert "ExecStart=" in u


@pytest.mark.parametrize("unite", UNITES.values())
def test_les_noms_d_unite_passent_la_regle_polkit_existante(unite):
    """La règle (50-secubox-system.rules) n'autorise que /^secubox-[A-Za-z0-9@._-]+\\.service$/ et les verbes start/stop/restart/reload."""
    regle = (SYSTEM / "polkit" / "50-secubox-system.rules").read_text()
    motif = re.search(r"test\(unite\)|\.test\(unite\)", regle) and re.search(r"/(\^secubox-[^/]+)/\.test", regle).group(1)
    assert re.match(motif, unite), (motif, unite)


def test_le_pare_feu_n_est_jamais_recharge_a_sec():
    """`/etc/nftables.conf` commence par `flush ruleset` : un rechargement viderait les ensembles dynamiques (bannissements du WAF…). On VÉRIFIE seulement."""
    u = (SYSTEM / "systemd" / UNITES["reload_firewall"]).read_text()
    assert "nft -c -f /etc/nftables.conf" in u and "reload" not in u.lower().replace("reloadés", "")


def test_les_actions_de_puissance_programment_dans_une_minute():
    assert "shutdown -r +1" in (SYSTEM / "systemd" / UNITES["reboot"]).read_text()
    assert "shutdown -h +1" in (SYSTEM / "systemd" / UNITES["shutdown"]).read_text()


def test_les_unites_sont_installees_par_le_paquet():
    rules = (SYSTEM / "debian" / "rules").read_text()
    for unite in UNITES.values():
        assert unite in rules, unite


def test_les_caches_ont_besoin_du_noyau_en_ecriture():
    u = (SYSTEM / "systemd" / UNITES["clear_cache"]).read_text()
    assert "drop_caches" in u and "ProtectKernelTunables=true" not in u


# ---------- l'API ----------

def test_une_action_reussie_dit_ce_qu_elle_a_fait(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels))
    r = api.sync_time(user={"sub": "admin"})
    assert r["success"] is True and appels[0] == ["systemctl", "start", UNITES["sync_time"]]


def test_une_action_refusee_donne_la_vraie_raison_pas_http_200_muet(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels, rc=1, err="Failed to start: Interactive authentication required.", journal="ligne du journal"))
    with pytest.raises(HTTPException) as e:
        api.sync_time(user={"sub": "admin"})
    assert e.value.status_code == 502 and "Interactive authentication required" in e.value.detail


def test_la_raison_vient_du_journal_quand_systemctl_se_tait(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels, rc=1, err="", journal="nft: erreur de syntaxe ligne 42"))
    with pytest.raises(HTTPException) as e:
        api.reload_firewall(user={"sub": "admin"})
    assert "erreur de syntaxe ligne 42" in e.value.detail


def test_recharger_le_pare_feu_verifie_la_configuration_sans_la_charger(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels))
    r = api.reload_firewall(user={"sub": "admin"})
    assert appels[0] == ["systemctl", "start", UNITES["reload_firewall"]]
    assert r["success"] is True and "vérifi" in r["message"].lower() and "non rechargé" in r["message"].lower()


def test_vider_les_caches_passe_par_l_unite_root(api, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels))
    assert api.clear_cache(user={"sub": "admin"})["success"] is True and appels[0][2] == UNITES["clear_cache"]


@pytest.mark.parametrize("fn,cle", [("reboot", "reboot"), ("shutdown", "shutdown")])
def test_la_puissance_n_annonce_rien_si_la_commande_echoue(api, monkeypatch, fn, cle):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels, rc=1, err="refusé"))
    monkeypatch.setattr(api.subprocess, "Popen", lambda *a, **k: pytest.fail("plus de Popen aveugle"))
    with pytest.raises(HTTPException):
        getattr(api, fn)(user={"sub": "admin"})


@pytest.mark.parametrize("fn,cle,mot", [("reboot", "reboot", "redémarrage"), ("shutdown", "shutdown", "extinction")])
def test_la_puissance_programmee_est_annoncee_apres_succes(api, monkeypatch, fn, cle, mot):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux_systemctl(appels))
    r = getattr(api, fn)(user={"sub": "admin"})
    assert r["success"] is True and mot in r["message"].lower() and appels[0][2] == UNITES[cle]


def test_le_delai_d_une_unite_est_une_erreur_pas_un_succes(api, monkeypatch):
    def lent(argv, *a, **k):
        raise subprocess.TimeoutExpired(argv, 30)
    monkeypatch.setattr(api.subprocess, "run", lent)
    with pytest.raises(HTTPException) as e:
        api.sync_time(user={"sub": "admin"})
    assert e.value.status_code == 504 and "délai" in e.value.detail.lower()


def test_le_redemarrage_en_bloc_des_services_est_refuse_honnetement(api, monkeypatch):
    """Il relançait hub, auth, nginx… et secubox-system lui-même, sans contrôler le code retour : un redémarrage général de l'agrégateur coupe l'admin dix minutes."""
    monkeypatch.setattr(api.subprocess, "run", lambda *a, **k: pytest.fail("aucun redémarrage en bloc"))
    with pytest.raises(HTTPException) as e:
        api.restart_services(user={"sub": "admin"})
    assert e.value.status_code == 409 and "module" in e.value.detail.lower()


# ---------- la page ----------

PAGE = (SYSTEM / "www" / "system" / "index.html").read_text(encoding="utf-8")


def test_la_page_affiche_la_raison_d_un_echec_meme_en_200():
    ligne = next(l for l in PAGE.splitlines() if l.strip().startswith("function detail(res)"))
    for champ in ("data.detail", "data.error", "data.message", "data.output"):
        assert champ in ligne, champ
    assert "HTTP ' + res.statut" in ligne, "le code seul reste le dernier recours"


def test_l_installation_ne_demarre_jamais_les_unites_d_action():
    """Sans override, le postinst de debhelper fait `deb-systemd-invoke start` sur TOUTES les unites : la mise a jour eteindrait la machine."""
    rules = (SYSTEM / "debian" / "rules").read_text()
    bloc = rules.split("override_dh_installsystemd:")[1]
    assert "dh_installsystemd secubox-admin.service secubox-ksm.service secubox-system.service" in bloc
    assert "secubox-systeme" not in bloc
