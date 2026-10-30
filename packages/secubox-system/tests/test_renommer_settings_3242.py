# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3242 (et #3126 L2 tâche 5) — POST /settings : le renommage échouait en silence.

CONSTAT (ESPRESSObin v7, futur gk5, 2026-10-28) : `hostnamectl set-hostname` lancé sous User=secubox (polkit refuse), code
de retour non lu, `{"success": true}` rendu ; même chose pour `timedatectl set-timezone` ; et hostnamectl seul oubliait
/etc/hosts et secubox.conf.
Parade, au patron de la page (#2788) : l'API (NoNewPrivileges, sudo neutralisé) démarre l'unité ROOT
`secubox-systeme-renommer@<nom>.service` (règle polkit bornée au sujet secubox-system.service), qui lance
/usr/sbin/secubox-renommer ; le code de sortie (ExecMainStatus) est lu et rendu avec son message."""
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
UNITE = "secubox-systeme-renommer@gk5.service"


def charge_api():
    spec = importlib.util.spec_from_file_location("api_systeme_3242", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Res:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.stderr, self.returncode = out, err, rc


@pytest.fixture(scope="module")
def api():
    return charge_api()


@pytest.fixture
def audits(api, monkeypatch):
    lignes = []
    monkeypatch.setattr(api.unites, "journaliser", lambda *a, **k: lignes.append(a))
    return lignes


def faux(appels, start_rc=0, statut="0", tz_rc=0, tz_err=""):
    def run(argv, *a, **k):
        appels.append(list(argv))
        assert k.get("timeout"), "toute commande est bornée"
        if argv[:2] == ["systemctl", "start"]:
            return Res("", start_rc, "Job for x failed." if start_rc else "")
        if argv[:2] == ["systemctl", "show"]:
            return Res(statut + "\n")
        if argv[0] == "timedatectl":
            return Res("", tz_rc, tz_err)
        return Res()
    return run


def test_settings_rend_l_echec(api, audits, monkeypatch):
    """Le cœur de #3242 : un renommage refusé n'est plus un succès. Code réel de secubox-renommer, message réel."""
    for statut, http, message in (("4", 409, "nom déjà pris au maillage"), ("6", 502, "hostnamectl en échec"),
                                  ("5", 500, "écriture impossible"), ("1", 500, "audit impossible"),
                                  ("77", 502, "renommage en échec")):
        appels = []
        monkeypatch.setattr(api.subprocess, "run", faux(appels, start_rc=1, statut=statut))
        with pytest.raises(HTTPException) as e:
            api.settings({"hostname": "gk5"}, user={"sub": "gk2admin"})
        assert e.value.status_code == http, statut
        assert message in e.value.detail and f"code {statut}" in e.value.detail, e.value.detail
        assert appels[0] == ["systemctl", "start", "--", UNITE]
        assert ["systemctl", "show", "-p", "ExecMainStatus", "--value", "--", UNITE] in appels
        assert not any(a[0] == "hostnamectl" for a in appels)
    assert all(a[3] == UNITE and a[4] == "echec" and a[1] == "gk2admin" for a in audits)


def test_settings_renomme_par_l_unite_root(api, audits, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux(appels))
    r = api.settings({"hostname": " GK5 "}, user={"sub": "gk2admin"})
    assert r["success"] is True and r["hostname"] == "gk5"
    assert appels == [["systemctl", "start", "--", UNITE]]
    assert audits == [("system", "gk2admin", "start", UNITE, "ok", 200)]


def test_settings_refuse_un_nom_invalide_sans_rien_lancer(api, audits, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux(appels))
    for nom, motif in (("gk_5", "nom invalide"), ("-gk5", "nom invalide"), ("a" * 64, "nom invalide"),
                       ("gk5;reboot", "nom invalide"), ("../x", "nom invalide"), ("admin", "nom réservé"),
                       ("localhost", "nom réservé")):
        with pytest.raises(HTTPException) as e:
            api.settings({"hostname": nom}, user={"sub": "gk2admin"})
        assert e.value.status_code == 400 and motif in e.value.detail, nom
    assert appels == [] and audits == []


def test_settings_delai_et_systemctl_absent(api, audits, monkeypatch):
    def lent(argv, *a, **k):
        raise subprocess.TimeoutExpired(argv, k.get("timeout"))
    monkeypatch.setattr(api.subprocess, "run", lent)
    with pytest.raises(HTTPException) as e:
        api.settings({"hostname": "gk5"}, user={"sub": "gk2admin"})
    assert e.value.status_code == 504

    def absent(argv, *a, **k):
        raise FileNotFoundError("systemctl")
    monkeypatch.setattr(api.subprocess, "run", absent)
    with pytest.raises(HTTPException) as e:
        api.settings({"hostname": "gk5"}, user={"sub": "gk2admin"})
    assert e.value.status_code == 503


def test_settings_fuseau_rend_l_echec(api, audits, monkeypatch):
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux(appels, tz_rc=1, tz_err="Access denied"))
    with pytest.raises(HTTPException) as e:
        api.settings({"timezone": "Europe/Paris"}, user={"sub": "gk2admin"})
    assert e.value.status_code == 502 and "Access denied" in e.value.detail
    assert appels == [["timedatectl", "set-timezone", "--", "Europe/Paris"]]
    appels.clear()
    with pytest.raises(HTTPException) as e:
        api.settings({"timezone": "../../etc/passwd"}, user={"sub": "gk2admin"})
    assert e.value.status_code == 400 and appels == []
    monkeypatch.setattr(api.subprocess, "run", faux(appels))
    assert api.settings({"timezone": "America/Port-au-Prince"}, user={"sub": "x"})["success"] is True


def test_unite_renommer_livree_root_et_bornee():
    u = (SYSTEM / "systemd" / "secubox-systeme-renommer@.service").read_text()
    assert u.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    actives = [x for x in u.splitlines() if x and not x.startswith("#")]
    assert "Type=oneshot" in actives and not any(x.startswith("User=") for x in actives)
    assert "ExecStart=/usr/sbin/secubox-renommer %i\n" in u          # %i : instance brute, jamais %I (« - » → « / »)
    assert re.search(r"^TimeoutStartSec=\d+$", u, re.M)
    # bac à sable : système en lecture seule sauf ce que l'outil écrit (/etc/hosts et /etc/secubox par renommage
    # atomique dans leur dossier, verrou dans /run, audit)
    for ligne in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/etc /run /var/log/secubox",
                  "ProtectHome=yes", "PrivateTmp=yes"):
        assert ligne in actives, ligne
    regles = (SYSTEM / "debian" / "rules").read_text()
    assert "systemd/secubox-systeme-renommer@.service" in regles
    assert "renommer" not in regles.split("override_dh_installsystemd:")[1]     # jamais démarrée à l'installation
    assert "secubox-core (>= 1.8.10~)" in (SYSTEM / "debian" / "control").read_text()
    # la règle polkit existante l'accepte (sujet secubox-system.service, unités secubox-*.service)
    regle = (SYSTEM / "polkit" / "50-secubox-system.rules").read_text()
    motif = re.search(r"/(\^secubox-[^/]+)/\.test\(unite\)", regle).group(1)
    assert re.match(motif, UNITE)


def test_polkit_fuseau_borne_a_l_unite_de_l_api():
    regle = (SYSTEM / "polkit" / "50-secubox-system.rules").read_text()
    assert "org.freedesktop.timedate1.set-timezone" in regle
    bloc = regle[regle.index("org.freedesktop.timedate1.set-timezone") - 200:]
    assert 'subject.system_unit !== "secubox-system.service"' in bloc
    assert "timedate1.set-time\"" not in regle and "set-ntp" not in regle         # le fuseau seulement


# ── Relecture de la tâche 5, tour 1 (R-L2-36) ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("actuel,envoye", [("secubox", "secubox"), ("SECUBOX", "secubox"), ("Secubox_Live", "Secubox_Live"),
                                           ("gk5", "GK5")])
def test_fuseau_seul_sur_une_box_au_nom_reserve_ou_hors_motif(api, audits, monkeypatch, actuel, envoye):
    """I2 : la page renvoie le nom actuel ; le nom par défaut « secubox » est réservé, un nom d'image peut être hors
    libellé DNS. Ce n'est pas un renommage : aucun 400, aucune unité, le fuseau est appliqué."""
    appels = []
    monkeypatch.setattr(api.subprocess, "run", faux(appels))
    monkeypatch.setattr(api.socket, "gethostname", lambda: actuel)
    r = api.settings({"hostname": envoye, "timezone": "Europe/Paris"}, user={"sub": "gk2admin"})
    assert r["success"] is True and r["timezone"] == "Europe/Paris" and "hostname" not in r
    assert appels == [["timedatectl", "set-timezone", "--", "Europe/Paris"]] and audits == []


def test_page_n_envoie_le_nom_que_s_il_a_change():
    page = (SYSTEM / "www" / "system" / "index.html").read_text(encoding="utf-8")
    assert "{ hostname: $('newHost').value, timezone: $('newTz').value }" not in page
    assert "NOM_CHARGE" in page and "if (nom && nom !== NOM_CHARGE) corps.hostname = nom;" in page


def test_polkit_renommer_start_seulement_instance_dns():
    """M3 : une branche dédiée borne secubox-systeme-renommer@ au verbe start et à une instance au motif DNS ; la règle
    générale reste pour les autres unités."""
    regle = (SYSTEM / "polkit" / "50-secubox-system.rules").read_text()
    assert "secubox-systeme-renommer@" in regle
    bloc = regle[regle.index("secubox-systeme-renommer@") - 400:regle.index("secubox-systeme-renommer@") + 600]
    assert 'verbe === "start"' in bloc and "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?" in bloc
    assert "polkit.Result.NO" in bloc
    assert '["start", "stop", "restart", "reload"]' in regle                  # règle générale gardée
