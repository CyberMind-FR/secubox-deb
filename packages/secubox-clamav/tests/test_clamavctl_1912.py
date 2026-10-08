# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""clamavctl : réveil à la demande, sommeil, âge de la base (#1912) — sans toucher à un vrai LXC."""
import importlib.machinery
import importlib.util
import os
import socket
import threading
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("clamavctl_t", str(PKG / "sbin" / "clamavctl"))
spec = importlib.util.spec_from_loader("clamavctl_t", loader)
c = importlib.util.module_from_spec(spec)
loader.exec_module(c)


class Rep:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class LxcFaux:
    """Simule lxc-info / lxc-start / lxc-stop ; l'état évolue comme celui d'un vrai conteneur."""
    def __init__(self, etat="STOPPED"):
        self.etat, self.appels = etat, []

    def __call__(self, cmd, **k):
        self.appels.append(cmd[0])
        if cmd[0] == "lxc-info":
            return Rep(0, self.etat) if self.etat != "ABSENT" else Rep(1)
        if cmd[0] == "lxc-start":
            self.etat = "RUNNING"
            return Rep(0)
        if cmd[0] == "lxc-stop":
            self.etat = "STOPPED"
            return Rep(0)
        return Rep(0)


@pytest.fixture(autouse=True)
def etat_temp(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "ETAT", tmp_path / "etat.json")


def test_deja_eveille_ne_demarre_rien():
    lxc = LxcFaux("RUNNING")
    assert c.reveiller(run=lxc, ping_fn=lambda: True) is True
    assert "lxc-start" not in lxc.appels


def test_endormi_est_demarre_puis_on_attend_pong():
    lxc = LxcFaux("STOPPED")
    reponses = iter([False, False, False, True])             # clamd charge sa base : quelques tours
    horloge = iter(range(0, 1000, 2))
    ok = c.reveiller(delai=60, run=lxc, ping_fn=lambda: next(reponses), dormir=lambda s: None,
                     maintenant=lambda: float(next(horloge)))
    assert ok is True and lxc.appels.count("lxc-start") == 1
    assert (c.ETAT).exists()                                  # horodatage du réveil et temps de démarrage


def test_clamd_qui_ne_repond_jamais_est_un_echec_pas_une_attente_infinie():
    lxc = LxcFaux("STOPPED")
    horloge = iter(range(0, 10000, 5))
    assert c.reveiller(delai=30, run=lxc, ping_fn=lambda: False, dormir=lambda s: None,
                       maintenant=lambda: float(next(horloge))) is False


def test_lxc_absent_renvoie_vers_install(capsys):
    assert c.reveiller(run=LxcFaux("ABSENT"), ping_fn=lambda: False) is False
    assert "clamavctl install" in capsys.readouterr().err


def test_sommeil_arrete_le_conteneur_et_ne_fait_rien_s_il_dort():
    lxc = LxcFaux("RUNNING")
    assert c.endormir(run=lxc) is True and lxc.etat == "STOPPED"
    avant = lxc.appels.count("lxc-stop")
    assert c.endormir(run=lxc) is True and lxc.appels.count("lxc-stop") == avant


def test_age_de_la_base_lu_sur_le_disque_conteneur_endormi(tmp_path):
    base = tmp_path / "clamav" / "rootfs" / "var" / "lib" / "clamav"
    base.mkdir(parents=True)
    (base / "daily.cld").write_text("x")
    (base / "main.cvd").write_text("x")
    ancien = os.stat(base / "main.cvd").st_mtime - 3 * 86400
    os.utime(base / "main.cvd", (ancien, ancien))
    ages = c.age_base_jours(chemin=str(tmp_path))
    assert set(ages) == {"daily", "main"} and 2.9 < ages["main"] < 3.1 and ages["daily"] < 0.1


def test_statut_base_a_jour_seulement_si_les_deux_fichiers_sont_recents(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "age_base_jours", lambda: {"daily": 1.0})
    e = c.etat_complet(run=LxcFaux("STOPPED"), ping_fn=lambda: False)
    assert e["base_a_jour"] is False and e["clamd"] is False and e["lxc"] == "STOPPED"
    monkeypatch.setattr(c, "age_base_jours", lambda: {"daily": 1.0, "main": 2.0})
    assert c.etat_complet(run=LxcFaux("RUNNING"), ping_fn=lambda: True)["base_a_jour"] is True
    monkeypatch.setattr(c, "age_base_jours", lambda: {"daily": 30.0, "main": 2.0})
    assert c.etat_complet(run=LxcFaux("STOPPED"), ping_fn=lambda: False)["base_a_jour"] is False   # périmée


def test_ping_parle_le_protocole_clamd():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serveur():
        conn, _ = srv.accept()
        assert conn.recv(16) == b"zPING\0"
        conn.sendall(b"PONG\0")
        conn.close()
    t = threading.Thread(target=serveur, daemon=True)
    t.start()
    assert c.ping("127.0.0.1", port) is True
    t.join(2)
    srv.close()
    assert c.ping("127.0.0.1", port, delai=0.3) is False      # plus personne n'écoute


# ── Les unités : le contrat du mandataire à la demande ────────────────────────

def _unite(nom):
    return (PKG / "systemd" / nom).read_text()


def test_le_mandataire_reveille_puis_rendort():
    s = _unite("secubox-clamav-proxy.service")
    assert "ExecStartPre=/usr/sbin/clamavctl wake" in s
    assert "ExecStopPost=/usr/sbin/clamavctl sleep" in s
    assert "--exit-idle-time=600s 10.100.0.220:3310" in s
    assert "TimeoutStartSec=300" in s                          # démarrage à froid, base comprise


def test_le_socket_n_ecoute_que_sur_le_pont_des_conteneurs():
    s = _unite("secubox-clamav-proxy.socket")
    assert "ListenStream=10.100.0.1:3310" in s and "FreeBind=true" in s
    assert "0.0.0.0" not in s


def test_le_conteneur_ne_demarre_pas_au_boot_et_clamd_n_ecoute_que_sur_son_ip():
    i = (PKG / "lxc" / "install-lxc.sh").read_text()
    assert "lxc.start.auto = 0" in i
    # L'écoute TCP se déclare sur l'UNITÉ SOCKET : clamd, démarré par activation de socket, ignore
    # TCPSocket de clamd.conf (régression mesurée sur gk2 : rien n'écoutait sur 3310).
    assert "clamav-daemon.socket.d/tcp.conf" in i and "ListenStream=$LXC_IP:$PORT" in i
    assert "ListenStream=0.0.0.0" not in i and "TCPAddr 0.0.0.0" not in i
    assert "TCPSocket" not in i.split("# secubox-clamav (#1912)")[1].split("CONF")[0]
    assert "ConcurrentDatabaseReload no" in i and "lxc.cgroup2.memory.max = 1800M" in i


def test_mise_a_jour_hebdomadaire():
    assert "OnCalendar=Sun" in _unite("secubox-clamav-update.timer")
    assert "clamavctl update" in _unite("secubox-clamav-update.service")


# ── État sans privilège (health-doctor tourne sous `secubox`, #1912) ───────────────

def test_sans_privilege_on_rend_le_dernier_etat_connu_pas_absent(monkeypatch):
    import json
    import time
    c.ETAT.write_text(json.dumps({"dernier_etat": "STOPPED", "base": {"ages": {"daily": 0.5, "main": 2.0}, "ts": time.time() - 86400}}))
    monkeypatch.setattr(c, "age_base_jours", lambda: {})          # rootfs illisible
    e = c.etat_complet(run=LxcFaux("ABSENT"), ping_fn=lambda: False)
    assert e["lxc"] == "STOPPED" and e["source"] == "cache"       # PAS « ABSENT » : un faux positif
    assert e["base_a_jour"] is True and 1.4 < e["base_age_jours"]["daily"] < 1.6   # vieilli d'un jour


def test_base_du_cache_perimee_reste_une_alerte(monkeypatch):
    import json
    import time
    c.ETAT.write_text(json.dumps({"dernier_etat": "STOPPED", "base": {"ages": {"daily": 5.0, "main": 5.0}, "ts": time.time() - 8 * 86400}}))
    monkeypatch.setattr(c, "age_base_jours", lambda: {})
    assert c.etat_complet(run=LxcFaux("ABSENT"), ping_fn=lambda: False)["base_a_jour"] is False   # 5 + 8 > 10


def test_vraiment_absent_sans_cache_reste_absent(monkeypatch):
    monkeypatch.setattr(c, "age_base_jours", lambda: {})
    e = c.etat_complet(run=LxcFaux("ABSENT"), ping_fn=lambda: False)
    assert e["lxc"] == "ABSENT" and e["base_a_jour"] is False


def test_le_sommeil_memorise_la_base(monkeypatch):
    import json
    monkeypatch.setattr(c, "age_base_jours", lambda: {"daily": 0.2, "main": 1.0})
    lxc = LxcFaux("RUNNING")
    c.endormir(run=lxc)
    d = json.loads(c.ETAT.read_text())
    assert d["dernier_etat"] == "STOPPED" and d["base"]["ages"] == {"daily": 0.2, "main": 1.0}


# ── LE BLOC RÉSEAU EN DOUBLE FAIT AVORTER lxc-start, ET LA BOÎTE S'ÉCROULE ────
# install-lxc.sh AJOUTAIT un bloc lxc.net.0 au bloc que le modèle de création pose déjà : deux
# `lxc.net.0.type`, lxc-start finissait « ABORTING ». Chaque connexion à 3310 (rspamd) relançait
# `clamavctl wake` : 37 échecs en 3 minutes sur gk2, lxc-start + apparmor_parser à chaque fois,
# sur une box déjà en swap. On répare la config au réveil, et on ne retente pas à l'aveugle.
DOUBLE = """lxc.include = /usr/share/lxc/config/common.conf
lxc.rootfs.path = dir:/data/lxc/clamav/rootfs
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.veth.pair = veth-clamav0
lxc.net.0.ipv4.address = 10.100.0.220/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.start.auto = 0
"""


def test_un_bloc_reseau_en_double_est_reduit_a_un_seul(tmp_path):
    (tmp_path / "clamav").mkdir()
    cfg = tmp_path / "clamav" / "config"
    cfg.write_text(DOUBLE)
    assert c.reparer_config(str(tmp_path), "clamav") is True
    lignes = cfg.read_text().splitlines()
    assert sum(1 for l in lignes if l.startswith("lxc.net.0.type")) == 1
    assert "lxc.net.0.veth.pair = veth-clamav0" in lignes
    assert "lxc.net.0.ipv4.address = 10.100.0.220/24" in lignes
    assert "lxc.start.auto = 0" in lignes and "lxc.rootfs.path = dir:/data/lxc/clamav/rootfs" in lignes
    assert c.reparer_config(str(tmp_path), "clamav") is False      # idempotent


def test_une_config_saine_n_est_pas_touchee(tmp_path):
    (tmp_path / "clamav").mkdir()
    cfg = tmp_path / "clamav" / "config"
    cfg.write_text("lxc.net.0.type = veth\nlxc.net.0.link = br-lxc\n")
    avant = cfg.stat().st_mtime_ns
    assert c.reparer_config(str(tmp_path), "clamav") is False
    assert cfg.stat().st_mtime_ns == avant


def test_apres_un_echec_de_demarrage_on_ne_retente_pas_tout_de_suite(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(c, "CHEMIN", str(tmp_path))
    lxc = LxcFaux("STOPPED")
    appels = []

    def run(cmd, **kw):
        appels.append(cmd[0])
        if cmd[0] == "lxc-start":
            return Rep(1, "", "ABORTING")
        return lxc(cmd, **kw)
    assert c.reveiller(delai=1, run=run, ping_fn=lambda: False) is False
    assert appels.count("lxc-start") == 1
    assert c.reveiller(delai=1, run=run, ping_fn=lambda: False) is False
    assert appels.count("lxc-start") == 1, "second essai immédiat : la boucle de 37 échecs en 3 minutes"


def test_l_installation_remplace_le_bloc_reseau_du_modele_au_lieu_d_en_ajouter_un():
    src = (PKG / "lxc" / "install-lxc.sh").read_text()
    assert "sed -i '/^lxc\\.net\\.0\\./d'" in src
    assert src.index("sed -i '/^lxc\\.net\\.0\\./d'") < src.index("lxc.net.0.type = veth")
