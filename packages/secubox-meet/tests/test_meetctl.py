# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""meetctl — contrat du contrôleur confiné de secubox-meet (#3154)."""
import json

from conftest import run_ctl, run_ctl_rc


def test_status_rapporte_les_cinq_services_separement(tmp_path):
    out = run_ctl(tmp_path, "status", lxc_state="RUNNING", is_active={"livekit": "failed"})
    d = json.loads(out)
    assert d["container"] == "running" and d["services"]["livekit"] == "failed" and d["services"]["nginx"] == "active"
    assert set(d["services"]) == {"postgresql", "redis", "livekit", "meet-backend", "nginx"}
    assert "secret" not in out.lower() and d["media"] == {"tcp_port": 7881, "udp_port": 7882, "exposed": False}


def test_status_domaines_et_adresse(tmp_path):
    d = json.loads(run_ctl(tmp_path, "status"))
    assert d["module"] == "meet" and d["version"] == "0.1.0" and d["installed"] is True
    assert d["domain"] == "visio.exemple.test" and d["livekit_domain"] == "livekit.exemple.test"
    assert d["lxc_ip"] == "10.100.0.195" and d["web_reachable"] is False


def test_status_exposition_et_client_oidc_par_presence_de_fichier(tmp_path):
    env_dst = tmp_path / "nftables.d"
    env_dst.mkdir()
    (env_dst / "secubox-meet-dnat.nft").write_text("table inet secubox-meet {}\n")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "oidc-client-secret").write_text("TOPSECRET-VALEUR\n")
    out = run_ctl(tmp_path, "status")
    d = json.loads(out)
    assert d["media"]["exposed"] is True and d["oidc"]["client_registered"] is True
    assert "TOPSECRET" not in out


def test_status_sans_client_oidc(tmp_path):
    assert json.loads(run_ctl(tmp_path, "status"))["oidc"] == {"client_registered": False}


def test_status_sans_conteneur(tmp_path):
    d = json.loads(run_ctl(tmp_path, "status", lxc_state="", rootfs=False))
    assert d["installed"] is False and all(v == "container-down" for v in d["services"].values())


def test_logs_refuse_une_unite_inconnue(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "logs", "sshd")
    assert rc == 2 and json.loads(out)["success"] is False


def test_start_sans_rootfs_echoue_proprement(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "start", rootfs=False)
    assert rc == 1 and json.loads(out)["error"] == "not installed"


def test_start_deja_demarre(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "start", lxc_state="RUNNING")
    assert rc == 0 and json.loads(out) == {"success": True, "already": True}


def test_stop_deja_arrete(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "stop", lxc_state="STOPPED")
    assert rc == 0 and json.loads(out)["already"] is True


def test_aide_et_verbe_inconnu(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "help")
    assert rc == 0 and "meetctl" in out
    rc, _ = run_ctl_rc(tmp_path, "nimportequoi")
    assert rc == 1


def test_status_reste_du_json_valide_avec_des_caracteres_de_controle(tmp_path):
    # Valeurs venant du TOML ou de secubox-domaine : tabulation, CR, saut de ligne, antislash (config_get retire les guillemets).
    (tmp_path / "meet.toml").write_bytes(b'lxc_name = "meet"\nlxc_ip = "10.100.0.195"\ndomain = "a\tb\rc\\d"\n')
    d = json.loads(run_ctl(tmp_path, "status", domaine="x\ny\tz"))
    assert d["domain"] == "a\tb\rc\\d"
    assert d["livekit_domain"] == "x\ny\tz"
