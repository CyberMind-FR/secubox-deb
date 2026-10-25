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


DISCOVERY = json.dumps({"issuer": "https://hall.exemple.test/oidc", "jwks_uri": "https://hall.exemple.test/oidc/jwks"})
JWKS = json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB"}]})
REDIRECT = "https://visio.exemple.test/api/v1.0/callback/"


def test_oidc_enregistrer_ecrit_le_secret_0600_et_ne_l_imprime_pas(tmp_path):
    out = run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="S3CR3T")
    assert "S3CR3T" not in out and json.loads(out)["redirect_uri"] == REDIRECT
    assert json.loads(out)["client_id"] == "meet" and json.loads(out)["success"] is True
    f = tmp_path / "secrets" / "oidc-client-secret"
    assert f.read_text().strip() == "S3CR3T" and oct(f.stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "appels").read_text().split("\n")[0] == f"client-add meet --name Visio --redirect {REDIRECT}"
    assert not list((tmp_path / "secrets").glob("*.tmp*"))


def test_oidc_enregistrer_est_idempotent(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B"))
    assert d["already"] is True and (tmp_path / "secrets" / "oidc-client-secret").read_text().strip() == "A"
    assert len((tmp_path / "appels").read_text().splitlines()) == 1


def test_oidc_enregistrer_renouveler_reenregistre(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    out = run_ctl(tmp_path, "oidc-enregistrer", "--renouveler", oidcctl_secret="B")
    assert "already" not in json.loads(out) and "B" not in out.replace("success", "")
    assert (tmp_path / "secrets" / "oidc-client-secret").read_text().strip() == "B"


def test_oidc_enregistrer_echec_ne_laisse_pas_de_fichier(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "oidc-enregistrer")
    assert rc == 1 and json.loads(out)["success"] is False
    assert not (tmp_path / "secrets" / "oidc-client-secret").exists()


def test_oidc_enregistrer_sans_domaine_refuse(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "oidc-enregistrer", domaine="", oidcctl_secret="X")
    assert rc == 1 and json.loads(out)["success"] is False
    assert not (tmp_path / "appels").exists()


def test_oidc_verifier_depuis_le_conteneur(tmp_path):
    d = json.loads(run_ctl(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": DISCOVERY, "jwks": JWKS}))
    assert d["discovery"] and d["jwks"] and d["keys"] == 1 and d["issuer"] == "https://hall.exemple.test/oidc"
    assert d["redirect_registered"] is False and d["hint"] == ""
    rc, out = run_ctl_rc(tmp_path, "oidc-verifier", attach_curl={})
    assert rc == 1 and json.loads(out)["discovery"] is False and "hosts" in json.loads(out)["hint"]


def test_oidc_verifier_ne_fuit_pas_le_secret_et_signale_l_enregistrement(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="S3CR3T")
    out = run_ctl(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": DISCOVERY, "jwks": JWKS})
    assert "S3CR3T" not in out and json.loads(out)["redirect_registered"] is True


def test_oidc_verifier_jwks_en_echec(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": DISCOVERY})
    d = json.loads(out)
    assert rc == 0 and d["discovery"] is True and d["jwks"] is False and d["keys"] == 0 and d["hint"]


def test_oidc_verifier_conteneur_arrete(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "oidc-verifier", lxc_state="STOPPED")
    d = json.loads(out)
    assert rc == 1 and d["discovery"] is False and "arrêt" in d["hint"]
