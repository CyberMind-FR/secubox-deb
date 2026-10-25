# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""meetctl — contrat du contrôleur confiné de secubox-meet (#3154)."""
import json

from conftest import _ecrire_exec, run_ctl, run_ctl_rc


def test_status_rapporte_les_cinq_services_separement(tmp_path):
    out = run_ctl(tmp_path, "status", lxc_state="RUNNING", is_active={"livekit": "failed"})
    d = json.loads(out)
    assert d["container"] == "running" and d["services"]["livekit"] == "failed" and d["services"]["nginx"] == "active"
    assert set(d["services"]) == {"postgresql", "redis", "livekit", "meet-backend", "nginx"}
    assert "secret" not in out.lower() and d["media"] == {"tcp_port": 7881, "udp_port": 7882, "exposed": False}


def test_status_domaines_et_adresse(tmp_path):
    d = json.loads(run_ctl(tmp_path, "status"))
    assert d["module"] == "meet" and d["version"] == "0.1.1" and d["installed"] is True
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
    assert not list((tmp_path / "secrets").glob(".oidc-client-secret.*"))


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


def test_oidc_verifier_ignore_le_jwks_uri_distant(tmp_path):
    piege = json.dumps({"issuer": "https://hall.exemple.test/oidc", "jwks_uri": "file:///etc/shadow"})
    d = json.loads(run_ctl(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": piege, "jwks": JWKS}))
    assert d["discovery"] and d["jwks"] and d["keys"] == 1
    urls = (tmp_path / "urls").read_text()
    assert "shadow" not in urls and "https://hall.exemple.test/oidc/jwks" in urls
    assert all("--proto =https --" in ligne for ligne in urls.splitlines())


def test_oidc_verifier_refuse_un_issuer_different(tmp_path):
    autre = json.dumps({"issuer": "https://hall.autre.test/oidc", "jwks_uri": "x"})
    rc, out = run_ctl_rc(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": autre, "jwks": JWKS})
    d = json.loads(out)
    assert rc == 1 and d["discovery"] is False and d["jwks"] is False
    assert "issuer" in d["hint"] and "hall.autre.test" in d["hint"] and "hall.exemple.test" in d["hint"]


def test_oidc_enregistrer_honore_le_domaine_de_l_environnement(tmp_path):
    out = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="S",
                             env_extra={"SECUBOX_MEET_DOMAIN": "autre.exemple.test"}))
    assert out["redirect_uri"] == "https://autre.exemple.test/api/v1.0/callback/"
    assert "--redirect https://autre.exemple.test/api/v1.0/callback/" in (tmp_path / "appels").read_text()


def test_oidc_enregistrer_reenregistre_si_le_client_a_disparu_chez_le_fournisseur(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    (tmp_path / "appels").unlink()  # le fournisseur ne connaît plus « meet »
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B"))
    assert "already" not in d
    assert (tmp_path / "secrets" / "oidc-client-secret").read_text().strip() == "B"


def test_oidc_enregistrer_reenregistre_si_le_fichier_secret_est_vide(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    (tmp_path / "secrets" / "oidc-client-secret").write_text("")
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B"))
    assert "already" not in d and (tmp_path / "secrets" / "oidc-client-secret").read_text().strip() == "B"


def test_oidc_verifier_redirect_registered_suit_le_fournisseur(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    (tmp_path / "appels").unlink()
    d = json.loads(run_ctl(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": DISCOVERY, "jwks": JWKS}))
    assert d["redirect_registered"] is False


# ── m4 : l'état de postgresql vient de pg_isready, pas de l'unité parapluie ─────────────────────────

def test_status_postgresql_par_pg_isready(tmp_path):
    d = json.loads(run_ctl(tmp_path, "status", is_active={"postgresql": "active"}, env_extra={"FAKE_PG_READY": "2"}))
    assert d["services"]["postgresql"] == "failed"
    d = json.loads(run_ctl(tmp_path, "status", is_active={"postgresql": "inactive"}, env_extra={"FAKE_PG_READY": "0"}))
    assert d["services"]["postgresql"] == "active"
    assert "pg_isready -q" in (tmp_path / "urls").read_text()


# ── I3 : autostart on|off, seule la clé lxc.start.auto change ──────────────────────────────────────

CONFIG_LXC = ("# SecuBox-managed - voir secubox-meet / install-lxc.sh\nlxc.uts.name = meet\n"
              "# lxc.start.auto = 1 (exemple commenté)\nlxc.start.auto = 1\nlxc.start.delay = 5\n")


def _config_lxc(tmp_path, texte=CONFIG_LXC):
    c = tmp_path / "lxc" / "meet" / "config"
    c.parent.mkdir(parents=True, exist_ok=True)
    c.write_text(texte)
    c.chmod(0o640)
    return c


def test_autostart_off_puis_on_ne_change_que_cette_cle(tmp_path):
    c = _config_lxc(tmp_path)
    assert json.loads(run_ctl(tmp_path, "autostart", "off")) == {"success": True, "autostart": False}
    assert c.read_text() == CONFIG_LXC.replace("\nlxc.start.auto = 1\n", "\nlxc.start.auto = 0\n")
    assert c.stat().st_mode & 0o777 == 0o640
    assert json.loads(run_ctl(tmp_path, "autostart", "on")) == {"success": True, "autostart": True}
    assert c.read_text() == CONFIG_LXC


def test_autostart_pose_la_cle_absente(tmp_path):
    c = _config_lxc(tmp_path, "lxc.uts.name = meet\n")
    run_ctl(tmp_path, "autostart", "off")
    assert c.read_text() == "lxc.uts.name = meet\nlxc.start.auto = 0\n"


def test_autostart_refuse_une_valeur_inconnue(tmp_path):
    c = _config_lxc(tmp_path)
    rc, out = run_ctl_rc(tmp_path, "autostart", "peut-etre")
    assert rc == 2 and json.loads(out)["success"] is False and c.read_text() == CONFIG_LXC


def test_autostart_sans_conteneur(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "autostart", "off", rootfs=False)
    assert rc == 1 and json.loads(out)["success"] is False


# ── I2 : un NOUVEAU secret OIDC est porté jusqu'au conteneur (rendu seul) ──────────────────────────

def _install_faux(tmp_path, provisionne=True):
    """Faux install-lxc.sh : journalise son mode ; comme le vrai, note l'empreinte du secret appliqué s'il réussit."""
    if provisionne:
        (tmp_path / "etat").mkdir(exist_ok=True)
        (tmp_path / "etat" / ".lxc-provisioned").write_text("2026-10-25\n")
    faux = tmp_path / "install-faux.sh"
    secrets = tmp_path / "secrets"
    _ecrire_exec(faux, f"""#!/bin/bash
echo "RENDRE_SEULEMENT=${{SECUBOX_MEET_RENDRE_SEULEMENT:-}}" >> "{tmp_path}/install-appels"
[ "${{FAKE_INSTALL_RC:-0}}" = 0 ] || exit "$FAKE_INSTALL_RC"
printf '%s' "$(cat "{secrets}/oidc-client-secret")" | sha256sum | cut -d' ' -f1 > "{secrets}/.oidc-applique"
""")
    return {"SECUBOX_MEET_INSTALL_SCRIPT": str(faux)}


def _appels_install(tmp_path):
    f = tmp_path / "install-appels"
    return f.read_text().splitlines() if f.exists() else []


def test_oidc_nouveau_secret_applique_au_conteneur_qui_tourne(tmp_path):
    env = _install_faux(tmp_path)
    out = run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="S3CR3T", env_extra=env)
    d = json.loads(out)
    assert d["success"] is True and d["applique"] is True and "S3CR3T" not in out
    assert _appels_install(tmp_path) == ["RENDRE_SEULEMENT=1"]


def test_oidc_secret_inchange_et_applique_n_appelle_pas_le_rendu(tmp_path):
    env = _install_faux(tmp_path)
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A", env_extra=env)
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B", env_extra=env))
    assert d["already"] is True and "applique" not in d
    assert _appels_install(tmp_path) == ["RENDRE_SEULEMENT=1"]


def test_oidc_conteneur_arrete_le_dit_puis_applique_au_clic_suivant(tmp_path):
    env = _install_faux(tmp_path)
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A", lxc_state="STOPPED", env_extra=env))
    assert d["success"] is True and d["applique"] is False and "arrêt" in d["hint"]
    assert _appels_install(tmp_path) == []
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B", lxc_state="RUNNING", env_extra=env))
    assert d["already"] is True and d["applique"] is True
    assert _appels_install(tmp_path) == ["RENDRE_SEULEMENT=1"]


def test_oidc_sans_provisionnement_termine_n_applique_pas(tmp_path):
    env = _install_faux(tmp_path, provisionne=False)
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A", env_extra=env))
    assert d["applique"] is False and "provisionnement" in d["hint"] and _appels_install(tmp_path) == []


def test_oidc_appele_par_le_provisionnement_ne_relance_pas_le_rendu(tmp_path):
    env = {**_install_faux(tmp_path), "SECUBOX_MEET_APPLIQUER": "0"}
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A", env_extra=env))
    assert d["success"] is True and d["applique"] is False and _appels_install(tmp_path) == []


def test_oidc_rendu_en_echec_est_signale(tmp_path):
    env = {**_install_faux(tmp_path), "FAKE_INSTALL_RC": "1"}
    rc, out = run_ctl_rc(tmp_path, "oidc-enregistrer", oidcctl_secret="A", env_extra=env)
    d = json.loads(out)
    assert rc == 0 and d["success"] is True and d["applique"] is False and "journalctl" in d["hint"]
    assert not (tmp_path / "secrets" / ".oidc-applique").exists()
