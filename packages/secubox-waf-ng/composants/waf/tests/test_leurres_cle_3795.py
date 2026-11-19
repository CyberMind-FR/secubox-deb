# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3795 : la clé des leurres est garantie avant l'API du WAF (LoadCredential= sur une source absente = 243)."""
import os
import stat
import subprocess
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[3]
SCRIPT = PAQUET / "composants/waf/scripts/secubox-waf-leurres-cle"
UNITE = PAQUET / "systemd/secubox-waf-leurres-cle.service"
DROPIN = PAQUET / "systemd/secubox-waf-gestes-ia.conf"
POSTINST = PAQUET / "debian/postinst"
RULES = PAQUET / "debian/rules"


def _lancer(cle):
    import grp
    groupe = grp.getgrgid(os.getgid()).gr_name
    return subprocess.run(["sh", str(SCRIPT)], env={**os.environ, "SECUBOX_LEURRES_CLE": str(cle),
                                                    "SECUBOX_LEURRES_GROUPE": groupe,
                                                    "SECUBOX_LEURRES_PROPRIETAIRE": str(os.getuid())}, capture_output=True, text=True)


def test_script_cree_puis_idempotent(tmp_path):
    cle = tmp_path / "leurres-hmac.key"
    assert _lancer(cle).returncode == 0
    brut = cle.read_bytes()
    assert len(brut) == 32 and stat.S_IMODE(cle.stat().st_mode) == 0o640
    assert _lancer(cle).returncode == 0 and cle.read_bytes() == brut          # jamais tournée
    assert [p.name for p in tmp_path.iterdir()] == ["leurres-hmac.key"]       # aucun temporaire laissé


def test_script_echec_bruyant(tmp_path):
    r = _lancer(tmp_path / "absent" / "leurres-hmac.key")
    assert r.returncode == 1 and "ERREUR" in r.stderr


def test_unites_presentes_et_ordonnees():
    u = UNITE.read_text()
    for l in ("Type=oneshot", "RemainAfterExit=no", "ExecStart=/usr/sbin/secubox-waf-leurres-cle", "PrivateNetwork=yes",
              "ProtectHome=yes", "PrivateTmp=yes", "ReadWritePaths=/etc/secubox/secrets", "Before=secubox-waf.service"):
        assert l in u, l
    d = DROPIN.read_text()
    assert "Wants=secubox-waf-leurres-cle.service" in d and "After=secubox-waf-leurres-cle.service" in d
    actives = [l for l in d.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert not any(l.startswith(("LoadCredential", "Requires", "BindsTo", "Requisite")) for l in actives)
    assert d.index("\n[Unit]") < d.index("\nWants=") < d.index("\n[Service]")
    r = RULES.read_text()
    assert "systemd/secubox-waf-leurres-cle.service" in r and "scripts/secubox-waf-leurres-cle" in r


def test_postinst_avertit_si_cle_absente(tmp_path):
    p = POSTINST.read_text()
    i = p.index("      /usr/sbin/secubox-waf-leurres-cle || true")
    bloc = p[i:p.index("deb-systemd-helper enable secubox-waf-leurres-cle.service", i)]
    assert "ATTENTION" in bloc and ">&2" in bloc and "leurres-hmac-absente" in bloc and "audit.log" in bloc
    # Exécution du chemin d'avertissement sur des chemins de test.
    audit = tmp_path / "audit.log"
    essai = (bloc.replace("/usr/sbin/secubox-waf-leurres-cle", "false")
             .replace("/etc/secubox/secrets/leurres-hmac.key", str(tmp_path / "k"))
             .replace("/var/log/secubox/audit.log", str(audit)).replace("/var/log/secubox", str(tmp_path))
             .replace("deb-systemd-helper", "true"))
    r = subprocess.run(["sh", "-c", essai + "\n    :\n  fi\n" if essai.rstrip().endswith("then") else essai],
                       capture_output=True, text=True)
    assert "ATTENTION" in r.stderr and "leurres-hmac-absente" in audit.read_text()


def test_postinst_remet_une_cle_0600_en_0640_sans_la_regenerer(tmp_path):
    import grp
    p = POSTINST.read_text()
    i = p.index("      # Clé d'une installation antérieure")
    bloc = p[i:p.index("      /usr/sbin/secubox-waf-leurres-cle || true", i)]
    cle = tmp_path / "k"
    cle.write_bytes(b"x" * 32)
    os.chmod(cle, 0o600)
    groupe = grp.getgrgid(os.getgid()).gr_name
    essai = (bloc.replace("/etc/secubox/secrets/leurres-hmac.key", str(cle)).replace("root:secubox", f":{groupe}")
             .replace("getent group secubox", "true"))
    assert subprocess.run(["sh", "-c", essai]).returncode == 0
    assert stat.S_IMODE(cle.stat().st_mode) == 0o640 and cle.read_bytes() == b"x" * 32
    assert "chown root:secubox" in bloc and "chmod 0640" in bloc
