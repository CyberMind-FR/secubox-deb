# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 relecture finale — envoi hors du passage, profils AppArmor, chemins inscriptibles, route nginx."""
import importlib.machinery
import importlib.util
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE.parents[1] / "common"))

from garde import base, notifs  # noqa: E402


def _regles_reseau(profil: str) -> list:
    return sorted(re.findall(r"^\s*network\s+([^,]+),", (RACINE / "apparmor" / profil).read_text(), re.M))


def _unite(nom: str) -> str:
    return (RACINE / "debian" / nom).read_text()


def test_passage_sans_reseau_ip():
    assert _regles_reseau("secubox-garde-passage") == ["netlink raw", "unix stream"]
    texte = (RACINE / "apparmor" / "secubox-garde-passage").read_text()
    assert "ssl_certs" not in texte and "garde-sms" not in texte.replace("garde-*", "")


def test_envoi_reseau_et_lectures_exactes():
    assert _regles_reseau("secubox-garde-envoi") == [
        "inet dgram", "inet stream", "inet6 dgram", "inet6 stream", "unix stream"]
    texte = (RACINE / "apparmor" / "secubox-garde-envoi").read_text()
    for regle in ("#include <abstractions/nameservice>", "#include <abstractions/ssl_certs>",
                  "/etc/secubox/metrics.toml r,", "/etc/secubox/secubox.conf r,", "/etc/secubox/garde.toml r,",
                  "/etc/secubox/secrets/garde-sms r,", "/etc/secubox/secrets/*smtp* r,",
                  "/var/lib/secubox/garde/garde.db* rwk,"):
        assert regle in texte
    # Aucun sudo, aucun autre exécutable que l'interpréteur.
    regles = "\n".join(lg for lg in texte.splitlines() if not lg.lstrip().startswith("#"))
    assert "sudo" not in regles and not re.search(r"\s[PpCcUu]x,", regles)
    assert re.findall(r"^\s*(\S+)\s+[a-z]*x[a-z]*,", texte, re.M) == ["/usr/bin/python3*"]


def test_unites_envoi_apres_passage():
    passage = _unite("secubox-garde-passage.service")
    assert "Wants=secubox-garde-envoi.service" in passage
    envoi = _unite("secubox-garde-envoi.service")
    assert "After=secubox-garde-passage.service" in envoi
    assert "AppArmorProfile=secubox-garde-envoi" in envoi and "ExecStart=/usr/sbin/secubox-garde-envoi" in envoi
    assert "NoNewPrivileges=yes" in envoi and "CapabilityBoundingSet=\n" in envoi
    regles = (RACINE / "debian" / "rules").read_text()
    for f in ("debian/secubox-garde-envoi.service", "apparmor/secubox-garde-envoi", "sbin/secubox-garde-envoi"):
        assert f in regles
    assert "secubox-garde-envoi" in (RACINE / "debian" / "postinst").read_text()


def test_passage_ne_fait_que_mettre_en_file():
    texte = (RACINE / "sbin" / "secubox-garde-passage").read_text()
    assert "vider_file" not in texte and "_sms_defaut" not in texte


def test_envoi_vide_la_file_avec_les_vrais_expediteurs(tmp_path, monkeypatch):
    chargeur = importlib.machinery.SourceFileLoader("garde_envoi", str(RACINE / "sbin" / "secubox-garde-envoi"))
    spec = importlib.util.spec_from_loader("garde_envoi", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    monkeypatch.setattr(base, "BASE", tmp_path / "g.db")
    monkeypatch.setattr(base, "reglages", lambda: {"courriel": "a@b.fr"})
    vu = {}

    def vider(db, reglages, envoyer_sms, envoyer_courriel, maintenant):
        vu.update(reglages=reglages, sms=envoyer_sms, courriel=envoyer_courriel, maintenant=maintenant)
        return {"envoyes": 0, "en_attente": 0}

    monkeypatch.setattr(notifs, "vider_file", vider)
    assert m.main() == 0
    assert vu["sms"] is notifs._sms_defaut and vu["courriel"] is notifs._courriel_defaut
    assert vu["reglages"] == {"courriel": "a@b.fr"} and vu["maintenant"] > 0


def test_passage_chemins_inscriptibles_du_controleur_adguard():
    passage = _unite("secubox-garde-passage.service")
    rw = " ".join(re.findall(r"^ReadWritePaths=(.*)$", passage, re.M)).split()
    for chemin in ("-/var/lib/secubox/ad-guard", "-/var/lib/secubox-adguard-tv", "-/etc/unbound/unbound.conf.d",
                   "/var/log/secubox", "/var/lib/secubox/garde"):
        assert chemin in rw
    assert "ProtectSystem=strict" in passage and "PrivateTmp=yes" in passage


def test_route_nginx_une_fois_par_dossier():
    regles = (RACINE / "debian" / "rules").read_text()
    poses = re.findall(r"install -m 644 nginx/garde\.conf \$\(P\)(\S+)", regles)
    assert sorted(poses) == ["/etc/nginx/secubox-routes.d/", "/etc/nginx/secubox.d/"]
