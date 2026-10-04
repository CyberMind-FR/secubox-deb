# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le paquet lui-même : profil AppArmor, droits, postinst, unités, route nginx (relecture de sécurité #1962)."""
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent


def lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def test_profil_api_autorise_le_registre_des_sessions_et_interdit_les_secrets():
    p = lire("apparmor/secubox-webfilter")
    api = p[p.index("/usr/sbin/secubox-webfilter-api {"):p.index("/usr/sbin/secubox-webfilter-feed {")]
    assert "/var/lib/secubox/auth/sessions.json r," in api              # sans lui : 401 partout (registre vu vide, #942)
    assert "/var/log/secubox/delegation.log w," in api and "network unix dgram," in api
    assert "deny /etc/secubox/secrets/** r," in api
    assert "/etc/secubox/** r," not in api and "/etc/secubox/secubox.conf r," in api


def test_profil_synchronisation_sans_etc_ssl_complet():
    p = lire("apparmor/secubox-webfilter")
    sync = p[p.index("/usr/sbin/secubox-webfilter-sync {"):]
    assert "/etc/ssl/** r," not in sync and "abstractions/ssl_certs" in sync


def test_dossier_d_etat_reserve_au_compte_du_service():
    t = lire("tmpfiles/secubox-webfilter.conf")
    assert "d /var/lib/secubox/webfilter 0700 secubox-webfilter secubox-webfilter -" in t
    assert "d /var/lib/secubox/webfilter/listes 0700 secubox-webfilter secubox-webfilter -" in t


def test_postinst_ne_donne_pas_le_journal_a_tous_les_services():
    s = lire("debian/postinst")
    assert not re.search(r"^\s*adduser secubox-webfilter systemd-journal", s, re.M)
    assert "deluser secubox-webfilter systemd-journal" in s                 # retiré aussi des installations déjà faites
    assert re.search(r"systemctl daemon-reload\s*\|\|\s*true", s)
    assert "SupplementaryGroups=systemd-journal" in lire("systemd/secubox-webfilter-feed.service")


def test_dependances_declarees():
    dep = lire("debian/control")
    assert re.search(r"\badduser\b", dep) and re.search(r"\biproute2\b", dep)


def test_postrm_purge_les_donnees_et_decharge_le_profil():
    s = lire("debian/postrm")
    assert re.search(r"purge\)[^;]*\n[^\n]*rm -rf /var/lib/secubox/webfilter", s) or "rm -rf /var/lib/secubox/webfilter" in s
    assert "apparmor_parser -R" in s and s.rstrip().endswith("exit 0")


def test_route_nginx_dans_le_dossier_lu_et_erreurs_json_conservees():
    assert "proxy_intercept_errors" not in lire("nginx/webfilter.conf")
    assert "secubox-routes.d" in lire("debian/rules")


def test_le_demon_d_alimentation_ne_demarre_pas_unbound():
    u = lire("systemd/secubox-webfilter-feed.service")
    assert "After=unbound.service" in u and "Wants=unbound.service" not in u


@pytest.mark.parametrize("rel", ["systemd/secubox-webfilter.service", "systemd/secubox-webfilter-feed.service", "systemd/secubox-webfilter-sync.service",
                                 "systemd/secubox-webfilter-sync.path", "systemd/secubox-webfilter-sync.timer", "debian/rules", "debian/postrm"])
def test_en_tete_spdx(rel):
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in "\n".join(lire(rel).splitlines()[:4])


def test_l_alimentation_lit_le_journal_avec_horodatage():
    assert '"short-unix"' in lire("sbin/secubox-webfilter-feed")


def test_le_lanceur_de_l_api_utilise_une_socket_en_0660():
    s = lire("sbin/secubox-webfilter-api")
    assert "creer_socket" in s and "fd=" in s
