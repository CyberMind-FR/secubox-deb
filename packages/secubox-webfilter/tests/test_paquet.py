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


# ── phase 2 : contrôleur root et unités d'application (#1962) ────────────────────────────────────────────────────────────────────
def test_service_du_controleur_est_root_deplenche_par_fichier_et_bac_a_sable():
    u = lire("systemd/secubox-webfilter-apply.service")
    assert not re.search(r"^User=", u, re.M) and "Type=oneshot" in u                       # root : écrit dans /etc/unbound
    assert "ExecStart=/usr/sbin/secubox-webfilter-ctl apply" in u
    assert "ExecStopPost=/bin/rm -f /var/lib/secubox/webfilter/appliquer.demande" in u
    assert "NoNewPrivileges=true" in u and "ProtectSystem=strict" in u and "PrivateTmp=true" in u
    assert "Wants=unbound" not in u and "Requires=unbound" not in u
    rw = re.search(r"^ReadWritePaths=(.*)$", u, re.M).group(1).split()
    assert set(rw) == {"/etc/unbound/unbound.conf.d", "/var/lib/secubox/webfilter", "/var/lib/secubox-webfilter-ctl", "/var/log/secubox"}
    assert "AF_INET" in u and "IPAddressDeny=any" in u and "IPAddressAllow=localhost" in u        # unbound-control : boucle locale seulement


def test_la_demande_et_la_minuterie_de_4_heures():
    p = lire("systemd/secubox-webfilter-apply.path")
    assert "PathExists=/var/lib/secubox/webfilter/appliquer.demande" in p and "Unit=secubox-webfilter-apply.service" in p
    t = lire("systemd/secubox-webfilter-apply.timer")
    assert "OnCalendar=*-*-* 04:00:00" in t and "Persistent=true" in t and "Unit=secubox-webfilter-apply.service" in t


def test_la_synchronisation_ne_recharge_jamais_unbound():
    assert "unbound-control" not in lire("systemd/secubox-webfilter-sync.service") and "unbound-control" not in lire("webfilter/sync.py")
    assert "unbound-control" not in lire("webfilter/sources.py")


def test_le_controleur_ne_redemarre_jamais_unbound():
    src = lire("webfilter/ctl.py")
    assert '"restart"' not in src and "systemctl" not in src and '"reload"' in src


def test_l_api_n_utilise_ni_sudo_ni_la_levee_de_no_new_privileges():
    u = lire("systemd/secubox-webfilter.service")
    assert "NoNewPrivileges=true" in u and "NoNewPrivileges=false" not in u
    for f in ("api/main.py", "webfilter/etat.py"):                                           # l'API ne lance AUCUN sous-processus : elle dépose des fichiers
        assert "subprocess" not in lire(f) and "os.system" not in lire(f), f


def test_postinst_cree_le_dossier_racine_et_active_la_minuterie_et_la_demande():
    s = lire("debian/postinst")
    assert "install -d -m 0700 -o root -g root /var/lib/secubox-webfilter-ctl" in s
    assert "secubox-webfilter-apply.path" in s and "secubox-webfilter-apply.timer" in s


def test_regles_installent_le_controleur_et_la_version_est_0_2_0():
    assert "sbin/secubox-webfilter-ctl" in lire("debian/rules")
    assert lire("debian/changelog").startswith("secubox-webfilter (0.2.0-1~bookworm1) bookworm;")
    assert "secubox-webfilter (0.1.0-1~bookworm1)" in lire("debian/changelog")                   # l'historique est conservé


def test_profil_du_controleur_n_ecrit_que_son_fichier_dans_unbound():
    p = lire("apparmor/secubox-webfilter")
    assert "/usr/sbin/secubox-webfilter-ctl {" in p
    ctl = p[p.index("/usr/sbin/secubox-webfilter-ctl {"):]
    assert "/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf rw," in ctl
    assert not re.search(r"/etc/unbound/\*\*?\s+\S*w", ctl) and "/etc/unbound/unbound.conf.d/** w" not in ctl
    assert "/usr/sbin/unbound-checkconf" in ctl and "/usr/sbin/unbound-control" in ctl and "/var/lib/secubox-webfilter-ctl/" in ctl


def test_le_readme_decrit_la_phase_2():
    r = lire("README.md")
    for mot in ("profils", "appliquer.demande", "93-secubox-webfilter.conf", "04:00", "ad-guard"):
        assert mot in r, mot
