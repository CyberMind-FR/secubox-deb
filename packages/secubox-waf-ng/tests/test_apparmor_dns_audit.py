# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Profil AppArmor de sbxwaf (enforce sur gk2) : la vérification DNS des robots d'indexation (FCrDNS) a besoin d'UDP et des fichiers du résolveur ; sans
cela elle échoue EN SILENCE et personne n'est exempté (les robots restent bannis). Les lignes d'audit du kill switch vont dans le répertoire que le service
peut écrire, pas dans /var/log/secubox/audit.log (secubox:secubox 0640, fermé à l'utilisateur secubox-waf)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
PROFIL = (RACINE / "debian" / "secubox-waf-ng.apparmor").read_text()
REEVAL = (RACINE.parent / "secubox-toolbox-ng" / "cmd" / "sbxwaf" / "reevaluation.go").read_text()


def regles(txt):
    return {re.sub(r"\s+", " ", l.split("#")[0]).strip() for l in txt.splitlines() if l.strip() and not l.strip().startswith("#")}


def test_le_profil_autorise_udp_pour_le_dns():
    r = regles(PROFIL)
    assert "network inet dgram," in r and "network inet6 dgram," in r


def test_le_profil_autorise_la_lecture_des_fichiers_du_resolveur():
    r = regles(PROFIL)
    for f in ("/etc/resolv.conf r,", "/etc/nsswitch.conf r,", "/etc/hosts r,", "/etc/host.conf r,"):
        assert f in r, f


def test_l_audit_de_la_reevaluation_va_dans_le_repertoire_ecrivable_du_service():
    m = re.search(r'audit:\s*"([^"]+)"', REEVAL)
    assert m and m.group(1).startswith("/var/log/secubox/waf/"), m and m.group(1)


def test_le_postinst_recharge_le_profil_deja_charge():
    """`aa-enforce` sur un profil déjà en enforce ne recharge pas les règles : une mise à jour du profil restait sans effet dans le noyau
    (constat gk2 : le DNS des robots refusé jusqu'à un `apparmor_parser -r` manuel). Le paquet recharge lui-même."""
    post = (RACINE / "debian" / "postinst").read_text()
    bloc = post[post.index("AppArmor profile"):post.index("Systemd: single hardened unit")]
    assert "apparmor_parser -r /etc/apparmor.d/usr.sbin.sbxwaf" in bloc
    assert bloc.index("aa-enforce") < bloc.index("apparmor_parser -r")
