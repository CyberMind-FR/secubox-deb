# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3274 — les conteneurs mail et roundcube naissent en trixie, sans version de PHP en dur.

Roundcube de bookworm (1.6.5 deb12u12) reste vulnérable aux CVE corrigées en 1.6.20 ;
seul trixie a le correctif. Une version de PHP écrite en dur (php8.2) casse le passage
à PHP 8.4 : paquets introuvables, drop-in ini dans un dossier mort, FPM non relancée.
"""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
INSTALL = (PAQUET / "lib/mail/install.sh").read_text()
MAILCTL = (PAQUET / "sbin/mailctl").read_text()


def test_bootstrap_en_trixie():
    assert re.search(r"debootstrap\b[^\n]*\\\n\s*trixie\b", INSTALL), "debootstrap doit viser trixie"
    assert not re.search(r"^\s*bookworm\s", INSTALL, re.M)


def test_aucune_version_de_php_en_dur():
    for nom, texte in (("install.sh", INSTALL), ("mailctl", MAILCTL)):
        assert not re.search(r"php8\.\d|php/8\.\d", texte), f"{nom} écrit une version de PHP en dur"


def test_paquets_php_sans_version():
    assert "libapache2-mod-php " in INSTALL
    for ext in ("php-ldap", "php-curl", "php-xml", "php-mbstring", "php-intl", "php-sqlite3", "php-zip", "php-gd"):
        assert ext in INSTALL, ext


def test_ini_et_module_suivent_la_version_du_conteneur():
    # La version vient de PHP installé dans le conteneur, pas d'une constante.
    assert "PHP_MAJOR_VERSION" in INSTALL
    assert '/etc/php/$PHPV/apache2/conf.d/99-secubox-attach.ini' in INSTALL
    assert 'a2enmod "php$PHPV"' in INSTALL


def test_mailctl_relance_la_fpm_presente():
    assert "'php*-fpm'" in MAILCTL


def test_unites_systemd_257_sans_credentials_dans_le_lxc():
    # systemd 257 (trixie) : ImportCredential= échoue en LXC non privilégié (243/CREDENTIALS),
    # journald, sysctl et tmpfiles restent en échec. Constaté sur gk2 le 29/10/2026.
    for unite in ("systemd-journald", "systemd-sysctl", "systemd-tmpfiles-setup", "systemd-tmpfiles-clean"):
        assert unite in INSTALL, unite
    assert "ImportCredential=" in INSTALL


def test_pas_de_gnupg_qui_tire_un_mta():
    # gnupg (trixie) dépend de gpg-wks-server, qui tire exim4 : un MTA de trop dans le conteneur.
    assert not re.search(r"--include=[^\s]*\bgnupg\b", INSTALL)
    assert re.search(r"--include=[^\s]*\bgpg\b", INSTALL)
