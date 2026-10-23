# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3059 — la déconnexion du webmail ne coupe l'ouverture d'office QUE pour la session du Hall fermée.

Avant : `secubox_sso_off=1` en cookie de session (durée 0). Firefox restaure les cookies de session à la
réouverture : une seule déconnexion de Roundcube coupait le SSO pour toujours dans ce navigateur, même
après une nouvelle connexion au Hall — le greffon se taisait avant même d'appeler la box.

Après : le cookie d'arrêt porte l'empreinte SHA-256 du jeton `secubox_session` présent à la déconnexion,
avec une durée bornée ; il n'arrête le SSO que si le jeton courant a la même empreinte. Un autre jeton
(nouvelle connexion au Hall) ou l'ancien format (« 1 ») : le cookie est retiré et le webmail s'ouvre.

Tests statiques : pas d'interpréteur PHP sur le poste ; `mailctl webmail-sso` fait `php -l` au déploiement."""
import re
from pathlib import Path

GREFFON = (Path(__file__).resolve().parents[2] / "roundcube" / "sso" / "secubox_sso" / "secubox_sso.php").read_text()


def _corps(fonction: str) -> str:
    m = re.search(rf"function {fonction}\([^)]*\)\s*\{{(.*?)\n    \}}", GREFFON, re.S)
    assert m, f"fonction {fonction} absente"
    return m.group(1)


def test_l_arret_porte_l_empreinte_du_jeton_du_hall_et_une_duree_bornee():
    deconnecte = _corps("deconnecte")
    assert "secubox_sso_off', '1', 0" not in deconnecte, "cookie de session « 1 » : restauré par le navigateur, coupe le SSO pour toujours"
    assert "empreinte()" in deconnecte
    assert re.search(r"setcookie\('secubox_sso_off', \$e, time\(\) \+ self::ARRET_S\)", deconnecte)
    assert re.search(r"const ARRET_S = \d+;", GREFFON)


def test_l_empreinte_est_le_sha256_du_jeton_de_session():
    empreinte = _corps("empreinte")
    assert "secubox_session" in empreinte
    assert "hash('sha256'" in empreinte
    assert "return $jeton === '' ? ''" in empreinte, "sans jeton du Hall : pas d'empreinte, donc pas de cookie d'arrêt"


def test_le_demarrage_ne_se_tait_que_pour_le_meme_jeton():
    startup = _corps("startup")
    assert "$_COOKIE['secubox_sso_off']" not in startup, "la comparaison brute du cookie est remplacée par coupe()"
    assert "!$this->coupe()" in startup
    coupe = _corps("coupe")
    assert "hash_equals($this->empreinte(), $off)" in coupe
    # un cookie d'arrêt d'un autre jeton ou de l'ancien format est retiré, et le SSO reprend
    assert re.search(r"setcookie\('secubox_sso_off', '', time\(\) - \d+\)", coupe)
    assert coupe.strip().endswith("return false;")
