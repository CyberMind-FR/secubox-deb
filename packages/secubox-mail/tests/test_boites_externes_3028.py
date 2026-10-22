# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3028 — le volet « Boîtes externes » est branché sur l'état réel : greffon ident_switch et relais SMTP sortant."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
CTL = (PKG / "sbin" / "mailctl").read_text(encoding="utf-8")
API = (PKG / "api" / "main.py").read_text(encoding="utf-8")
HTML = (PKG / "www" / "mail" / "index.html").read_text(encoding="utf-8")


def test_mailctl_webmail_comptes_sans_identifiant():
    assert "cmd_webmail_comptes() {" in CTL and "webmail-comptes) cmd_webmail_comptes ;;" in CTL
    corps = CTL.split("cmd_webmail_comptes() {", 1)[1].split("\ncmd_fix_ports() {", 1)[0]
    assert "ident_switch" in corps and "json_group_array" in corps and "imap_host" in corps
    for secret in ("password", "smtp_password", "sieve_password", "username"):
        assert not re.search(r"select[^;]*\b%s\b" % secret, corps), secret     # jamais un identifiant dans une requête
    assert '"greffon":%s' in corps and '"hotes":%s' in corps


def test_route_comptes_externes_en_lecture_et_hors_boucle():
    assert '@app.get("/webmail/comptes-externes", dependencies=[Depends(require_lecture)])' in API
    bloc = API.split('"/webmail/comptes-externes"', 1)[1].split("@app.get", 1)[0]
    assert 'asyncio.to_thread(run_cmd, ["/usr/sbin/mailctl", "webmail-comptes"]' in bloc
    assert '"greffon": None' in bloc                   # réponse illisible ⇒ « — », jamais 0


def test_le_volet_lit_les_deux_branchements_sans_action_nouvelle():
    assert "lire('/webmail/comptes-externes')" in HTML
    assert "fetch('/api/v1/smtp-relay/status'" in HTML
    assert 'id="externeImap"' in HTML and 'id="externeRelais"' in HTML and 'href="/smtp-relay/"' in HTML
    assert "l’ancienne page interrogeait une route inexistante" not in HTML
    assert "if (nom === 'externe') chargerExterne();" in HTML
    volet = HTML.split("async function chargerExterne()", 1)[1].split("function rendreExterne()", 1)[0]
    assert "ecrire(" not in volet and "method: 'POST'" not in volet
    assert "hotes: ['imap.gmail.com'" in HTML            # démonstration renseignée
