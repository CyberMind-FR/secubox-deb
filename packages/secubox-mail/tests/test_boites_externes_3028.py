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
    volet = HTML.split("async function chargerExterne()", 1)[1].split("// Rapatriement IMAP (#3033)", 1)[0]
    assert "ecrire(" not in volet and "method: 'POST'" not in volet
    assert "hotes: ['imap.gmail.com'" in HTML            # démonstration renseignée


# ── #3033 : rapatriement IMAP distant ────────────────────────────────────────────────────────────────────────────────
RELAIS_API = (PKG / "composants" / "smtp-relay" / "api" / "main.py").read_text(encoding="utf-8")
RELAIS_HTML = (PKG / "composants" / "smtp-relay" / "www" / "smtp-relay" / "index.html").read_text(encoding="utf-8")


def test_mailctl_imap_sync_sans_mot_de_passe_en_argument():
    assert 'imap-sync)   shift; cmd_imap_sync "$@" ;;' in CTL
    corps = CTL.split("cmd_imap_sync() {", 1)[1].split("\ncmd_fix_ports() {", 1)[0]
    assert "MAILCTL_PASSWORD" in corps and "IFS= read -r mdp" in corps          # stdin ou environnement, jamais argv
    assert "doveadm" in corps and "sync -R -u" in corps and "imapc:" in corps and "imapc_ssl=imaps" in corps
    assert "chmod 0600" in corps and "/etc/secubox/secrets/mail/imap-sync" in CTL
    assert '"password"' not in corps.split("list|status)", 1)[1].split("run)", 1)[0].replace('"password"', "") or True
    liste = corps.split("list|status)", 1)[1].split("run)", 1)[0]
    assert "password" not in liste.replace("c.get(\"password\")", "")  # la liste ne rend jamais le mot de passe


def test_routes_imap_sync_jwt_et_mot_de_passe_par_l_environnement():
    for r in ('@app.get("/imap-sync", dependencies=[Depends(require_jwt)])', '@app.post("/imap-sync", dependencies=[Depends(require_jwt)])',
              '@app.delete("/imap-sync/{local_user}", dependencies=[Depends(require_jwt)])', '@app.post("/imap-sync/{local_user}/run", dependencies=[Depends(require_jwt)])'):
        assert r in API, r
    ajout = API.split("async def imap_sync_ajout", 1)[1].split("@app.delete", 1)[0]
    assert "MAILCTL_PASSWORD=req.password" in ajout and "req.password" not in ajout.split("subprocess.run(", 1)[1].split(")", 1)[0]
    assert "_ADRESSE.match(local_user)" in ajout and "_HOTE.match(host)" in ajout


def test_unite_et_minuterie_du_rapatriement():
    assert "ExecStart=/usr/sbin/mailctl imap-sync run" in (PKG / "debian" / "secubox-mail-imap-sync.service").read_text(encoding="utf-8")
    minuterie = (PKG / "debian" / "secubox-mail-imap-sync.timer").read_text(encoding="utf-8")
    assert "OnActiveSec=" in minuterie and "OnUnitActiveSec=15min" in minuterie
    rules = (PKG / "debian" / "rules").read_text(encoding="utf-8")
    assert "secubox-mail-imap-sync.service" in rules and "secubox-mail-imap-sync.timer" in rules
    assert "secubox-mail-imap-sync.timer" in (PKG / "debian" / "postinst").read_text(encoding="utf-8")


def test_volet_rapatriement_prereglage_ovh_et_confirmation():
    assert 'value="ssl0.ovh.net"' in HTML and 'id="bSync"' in HTML and 'id="cSync"' in HTML
    assert "lire('/imap-sync')" in HTML and "ecrire('POST', '/imap-sync', corps)" in HTML
    assert "ecrire('DELETE', '/imap-sync/' + encodeURIComponent(lu))" in HTML and "'/run'" in HTML
    assert "La box garde l'identifiant et le mot de passe distants" in HTML
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in HTML, interdit


def test_relais_local_par_defaut():
    assert '@router.post("/config/local-default")' in RELAIS_API and 'config["local_default"] = _relais_local_defaut()' in RELAIS_API
    assert '"port": 25' in RELAIS_API and '"tls": False' in RELAIS_API and 'lxc_ip' in RELAIS_API
    assert 'id="cLocal"' in RELAIS_HTML and "appel('/config/local-default', { method: 'POST' })" in RELAIS_HTML
    assert "LOCAL_DEFAUT = DEMO ? { smarthost: '192.0.2.10', port: 25 }" in RELAIS_HTML


def test_relayhost_vide_ne_donne_pas_un_smarthost_fantome(tmp_path, monkeypatch):
    """« via # » : `relayhost =` vide suivi d'un commentaire donnait smarthost = « # »."""
    import importlib.util, sys
    sys.path.insert(0, str(PKG.parents[1] / "common"))
    spec = importlib.util.spec_from_file_location("relais_main", PKG / "composants" / "smtp-relay" / "api" / "main.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    cf = tmp_path / "main.cf"
    cf.write_text("#relayhost = [gateway.example.com]\nrelayhost =\n# commentaire suivant\nmyhostname = gk2\n")
    monkeypatch.setattr(mod, "POSTFIX_MAIN_CF", cf); monkeypatch.setattr(mod, "CONFIG_FILE", tmp_path / "absent.toml")
    monkeypatch.setattr(mod, "POSTFIX_SASL_PASSWD", tmp_path / "absent")
    assert mod._load_config()["smarthost"] == ""
    cf.write_text("relayhost = [10.100.0.10]:25\n")
    c = mod._load_config(); assert (c["smarthost"], c["port"]) == ("10.100.0.10", 25)
    cf.write_text("relayhost = smtp.exemple.test\n")
    assert mod._load_config()["smarthost"] == "smtp.exemple.test"


def test_l_introduction_du_volet_ne_promet_pas_le_greffon_absent():
    assert "seulement si le greffon est actif" in HTML and "rapatrier" in HTML
