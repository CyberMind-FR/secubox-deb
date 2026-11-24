# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3919, lot 1 : chaque service atteint les fichiers que ses options nomment PAR DÉFAUT (base ASN, catalogue des classes
et sa surcharge, état des campagnes d'authwatch). Les chemins sont lus dans les sources, jamais recopiés à la main."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
TNG = PAQUET.parent / "secubox-toolbox-ng"
PROFIL = (PAQUET / "debian" / "secubox-waf-ng.apparmor").read_text(encoding="utf-8")
POSTINST = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
ACTORD = (PAQUET / "systemd" / "secubox-actord.service").read_text(encoding="utf-8")
AUTHWATCH = (TNG / "debian" / "secubox-authwatch.service").read_text(encoding="utf-8")


def _defaut(commande, option):
    src = (TNG / "cmd" / commande / "main.go").read_text(encoding="utf-8")
    return re.search(r'flag\.String\("%s",\s*"([^"]*)"' % re.escape(option), src).group(1)


def _regles():
    return {re.sub(r"\s+", " ", l.split("#")[0]).strip() for l in PROFIL.splitlines() if l.strip()}


def _valeurs(unite, cle):
    out = []
    for l in unite.splitlines():
        if l.startswith(cle + "="):
            out += l.split("=", 1)[1].split()
    return out


def test_sbxwaf_lit_la_base_asn_et_les_catalogues_sous_apparmor():
    r = _regles()
    for chemin in [_defaut("sbxwaf", "geoip-asn")] + _defaut("sbxwaf", "reseaux-classes").split(","):
        couvert = chemin + " r," in r or (chemin.startswith("/etc/secubox/waf/") and "/etc/secubox/waf/** r," in r)
        assert couvert, chemin


def test_la_lecture_accordee_est_au_fichier_pres():
    r = _regles()
    assert not [x for x in r if x.startswith("/var/lib/GeoIP/") and "*" in x]
    assert not [x for x in r if x.startswith("/usr/share/secubox/") and "*" in x]


def test_les_trois_demons_ont_les_memes_chemins():
    for option in ("geoip-asn", "reseaux-classes"):
        assert len({_defaut(c, option) for c in ("sbxwaf", "sbx-actord", "sbx-authwatch")}) == 1, option


def test_postinst_recharge_le_profil_meme_sans_apparmor_utils():
    bloc = POSTINST[POSTINST.index("AppArmor profile"):POSTINST.index("# waf-blocs (#3716, P8)")]
    assert "/sys/kernel/security/apparmor/profiles" in bloc
    assert re.search(r"command -v apparmor_parser", bloc)


def test_actord_traverse_etc_secubox_waf_par_acl_nommee_jamais_par_le_groupe_du_waf():
    """/etc/secubox/waf est root:secubox-waf 0750 : sbx-actord y traverse par une ACL « x », posée APRÈS le chmod."""
    acl = "setfacl -m u:secubox-actord:x /etc/secubox/waf"
    assert acl in POSTINST
    assert POSTINST.index("chmod 0750 /etc/secubox/waf\n") < POSTINST.index(acl)
    assert "secubox-waf" not in _valeurs(ACTORD, "SupplementaryGroups")


def test_actord_se_recharge_par_sighup():
    assert _valeurs(ACTORD, "ExecReload") == ["/bin/kill", "-HUP", "$MAINPID"]
    src = (TNG / "cmd" / "sbx-actord" / "main.go").read_text(encoding="utf-8")
    assert src.index("signal.Notify(hupReseau, syscall.SIGHUP)") < src.index("srv.rebuild()")


def test_authwatch_ecrit_son_etat_dans_son_propre_dossier():
    """Jamais /run/secubox en écriture (sockets de tous les modules) : un RuntimeDirectory propre, effacé à l'arrêt."""
    etat = Path(_defaut("sbx-authwatch", "campagnes-etat"))
    assert "ProtectSystem=strict" in AUTHWATCH
    assert _valeurs(AUTHWATCH, "RuntimeDirectory") == ["secubox-authwatch"]
    assert str(etat.parent) == "/run/secubox-authwatch"
    assert _valeurs(AUTHWATCH, "RuntimeDirectoryMode") == ["0755"]
    assert _valeurs(AUTHWATCH, "RuntimeDirectoryPreserve") in ([], ["no"])
    assert _valeurs(AUTHWATCH, "ReadWritePaths") == ["/var/log/secubox/waf"]


def test_le_releve_lit_l_etat_la_ou_authwatch_l_ecrit():
    src = (PAQUET / "composants" / "waf" / "api" / "populations.py").read_text(encoding="utf-8")
    assert re.search(r'^AUTHWATCH_CAMPAGNES = "([^"]+)"', src, re.M).group(1) == _defaut("sbx-authwatch", "campagnes-etat")


def test_l_api_a_de_quoi_lire_les_bases():
    control = (PAQUET / "debian" / "control").read_text(encoding="utf-8")
    depends = control[control.index("\nDepends:"):control.index("\nConflicts:")]
    assert re.search(r"^ python3-maxminddb,?$", depends, re.M)
    assert re.search(r"^ acl,?$", depends, re.M)


def test_actord_a_de_quoi_tenir_le_cache_de_pages_de_ses_bases():
    """À 200M, l'ouverture relisait des pages aussitôt évincées (3 Go lus, API fermée 10 min sur gk2)."""
    def mo(cle):
        v = _valeurs(ACTORD, cle)[0]
        assert v.endswith("M")
        return int(v[:-1])
    assert mo("MemoryHigh") >= 450 and mo("MemoryMax") >= mo("MemoryHigh")
    assert "GOMEMLIMIT=180MiB" in _valeurs(ACTORD, "Environment")      # la mémoire propre reste bornée


def test_un_fichier_disparu_ne_bloque_pas_le_demarrage_du_waf():
    """`find … -exec chown` échoue si un fichier (temporaire du relevé) disparaît pendant la passe : jamais fatal."""
    waf = (PAQUET / "systemd" / "secubox-waf-ng.service").read_text(encoding="utf-8")
    lignes = [l for l in waf.splitlines() if l.startswith("ExecStartPre=") and "/usr/bin/find" in l]
    assert len(lignes) == 1 and lignes[0].startswith("ExecStartPre=-+/usr/bin/find /var/lib/secubox/waf ")
    assert "ExecStartPre" not in (PAQUET / "conf" / "honeypot.conf").read_text(encoding="utf-8")   # rien à refléter


def test_actord_capte_l_arret_avant_le_rejeu():
    """SIGTERM pendant le rejeu : sortie par les `defer` (liste des pages libres écrite), jamais un arrêt brutal."""
    src = (TNG / "cmd" / "sbx-actord" / "main.go").read_text(encoding="utf-8")
    ctx = src.index("signal.NotifyContext(")
    assert src.index("defer led.Close()") < ctx < src.index("srv.rebuild()") < src.index("if ctx.Err() != nil")
    assert src.index("if ctx.Err() != nil") < src.index("srv.serveIngest(") and src.count("signal.NotifyContext(") == 1
