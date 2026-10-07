# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 : chaque paquet absorbé devient un composant de l'absorbant (mêmes chemins) et un transitoire vide ; plus rien n'en dépend."""
import re
from pathlib import Path

PAQ = Path(__file__).resolve().parents[2] / "packages"
# (absorbant, absorbé) — les fusions déjà faites par scripts/absorber-paquet.py (S1, S2 et N1 ont leurs propres tests)
FUSIONS = [("matrix", "jabber"), ("dns-guard", "network-anomaly"), ("dns", "dns-provider"), ("threats", "ai-insights"),
           ("health", "health-doctor"), ("health", "watchdog"), ("webos", "sbxui"), ("appstore", "metacatalog"),
           ("dns", "dns-lan"), ("qos", "traffic"), ("streamlit", "streamforge"), ("media", "smb"), ("media", "freeboxtv"), ("repo", "release"), ("jitsi", "turn"), ("mail", "smtp-relay"), ("annuaire", "openpgp"), ("p2p", "meshname"), ("haproxy", "vhost"), ("haproxy", "exposure"), ("ipblock", "vortex-firewall"), ("ipblock", "cyberfeed"), ("tor", "proxypac"), ("tor", "macro"), ("routes", "netdiag"), ("metanews", "devwatch"), ("metanews", "yacy"), ("dpi", "ndpid"), ("dpi", "mediaflow"), ("metrics", "grafana"), ("metablogizer", "droplet"), ("metablogizer", "publish"), ("ytsas", "torrent"), ("mqtt", "zigbee"),
           ("backup", "cloner"), ("metrics", "glances"), ("metrics", "reporter"), ("ai-gateway", "localrecall"),
           ("ai-gateway", "mcp-server")]


def _c(p):
    return (PAQ / p / "debian/control").read_text()


def test_les_absorbes_sont_transitoires_et_vides():
    for a, o in FUSIONS:
        c = _c(f"secubox-{o}")
        assert re.search(r"(?m)^Section: oldlibs\s*$", c), o
        assert re.search(rf"(?m)^Depends:.*secubox-{a} \(>= ", c), o
        for d in ("api", "www", "nginx", "systemd", "menu.d", "sbin", "tests"):
            restes = [f for f in (PAQ / f"secubox-{o}" / d).rglob("*") if f.is_file() and "__pycache__" not in f.parts]
            assert not restes, f"{o}/{d} : {restes}"
        # seul un postinst qui remet l'unité en route est permis (voir plus bas)
        if o not in ARRETAIENT_A_LA_MISE_A_JOUR:
            assert not (PAQ / f"secubox-{o}/debian/postinst").exists()


def test_les_absorbants_portent_le_composant_et_remplacent_l_ancien():
    for a, o in FUSIONS:
        assert (PAQ / f"secubox-{a}/composants/{o}").is_dir(), (a, o)
        c = _c(f"secubox-{a}")
        for champ in ("Replaces", "Breaks"):
            assert re.search(rf"(?ms)^{champ}:.*?secubox-{o} \(<< ", c), (a, o, champ)
        rules = (PAQ / f"secubox-{a}/debian/rules").read_text()
        assert f"composants/{o}/" in rules and f"debian/secubox-{a}/" in rules and f"debian/secubox-{o}/" not in rules


def test_aucun_paquet_ne_depend_plus_de_l_absorbe():
    liens = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances")
    for a, o in FUSIONS:
        motif = re.compile(rf"secubox-{re.escape(o)}(?![\w-])")
        for ctrl in PAQ.glob("*/debian/control"):
            nom = ctrl.parts[-3].removeprefix("secubox-")
            if nom == o or "/debian/secubox-" in str(ctrl):
                continue
            champ = None
            for ligne in ctrl.read_text().splitlines():
                if ligne and not ligne[0].isspace():
                    champ = ligne.split(":", 1)[0]
                if champ in liens and motif.search(ligne):
                    raise AssertionError(f"{ctrl} : {ligne.strip()}")


def test_l_arbre_met_les_absorbes_hors_arbre():
    arbre = (PAQ / "secubox-meta/arbre.yaml").read_text()
    avant, _, apres = arbre.partition("# ═══ RACINES")
    for _, o in FUSIONS:
        assert re.search(rf"secubox-{o}(?![\w-])", avant), o
        assert not re.search(rf"(?m)^\s+- secubox-{o}(?![\w-])", apres), o


# L'ancien prerm de ces paquets arrêtait l'unité à la mise à jour : le transitoire la remet en route (#2050).
ARRETAIENT_A_LA_MISE_A_JOUR = ("grafana", "reporter", "smtp-relay", "traffic", "zigbee", "ndpid", "mediaflow", "devwatch", "yacy", "netdiag", "proxypac", "vortex-firewall", "cyberfeed", "vhost", "exposure", "openpgp", "meshname")


def test_transitoires_remettent_l_unite_en_route():
    for o in ARRETAIENT_A_LA_MISE_A_JOUR:
        postinst = PAQ / f"secubox-{o}" / "debian" / "postinst"
        assert postinst.is_file(), o
        t = postinst.read_text()
        assert f"secubox-{o}.service" in t and "masked" in t and "#DEBHELPER#" in t, o
        assert postinst.stat().st_mode & 0o111, f"{o} : postinst non exécutable"
