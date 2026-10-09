# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 : chaque paquet absorbé devient un composant de l'absorbant (mêmes chemins) et un transitoire vide ; plus rien n'en dépend."""
import re
from pathlib import Path

PAQ = Path(__file__).resolve().parents[2] / "packages"
# (absorbant, absorbé) — les fusions déjà faites par scripts/absorber-paquet.py (S1, S2 et N1 ont leurs propres tests)
FUSIONS = [("matrix", "jabber"), ("dns-guard", "network-anomaly"), ("dns", "dns-provider"), ("threats", "ai-insights"),
           ("health", "health-doctor"), ("health", "watchdog"), ("webos", "sbxui"), ("appstore", "metacatalog"),
           ("dns", "dns-lan"), ("qos", "traffic"), ("streamlit", "streamforge"), ("media", "smb"), ("media", "freeboxtv"), ("repo", "release"), ("jitsi", "turn"), ("mail", "smtp-relay"), ("security-posture", "cve-triage"), ("security-posture", "antirootkit"), ("waf-ng", "waf"), ("cdn", "mirror"), ("qos", "nettweak"), ("system", "system-hub"), ("system", "admin"), ("system", "ksm"), ("system", "system-tuning"), ("auth", "users"), ("auth", "sbxid"), ("auth", "oidc"), ("annuaire", "openpgp"), ("p2p", "meshname"), ("haproxy", "vhost"), ("haproxy", "exposure"), ("ipblock", "vortex-firewall"), ("ipblock", "cyberfeed"), ("tor", "proxypac"), ("tor", "macro"), ("routes", "netdiag"), ("metanews", "devwatch"), ("metanews", "yacy"), ("dpi", "ndpid"), ("dpi", "mediaflow"), ("metrics", "grafana"), ("metablogizer", "droplet"), ("metablogizer", "publish"), ("ytsas", "torrent"), ("mqtt", "zigbee"),
           ("backup", "cloner"), ("metrics", "glances"), ("metrics", "reporter"), ("ai-gateway", "localrecall"),
           ("ai-gateway", "mcp-server")]


def _c(p):
    return (PAQ / p / "debian/control").read_text()


def test_les_absorbes_sont_retires_du_depot():
    """Le transitoire est resté publié un cycle (alpha.10) ; il n'existe plus dans les sources (#2050, vague 5)."""
    for a, o in FUSIONS:
        assert not (PAQ / f"secubox-{o}").exists(), f"secubox-{o} : transitoire à retirer"


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


def test_l_arbre_ne_met_pas_les_absorbes_dans_les_racines():
    arbre = (PAQ / "secubox-meta/arbre.yaml").read_text()
    _, _, apres = arbre.partition("# ═══ RACINES")
    for _, o in FUSIONS:
        assert not re.search(rf"(?m)^\s+- secubox-{o}(?![\w-])", apres), o


def test_aucun_transitoire_ne_garde_un_fichier_compat():
    """`debian/compat` en plus de `debhelper-compat` dans control : dh refuse (« compat level specified both… »)."""
    for ctrl in PAQ.glob("*/debian/control"):
        if "Section: oldlibs" in ctrl.read_text():
            assert not (ctrl.parent / "compat").exists(), ctrl
