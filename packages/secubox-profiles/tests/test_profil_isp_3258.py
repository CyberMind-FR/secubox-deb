# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 (audit R3) — le profil d'activation « isp » existe.

CONSTAT : une box Auto-Load « isp » installait secubox-isp puis échouait à l'étape « application » : aucun profil
`isp.toml` (`secubox-profilectl apply --profile isp` → « profil inconnu »).
DÉCISION DU PROPRIÉTAIRE (2026-10-29) : isp = lite + DPI (nDPI, nDPId), NetFlow (Media Flow) et la cabine numérique
(toolbox, ce que #3259 a retiré de lite, intercepteur). Ni « standard » ni « custom »."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from api.manifest import PROTECTED_IDS
from api.state import load_profile

PKG = Path(__file__).resolve().parents[1]
PAQUETS = PKG.parent
PROFILS = PKG / "profiles"
LITE = load_profile(PROFILS / "lite.toml")

# Ajouts d'isp à lite, nommés par la décision ; les moteurs du DPI sans lesquels « DPI » et « nDPId » ne marchent pas
# (un profil est EXHAUSTIF : absents de `on`, l'apply les arrêterait).
DPI = {"dpi", "dpi-flowcap", "ndpid", "ndpid-engine", "ndpisrvd"}
NETFLOW = {"mediaflow"}
CABINE = {"toolbox", "toolbox-wg-restore", "authwatch", "toolbox-egress-proxy", "interceptor"}   # #3259 : retirés de lite
AJOUTS = DPI | NETFLOW | CABINE
MENUS_RENDUS = {"dpi", "ndpid", "mediaflow", "toolbox"}
MINUTEURS_RENDUS = {"dpi-resume", "yt-dlp-refresh"}        # DPI et Media Flow (secubox-mediaflow.secubox-yt-dlp-refresh)

# Services durables de la fermeture de secubox-isp VOLONTAIREMENT hors du profil : l'apply les arrête.
# Décision du 2026-10-29 : isp = lite + DPI, NetFlow, cabine numérique — rien d'autre (voir le rapport de l'étape 0).
HORS_PROFIL_ISP = {
    "mail": "décision du 2026-10-29", "smtp-relay": "décision du 2026-10-29",
    "metablogizer": "décision du 2026-10-29", "droplet": "décision du 2026-10-29", "publish": "décision du 2026-10-29",
    "metrics": "décision du 2026-10-29", "reporter": "décision du 2026-10-29",
    "grafana": "décision du 2026-10-29", "glances": "décision du 2026-10-29",
    "modem": "décision du 2026-10-29", "saas-relay": "décision du 2026-10-29", "federation": "décision du 2026-10-29",
    "mirror": "décision du 2026-10-29", "streamlit": "décision du 2026-10-29",
    "streamlit-demarrage": "décision du 2026-10-29", "streamforge": "décision du 2026-10-29",
}


def _allegement():
    spec = importlib.util.spec_from_file_location("allegement_3218_pour_3258", PKG / "tests" / "test_allegement_3218.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _isp():
    return load_profile(PROFILS / "isp.toml")


def test_le_profil_isp_est_livre_et_se_charge():
    assert (PROFILS / "isp.toml").is_file(), "isp.toml absent : l'apply Auto-Load « isp » échoue"
    isp = _isp()
    assert isp.name == "isp"
    assert isp.label.startswith("ISP — ")
    assert not isp.proteges_off


def test_isp_contient_tout_lite():
    isp = _isp()
    assert LITE.on <= isp.on, sorted(LITE.on - isp.on)


def test_isp_ajoute_le_dpi_netflow_et_la_cabine_numerique_et_rien_d_autre():
    isp = _isp()
    assert {"dpi", "ndpid", "mediaflow", "toolbox"} <= isp.on
    assert AJOUTS <= isp.on, sorted(AJOUTS - isp.on)
    assert isp.on - LITE.on == AJOUTS, sorted((isp.on - LITE.on) ^ AJOUTS)


def test_les_menus_du_dpi_de_netflow_et_de_la_toolbox_sont_visibles():
    isp = _isp()
    assert not {"dpi", "ndpid", "mediaflow", "toolbox"} & isp.menu_off
    assert isp.menu_off == LITE.menu_off - MENUS_RENDUS


def test_les_minuteries_du_dpi_et_de_media_flow_sont_retablies():
    isp = _isp()
    assert not MINUTEURS_RENDUS & isp.minuteurs_off
    assert isp.minuteurs_off == (LITE.minuteurs_off - MINUTEURS_RENDUS) | MINUTEURS_RELANCEURS


# Revue #3258 (I1) : secubox-streamlit-idle.timer (toutes les 5 min) lance secubox-streamlit-idle.service, qui porte
# Requires=secubox-streamlit.service. L'apply désactive et arrête streamlit sans le masquer : la minuterie le relançait.
MINUTEURS_RELANCEURS = {"streamlit-idle"}
DEPENDANCES = re.compile(r"^(?:Requires|BindsTo|Wants|Requisite|PartOf)=(.*)$", re.M)


def _nom_unite(f: Path) -> str:
    """`<paquet>.<unité>` (unité installée par dh_installsystemd) → `<unité>` ; sinon le nom du fichier."""
    return f.name.split(".", 1)[1] if f.name.count(".") >= 2 else f.name


def _minuteries_et_leurs_cibles(paquets) -> dict[str, set[str]]:
    """id de minuterie (`secubox-<id>.timer`) → ids des services `secubox-<id>.service` qu'elle peut démarrer : son
    service et ce que ce service tire par Requires=, BindsTo=, Wants=, Requisite= ou PartOf=."""
    a = _allegement()
    out: dict[str, set[str]] = {}
    for p in sorted(paquets):
        racine = a.INDEX[p][0]
        services = {_nom_unite(f): f for f in racine.rglob("*.service") if "/tests/" not in f.as_posix()}
        for f in racine.rglob("*.timer"):
            nom = _nom_unite(f)
            if "/tests/" in f.as_posix() or not nom.startswith("secubox-"):
                continue
            tid = nom[len("secubox-"):-len(".timer")]
            m = re.search(r"^Unit=(\S+)", f.read_text(errors="replace"), re.M)
            service = m.group(1) if m else nom[:-len(".timer")] + ".service"
            cibles = {service}
            if service in services:
                for ligne in DEPENDANCES.findall(services[service].read_text(errors="replace")):
                    cibles |= set(ligne.split())
            out[tid] = {c[len("secubox-"):-len(".service")] for c in cibles
                        if c.startswith("secubox-") and c.endswith(".service")}
    return out


def test_aucune_minuterie_active_dans_isp_ne_relance_un_service_arrete():
    """Une minuterie que le profil laisse active ne doit démarrer aucun service durable que l'apply arrête."""
    a = _allegement()
    isp = _isp()
    paquets = a._fermeture("secubox-isp")
    unites = a._unites(paquets)
    durables = {mid for mid, textes in unites.items() if not all(a._oneshot_de_minuterie(t) for t in textes)}
    arretes = durables - isp.on - PROTECTED_IDS
    minuteries = _minuteries_et_leurs_cibles(paquets)
    assert "streamlit-idle" in minuteries and "streamlit" in minuteries["streamlit-idle"], "le relevé ne voit plus streamlit-idle"
    fautives = {tid: sorted(c & arretes) for tid, c in minuteries.items() if c & arretes and tid not in isp.minuteurs_off}
    assert not fautives, fautives
    assert MINUTEURS_RELANCEURS <= isp.minuteurs_off


def test_ni_standard_ni_custom():
    assert not (PROFILS / "standard.toml").exists() and not (PROFILS / "custom.toml").exists()


def test_chaque_profil_auto_load_a_son_profil_d_activation():
    """R3 : l'agent Auto-Load installe le méta-paquet puis `secubox-profilectl apply --profile <profil>`."""
    src = (PAQUETS / "secubox-autoload-agent" / "autoload_agent" / "moteur.py").read_text(encoding="utf-8")
    bloc = re.search(r"^PROFILS_PAQUET = \{(.*?)\}", src, re.M).group(1)
    for nom in re.findall(r'"([a-z-]+)":', bloc):
        assert (PROFILS / f"{nom}.toml").is_file(), nom


def test_chaque_service_durable_de_secubox_isp_est_dans_le_profil_ou_hors_profil_nomme():
    """Un profil est EXHAUSTIF : ce que secubox-isp installe et qu'isp ne nomme pas est ARRÊTÉ par l'apply."""
    a = _allegement()
    isp = _isp()
    unites = a._unites(a._fermeture("secubox-isp"))
    durables = {mid for mid, textes in unites.items() if not all(a._oneshot_de_minuterie(t) for t in textes)}
    oublies = durables - isp.on - set(HORS_PROFIL_ISP) - set(a.HORS_PROFIL_LITE) - PROTECTED_IDS
    assert not oublies, sorted(oublies)
    assert not set(HORS_PROFIL_ISP) & isp.on


def test_aucun_oneshot_de_minuterie_dans_isp():
    a = _allegement()
    unites = a._unites(a._fermeture("secubox-isp"))
    fautifs = sorted(mid for mid in _isp().on if any(a._oneshot_de_minuterie(t) for t in unites.get(mid, [])))
    assert not fautifs, fautifs
