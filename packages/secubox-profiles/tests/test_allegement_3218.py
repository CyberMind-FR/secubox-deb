# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3218 — allègement des profils minimal et lite, d'après le banc de l'ESPRESSObin de 1 Go (gk5, 2026-10-28).

Fige : les exclusions décidées par le propriétaire (minimal ET lite : ksm, Centres, nDPId, DPI, Media Flow, « Boxes à préparer » ;
minimal seul : admin, API profiles, routes, netdiag, network-anomaly, premier-pas-console, portal, courbes et huit minuteries),
le socle présent (connexion, maillage, relais), la cohérence avec les méta-paquets, et le moteur qui rend tout cela applicable :
`minuteurs_off`, `proteges_off`, mise à jour des profils de référence non modifiés."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

from api import minuteurs
from api.diff import plan_changes
from api.manifest import PROTECTED_IDS, Manifest
from api.observe import Actual
from api.state import Profile, StateError, load_profile

PKG = Path(__file__).resolve().parents[1]
PAQUETS = PKG.parent
PROFILS = PKG / "profiles"
MINIMAL = load_profile(PROFILS / "minimal.toml")
LITE = load_profile(PROFILS / "lite.toml")

# ── décisions du propriétaire ────────────────────────────────────────────────

# Hors de minimal ET de lite : ksm, centres, nDPId, DPI (et ses minuteries), Media Flow, « Boxes à préparer ».
HORS_DES_DEUX = {"ksm", "ndpid", "ndpid-engine", "ndpisrvd", "dpi", "dpi-flowcap", "dpi-resume", "mediaflow",
                 "premier-pas-decouverte", "premier-pas-maitre", "centers"}
MENUS_HORS_DES_DEUX = {"ksm", "centers", "premier-pas-maitre", "dpi", "ndpid", "mediaflow"}
# Hors de minimal en plus (surplus mesurés), et le service portal (sans tête).
HORS_MINIMAL = {"admin", "profiles", "routes", "netdiag", "network-anomaly", "premier-pas-console", "portal", "courbes"}
MINUTEURS_MINIMAL = {"dpi-resume", "yt-dlp-refresh", "courbes-serie", "metrics-publish", "netstats",
                     "network-anomaly-collecte", "profiles-releve", "cache-warm@jitsi", "cache-warm@metacatalog",
                     "streamlit-idle"}   # #3258 : relancerait Streamlit (union des minuteurs_off)
# Le socle que `profilectl diff --profile minimal` voulait ARRÊTER sur gk5, et ce qui reste.
# Le sleeper en est sorti par la relecture (#3248) : livré désactivé, hors profil (test_relecture_3218).
SOCLE = {"p2p", "annuaire", "users", "waker", "meshname", "net-fallback", "groupe-declares"}
FONCTIONS_MINIMAL = {"freebox", "ipv6guard", "nac", "dns-guard", "ad-guard", "webfilter", "wireguard", "autoload-agent",
                     "auth", "aggregator", "core", "hub", "system", "hardening"}


def test_minimal_et_lite_excluent_dpi_ndpid_ksm_centres_mediaflow_et_boxes_a_preparer():
    for prof in (MINIMAL, LITE):
        assert not prof.on & HORS_DES_DEUX, (prof.name, prof.on & HORS_DES_DEUX)
        assert MENUS_HORS_DES_DEUX <= prof.menu_off, (prof.name, MENUS_HORS_DES_DEUX - prof.menu_off)
        assert {"dpi-resume", "yt-dlp-refresh"} <= prof.minuteurs_off, prof.name


def test_minimal_exclut_les_surplus_mesures_et_leurs_minuteries():
    assert not MINIMAL.on & HORS_MINIMAL, MINIMAL.on & HORS_MINIMAL
    assert MINUTEURS_MINIMAL == MINIMAL.minuteurs_off
    assert MINIMAL.proteges_off == {"profiles"}          # l'API du panneau ; la CLI secubox-profilectl reste
    assert {"admin", "profiles", "network-anomaly", "netdiag", "grafana", "glances"} <= MINIMAL.menu_off


def test_le_socle_et_les_fonctions_sont_dans_minimal():
    assert SOCLE | FONCTIONS_MINIMAL <= MINIMAL.on, (SOCLE | FONCTIONS_MINIMAL) - MINIMAL.on


def test_le_socle_est_dans_lite():
    assert SOCLE <= LITE.on, SOCLE - LITE.on
    assert not LITE.proteges_off                         # lite garde le panneau /profiles/


def test_tous_les_profils_de_reference_se_chargent():
    noms = set()
    for p in sorted(PROFILS.glob("*.toml")):
        noms.add(load_profile(p).name)
    assert {"minimal", "lite", "full", "secure-gateway", "media-lab"} <= noms


# ── cohérence avec les méta-paquets (sources du dépôt) ───────────────────────

def _champ(bloc: str, nom: str) -> set[str]:
    m = re.search(rf"^{nom}:((?:.*\n?)(?:[ \t].*\n?)*)", bloc, re.M)
    if not m:
        return set()
    return {x.group(1) for a in m.group(1).replace("\n", " ").split(",") for alt in a.split("|")[:1]
            if (x := re.match(r"\s*((?:secubox|sbxos)-[a-z0-9.+-]+)", alt))}


def _index() -> dict:
    idx = {}
    for c in PAQUETS.glob("*/debian/control"):
        t = re.sub(r"^#.*\n", "", c.read_text(encoding="utf-8"), flags=re.M)
        for b in re.split(r"\n\n+", t):
            m = re.search(r"^Package:\s*(\S+)", b, re.M)
            if m:
                idx[m.group(1)] = (c.parents[1], _champ(b, "Depends") | _champ(b, "Recommends"), _champ(b, "Conflicts"))
    return idx


INDEX = _index()


def _fermeture(meta: str) -> set[str]:
    """Ce qu'apt installe : Depends et Recommends (apt les prend par défaut), moins les Conflicts du méta-paquet."""
    conflits, vus, pile = INDEX[meta][2], set(), [meta]
    while pile:
        p = pile.pop()
        if p in vus or p in conflits or p not in INDEX:
            continue
        vus.add(p)
        pile.extend(INDEX[p][1])
    return vus


def _unites(paquets: set[str]) -> dict[str, list[str]]:
    """id -> textes des unités `secubox-<id>.service` (non gabarits) trouvées dans les sources des paquets."""
    out: dict[str, list[str]] = {}
    for p in sorted(paquets):
        for f in sorted(INDEX[p][0].rglob("*.service")):
            if "/tests/" in f.as_posix():
                continue
            n = f.name[len(p) + 1:] if f.name.startswith(p + ".") and f.name.count(".") >= 2 else f.name
            if n.startswith("secubox-") and "@" not in n:
                out.setdefault(n[len("secubox-"):-len(".service")], []).append(f.read_text(errors="replace"))
    return out


def _oneshot_de_minuterie(texte: str) -> bool:
    return bool(re.search(r"^Type=oneshot", texte, re.M)) and not re.search(r"^RemainAfterExit=(yes|true)", texte, re.M)


# Services durables livrés par la fermeture du méta-paquet et VOLONTAIREMENT hors du profil (l'apply les arrête).
HORS_PROFIL_MINIMAL = {
    "admin": "surplus mesuré (40 Mo), composant de secubox-system",
    "ksm": "décision du 2026-10-28 : sans VM ni conteneur, rien à fusionner",
    "profiles": "API du panneau, coupée par proteges_off ; la CLI reste",
    "portal": "sans tête : l'agrégateur sert /api/v1/portal ; le paquet reste pour login.html",
    "network-anomaly": "surplus mesuré (39 Mo), composant de secubox-dns-guard",
    "premier-pas-console": "assistant tty1 du premier démarrage, déjà passé (et Conflicts=getty@tty1 secubox-console)",
    "kiosk": "carte sans écran",
    "ad-guard-dnsfeed": "POC TV : le paquet ne l'active pas",
    "openpgp": "à l'arrêt sur gk5 pendant le banc ; échange de clés inter-box",
    "led-heartbeat": "source restée dans secubox-core, unité livrée par secubox-led-heartbeat (hors profil)",
    "sleeper": "livré désactivé, choix de l'opérateur ; hors profil (relecture #3248)",
}
HORS_PROFIL_LITE = {
    "ksm": "décision du 2026-10-28",
    "ad-guard-dnsfeed": "POC TV : le paquet ne l'active pas",
    "lan-dhcp": "DHCP du mode routeur : ni activé ni démarré par le paquet",
    # Jamais dans `on` : Conflicts=getty@tty1 secubox-console, et un START arrête ces deux-là même si sa condition échoue.
    "premier-pas-console": "assistant tty1 du premier démarrage ; le démarrer arrêterait la console",
    "sentinelle-gsm": "matériel, à la demande",
    "webos": "Hall, hors de lite (tiré par secubox-soc pour la vue Actor)",
    "sleeper": "livré désactivé, choix de l'opérateur ; hors profil (relecture #3248)",
    "led-heartbeat": "source restée dans secubox-core, unité livrée par secubox-led-heartbeat (hors profil)",
}


@pytest.mark.parametrize("meta, profil, hors", [("secubox-minimal", MINIMAL, HORS_PROFIL_MINIMAL),
                                                ("secubox-lite", LITE, HORS_PROFIL_LITE)])
def test_chaque_service_durable_du_meta_paquet_est_dans_le_profil_ou_hors_profil_nomme(meta, profil, hors):
    """Un profil est EXHAUSTIF : un service livré et absent du profil est arrêté par l'apply. Sur gk5, `diff --profile minimal`
    voulait arrêter le maillage (p2p, annuaire, meshname), users, sleeper, waker, groupe-declares : le socle."""
    unites = _unites(_fermeture(meta))
    durables = {mid for mid, textes in unites.items() if not all(_oneshot_de_minuterie(t) for t in textes)}
    oublies = durables - profil.on - set(hors) - PROTECTED_IDS
    assert not oublies, sorted(oublies)
    assert not set(hors) & profil.on


@pytest.mark.parametrize("meta, profil", [("secubox-minimal", MINIMAL), ("secubox-lite", LITE)])
def test_aucun_oneshot_de_minuterie_dans_on(meta, profil):
    """Listé dans `on`, un oneshot sans RemainAfterExit est DÉMARRÉ par l'apply, ne devient jamais « actif » : l'attente expire
    et tout l'apply est annulé (minimal listait annuaire-apply, webfilter-sync, premier-pas-appliquer...)."""
    unites = _unites(_fermeture(meta))
    fautifs = sorted(mid for mid in profil.on if any(_oneshot_de_minuterie(t) for t in unites.get(mid, [])))
    assert not fautifs, fautifs


def test_aucun_profil_ne_demarre_premier_pas_console_mais_minimal_et_lite_gardent_premier_pas():
    """premier-pas-console porte Conflicts=getty@tty1 secubox-console : un START (même condition non remplie) les arrête.
    premier-pas, lui, DOIT rester : l'assistant silencieux appelle l'apply depuis cette unité, l'arrêter le tuerait."""
    for p in sorted(PROFILS.glob("*.toml")):
        assert "premier-pas-console" not in load_profile(p).on, p.name
    assert "premier-pas" in MINIMAL.on and "premier-pas" in LITE.on


def test_les_meta_paquets_ne_tirent_plus_le_dpi():
    assert not {"secubox-dpi", "secubox-ndpid-engine"} & _fermeture("secubox-minimal")
    assert not {"secubox-dpi", "secubox-ndpid-engine"} & _fermeture("secubox-lite")
    assert {"secubox-dpi", "secubox-ndpid-engine"} <= _fermeture("secubox-full")      # isp et full gardent le DPI
    assert {"secubox-courbes", "secubox-routes"}.isdisjoint(_fermeture("secubox-minimal"))
    assert "secubox-profiles" in _fermeture("secubox-minimal")                          # la CLI reste (autoload-agent)


# ── moteur : chargement ──────────────────────────────────────────────────────

def _ecrire(dossier: Path, nom: str, corps: str) -> Path:
    dossier.mkdir(parents=True, exist_ok=True)
    p = dossier / f"{nom}.toml"
    p.write_text(f'name = "{nom}"\nlabel = "{nom}"\n{corps}', encoding="utf-8")
    return p


def test_proteges_off_refuse_tout_autre_id_que_profiles(tmp_path):
    for id_ in ("auth", "aggregator", "vault", "autoload-agent", "core"):
        with pytest.raises(StateError):
            load_profile(_ecrire(tmp_path, "p", f'on = []\nproteges_off = ["{id_}"]\n'))
    assert load_profile(_ecrire(tmp_path, "p", 'on = []\nproteges_off = ["profiles"]\n')).proteges_off == {"profiles"}


@pytest.mark.parametrize("mauvais", ["../x", "secubox-netstats.timer", "Netstats", "a b", "x@", ""])
def test_minuterie_invalide_refusee(tmp_path, mauvais):
    with pytest.raises(StateError):
        load_profile(_ecrire(tmp_path, "p", f'on = []\nminuteurs_off = ["{mauvais}"]\n'))


# ── moteur : etendre ─────────────────────────────────────────────────────────

def _m(mid: str, protected: bool = False) -> Manifest:
    return Manifest(id=mid, category="infra", runtime="native", exposure="internal", units=(f"secubox-{mid}.service",),
                    protected=protected)


@pytest.fixture()
def dossier(tmp_path):
    d = tmp_path / "profiles"
    _ecrire(d, "minimal", 'on = ["hub"]\nminuteurs_off = ["netstats", "cache-warm@jitsi"]\nproteges_off = ["profiles"]\n')
    _ecrire(d, "lite", 'on = ["hub"]\nminuteurs_off = ["dpi-resume"]\n')
    _ecrire(d, "full", 'on = ["hub"]\n')
    (d / "casse.toml").write_text("name = ", encoding="utf-8")            # un profil illisible n'empêche rien
    return d


def test_etendre_union_des_minuteries_et_sens_par_profil(dossier):
    base = {"hub": _m("hub"), "profiles": _m("profiles", protected=True)}
    eff, prof = minuteurs.etendre(base, load_profile(dossier / "minimal.toml"), dossier, presente=lambda u: True)
    assert {"minuteur:netstats", "minuteur:cache-warm@jitsi", "minuteur:dpi-resume"} <= set(eff)
    assert eff["minuteur:netstats"].units == ("secubox-netstats.timer",)
    assert "minuteur:netstats" not in prof.on and "minuteur:cache-warm@jitsi" not in prof.on
    assert "minuteur:dpi-resume" in prof.on                     # nommée par lite seulement : minimal la rétablit
    eff, prof = minuteurs.etendre(base, load_profile(dossier / "full.toml"), dossier, presente=lambda u: True)
    assert {"minuteur:netstats", "minuteur:cache-warm@jitsi", "minuteur:dpi-resume"} <= prof.on


def test_etendre_ignore_une_minuterie_dont_l_unite_est_absente(dossier):
    eff, prof = minuteurs.etendre({}, load_profile(dossier / "full.toml"), dossier,
                                  presente=lambda u: u != "secubox-dpi-resume.timer")
    assert "minuteur:dpi-resume" not in eff and "minuteur:dpi-resume" not in prof.on


def test_unite_presente_lit_le_gabarit_d_une_instance(tmp_path):
    (tmp_path / "secubox-cache-warm@.timer").write_text("[Timer]\n")
    assert minuteurs.unite_presente("secubox-cache-warm@jitsi.timer", dossiers=(tmp_path,))
    assert not minuteurs.unite_presente("secubox-netstats.timer", dossiers=(tmp_path,))


def test_etendre_sans_profil_ne_change_rien(dossier):
    base = {"hub": _m("hub")}
    assert minuteurs.etendre(base, None, dossier, presente=lambda u: True) == (base, None)


def test_proteges_off_coupe_profiles_dans_le_plan_seulement(dossier):
    base = {"hub": _m("hub"), "profiles": _m("profiles", protected=True), "auth": _m("auth", protected=True)}
    eff, prof = minuteurs.etendre(base, load_profile(dossier / "minimal.toml"), dossier, presente=lambda u: False)
    assert base["profiles"].protected and not eff["profiles"].protected and eff["auth"].protected
    allume = Actual(enabled=True, active=True)
    plan = plan_changes(eff, prof, {}, {"hub": allume, "profiles": allume, "auth": allume})
    assert [(c.id, c.action) for c in plan] == [("profiles", "stop")]
    assert "proteges_off" in plan[0].reason
    # lite ne coupe rien : profiles reste protégé, donc allumé.
    eff, prof = minuteurs.etendre(base, load_profile(dossier / "lite.toml"), dossier, presente=lambda u: False)
    assert plan_changes(eff, prof, {}, {"hub": allume, "profiles": allume, "auth": allume}) == []


def test_plan_arrete_la_minuterie_dans_minimal_et_la_retablit_ailleurs(dossier):
    eff, prof = minuteurs.etendre({}, load_profile(dossier / "minimal.toml"), dossier,
                                  presente=lambda u: u == "secubox-netstats.timer")
    plan = plan_changes(eff, prof, {}, {"minuteur:netstats": Actual(enabled=True, active=True)})
    assert [(c.id, c.action) for c in plan] == [("minuteur:netstats", "stop")]
    assert "minuteurs_off" in plan[0].reason and plan[0].priority == minuteurs.PRIORITE
    eff, prof = minuteurs.etendre({}, load_profile(dossier / "full.toml"), dossier,
                                  presente=lambda u: u == "secubox-netstats.timer")
    plan = plan_changes(eff, prof, {}, {"minuteur:netstats": Actual(enabled=False, active=False)})
    assert [(c.id, c.action) for c in plan] == [("minuteur:netstats", "start")]


def test_actuation_d_une_minuterie_desactive_puis_arrete_le_timer():
    from api.actuate import actuate
    from api.diff import Change
    vus = []
    actuate(Change("minuteur:netstats", "stop", "r", 10), minuteurs.manifeste("netstats"),
            run=lambda argv: (vus.append(argv), (0, ""))[1])
    assert vus == [["systemctl", "disable", "secubox-netstats.timer"],
                   ["systemctl", "stop", "--no-block", "secubox-netstats.timer"]]


def test_le_rollback_restaure_les_minuteries_du_snapshot():
    snap = {"modules": {"minuteur:netstats": {"on": True}, "minuteur:../x": {"on": True}, "hub": {"on": True}}}
    eff = minuteurs.manifestes_du_snapshot(snap)
    assert set(eff) == {"minuteur:netstats"} and eff["minuteur:netstats"].units == ("secubox-netstats.timer",)
    assert minuteurs.manifestes_du_snapshot({}) == {}


def test_cli_diff_minimal_planifie_les_minuteries(tmp_path, monkeypatch, capsys):
    from api.cli import main
    racine = tmp_path / "etc"
    (racine / "modules.d").mkdir(parents=True)
    _ecrire(racine / "profiles", "minimal", 'on = []\nminuteurs_off = ["netstats"]\n')
    unites = tmp_path / "unites"
    unites.mkdir()
    (unites / "secubox-netstats.timer").write_text("[Timer]\n")
    monkeypatch.setattr(minuteurs, "DOSSIERS_UNITES", (unites,))
    monkeypatch.setattr("api.cli._observe_all", lambda ms, routes: {
        mid: Actual(enabled=True, active=True) for mid in ms})
    assert main(["--root", str(racine), "diff", "--profile", "minimal", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [(c["id"], c["action"]) for c in out["changes"]] == [("minuteur:netstats", "stop")]


def test_le_panneau_garde_les_cles_du_profil_en_le_reecrivant(tmp_path):
    import api.web as web
    chemin = _ecrire(tmp_path, "minimal", 'on = ["hub"]\nmenu_off = ["ksm"]\nminuteurs_off = ["netstats"]\n'
                                          'proteges_off = ["profiles"]\n')
    prof = load_profile(chemin)
    web._write_profile(chemin, dataclasses.replace(prof, on=frozenset({"hub", "nac"})))
    relu = load_profile(chemin)
    assert relu.on == {"hub", "nac"} and relu.menu_off == {"ksm"}
    assert relu.minuteurs_off == {"netstats"} and relu.proteges_off == {"profiles"}


def test_profile_reste_constructible_sans_les_cles_facultatives():
    p = Profile(name="x", label="x", on=frozenset({"a"}))
    assert p.menu_off == p.minuteurs_off == p.proteges_off == frozenset()


# ── profils de référence : mise à jour à l'installation ──────────────────────

SCRIPT = PKG / "scripts" / "maj-references.py"
EMPREINTES = PROFILS / "empreintes-livrees.txt"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_les_versions_actuelles_sont_dans_les_empreintes_livrees():
    """Sinon la PROCHAINE mise à jour prendrait ces copies pour des modifications de l'opérateur.
    Après avoir modifié un profil : python3 packages/secubox-profiles/scripts/gen-empreintes-livrees.py"""
    lignes = set(EMPREINTES.read_text(encoding="utf-8").splitlines())
    for p in sorted(PROFILS.glob("*.toml")):
        assert f"{_sha(p.read_bytes())}  {p.name}" in lignes, p.name


def test_le_paquet_installe_le_script_et_les_empreintes_et_le_postinst_l_appelle():
    install = (PKG / "debian" / "install").read_text(encoding="utf-8")
    assert "profiles/empreintes-livrees.txt" in install and "scripts/maj-references.py" in install
    post = (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert "python3 -I /usr/lib/secubox/profiles/maj-references.py" in post


def _lancer(src: Path, dst: Path, emp: Path) -> str:
    import os
    import sys
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(src), str(dst), str(emp)], capture_output=True,
                       text=True, timeout=30, check=True, env=dict(os.environ, PREPA=str(dst.parent)))
    return r.stderr


@pytest.fixture()
def refs(tmp_path):
    src, dst = tmp_path / "share", tmp_path / "etc"
    src.mkdir()
    dst.mkdir()
    ancien = b'name = "minimal"\non = ["dpi"]\n'
    (src / "minimal.toml").write_bytes(b'name = "minimal"\non = ["hub"]\n')
    (src / "lite.toml").write_bytes(b'name = "lite"\non = []\n')
    emp = src / "empreintes-livrees.txt"
    emp.write_text(f"# commentaire\n{_sha(ancien)}  minimal.toml\n", encoding="utf-8")
    return src, dst, emp, ancien


def test_une_copie_livree_non_modifiee_est_remplacee(refs):
    src, dst, emp, ancien = refs
    (dst / "minimal.toml").write_bytes(ancien)
    err = _lancer(src, dst, emp)
    assert (dst / "minimal.toml").read_bytes() == (src / "minimal.toml").read_bytes()
    assert (dst / "lite.toml").is_file()                                   # absente : installée
    assert "mis à jour" in err and not list(dst.glob(".reference.*"))


def test_une_copie_modifiee_est_gardee_et_la_reference_posee_a_cote(refs):
    src, dst, emp, _ = refs
    (dst / "minimal.toml").write_bytes(b'name = "minimal"\non = ["hub", "a-moi"]\n')
    err = _lancer(src, dst, emp)
    assert b"a-moi" in (dst / "minimal.toml").read_bytes()
    assert (dst / "minimal.toml.dpkg-dist").read_bytes() == (src / "minimal.toml").read_bytes()
    assert "modifié localement" in err


def test_une_copie_deja_a_jour_n_est_pas_touchee(refs):
    src, dst, emp, _ = refs
    (dst / "minimal.toml").write_bytes((src / "minimal.toml").read_bytes())
    avant = (dst / "minimal.toml").stat().st_mtime_ns
    _lancer(src, dst, emp)
    assert (dst / "minimal.toml").stat().st_mtime_ns == avant and not (dst / "minimal.toml.dpkg-dist").exists()


def test_la_copie_actuelle_de_gk5_serait_mise_a_jour():
    """gk5 (image du 2026-10-27) porte le minimal.toml de #2909 : il figure parmi les versions livrées."""
    lignes = EMPREINTES.read_text(encoding="utf-8").splitlines()
    assert sum(1 for x in lignes if x.endswith("  minimal.toml")) >= 10
