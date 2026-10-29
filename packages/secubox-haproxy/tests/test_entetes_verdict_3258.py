# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: aucun en-tête de VERDICT X-SecuBox-* ne franchit l'entrée publique (#3258, audit R10).

Seul `onion-in` effaçait `X-SecuBox-` (#3112). Par `http-in` et `https-in`, un client d'Internet pouvait envoyer
`X-SecuBox-LAN: 1` à travers HAProxy et sbxwaf jusqu'au waker (wakerproxy.go recopie les en-têtes du client) ou
jusqu'à tout amont qui fait confiance à cette marque. On vérifie :

  (a) chaque en-tête de verdict (V : posé par un composant interne en aval de l'entrée, lu comme une affirmation)
      est effacé dans les deux frontaux publics, AVANT tout `set-header` ;
  (b) aucun en-tête de protocole (P : envoyé par l'émetteur, vérifié par le récepteur) n'y est effacé ;
  (c) tout en-tête X-SecuBox-* qu'un relais nginx du dépôt POSE avec une valeur est effacé à l'entrée : un nouveau
      verdict ne peut pas naître sans qu'on décide de son sort ;
  (d) le générateur de l'API (`POST /haproxy/generate`, bouton de la page) efface la même liste, dans les deux
      frontaux : sinon un clic réécrirait une entrée sans protection.
"""
import asyncio
import importlib.util
import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
CTL = PKG / "sbin" / "haproxyctl"

# Classement prouvé par le code (rapport de l'étape 0 de #3258 : qui pose, qui lit).
VERDICTS = [
    "X-SecuBox-LAN",              # nginx `$lan_client` → secubox_core.auth, premier-pas, webos, waker
    "X-SecuBox-Onion",            # HAProxy onion-in → marque « client onion »
    "X-SecuBox-Console",          # nginx :9078 (secret du port console) → secubox-auth /console/jeton
    "X-SecuBox-Console-Hote",     # nginx :9078 `$host` → secubox-auth /console/jeton
    "X-SecuBox-Console-Paire",    # nginx :9078 adresse:port de la connexion → secubox-auth /console/jeton
    "X-SecuBox-Origin-Status",    # nginx `$upstream_status` (secubox-waking.conf) → waker.py
    "X-SecuBox-Netboot-Lot",      # nginx :8099 → secubox-netboot /lot-flash
    "X-SecuBox-Adresse-Serveur",  # nginx :8099 `$server_addr` → secubox-netboot /lot-flash
    # Arbitrage du contrôleur (#3258) : verdicts posés en aval de HAProxy ; le maillage passe par le tunnel nginx.
    "X-SecuBox-Pair",             # nginx :7331 (wg-mesh), jeton `$p2p_pair_cle` → secubox-p2p master-link
    "X-SecuBox-Maillage",         # nginx :8799 (wg-mesh) « 1 » → secubox-annuaire, openpgp boite/depot
    "X-SecuBox-Relais",           # agrégateur, relais web vers vault → vault (routes hors relais)
    "X-SecuBox-Second-Facteur",   # agrégateur après TOTP → vault /ouvrir hors LAN
]
PROTOCOLE = [
    "X-SecuBox-Signature",        # HMAC posé par l'émetteur du webhook, vérifié par le récepteur
    "X-SecuBox-Healthcheck",      # posé par le JS des pages d'erreur HAProxy (navigateur), lu par personne
    "X-SecuBox-Droplet",          # en-tête de COURRIEL (alerte droplet), jamais HTTP : rien à effacer
]


def _onion():
    spec = importlib.util.spec_from_file_location("onion_in_3112_pour_3258", PKG / "tests" / "test_onion_in_3112.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    return _onion()._generer(tmp_path_factory.mktemp("verdicts"))


def _bloc(cfg, entete):
    return _onion()._bloc(cfg, entete)


FRONTAUX = ("frontend http-in", "frontend https-in")


# ── (a) les verdicts sont effacés tôt ────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fe", FRONTAUX)
@pytest.mark.parametrize("nom", VERDICTS)
def test_chaque_verdict_est_efface_dans_les_frontaux_publics(cfg, fe, nom):
    bloc = _bloc(cfg, fe)
    assert f"http-request del-header {nom}" in bloc, f"{nom} doit être effacé dans {fe}"


@pytest.mark.parametrize("fe", FRONTAUX)
def test_les_effacements_precedent_tout_set_header(cfg, fe):
    bloc = _bloc(cfg, fe)
    poses = [i for i, x in enumerate(bloc) if x.startswith("http-request set-header")]
    assert poses, f"{fe} pose au moins X-Forwarded-Proto"
    for nom in VERDICTS:
        assert bloc.index(f"http-request del-header {nom}") < min(poses), f"{nom} effacé trop tard dans {fe}"


@pytest.mark.parametrize("fe", FRONTAUX)
def test_les_effacements_precedent_tout_routage(cfg, fe):
    bloc = _bloc(cfg, fe)
    routes = [i for i, x in enumerate(bloc) if x.startswith(("use_backend", "default_backend", "redirect"))]
    for nom in VERDICTS:
        assert bloc.index(f"http-request del-header {nom}") < min(routes), f"{nom} : effacer avant de router ({fe})"


# ── (b) rien d'autre n'est effacé ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fe", FRONTAUX)
def test_aucun_en_tete_de_protocole_n_est_efface(cfg, fe):
    bloc = _bloc(cfg, fe)
    for nom in PROTOCOLE:
        assert f"http-request del-header {nom}" not in bloc, f"{nom} ne doit pas être effacé ({fe})"
    # pas d'effacement en bloc, qui emporterait les en-têtes de protocole
    assert not [x for x in bloc if re.match(r"http-request del-header X-SecuBox-\S*\s+-m", x)], "aucun effacement par motif"
    effaces = {x.split()[2] for x in bloc if x.startswith("http-request del-header X-SecuBox-")}
    assert effaces == set(VERDICTS)


# ── (c) tout verdict posé par un relais nginx du dépôt est classé ────────────────────────────────────────────────
POSE = re.compile(r"proxy_set_header\s+(X-SecuBox-[A-Za-z-]+)\s+(\"[^\"]*\"|[^;\s]+)\s*;", re.I)


def _sources_nginx():
    motifs = ("packages/*/nginx/**/*", "packages/*/composants/*/nginx/**/*", "common/nginx/**/*",
              "packages/*/sbin/*", "packages/*/debian/postinst")
    for motif in motifs:
        for p in REPO.glob(motif):
            if p.is_file():
                yield p


def test_tout_verdict_pose_par_nginx_est_classe():
    poses = {}
    for p in _sources_nginx():
        try:
            texte = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for nom, valeur in POSE.findall(texte):
            if valeur.strip('"'):
                poses.setdefault(nom, set()).add(str(p.relative_to(REPO)))
    assert "X-SecuBox-LAN" in poses, "le relevé ne voit plus les relais nginx"
    connus = {n.lower() for n in VERDICTS}
    inconnus = {n: sorted(f) for n, f in poses.items() if n.lower() not in connus}
    assert not inconnus, f"verdict posé par nginx et non classé à l'entrée publique : {inconnus}"


def test_le_frontal_onion_pose_un_verdict_classe():
    ctl = CTL.read_text(encoding="utf-8")
    for nom in re.findall(r"http-request set-header (X-SecuBox-[A-Za-z-]+)", ctl):
        assert nom in VERDICTS, nom


# ── (d) le générateur de l'API efface la même liste ──────────────────────────────────────────────────────────────
def test_l_api_et_haproxyctl_effacent_la_meme_liste():
    api = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    m = re.search(r"^ENTETES_VERDICT = \((.*?)\)$", api, re.M | re.S)
    assert m, "ENTETES_VERDICT introuvable dans api/main.py"
    assert re.findall(r'"(X-SecuBox-[A-Za-z-]+)"', m.group(1)) == VERDICTS
    ctl = CTL.read_text(encoding="utf-8")
    m = re.search(r"^ENTETES_VERDICT=\((.*?)\)$", ctl, re.M | re.S)
    assert m, "ENTETES_VERDICT introuvable dans haproxyctl"
    assert m.group(1).split() == VERDICTS


def test_le_generateur_de_l_api_efface_les_verdicts_dans_les_deux_frontaux(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(PKG))
    from api import main as api

    cfg_path = tmp_path / "haproxy.cfg"
    monkeypatch.setattr(api, "HAPROXY_CFG", str(cfg_path))
    monkeypatch.setattr(api, "_load_vhosts", lambda: [{"name": "hall", "domain": "hall.gk2.secubox.in",
                                                        "backend": "nginx_vhosts", "enabled": True, "ssl": True}])
    monkeypatch.setattr(api, "_load_backends", lambda: [])

    class Res:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(api.subprocess, "run", lambda *a, **k: Res())

    async def rien():
        return None

    monkeypatch.setattr(api, "sync_waf_routes", rien)
    asyncio.run(api.generate_config())
    texte = "\n" + cfg_path.read_text(encoding="utf-8")
    for fe in FRONTAUX:
        bloc = _bloc(texte, fe)
        for nom in VERDICTS:
            assert f"http-request del-header {nom}" in bloc, (fe, nom)
        for nom in PROTOCOLE:
            assert f"http-request del-header {nom}" not in bloc, (fe, nom)
