# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: onion du webui jamais LAN (#3112).

Le service onion « webui » livrait à nginx :9080 en direct : chaque visiteur Tor arrivait de 127.0.0.1, adresse
que nginx croit (set_real_ip_from) et classe LAN (geo 127.0.0.0/8), et un X-Forwarded-For forgé était cru aussi.
Désormais Tor livre au frontal HAProxy `onion-webui`, qui efface l'adresse annoncée par le client et pose le
marqueur NON LAN 192.0.2.80 avant l'inspection sbxwaf. On vérifie ici :

  (a) le frontal généré par `haproxyctl generate` efface X-Forwarded-For du client PUIS pose le marqueur,
      et passe par sbxwaf — jamais webui_direct ni nginx en direct ;
  (b) 192.0.2.80 n'est dans AUCUNE plage LAN de secubox-lan-geo.conf, ni relais de confiance de nginx,
      ni plage privée de sbxwaf ou de HAProxy ;
  (c) les ports concordent entre haproxyctl, l'API haproxy et le composant exposure (jamais 9080).
"""
import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
CTL = PKG / "sbin" / "haproxyctl"
LAN_GEO = REPO / "packages" / "secubox-hub" / "nginx" / "secubox-lan-geo.conf"
SBXWAF_INSPECT = REPO / "packages" / "secubox-toolbox-ng" / "cmd" / "sbxwaf" / "inspect.go"
EXPOSURE = PKG / "composants" / "exposure" / "api" / "main.py"
MARQUEUR = ipaddress.ip_address("192.0.2.80")

TOML = """\
mode = "native"
http_port = 80
https_port = 443
stats_port = 8404
waf_enabled = true
waf_backend_ip = "127.0.0.1"
waf_backend_port = 8085
{extra}
[vhosts.hall]
domain = "hall.gk2.secubox.in"
backend = "nginx_vhosts"
enabled = true
ssl = true
"""


def _generer(base: Path, extra: str = "") -> str:
    """Lance `haproxyctl generate` sur un haproxy.toml témoin et rend le cfg produit."""
    if not shutil.which("bash"):
        pytest.skip("bash absent")
    for d in ("conf", "cfg", "cfgd", "bin", "run"):
        (base / d).mkdir()
    toml = base / "conf" / "haproxy.toml"
    toml.write_text(TOML.format(extra=extra), encoding="utf-8")
    # `haproxy -c` valide tout : on teste le GÉNÉRATEUR, HAProxy n'est pas installé sur un poste de dev.
    faux = base / "bin" / "haproxy"
    faux.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    faux.chmod(0o755)
    # Seules adaptations du script, pour tourner sans root : /run/haproxy devient un répertoire du test et
    # l'installation finale ne force plus le propriétaire root. Rien de ce qui est généré n'en dépend.
    source = CTL.read_text(encoding="utf-8")
    for avant, apres in (('mkdir -p "$CONFIG_DIR" /run/haproxy', f'mkdir -p "$CONFIG_DIR" {base / "run"}'),
                         ('install -m 0644 -o root -g root "$out"', 'install -m 0644 "$out"')):
        assert avant in source, f"adaptation de test périmée : {avant}"
        source = source.replace(avant, apres)
    ctl = base / "haproxyctl"
    ctl.write_text(source, encoding="utf-8")
    env = dict(os.environ)
    env.update(
        PATH=f"{base / 'bin'}{os.pathsep}{env.get('PATH', '')}",
        SECUBOX_HAPROXY_CONF=str(toml),
        SECUBOX_HAPROXY_CONFIG_DIR=str(base / "cfg"),
        HAPROXY_DATA_PATH=str(base / "data"),
        HAPROXY_EXTRA_CFG_DIR=str(base / "cfgd"),
    )
    p = subprocess.run(["bash", str(ctl), "generate"], env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, f"generate a échoué :\n{p.stdout}\n{p.stderr}"
    return (base / "cfg" / "haproxy.cfg").read_text(encoding="utf-8")


def _bloc(cfg: str, entete: str) -> list:
    """Lignes (sans blanc) d'une section `frontend <nom>` / `backend <nom>` du cfg."""
    debut = cfg.index(f"\n{entete}\n")
    suite = re.search(r"\n(frontend|backend|listen|global|defaults)\b", cfg[debut + len(entete) + 2:])
    fin = debut + len(entete) + 2 + (suite.start() if suite else len(cfg))
    return [x.strip() for x in cfg[debut:fin].splitlines() if x.strip() and not x.strip().startswith("#")]


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    return _generer(tmp_path_factory.mktemp("onion"))


# ── (a) le frontal onion efface l'adresse du client, pose le marqueur, inspecte ──────────────────────────────────
def test_le_frontal_onion_n_ecoute_que_sur_la_boucle_locale(cfg):
    bloc = _bloc(cfg, "frontend onion-webui")
    binds = [x for x in bloc if x.startswith("bind ")]
    assert binds == ["bind 127.0.0.1:9180"]


def test_le_frontal_onion_efface_le_x_forwarded_for_du_client_puis_pose_le_marqueur(cfg):
    bloc = _bloc(cfg, "frontend onion-webui")
    efface = bloc.index("http-request del-header X-Forwarded-For")
    pose = bloc.index("http-request set-header X-Forwarded-For 192.0.2.80")
    assert efface < pose, "le marqueur doit être posé APRÈS l'effacement de la valeur du client"
    for entete in ("Forwarded", "X-Real-IP", "X-Client-IP"):
        assert f"http-request del-header {entete}" in bloc
    assert "http-request del-header X-SecuBox- -m beg" in bloc, "aucun X-SecuBox-* du client ne passe"
    # set-src : %[src], donc X-Real-IP et le X-Forwarded-For ajouté par option forwardfor, portent le marqueur.
    assert bloc.index("http-request set-src ipv4(192.0.2.80)") < pose
    assert "http-request set-header X-SecuBox-Onion 1" in bloc
    assert bloc.index("http-request del-header X-SecuBox- -m beg") < bloc.index(
        "http-request set-header X-SecuBox-Onion 1")


def test_le_frontal_onion_passe_par_sbxwaf_jamais_en_direct(cfg):
    bloc = _bloc(cfg, "frontend onion-webui")
    assert "default_backend sbxwaf_inspector" in bloc
    assert not [x for x in bloc if "webui_direct" in x or "nginx_vhosts" in x or "9080" in x]
    assert not [x for x in bloc if x.startswith("use_backend")], "aucune dérivation hors inspection"


def test_les_frontaux_publics_refusent_un_nom_onion_venu_d_ailleurs_que_tor(cfg):
    """La route sbxwaf de l'onion ne doit pas servir d'oracle : Host <onion> présenté à l'IP publique ⇒ refus."""
    for fe in ("frontend http-in", "frontend https-in"):
        bloc = _bloc(cfg, fe)
        assert ("http-request deny deny_status 404 if { req.hdr(host),field(1,:) -m end -i .onion } "
                "!{ src 127.0.0.0/8 ::1 }") in bloc, fe


def test_le_port_du_frontal_onion_est_surchargeable(tmp_path):
    cfg = _generer(tmp_path, extra="onion_webui_port = 9280\n")
    assert "bind 127.0.0.1:9280" in _bloc(cfg, "frontend onion-webui")


# ── (b) le marqueur n'est LAN pour personne ──────────────────────────────────────────────────────────────────────
def _plages(texte: str) -> list:
    return [ipaddress.ip_network(c, strict=False)
            for c in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b", texte)]


def test_le_marqueur_n_est_dans_aucune_plage_lan_de_nginx():
    texte = LAN_GEO.read_text(encoding="utf-8")
    geo = re.search(r"geo \$lan_client \{(.*?)\}", texte, re.S)
    assert geo, "bloc geo $lan_client introuvable"
    plages = [n for n, v in re.findall(r"^\s*(\S+)\s+(\d)\s*;", geo.group(1), re.M) if v == "1"]
    assert "127.0.0.0/8" in plages, "127.0.0.0/8 reste LAN pour les vrais outils locaux"
    for p in plages:
        assert MARQUEUR not in ipaddress.ip_network(p, strict=False), f"192.0.2.80 serait LAN via {p}"
    relais = re.findall(r"^\s*set_real_ip_from\s+(\S+);", texte, re.M)
    for r in relais:
        assert MARQUEUR not in ipaddress.ip_network(r, strict=False), "le marqueur ne doit pas être un relais cru"


def test_le_marqueur_n_est_ni_prive_pour_sbxwaf_ni_un_mandataire_de_confiance():
    """Sinon sbxwaf le dispenserait d'inspection (plages privées) ou relirait son X-Forwarded-For."""
    go = SBXWAF_INSPECT.read_text(encoding="utf-8")
    prives = re.search(r'for _, cidr := range \[\]string\{(.*?)\}', go, re.S).group(1)
    confiance = re.search(r"var trustedProxies = map\[string\]struct\{\}\{(.*?)\n\}", go, re.S).group(1)
    for n in _plages(prives):
        assert MARQUEUR not in n
    assert "192.0.2.80" not in confiance
    assert MARQUEUR in ipaddress.ip_network("192.0.2.0/24")  # TEST-NET-1 (RFC 5737) : jamais routée


def test_le_marqueur_n_est_pas_une_source_privee_pour_haproxy(cfg):
    for ligne in cfg.splitlines():
        if "acl src_privee src" in ligne:
            for n in _plages(ligne.split("src", 2)[2]):
                assert MARQUEUR not in n


# ── (c) un seul port, partout, et jamais 9080 ────────────────────────────────────────────────────────────────────
def test_les_ports_concordent_entre_haproxyctl_l_api_et_exposure():
    ctl = CTL.read_text(encoding="utf-8")
    assert "local onion_webui_port=$(cle_conf onion_webui_port 9180)" in ctl
    expo = EXPOSURE.read_text(encoding="utf-8")
    assert re.search(r"^ONION_WEBUI_PORT_DEFAUT = 9180$", expo, re.M)
    api = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    assert re.search(r"^ONION_WEBUI_PORT_DEFAUT = 9180$", api, re.M)
    assert re.search(r'^ONION_CLIENT_MARQUEUR = "192.0.2.80"$', api, re.M)
