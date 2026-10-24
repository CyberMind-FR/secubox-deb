# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: un visiteur onion n'est jamais LAN (#3112, #3123).

Les services onion livraient à nginx :9080 (webui) ou à http-in :80 (vhosts, metablogizer) : chaque visiteur Tor
arrivait de 127.0.0.1, adresse que nginx croit (set_real_ip_from) et classe LAN (geo 127.0.0.0/8), et un
X-Forwarded-For forgé était cru aussi ; par http-in, un Host admin.<box> menait au webui en direct. Désormais tout
onion livre au frontal HAProxy `onion-in`, qui refuse tout Host non .onion, efface l'adresse annoncée par le client
et pose le marqueur NON LAN 192.0.2.80 avant l'inspection sbxwaf. On vérifie ici :

  (a) le frontal généré par `haproxyctl generate` efface X-Forwarded-For du client PUIS pose le marqueur,
      et passe par sbxwaf — jamais webui_direct ni nginx en direct ;
  (b) 192.0.2.80 n'est dans AUCUNE plage LAN de secubox-lan-geo.conf, ni relais de confiance de nginx,
      ni plage privée de sbxwaf ou de HAProxy ;
  (c) les ports concordent entre haproxyctl, l'API haproxy et le composant exposure, et AUCUN écrivain d'onion
      (exposure, metablogizerctl) ne vise encore 9080 ou 80 ;
  (d) bout en bout avec un vrai HAProxy (si disponible : `haproxy` dans le PATH ou SECUBOX_TEST_HAPROXY) : une
      requête entrée par l'onion avec Host admin.* est refusée, avec Host de l'onion du webui et un
      X-Forwarded-For forgé elle arrive à sbxwaf avec 192.0.2.80 seulement.
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
    bloc = _bloc(cfg, "frontend onion-in")
    binds = [x for x in bloc if x.startswith("bind ")]
    assert binds == ["bind 127.0.0.1:9180"]


def test_le_frontal_onion_efface_le_x_forwarded_for_du_client_puis_pose_le_marqueur(cfg):
    bloc = _bloc(cfg, "frontend onion-in")
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


def test_le_frontal_onion_refuse_tout_host_qui_n_est_pas_en_onion(cfg):
    """I4 / C1 : aucun nom clair (admin.<box>, vhost public) ne se joint par un onion ; refus AVANT tout le reste."""
    bloc = _bloc(cfg, "frontend onion-in")
    garde = "http-request deny deny_status 404 unless { req.hdr(host),field(1,:) -m end -i .onion }"
    assert garde in bloc
    assert bloc.index(garde) < bloc.index("http-request del-header X-Forwarded-For")


def test_le_frontal_onion_passe_par_sbxwaf_jamais_en_direct(cfg):
    bloc = _bloc(cfg, "frontend onion-in")
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
    cfg = _generer(tmp_path, extra="onion_in_port = 9280\n")
    assert "bind 127.0.0.1:9280" in _bloc(cfg, "frontend onion-in")


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
    assert "local onion_in_port=$(cle_conf onion_in_port 9180)" in ctl
    expo = EXPOSURE.read_text(encoding="utf-8")
    assert re.search(r"^ONION_IN_PORT_DEFAUT = 9180$", expo, re.M)
    api = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    assert re.search(r"^ONION_IN_PORT_DEFAUT = 9180$", api, re.M)
    assert re.search(r'^ONION_CLIENT_MARQUEUR = "192.0.2.80"$', api, re.M)


def test_aucun_ecrivain_d_onion_ne_vise_une_entree_http_directe():
    """C1 : l'onion d'un vhost ou d'un site metablogizer livrait à http-in (:80), qui ne nettoie rien."""
    expo = EXPOSURE.read_text(encoding="utf-8")
    assert "_tor_add_sync(name, local_port=_port_onion_in(), onion_port=80)" in expo
    assert not re.search(r"_tor_add_sync\([^)]*local_port=(80|9080)\b", expo)
    ctl = (REPO / "packages" / "secubox-metablogizer" / "sbin" / "metablogizerctl").read_text(encoding="utf-8")
    assert "HiddenServicePort 80 127.0.0.1:$ONION_IN_PORT" in ctl
    assert not re.search(r"HiddenServicePort \d+ 127\.0\.0\.1:(80|9080)\b", ctl)
    assert 'secubox-exposure emancipate "metablogizer-${name}" "$ONION_IN_PORT" --tor' in ctl


# ── (d) bout en bout, vrai HAProxy ───────────────────────────────────────────────────────────────────────────────
WEBUI_ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"


def _haproxy() -> str:
    return os.environ.get("SECUBOX_TEST_HAPROXY") or shutil.which("haproxy") or ""


def _port_libre() -> int:
    import socket
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


@pytest.fixture(scope="module")
def chaine(cfg, tmp_path_factory):
    """Frontal onion-in + backend sbxwaf_inspector GÉNÉRÉS, devant un faux sbxwaf qui renvoie ce qu'il reçoit."""
    binaire = _haproxy()
    if not binaire:
        pytest.skip("haproxy absent (SECUBOX_TEST_HAPROXY pour le désigner)")
    import http.server
    import json
    import threading
    recus = []

    class Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            recus.append([(k.lower(), v) for k, v in self.headers.items()])
            corps = json.dumps(recus[-1]).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    waf = http.server.HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=waf.serve_forever, daemon=True).start()
    p_onion = _port_libre()

    def section(entete):
        debut = cfg.index(f"\n{entete}\n") + 1
        suite = re.search(r"\n(frontend|backend|listen|global|defaults)\b", cfg[debut + len(entete):])
        return cfg[debut:debut + len(entete) + (suite.start() if suite else len(cfg))]

    fe = section("frontend onion-in").replace("bind 127.0.0.1:9180", f"bind 127.0.0.1:{p_onion}")
    be = re.sub(r"server waf \S+", f"server waf 127.0.0.1:{waf.server_address[1]}", section("backend sbxwaf_inspector"))
    base = tmp_path_factory.mktemp("e2e")
    (base / "e2e.cfg").write_text("global\n    log stdout format raw local0\ndefaults\n    mode http\n"
                                  "    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n"
                                  "    option forwardfor\n\n" + fe + "\n" + be.replace(" check", "") + "\n")
    proc = subprocess.Popen([binaire, "-db", "-f", str(base / "e2e.cfg")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import socket
    import time
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", p_onion), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield p_onion, recus
    proc.terminate()
    proc.wait(timeout=5)
    waf.shutdown()


def _get(port, host, entetes):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/api/v1/x?y=1", headers={"Host": host, **entetes})
    r = c.getresponse()
    r.read()
    return r.status


FORGES = {"X-Forwarded-For": "192.168.1.50", "X-Real-IP": "192.168.1.50", "Forwarded": "for=192.168.1.50",
          "X-Client-IP": "192.168.1.50", "X-SecuBox-LAN": "1", "X-Forwarded-Proto": "https"}


@pytest.mark.parametrize("host", ["admin.gk2.secubox.in", "admin.gk2.secubox.in:80", "hall.gk2.secubox.in"])
def test_e2e_un_nom_clair_par_l_onion_est_refuse_et_n_atteint_jamais_sbxwaf(chaine, host):
    port, recus = chaine
    avant = len(recus)
    assert _get(port, host, FORGES) == 404
    assert len(recus) == avant, "la requête ne doit atteindre aucun amont"


def test_e2e_l_onion_du_webui_avec_xff_forge_arrive_avec_le_seul_marqueur(chaine):
    port, recus = chaine
    assert _get(port, WEBUI_ONION, FORGES) == 200
    h = recus[-1]
    assert [v for k, v in h if k == "x-forwarded-for"] and all(
        v == "192.0.2.80" for k, v in h if k == "x-forwarded-for")
    assert ("x-real-ip", "192.0.2.80") in h
    assert ("x-secubox-onion", "1") in h and ("x-forwarded-proto", "http") in h
    assert not [k for k, _ in h if k in ("forwarded", "x-client-ip", "x-secubox-lan")]
    assert "192.168.1.50" not in str(h)


def test_e2e_sans_rien_forger_le_visiteur_onion_n_est_pas_127_0_0_1(chaine):
    port, recus = chaine
    assert _get(port, WEBUI_ONION, {}) == 200
    assert all(v == "192.0.2.80" for k, v in recus[-1] if k in ("x-forwarded-for", "x-real-ip"))
