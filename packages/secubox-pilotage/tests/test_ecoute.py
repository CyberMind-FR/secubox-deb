# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126) : l'écouteur de tunnel (secubox-pilotage-ecoute) — nginx sur les seules IP de tunnel, règles nft insérées à chaud.

Les commandes du système (ip, nginx, nft, systemctl) sont de faux exécutables posés en tête du PATH ; les fichiers vivent sous une racine
temporaire (PILOTAGE_ECOUTE_RACINE)."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
SCRIPT = ICI / "sbin" / "secubox-pilotage-ecoute"
REGLE_MESH = 'iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept'
REGLE_AUTOLOAD = 'iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept'
NFTABLES = """#!/usr/sbin/nft -f
flush ruleset
table inet secubox_filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "lo" accept
        drop
    }
}
"""


def _faux(chemin: Path, corps: str) -> None:
    chemin.write_text("#!/bin/sh\n" + corps)
    chemin.chmod(chemin.stat().st_mode | stat.S_IXUSR)


FAUX_NFT = r"""#!/usr/bin/python3
import json, os, sys
etat = os.environ["BANC_ETAT"]
with open(etat + "/appels", "a") as f:
    f.write("nft " + " ".join(sys.argv[1:]) + "\n")
chemin = etat + "/tables.json"
tables = json.load(open(chemin)) if os.path.exists(chemin) else {}
a = sys.argv[1:]
if a[:1] == ["-c"]:
    sys.exit(1 if os.environ.get("BANC_NFT_C_REFUSE") else 0)
avec_handles = a[:1] == ["-a"]
if avec_handles:
    a = a[1:]
def sauve():
    json.dump(tables, open(chemin, "w"))
if a[:2] == ["list", "chain"]:
    fam, t, c = a[2:5]
    if t not in tables:
        sys.exit(1)
    for r in tables[t]:
        print("\t\t" + r["r"] + ((" # handle %d" % r["h"]) if avec_handles else ""))
    sys.exit(0)
if a[0] in ("insert", "add", "delete") and a[1] == "rule":
    fam, t, c = a[2:5]
    if t not in tables:
        sys.exit(1)
    reste = a[5:]
    suivant = max([r["h"] for r in tables[t]] + [0]) + 1
    if a[0] == "delete":
        h = int(reste[1])
        tables[t] = [r for r in tables[t] if r["h"] != h]
    elif a[0] == "insert" and reste[:1] == ["handle"]:
        h = int(reste[1]); regle = " ".join(reste[2:])
        i = [x["h"] for x in tables[t]].index(h)
        tables[t].insert(i, {"h": suivant, "r": regle})
    elif a[0] == "insert":
        tables[t].insert(0, {"h": suivant, "r": " ".join(reste)})
    else:
        tables[t].append({"h": suivant, "r": " ".join(reste)})
    sauve()
sys.exit(0)
"""

NFT_SECUBOX = """table inet secubox_filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ip saddr @bans drop
        iifname "lo" accept
        drop
    }
}
"""
NFT_UNIFIE = """table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ip saddr @bans drop
        tcp dport 22 accept
        drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        drop
    }
}
"""


def vivant(banc, table="secubox_filter"):
    """Les règles vives de la chaîne input, dans l'ordre (état du faux nft)."""
    chemin = banc.etat / "tables.json"
    return [r["r"] for r in json.loads(chemin.read_text())[table]] if chemin.exists() else []


@pytest.fixture()
def banc(tmp_path):
    racine = tmp_path / "racine"
    (racine / "etc/nginx/conf.d").mkdir(parents=True)
    (racine / "usr/share/secubox/pilotage").mkdir(parents=True)
    (racine / "usr/share/secubox/pilotage/pilotage-canal.conf.tpl").write_text((ICI / "nginx/pilotage-canal.conf.tpl").read_text())
    (racine / "etc/nftables.conf").write_text(NFTABLES)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    etat = tmp_path / "etat"
    etat.mkdir()
    (etat / "tables.json").write_text(json.dumps({"secubox_filter": [{"h": 1, "r": "ct state established,related accept"}, {"h": 2, "r": "ip saddr @bans drop"}, {"h": 3, "r": "drop"}]}))
    _faux(bin_ / "ip", 'for a in "$@"; do i="$a"; done\n'
                       'case "$i" in wg-mesh) [ -n "$BANC_MESH" ] && echo "7: wg-mesh    inet $BANC_MESH/24 scope global wg-mesh";;\n'
                       'wg-autoload) [ -n "$BANC_AUTOLOAD" ] && echo "8: wg-autoload    inet $BANC_AUTOLOAD/16 scope global wg-autoload";; esac\nexit 0\n')
    _faux(bin_ / "nginx", 'echo nginx "$@" >> "$BANC_ETAT/appels"\n[ -z "$BANC_NGINX_REFUSE" ]\n')
    # systemd-run : le vrai lance la commande dans le contexte de PID 1 ; le faux la note et rend le verdict du banc
    _faux(bin_ / "systemd-run", 'echo systemd-run "$@" >> "$BANC_ETAT/appels"\n[ -z "$BANC_NGINX_REFUSE" ]\n')
    (racine / "run/systemd/system").mkdir(parents=True)
    _faux(bin_ / "systemctl", 'echo systemctl "$@" >> "$BANC_ETAT/appels"\n')
    (bin_ / "nft").write_text(FAUX_NFT)
    (bin_ / "nft").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "PILOTAGE_ECOUTE_RACINE": str(racine), "BANC_ETAT": str(etat),
           "BANC_MESH": "10.10.0.1", "BANC_AUTOLOAD": "10.64.0.1"}
    env.pop("BANC_NGINX_REFUSE", None)

    class Banc:
        pass

    b = Banc()
    b.racine, b.etat, b.env = racine, etat, env
    b.conf = racine / "etc/nginx/conf.d/secubox-pilotage-canal.conf"
    b.nft = racine / "etc/nftables.conf"

    def lancer(**surcharge):
        arg = surcharge.pop("ARG", None)
        e = {**env, **surcharge}
        for k in [k for k, v in e.items() if v is None]:
            del e[k]
        return subprocess.run(["bash", str(SCRIPT)] + ([arg] if arg else []), env=e, capture_output=True, text=True, timeout=30)

    b.lancer = lancer
    b.appels = lambda: (etat / "appels").read_text() if (etat / "appels").exists() else ""
    return b


def test_ecouteur_seulement_sur_les_ip_de_tunnel(banc):
    r = banc.lancer()
    assert r.returncode == 0, r.stderr
    rendu = banc.conf.read_text()
    assert re.findall(r"^\s*listen\s+(\S+);", rendu, re.M) == ["10.10.0.1:8472", "10.64.0.1:8472"]
    assert "0.0.0.0" not in rendu and not re.search(r"listen\s+(\[::\]:)?8472", rendu)
    assert rendu.count("proxy_pass http://unix:/run/secubox/pilotage-canal.sock") >= 2
    assert rendu.count("proxy_set_header X-Real-IP $realip_remote_addr;") >= 2 and rendu.count("set_real_ip_from 255.255.255.255;") == 2
    assert rendu.count("client_max_body_size 256k;") >= 2 and rendu.count("proxy_read_timeout 60s;") >= 2
    assert "allow 10.10.0.0/24;" in rendu and "allow 10.64.0.0/16;" in rendu and "deny all;" in rendu
    assert "pilotage.sock" not in rendu.replace("pilotage-canal.sock", "")   # la socket d'administration n'est jamais exposée


def test_gabarit_canal_pose_le_marqueur(banc):
    """M6 (L2 T0) : le marqueur X-SecuBox-Pilotage-Tunnel est posé par le SEUL gabarit du canal (un par server rendu, valeur 1) ; le snippet
    commun secubox-proxy.conf le vide sur tout autre proxy, dont l'administration du pilotage (même précédent que X-SecuBox-Maillage, #1530)."""
    assert banc.lancer().returncode == 0
    rendu = banc.conf.read_text()
    reel = "\n".join(x for x in rendu.splitlines() if not x.lstrip().startswith("#"))
    assert len(re.findall(r"^\s*proxy_set_header\s+X-SecuBox-Pilotage-Tunnel\s+1;\s*$", reel, re.M)) == 2
    assert reel.count("X-SecuBox-Pilotage-Tunnel") == 2
    commun = (ICI.parents[1] / "common" / "nginx" / "secubox-proxy.conf").read_text()
    assert re.search(r'^proxy_set_header\s+X-SecuBox-Pilotage-Tunnel\s+"";\s*$', commun, re.M)
    admin = (ICI / "nginx" / "pilotage.conf").read_text()
    assert "include /etc/nginx/snippets/secubox-proxy.conf;" in admin and "X-SecuBox-Pilotage-Tunnel" not in admin


def test_un_seul_tunnel_present(banc):
    r = banc.lancer(BANC_AUTOLOAD=None)
    assert r.returncode == 0, r.stderr
    rendu = banc.conf.read_text()
    assert "10.10.0.1:8472" in rendu and "10.64.0.1" not in rendu
    # une adresse de tunnel qui n'est pas celle du maître n'ouvre rien
    r = banc.lancer(BANC_MESH="10.10.0.7", BANC_AUTOLOAD=None)
    assert r.returncode == 0, r.stderr
    assert not banc.conf.exists()


def test_ecouteur_retire_si_nginx_refuse(banc):
    r = banc.lancer(BANC_NGINX_REFUSE="1")
    assert r.returncode == 0, r.stderr
    assert not banc.conf.exists()
    assert not list(banc.conf.parent.glob("*pilotage*")) and not list(banc.conf.parent.glob(".*"))   # aucun temporaire laissé


def test_pas_de_rechargement_apres_un_refus_de_nginx(banc):
    """M8 : nginx -t refusé -> le fichier part, mais un rechargement n'a pas de sens (et échouerait)."""
    assert banc.lancer().returncode == 0
    assert banc.appels().count("systemctl reload nginx") == 1
    banc.lancer(BANC_NGINX_REFUSE="1", BANC_MESH="10.10.0.1", BANC_AUTOLOAD=None)      # rendu différent, refusé
    assert not banc.conf.exists() and banc.appels().count("systemctl reload nginx") == 1


def test_limit_conn_et_zone_une_seule_fois(banc):
    rendu = (banc.lancer(), banc.conf.read_text())[1]
    assert rendu.count("limit_conn_zone $binary_remote_addr zone=pilotage_canal:1m;") == 1
    assert rendu.count("limit_conn pilotage_canal 4;") == 2 and rendu.count("limit_conn_status 429;") == 2


def test_pas_de_rechargement_si_le_rendu_ne_change_pas(banc):
    assert banc.lancer().returncode == 0
    assert banc.appels().count("systemctl reload nginx") == 1
    assert banc.lancer().returncode == 0
    assert banc.appels().count("systemctl reload nginx") == 1


def test_fichier_retire_quand_les_interfaces_disparaissent(banc):
    banc.lancer()
    assert banc.conf.exists()
    r = banc.lancer(BANC_MESH=None, BANC_AUTOLOAD=None)
    assert r.returncode == 0 and not banc.conf.exists()
    assert banc.appels().count("systemctl reload nginx") == 2


def test_regles_nft_avant_le_drop_et_idempotentes(banc):
    assert banc.lancer().returncode == 0
    lignes = [x.strip() for x in banc.nft.read_text().splitlines()]
    assert REGLE_MESH in lignes and REGLE_AUTOLOAD in lignes
    drop = lignes.index("drop")
    assert lignes.index(REGLE_MESH) < drop and lignes.index(REGLE_AUTOLOAD) < drop
    # à chaud : juste avant le drop, donc APRÈS les règles de ban (R28), jamais en tête
    v = vivant(banc)
    assert v[-1] == "drop" and set(v[-3:-1]) == {REGLE_MESH, REGLE_AUTOLOAD}
    assert v.index("ip saddr @bans drop") < v.index(REGLE_MESH) and v[0] != REGLE_MESH and v[0] != REGLE_AUTOLOAD
    avant_fichier, avant_appels = banc.nft.read_text(), banc.appels()
    assert banc.lancer().returncode == 0
    assert banc.nft.read_text() == avant_fichier                       # fichier inchangé
    assert banc.appels().count("insert") == avant_appels.count("insert") == 2   # aucune insertion de plus
    assert banc.nft.read_text().count("dport 8472") == 2 and vivant(banc) == v


def test_jamais_nft_f_du_fichier_entier(banc):
    banc.lancer()
    for ligne in banc.appels().splitlines():
        if ligne.startswith("nft "):
            assert ligne.startswith(("nft -c -f ", "nft list ", "nft -a list ", "nft insert ", "nft add ")), ligne
    source = SCRIPT.read_text()
    assert not re.search(r"^\s*nft -f", source, re.M)


def test_regle_vive_reparee_si_disparue(banc):
    banc.lancer()
    (banc.etat / "tables.json").write_text(json.dumps({"secubox_filter": [{"h": 1, "r": "ip saddr @bans drop"}, {"h": 2, "r": "drop"}]}))
    banc.lancer()
    v = vivant(banc)
    assert v[-1] == "drop" and set(v[-3:-1]) == {REGLE_MESH, REGLE_AUTOLOAD}
    assert banc.nft.read_text().count("dport 8472") == 2               # le fichier n'a pas doublé


def test_regle_seulement_pour_le_tunnel_present(banc):
    banc.lancer(BANC_AUTOLOAD=None)
    assert REGLE_MESH in banc.nft.read_text() and REGLE_AUTOLOAD not in banc.nft.read_text()


def test_fichier_nft_sans_aucune_table_connue_intact_et_journalise(banc):
    banc.nft.write_text("table inet autre {\n chain input {\n drop\n }\n}\n")
    (banc.etat / "tables.json").write_text("{}")
    r = banc.lancer()
    assert r.returncode == 0
    assert banc.nft.read_text() == "table inet autre {\n chain input {\n drop\n }\n}\n"
    assert "aucune table" in r.stderr and "inet filter" in r.stderr and "secubox_filter" in r.stderr   # M1 : jamais un silence


def test_base_unifiee_inet_filter(banc):
    """R28 : sur gk2 (secubox-hardening >= 1.5.1) la base est `inet filter`, pas `inet secubox_filter`."""
    banc.nft.write_text(NFT_UNIFIE)
    (banc.etat / "tables.json").write_text(json.dumps({"filter": [{"h": 1, "r": "iifname \"lo\" accept"}, {"h": 2, "r": "ip saddr @bans drop"},
                                                                   {"h": 3, "r": "tcp dport 22 accept"}, {"h": 4, "r": "drop"}]}))
    assert banc.lancer().returncode == 0
    v = vivant(banc, "filter")
    assert v[-1] == "drop" and set(v[-3:-1]) == {REGLE_MESH, REGLE_AUTOLOAD} and v.index("ip saddr @bans drop") < v.index(REGLE_MESH)
    fichier = banc.nft.read_text().splitlines()
    chain_forward = fichier.index("    chain forward {")
    chain_input = fichier.index("    chain input {")
    for regle in (REGLE_MESH, REGLE_AUTOLOAD):
        pos = [i for i, x in enumerate(fichier) if x.strip() == regle]
        assert len(pos) == 1 and chain_input < pos[0] < chain_forward              # dans la chaîne input, pas dans forward
        assert pos[0] < fichier.index("        drop")                              # avant le drop de input
    assert fichier.count("        drop") == 2 and fichier[chain_forward + 2].strip() != REGLE_MESH


def test_retirer_enleve_les_regles_du_fichier_et_du_vif(banc):
    banc.lancer()
    r = banc.lancer(ARG="--retirer")
    assert r.returncode == 0, r.stderr
    assert "dport 8472" not in banc.nft.read_text()
    assert vivant(banc) == ["ct state established,related accept", "ip saddr @bans drop", "drop"]
    assert not banc.conf.exists()
    # idempotent
    assert banc.lancer(ARG="--retirer").returncode == 0


def test_script_sain():
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_nginx_t_hors_du_bac_a_sable_par_systemd_run(banc):
    """R30 : `nginx -t` crée de vraies sockets AF_INET, lie :80/:443 et écrit /run/nginx.pid : dans le bac à sable de l'unité il échouerait
    toujours (et le script retirerait le fichier à chaque passage). Il passe par systemd-run, dans le contexte de PID 1."""
    assert banc.lancer().returncode == 0
    appels = banc.appels().splitlines()
    assert "systemd-run --wait --pipe --collect --quiet /usr/sbin/nginx -t" in appels
    assert not [x for x in appels if x.startswith("nginx ")]            # jamais nginx -t lancé directement


def test_nginx_t_direct_sans_systemd_en_marche(banc):
    """Chroot d'image : pas de PID 1 systemd, donc pas de systemd-run ; nginx -t direct."""
    (banc.racine / "run/systemd/system").rmdir()
    assert banc.lancer().returncode == 0
    appels = banc.appels().splitlines()
    assert any(x.startswith("nginx -t") for x in appels) and not [x for x in appels if x.startswith("systemd-run")]


def test_refus_de_nginx_t_par_systemd_run_retire_le_fichier(banc):
    banc.lancer()
    assert banc.conf.exists()
    r = banc.lancer(BANC_NGINX_REFUSE="1", BANC_AUTOLOAD=None)
    assert not banc.conf.exists() and "refusé par nginx -t" in r.stderr


def test_deja_la_limite_a_la_table_visee(banc):
    """Une règle déjà présente dans UNE table ne dispense pas de la poser dans l'autre."""
    deux = NFT_SECUBOX + NFT_UNIFIE
    banc.nft.write_text(deux.replace('        iifname "lo" accept\n        drop', f'        iifname "lo" accept\n        {REGLE_MESH}\n        drop', 1))
    (banc.etat / "tables.json").write_text(json.dumps({"filter": [{"h": 1, "r": "drop"}], "secubox_filter": [{"h": 1, "r": "drop"}]}))
    assert banc.lancer().returncode == 0
    fichier = banc.nft.read_text()
    assert fichier.count(REGLE_MESH) == 2 and fichier.count(REGLE_AUTOLOAD) == 2          # une fois par table


def test_table_suivante_non_touchee(banc):
    """dans_t / dans_c repartent de zéro à chaque table : la chaîne input d'une AUTRE table n'est pas modifiée."""
    banc.nft.write_text(NFT_SECUBOX + "table inet autre {\n    chain input {\n        drop\n    }\n}\n")
    banc.lancer()
    assert banc.nft.read_text().endswith("table inet autre {\n    chain input {\n        drop\n    }\n}\n")


def test_refus_de_nft_c_journalise(banc):
    r = banc.lancer(BANC_NFT_C_REFUSE="1")
    assert r.returncode == 0
    assert banc.nft.read_text() == NFTABLES                                  # fichier intact
    assert "nft -c" in r.stderr and "refus" in r.stderr
