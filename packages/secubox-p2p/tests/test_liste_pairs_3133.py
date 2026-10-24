# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — le maître publie la liste de ses pairs vivants (liens WireGuard directs entre pairs).

wg_mesh.json peut contenir des clones périmés (même endpoint, plusieurs clés) : seuls les pairs à poignée de main
récente sont publiés, dédoublonnés par clé, et chaque champ est validé strictement (donnée écrite par les enrôlements)."""
import base64
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main
from api import pairs_directs as pd

MAINTENANT = 1_000_000.0
_CHARGEUR_REEL = main.mesh.load_handshakes
CONF = Path(__file__).resolve().parents[1] / "nginx" / "p2p-masterlink.conf"


def cle(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def pair(n, nom=None, ip=None, endpoint=None, **plus):
    p = {
        "public_key": cle(n),
        "allowed_ips": f"10.10.0.{n}/32",
        "mesh_ip": ip or f"10.10.0.{n}",
        "name": nom or f"box{n}",
        "endpoint": endpoint or f"192.168.1.{n}:51820",
    }
    p.update(plus)
    return p


def etat_gk2():
    """Sept entrées : trois vivantes, deux clones périmés, une doublon de clé, une sans poignée."""
    return {"peers": [
        pair(2), pair(3), pair(4),
        pair(5, nom="clone-vieux"),                  # poignée > 10 min
        pair(6, nom="clone-absent"),                 # aucune poignée
        pair(4, nom="doublon-de-4"),                 # même clé que box4 : la dernière entrée gagne
        pair(7, nom="box7-sans-endpoint", endpoint="inconnu"),
    ], "private_key": "SECRET"}


POIGNEES = {cle(2): MAINTENANT - 5, cle(3): MAINTENANT - 599, cle(4): MAINTENANT - 30,
            cle(5): MAINTENANT - 601, cle(7): MAINTENANT - 1}


def test_seuls_les_vivants_sans_doublon():
    liste = pd.liste_publiable(etat_gk2(), POIGNEES, MAINTENANT)
    assert [p["mesh_ip"] for p in liste] == ["10.10.0.2", "10.10.0.3", "10.10.0.4"]
    assert [p["nom"] for p in liste] == ["box2", "box3", "doublon-de-4"]
    assert set(liste[0]) == {"nom", "mesh_ip", "cle_publique", "endpoint"}
    assert "SECRET" not in repr(liste)


def test_doublon_de_cle_garde_la_derniere_entree():
    etat = {"peers": [pair(4, nom="ancien", endpoint="192.168.1.40:51820"),
                      pair(4, nom="recent", endpoint="192.168.1.41:51820")]}
    liste = pd.liste_publiable(etat, {cle(4): MAINTENANT - 1}, MAINTENANT)
    assert [(p["nom"], p["endpoint"]) for p in liste] == [("recent", "192.168.1.41:51820")]


@pytest.mark.parametrize("ai", ["0.0.0.0/0, 10.10.0.9/32", "10.10.0.77/32", "10.10.0.9/32, 10.10.0.0/24", None, 5, ["10.10.0.9/32"]])
def test_role_pair_exige_exactement_mesh_ip_slash_32(ai):
    mauvais = {**pair(9), "allowed_ips": ai}
    assert pd.liste_publiable({"peers": [mauvais]}, {cle(9): MAINTENANT - 1}, MAINTENANT) == []
    ok = {**pair(9), "allowed_ips": " 10.10.0.9/32 "}
    assert len(pd.liste_publiable({"peers": [ok]}, {cle(9): MAINTENANT - 1}, MAINTENANT)) == 1


def test_reseau_invalide_rend_none():
    assert pd.valider_pair(pair(9), reseau="pas-un-reseau") is None
    assert pd.valider_pair(pair(9), reseau="fd00::/64") is None


def test_chiffres_non_ascii_refuses():
    assert pd.valider_pair(pair(9, endpoint="192.168.1.\u0669:51820")) is None


@pytest.mark.parametrize("mauvais", [
    pair(8, endpoint="8.8.8.8:51822"),
    pair(8, endpoint="192.168.1.8:51820\nPersistentKeepalive = 1"),
    pair(8, endpoint="192.168.1.8:51820\n"),
    pair(8, endpoint="10.10.0.8:51820"),
    pair(8, endpoint="192.168.1.8:0"),
    pair(8, endpoint="192.168.1.8:70000"),
    pair(8, endpoint=["192.168.1.8:51820"]),
    pair(8, nom="box\nx"),
    pair(8, nom="box8\n"),
    pair(8, nom="Box8"),
    pair(8, nom="-box"),
    pair(8, nom="a" * 32),
    pair(8, ip="10.10.1.8"),
    pair(8, ip="10.10.0.8\n"),
    pair(8, ip=["10.10.0.8"]),
    {**pair(8), "public_key": "pas-une-cle"},
    {**pair(8), "allowed_ips": "10.10.0.0/24"},
    "pas un dict", None, 42,
])
def test_entrees_invalides_ecartees(mauvais):
    poignees = {cle(8): MAINTENANT - 1}
    assert pd.liste_publiable({"peers": [mauvais]}, poignees, MAINTENANT) == []


def test_poignees_inexploitables_valent_non_vivant():
    etat = {"peers": [pair(2)]}
    for ts in ("12", None, "abc", [], float("nan")):
        assert pd.liste_publiable(etat, {cle(2): ts}, MAINTENANT) == []
    assert pd.liste_publiable(etat, None, MAINTENANT) == []
    assert pd.liste_publiable({"peers": "x"}, POIGNEES, MAINTENANT) == []
    assert pd.liste_publiable("x", POIGNEES, MAINTENANT) == []


def test_plafond_32_et_tri_par_ip():
    peers = [pair(n) for n in range(2, 60)]
    poignees = {cle(n): MAINTENANT - 1 for n in range(2, 60)}
    liste = pd.liste_publiable({"peers": list(reversed(peers))}, poignees, MAINTENANT)
    assert len(liste) == 32
    ips = [tuple(map(int, p["mesh_ip"].split("."))) for p in liste]
    assert ips == sorted(ips)


def test_valider_pair_normalise():
    v = pd.valider_pair(pair(9))
    assert v == {"nom": "box9", "mesh_ip": "10.10.0.9", "cle_publique": cle(9), "endpoint": "192.168.1.9:51820"}
    assert pd.valider_pair(pair(9), reseau="10.20.0.0/24") is None


# --- route -----------------------------------------------------------------------------------------------------

JETON = "ab" * 32


@pytest.fixture
def fichier_jeton(tmp_path, monkeypatch):
    f = tmp_path / "pair.token"
    f.write_text(JETON + "\n")
    monkeypatch.setenv("SBX_P2P_PAIR_TOKEN", str(f))
    return f


@pytest.fixture
def client(monkeypatch, fichier_jeton):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")     # le mode tableau de bord du poste ne doit pas ouvrir la route
    monkeypatch.setattr(main, "get_wg_mesh_config", etat_gk2)
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: dict(POIGNEES, **{cle(5): 1.0}))
    monkeypatch.setattr(pd.time, "time", lambda: MAINTENANT)
    return TestClient(main.app)


def test_route_avec_le_jeton_sans_session(client):
    r = client.get("/master-link/pairs", headers={"X-SecuBox-Pair": JETON})
    assert r.status_code == 200
    corps = r.json()
    assert corps["version"] == 1
    assert [p["nom"] for p in corps["pairs"]] == ["box2", "box3", "doublon-de-4"]
    assert JETON not in r.text


@pytest.mark.parametrize("entetes", [{}, {"X-SecuBox-Pair": "0"}, {"X-SecuBox-Pair": "1"}, {"X-SecuBox-Pair": ""},
                                     {"X-SecuBox-Pair": "ab" * 31}, {"X-SecuBox-Pair": JETON + "0"},
                                     {"X-SecuBox-Pair": "cd" * 32}])
def test_route_refusee_sans_jeton_exact(client, entetes):
    assert client.get("/master-link/pairs", headers=entetes).status_code in (401, 403)


@pytest.mark.parametrize("contenu", [None, "", "\n", "  "])
def test_jeton_absent_ou_vide_refuse_meme_un_en_tete_vide_ou_un(client, fichier_jeton, contenu):
    if contenu is None:
        fichier_jeton.unlink()
    else:
        fichier_jeton.write_text(contenu)
    for h in ("", "1", JETON):
        assert client.get("/master-link/pairs", headers={"X-SecuBox-Pair": h}).status_code in (401, 403)


def test_jeton_illisible_refuse(client, fichier_jeton, monkeypatch):
    monkeypatch.setenv("SBX_P2P_PAIR_TOKEN", str(fichier_jeton.parent))      # un répertoire : illisible
    assert client.get("/master-link/pairs", headers={"X-SecuBox-Pair": JETON}).status_code in (401, 403)


def test_jeton_relu_quand_le_fichier_change(client, fichier_jeton):
    import os
    h = {"X-SecuBox-Pair": "ef" * 32}
    assert client.get("/master-link/pairs", headers=h).status_code in (401, 403)
    fichier_jeton.write_text("ef" * 32)
    os.utime(fichier_jeton, ns=(1, 2_000_000_000_000_000_000))
    assert client.get("/master-link/pairs", headers=h).status_code == 200


def test_comparaison_a_temps_constant():
    assert "hmac.compare_digest" in Path(pd.__file__).read_text()


def test_route_session_de_lecture(client, monkeypatch):
    async def lecteur(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(main, "require_lecture", lecteur)
    assert client.get("/master-link/pairs").status_code == 200


CORROMPUS = ['[1,2]', '{"written_at":"x","handshakes":{}}', '{"written_at":1,"handshakes":{"k":"abc"}}',
             '{"written_at":1,"handshakes":[1]}', "pas du json"]


@pytest.mark.parametrize("contenu", CORROMPUS)
def test_fichier_de_poignees_corrompu_donne_liste_vide_jamais_500(client, monkeypatch, tmp_path, contenu):
    f = tmp_path / "h.json"
    f.write_text(contenu)
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: _CHARGEUR_REEL(f, now=1.0))
    assert _CHARGEUR_REEL(f, now=1.0) is None
    r = client.get("/master-link/pairs", headers={"X-SecuBox-Pair": JETON})
    assert r.status_code == 200
    assert r.json() == {"version": 1, "pairs": []}


# --- nginx -----------------------------------------------------------------------------------------------------

def test_nginx_pose_l_en_tete_pair_depuis_la_carte_geo():
    texte = CONF.read_text()
    assert re.search(r"geo\s+\$remote_addr\s+\$p2p_pair_maille\s*\{[^}]*default\s+0;[^}]*10\.10\.0\.0/24\s+1;", texte, re.S)
    assert "proxy_set_header X-SecuBox-Pair $p2p_pair_cle;" in texte
    assert "X-SecuBox-LAN" in texte


def test_nginx_jeton_par_map_et_include():
    texte = CONF.read_text()
    assert "include /etc/nginx/secubox-p2p-pair.conf;" in texte
    assert "proxy_set_header X-SecuBox-Pair $p2p_pair_cle;" in texte
    assert "$p2p_pair_maille;" not in texte.split("proxy_set_header X-SecuBox-Pair")[1].split("\n")[0]


def test_aucun_jeton_dans_le_depot():
    racine = Path(__file__).resolve().parents[1]
    for f in list((racine / "nginx").glob("*")) + list((racine / "debian").glob("*")):
        if f.is_file():
            assert not re.search(r"\b[0-9a-f]{64}\b", f.read_text()), f


def test_postinst_genere_le_jeton_avant_le_vhost_sans_le_divulguer():
    t = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    i_jeton, i_vhost = t.index("openssl rand -hex 32"), t.index("ln -s ../sites-available/secubox-p2p-masterlink.conf")
    assert i_jeton < i_vhost
    assert "umask 077" in t and "set -x" not in t
    assert "chmod 0600" in t and "chmod 0640" in t and "chmod 0750" in t
    assert "_own root:secubox" in t
    assert not re.search(r"echo[^\n]*\$_t|echo[^\n]*\$\(cat", t)
    # la validation précède le rendu, et seul $_t (validé) est interpolé dans le printf de la map
    assert t.index("*[!0-9a-f]*)") < t.index("printf 'map")
    assert t.count("printf 'map") == 1 and '"$_t" > "$_ngx.new"' in t


def _fragment():
    t = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    return t.split("# BEGIN jeton-pair\n")[1].split("# END jeton-pair")[0]


def _rend(tmp_path, jeton):
    import subprocess
    d = tmp_path / "secrets"
    d.mkdir(exist_ok=True)
    if jeton is not None:
        (d / "pair.token").write_bytes(jeton)
    ngx = tmp_path / "pair.conf"
    env = {"PATH": "/usr/bin:/bin", "SBX_P2P_TEST": "1", "SBX_P2P_SECRETS_DIR": str(d), "SBX_P2P_PAIR_CONF": str(ngx)}
    r = subprocess.run(["sh", "-ec", _fragment() + "\n_rendre_jeton_pair"], env=env, capture_output=True, text=True)
    return r, d / "pair.token", ngx


PIEGE = b'x"; } server { listen 0.0.0.0:9999; location / { root /; autoindex on; } } map $a $b { default "\n'


@pytest.mark.parametrize("piege", [PIEGE, b"ab" * 31, b"AB" * 32, b"ab" * 32 + b"\nlisten 9999;\n", b"ab" * 32 + b"\x00" * 5,
                                   b"\xff\xfe" * 40, b"", None])
def test_postinst_jeton_pique_jamais_rendu_et_regenere(tmp_path, piege):
    r, tok, ngx = _rend(tmp_path, piege)
    assert r.returncode == 0, r.stderr
    nouveau = tok.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", nouveau)
    rendu = ngx.read_text()
    assert f'1 "{nouveau}";' in rendu and "server" not in rendu and "9999" not in rendu
    assert nouveau not in r.stderr and nouveau not in r.stdout
    assert oct(tok.stat().st_mode & 0o777) == "0o640" and oct(ngx.stat().st_mode & 0o777) == "0o600"
    assert oct(tok.parent.stat().st_mode & 0o777) == "0o750"


def test_postinst_jeton_valide_conserve(tmp_path):
    valide = "0123456789abcdef" * 4
    r, tok, ngx = _rend(tmp_path, (valide + "\n").encode())
    assert r.returncode == 0 and tok.read_text().strip() == valide and f'"{valide}"' in ngx.read_text()
    assert "regenere" not in r.stderr


def test_jeton_pair_fichier_binaire(fichier_jeton):
    fichier_jeton.write_bytes(b"\xff\xfe\x00\x80" * 20)
    assert pd.jeton_pair() == ""
    assert pd.en_tete_pair_valide("x") is False


def test_preinst_pose_une_map_vide_valide():
    t = (Path(__file__).resolve().parents[1] / "debian" / "preinst").read_text()
    assert 'default "";' in t and " 1 " not in t.split("printf")[1]


def test_aucun_proxy_vers_p2p_sock_ne_transmet_le_pair_autrement_que_par_la_cle():
    racine = Path(__file__).resolve().parents[3]
    fichiers = list((racine / "packages" / "secubox-p2p" / "nginx").glob("*.conf")) + list((racine / "common" / "nginx").glob("*.conf"))
    assert fichiers
    for f in fichiers:
        for m in re.finditer(r"proxy_set_header\s+X-SecuBox-Pair\s+([^;]*);", f.read_text()):
            assert m.group(1).strip() == "$p2p_pair_cle", f
