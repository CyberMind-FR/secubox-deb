# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 5 — vhost admin.<box>.secubox.in d'une box légère, côté contrôleur : plan, gabarit nginx, connexion avec les
identifiants du maître (jeton à portée du vhost), relais /relais/<box>/… vers l'agent par le canal."""
import asyncio
import base64
import json
import re
import time

import httpx
import jwt as pyjwt
import pytest

from secubox_core import auth

from api.main import creer_app_admin
from pilotage import vhosts as V
from pilotage.files import Files
from pilotage.identite import Box
from pilotage.inventaire import Inventaire
from pilotage.stockage import StockageSqlite
from outils import Horloge

SECRET = "secret-de-test-" + "x" * 32
GK5 = Box("gk5", "10.10.0.5", "maillage", None, None)
CLI = Box("cli", "10.64.0.9", "autoload", "acme", "actif")
GK6 = Box("gk6", "10.10.0.6", "maillage", None, None)


def valeurs(interface="distante", paquets=(("secubox-system", "1.4.0-1~trixie1"), ("secubox-dns", "2.0.0-1~trixie1")), mains=False):
    v = {}
    if interface is not None:
        v[V.INTERFACE] = interface
    if mains is not None:
        v[V.MAINS] = mains
    for i, (p, ver) in enumerate(paquets, 1):
        v[f"Device.X_SECUBOX_Packages.{i}.Name"] = p
        v[f"Device.X_SECUBOX_Packages.{i}.Version"] = ver
    return v


def ranger(s, box, vals, agent="0.4.2"):
    s.vu(box, {"agent_version": agent})
    s.inventaire_enregistrer(box, {"results": [{"path": "Device.", "params": vals}]})


class Monde:
    def __init__(self, tmp_path, monkeypatch, sub="alice", admin=True):
        monkeypatch.setenv("SECUBOX_JWT_SECRET", SECRET)
        monkeypatch.setattr(auth, "_secret", lambda: SECRET)
        self.sessions = {"j1"}
        monkeypatch.setattr(auth, "_session_validator", lambda jti: jti in self.sessions)
        monkeypatch.setattr(auth, "porteur_reconnu", lambda s: True)
        self.admins = {sub} if admin else set()
        monkeypatch.setattr(auth, "est_admin_reel", lambda p: str((p or {}).get("sub")) in self.admins)
        self.h = Horloge(time.time())
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes = []
        self.audit_ko = False
        self.inv = Inventaire(self.f, self.s, horloge=self.h)
        # pages extraites (arbre lu par le contrôleur pour I6 : modules d'un paquet servi)
        self.pages = tmp_path / "pages"
        for paquet, version, mods in (("secubox-system", "1.4.0-1~trixie1", ("system",)),
                                      ("secubox-dns", "2.0.0-1~trixie1", ("dns", "dns-provider"))):
            for m in mods:
                (self.pages / paquet / version / m).mkdir(parents=True)
        self.app = creer_app_admin(self.s, self.f, self.inv, self.audit, horloge=self.h, maitre="gk2", debit=V.Debit(par_minute=5),
                                   racine_pages=self.pages)
        self.sub = sub
        self.session = {"sub": sub, "jti": "j1", "exp": int(time.time()) + 86400}
        self.app.dependency_overrides[auth.require_jwt] = lambda: self.session

    def jeton_maitre(self, sub, jti="j1", **kw):
        return pyjwt.encode({"sub": sub, "jti": jti, "iat": int(time.time()), "exp": int(time.time()) + 86400, **kw}, SECRET,
                            algorithm="HS256")

    def jeton_vhost(self, box="gk5", sub=None):
        return V.frapper_jeton({"sub": sub or self.sub, "jti": "j1", "exp": int(time.time()) + 86400}, box, SECRET)[0]

    def audit(self, evenement, champs):
        if self.audit_ko:
            raise OSError("disque plein")
        self.lignes.append((evenement, dict(champs)))

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")

    async def agent(self, box, reponses, recus):
        """Agent qui sonde sans fin ; répond à chaque HTTP par la réponse suivante de `reponses`."""
        while True:
            for rq in await self.f.attendre_requetes(box.cle, 0.05):
                if rq["type"] != "HTTP":
                    continue
                recus.append(rq["body"])
                st, corps, *ct = reponses.pop(0) if reponses else (200, b'{"ok":true}')
                entetes = {"Content-Type": ct[0] if ct else "application/json", "Set-Cookie": "piege=1"}
                if len(ct) > 1:
                    entetes["Content-Disposition"] = ct[1]
                self.f.livrer_reponse(box.cle, {"msg_id": rq["msg_id"], "type": "HTTP_RESP", "body": {
                    "statut": st, "entetes": entetes,
                    "corps_b64": base64.b64encode(corps).decode()}})


def entetes_vhost(box="gk5", version="secubox-system=1.4.0-1~trixie1", jeton=None):
    e = {V.ENTETE_BOX: box, V.ENTETE_VERSION: version}
    if jeton:
        e["Authorization"] = f"Bearer {jeton}"
    return e


async def relayer(w, box_obj, methode="GET", chemin="/relais/gk5/api/v1/system/status", entetes=None, reponses=None, **kw):
    recus = []
    t = asyncio.create_task(w.agent(box_obj, list(reponses or []), recus))
    try:
        await asyncio.sleep(0.02)
        async with w.client() as c:
            r = await c.request(methode, chemin, headers=entetes, **kw)
    finally:
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
    return r, recus


@pytest.fixture
def w(tmp_path, monkeypatch):
    m = Monde(tmp_path, monkeypatch)
    ranger(m.s, GK5, valeurs())
    return m


# --- plan et gabarit ------------------------------------------------------------------------------------------------

def test_vhost_par_box_legere(tmp_path):
    """Une box « distante » a un vhost admin.<box>.secubox.in qui sert les pages de SES versions ; une box ordinaire n'en a pas."""
    p = V.plan([("gk5", valeurs()), ("gk6", valeurs(interface=None)), ("gk7", valeurs(interface="locale")),
                ("Mauvais nom", valeurs())])
    assert p == {"boxes": [{"box": "gk5", "pages": [{"paquet": "secubox-dns", "version": "2.0.0-1~trixie1"},
                                                     {"paquet": "secubox-system", "version": "1.4.0-1~trixie1"}]}]}
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.4.0-1~trixie1", "modules": ["system"]},
                                  {"paquet": "secubox-dns", "version": "2.0.0-1~trixie1", "modules": ["dns", "dns-provider"]}])
    assert "server_name admin.gk5.secubox.in;" in conf
    assert f"listen 0.0.0.0:{V.PORT_NGINX};" in conf
    # racine = www/<paquet>/<version>/<module>/ de la version DÉCLARÉE, jamais www/ entier
    assert "alias /var/lib/secubox-pilotage-pages/www/secubox-dns/2.0.0-1~trixie1/dns-provider/;" in conf
    assert re.search(r"alias /var/lib/secubox-pilotage-pages/www/;", conf) is None
    # l'API d'un module passe par le relais de la box, avec la version de la page posée par nginx
    bloc = conf.split("location ^~ /api/v1/dns/ {", 1)[1].split("}", 1)[0]
    assert "proxy_pass http://unix:/run/secubox/pilotage.sock:/relais/gk5/api/v1/dns/;" in bloc
    assert 'proxy_set_header X-SecuBox-Version-Page "secubox-dns=2.0.0-1~trixie1";' in bloc
    assert 'proxy_set_header X-SecuBox-Pilotage-Box "gk5";' in bloc
    assert 'proxy_set_header Cookie "";' in bloc and 'proxy_set_header X-SecuBox-LAN "";' in bloc


def test_plan_ecrit_seulement_s_il_change(tmp_path):
    f = tmp_path / "vhosts.json"
    assert V.ecrire_plan(f, {"boxes": []}) is True
    assert V.ecrire_plan(f, {"boxes": []}) is False
    assert oct(f.stat().st_mode & 0o777) == "0o640"


def test_csp_et_entetes_de_securite():
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.0", "modules": ["system"]}])
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)" always;', conf).group(1)
    for d in ("default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "form-action 'none'"):
        assert d in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert 'add_header X-Content-Type-Options "nosniff" always;' in conf
    assert 'add_header X-Frame-Options "DENY" always;' in conf
    assert "Access-Control-Allow-Origin" not in conf


def test_fichiers_en_point_refuses():
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.0", "modules": ["system"]}])
    # la règle des fichiers en point vient AVANT tout le reste et n'est pas masquée par un ^~ (qui couperait les regex)
    corps = conf.split("server {", 1)[1]
    assert corps.index("location ~ /\\. { return 404; }") < corps.index("location ^~ /system/")
    assert "location ^~ /system/" in corps
    # « ^~ » coupe la recherche des regex : chaque location de pages porte donc sa propre garde des fichiers en point
    bloc = conf.split("location ^~ /system/ {", 1)[1].split("\n    }", 1)[0]
    assert "location ~ /\\. { return 404; }" in bloc
    assert "disable_symlinks if_not_owner" in conf


@pytest.mark.parametrize("box", ["", "GK5", "gk5.evil", "a" * 41, "gk5;", "../x", "gk 5"])
def test_nom_de_box_invalide_refuse(box):
    with pytest.raises(ValueError):
        V.domaine(box)
    with pytest.raises(ValueError):
        V.rendre_nginx(box, [])


def test_module_en_double_ou_invalide_refuse():
    with pytest.raises(ValueError):
        V.rendre_nginx("gk5", [{"paquet": "secubox-a", "version": "1", "modules": ["x"]},
                               {"paquet": "secubox-b", "version": "1", "modules": ["x"]}])
    for m in ("api", "auth", ".cache", "a/b", 'x";'):
        with pytest.raises(ValueError):
            V.rendre_nginx("gk5", [{"paquet": "secubox-a", "version": "1", "modules": [m]}])


def test_ressources_partagees_composees_entre_paquets():
    """#3302 (banc gk4) : `luci-static` est livré en parties par plusieurs paquets (auth, dpi, netmodes, qos, wireguard). Il est
    composé (try_files en chaîne, ordre des paquets), sans route d'API ; tout autre module en double reste refusé."""
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-qos", "version": "1.6.1-1~trixie1", "modules": ["qos", "luci-static"]},
                                  {"paquet": "secubox-auth", "version": "1.8.10-1~trixie1", "modules": ["luci-static"]}])
    assert "location ^~ /luci-static/ {" in conf and "/api/v1/luci-static/" not in conf
    i_auth = conf.index("secubox-auth/1.8.10-1~trixie1;")
    i_qos = conf.index("secubox-qos/1.6.1-1~trixie1;")
    assert i_auth < i_qos                                   # ordre déterministe : nom du paquet
    assert "try_files $uri @luci-static-1;" in conf and "location @luci-static-1 {" in conf
    assert conf.rstrip().endswith("}") and "try_files $uri =404;" in conf
    assert conf.count("location ~ /\\. { return 404; }") >= 3   # garde des fichiers en point dans la location de tête
    with pytest.raises(ValueError):
        V.rendre_nginx("gk5", [{"paquet": "secubox-a", "version": "1", "modules": ["qos"]},
                               {"paquet": "secubox-b", "version": "1", "modules": ["qos"]}])


def test_csp_longue_decoupee_en_variables():
    """#3302 (banc gk4) : 58 modules donnent une CSP de plus de 4 Ko, paramètre que nginx refuse (« too long parameter »).
    Chaque morceau tient sous la limite ; la valeur reconstituée est la même politique."""
    mods = [f"module{i:02d}" for i in range(80)]
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-a", "version": "1.0-1~trixie1", "modules": mods}])
    assert all(len(li) < 3000 for li in conf.splitlines())
    sets = dict(re.findall(r'set \$(sbx_csp_\d+) "([^"]*)";', conf))
    entete = re.search(r'add_header Content-Security-Policy "([^"]*)" always;', conf).group(1)
    reconstruite = re.sub(r"\$(sbx_csp_\d+)", lambda m: sets[m.group(1)], entete)
    assert reconstruite == V.csp_pages("gk5", mods)


def test_scripts_integres_permis_par_empreinte_et_accueil():
    """#3302 (banc gk4) : les pages portées ont des scripts intégrés ; seuls ceux dont l'empreinte est calculée passent (jamais
    'unsafe-inline' pour les scripts). L'accueil (index.html du hub) est servi à la racine."""
    e = V.empreintes_scripts('<script>alert(1)</script><script src="/shared/x.js"></script>')
    assert e == ["'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='"]
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-hub", "version": "1.0", "modules": ["soc"], "accueil": True,
                                   "empreintes": {"soc": e, "": e}}])
    assert "location = / {" in conf and "try_files /index.html =404;" in conf
    bloc = conf[conf.index("location ^~ /soc/ {"):]
    bloc = bloc[:bloc.index("\n    }")]
    assert e[0] in bloc and "script-src" in bloc and "'unsafe-inline'" not in bloc.split("style-src")[0]
    assert "/api/" not in bloc.split("style-src")[0]


def test_module_en_double_le_paquet_proprietaire_l_emporte():
    """#3302 (banc gk4) : `portal` livré par secubox-hub et secubox-portal : secubox-portal sert /portal/, dans les deux ordres."""
    for ordre in (1, -1):
        pages = [{"paquet": "secubox-hub", "version": "1", "modules": ["portal"]},
                 {"paquet": "secubox-portal", "version": "2", "modules": ["portal"]}][::ordre]
        conf = V.rendre_nginx("gk5", pages)
        assert "/secubox-portal/2/portal/;" in conf and "/secubox-hub/1/portal/" not in conf


def test_pages_declarees_sans_deviner():
    v = valeurs(paquets=(("secubox-a", "1.0"), ("secubox-a", "2.0"), ("pas-secubox", "1.0"), ("secubox-b", "bad version")))
    assert V.pages_declarees(v) == {}


# --- connexion : identifiants saisis sur le maître seul, code à usage unique échangé sur le vhost (R-L5-25 C1c) -------------

async def code_du_maitre(w, box="gk5", retour=None):
    async with w.client() as c:
        r = await c.get(f"/boxes/{box}/connexion-vhost" + (f"?retour={retour}" if retour else ""))
    return r


def code_de(r):
    loc = r.headers["location"]
    return loc, re.search(r"#code=([A-Za-z0-9_-]+)", loc).group(1)


async def echanger(w, code, box="gk5", ip="203.0.113.7"):
    async with w.client() as c:
        return await c.post("/vhost/auth/echanger", json={"code": code}, headers={V.ENTETE_BOX: box, "X-Real-IP": ip})


def test_auth_du_maitre_sur_le_vhost(w):
    """L'administrateur est authentifié par le MAÎTRE (require_jwt, 2FA du maître) ; le vhost ne reçoit qu'un code à usage unique,
    échangé contre un jeton à portée : clé dérivée, aud = admin.<box>, iss distinct, refusé par les gardes du maître."""
    async def cas():
        r = await code_du_maitre(w, retour="/system/")
        assert r.status_code == 303
        loc, code = code_de(r)
        assert loc.startswith("https://admin.gk5.secubox.in/pilotage-connexion/#") and "retour=/system/" in loc
        r = await echanger(w, code)
        assert r.status_code == 200, r.text
        assert "set-cookie" not in r.headers
        tok = r.json()["access_token"]
        with pytest.raises(pyjwt.PyJWTError):
            pyjwt.decode(tok, SECRET, algorithms=["HS256"], options={"verify_aud": False})   # jamais la clé brute du maître
        p = pyjwt.decode(tok, V.cle_vhost(SECRET), algorithms=["HS256"], audience="admin.gk5.secubox.in")
        assert p["iss"] == V.EMETTEUR and p["scope"] == V.SCOPE and p["sub"] == "alice" and p["jti"] == "j1"
        assert p["exp"] - p["iat"] <= V.SESSION_MAX_S
        assert auth._validate_token(tok) is None
        ev = [e for e, _ in w.lignes]
        assert "pilotage_vhost_code" in ev and "pilotage_vhost_session" in ev
    asyncio.run(cas())


@pytest.mark.parametrize("site,attendu", [("cross-site", 403), ("same-site", 403), ("same-origin", 303), ("none", 303),
                                           (None, 303)])
def test_emission_du_code_refusee_hors_meme_origine(w, site, attendu):
    """Final I1 : un site tiers ne fait pas émettre de code avec le cookie du maître (Sec-Fetch-Site) ; absent = client non
    navigateur, garde require_jwt seule."""
    async def cas():
        async with w.client() as c:
            r = await c.get("/boxes/gk5/connexion-vhost", headers={"Sec-Fetch-Site": site} if site else {})
        assert r.status_code == attendu, r.text
        assert ("pilotage_vhost_code" in [e for e, _ in w.lignes]) == (attendu == 303)
    asyncio.run(cas())


def test_code_a_usage_unique_lie_a_la_box_et_borne(w):
    ranger(w.s, GK6, valeurs())

    async def cas():
        _, code = code_de(await code_du_maitre(w))
        assert (await echanger(w, code)).status_code == 200
        assert (await echanger(w, code)).status_code == 401            # réutilisé
        _, code = code_de(await code_du_maitre(w))
        assert (await echanger(w, code, box="gk6")).status_code == 401  # autre box : refusé ET consommé
        assert (await echanger(w, code)).status_code == 401
        _, code = code_de(await code_du_maitre(w))
        w.h.avance(61)
        assert (await echanger(w, code)).status_code == 401            # expiré (60 s)
        _, code = code_de(await code_du_maitre(w))
        w.sessions.clear()                                              # session du maître révoquée entre-temps
        assert (await echanger(w, code)).status_code == 401
        assert (await echanger(w, "inconnu")).status_code == 401
    asyncio.run(cas())


def test_code_refuse_retour_hors_module(w):
    async def cas():
        for retour in ("https://evil.example/", "//evil.example/", "/api/v1/x/", "/../x/"):
            r = await code_du_maitre(w, retour=retour)
            assert r.status_code == 422, retour
    asyncio.run(cas())


def test_pas_de_saisie_de_mot_de_passe_sur_le_vhost(w):
    """Plus aucune route ni page de saisie d'identifiants sur l'origine de la box."""
    from pathlib import Path
    async def cas():
        async with w.client() as c:
            for etape in ("login", "login/mfa", "set-password", "totp/enroll"):
                r = await c.post(f"/vhost/auth/{etape}", json={"username": "a", "password": "p"}, headers={V.ENTETE_BOX: "gk5"})
                assert r.status_code in (404, 405), etape
    asyncio.run(cas())
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.0", "modules": ["system"]}])
    assert "location = /api/v1/auth/echanger" in conf and "location ^~ /api/v1/auth/" not in conf
    page = Path(__file__).resolve().parents[1] / "www-vhost/pilotage-connexion"
    for f in page.iterdir():
        t = f.read_text().lower()
        assert "password" not in t and "mot de passe" not in t, f


def test_code_administrateur_sans_droit_ou_box_non_declaree(tmp_path, monkeypatch):
    w = Monde(tmp_path, monkeypatch, admin=False)
    ranger(w.s, GK5, valeurs())
    ranger(w.s, GK6, valeurs(interface=None))

    async def cas():
        _, code = code_de(await code_du_maitre(w))   # require_jwt (surchargé) : le refus vient de l'échange (admin réel)
        assert (await echanger(w, code)).status_code == 403
        w.admins.add("alice")
        assert (await code_du_maitre(w, box="gk6")).status_code == 404
        assert (await code_du_maitre(w, box="inconnue")).status_code == 404
    asyncio.run(cas())


def test_debit_de_l_echange_de_code(w):
    async def cas():
        codes = [(await echanger(w, f"faux{i}")).status_code for i in range(12)]
        assert codes[:10] == [401] * 10 and codes[-1] == 429
    asyncio.run(cas())


# --- relais ---------------------------------------------------------------------------------------------------------

def test_relais_transmet_par_le_canal(w):
    async def cas():
        r, recus = await relayer(w, GK5, entetes={**entetes_vhost(jeton=w.jeton_vhost()), "Cookie": "secubox_session=maitre",
                                                  "X-Autre": "1"}, reponses=[(200, b'{"etat":"ok"}')],
                                 chemin="/relais/gk5/api/v1/system/status?x=1")
        assert r.status_code == 200 and r.json() == {"etat": "ok"}
        assert "set-cookie" not in r.headers
        [b] = recus
        assert b["chemin"] == "/api/v1/system/status?x=1" and b["methode"] == "GET"
        assert b["version_page"] == "1.4.0-1~trixie1" and b["maitre"] == "gk2"
        # jamais Authorization ni Cookie du maître vers la box
        assert all(k.lower() not in ("authorization", "cookie") for k in b["entetes"])
    asyncio.run(cas())


def test_acteur_et_portee_pris_dans_la_session(w):
    """Un champ acteur/portée envoyé par le client (corps, requête, en-tête) est ignoré : la session décide."""
    async def cas():
        e = {**entetes_vhost(jeton=w.jeton_vhost()), "X-SecuBox-Acteur": "mallory", "X-Portee": "admin",
             "Content-Type": "application/json"}
        r, recus = await relayer(w, GK5, "POST", "/relais/gk5/api/v1/system/regler?acteur=mallory&portee=admin", entetes=e,
                                 content=json.dumps({"acteur": "mallory", "portee": "admin"}).encode())
        assert r.status_code == 200, r.text
        [b] = recus
        assert b["acteur"] == "alice" and b["portee"] == "admin"
        ev = [c for e_, c in w.lignes if e_ == "pilotage_http"]
        assert ev and all(c["acteur"] == "alice" for c in ev)
    asyncio.run(cas())


def test_portee_reduite_mains_liees(tmp_path, monkeypatch):
    w = Monde(tmp_path, monkeypatch)
    ranger(w.s, GK5, valeurs(mains=True))

    async def cas():
        r, recus = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()))
        assert r.status_code == 200 and recus[0]["portee"] == "lecture"
    asyncio.run(cas())


def test_relais_refuse_une_version_perimee(w):
    async def cas():
        for version in ("secubox-system=1.3.0-1~trixie1", "secubox-inconnu=1.0", "", "secubox-system"):
            r, recus = await relayer(w, GK5, entetes=entetes_vhost(version=version, jeton=w.jeton_vhost()))
            assert r.status_code == 409, version
            assert recus == []
    asyncio.run(cas())


def test_relais_box_non_declaree_404(w):
    ranger(w.s, GK6, valeurs(interface=None))

    async def cas():
        r, _ = await relayer(w, GK6, chemin="/relais/gk6/api/v1/system/status",
                             entetes=entetes_vhost(box="gk6", jeton=w.jeton_vhost("gk6")))
        assert r.status_code == 404
        # en-tête de box différent du chemin : 404 (une page d'une box ne parle jamais à une autre)
        r, _ = await relayer(w, GK5, entetes=entetes_vhost(box="gk6", jeton=w.jeton_vhost("gk6")))
        assert r.status_code == 404
        r, _ = await relayer(w, GK5, chemin="/relais/inconnue/api/v1/system/status",
                             entetes=entetes_vhost(box="inconnue", jeton=w.jeton_vhost("inconnue")))
        assert r.status_code == 404
    asyncio.run(cas())


def test_relais_jeton_d_une_autre_box_ou_du_maitre_refuse(w):
    async def cas():
        for tok in (w.jeton_vhost("gk6"), w.jeton_maitre("alice"), "x.y.z", None):
            r, recus = await relayer(w, GK5, entetes=entetes_vhost(jeton=tok))
            assert r.status_code == 401, tok
            assert recus == []
        w.sessions.clear()   # session du maître révoquée : le jeton à portée meurt avec elle
        r, _ = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()))
        assert r.status_code == 401
    asyncio.run(cas())


def test_relais_administrateur_sans_droit_403(w):
    async def cas():
        w.admins.clear()   # plus administrateur réel
        r, recus = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()))
        assert r.status_code == 403 and recus == []
    asyncio.run(cas())


def test_relais_box_cliente_sans_support_403(tmp_path, monkeypatch):
    w = Monde(tmp_path, monkeypatch)
    ranger(w.s, CLI, valeurs())

    async def cas():
        r, recus = await relayer(w, CLI, chemin="/relais/cli/api/v1/system/status",
                                 entetes=entetes_vhost(box="cli", jeton=w.jeton_vhost("cli")))
        assert r.status_code == 403 and recus == []
        w.s.support_demander(CLI.cle, "s1", 30, "alice")
        fin = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(w.h() + 600))
        w.s.support_noter(CLI.cle, "s1", "ouvert", fin)
        r, recus = await relayer(w, CLI, chemin="/relais/cli/api/v1/system/status",
                                 entetes=entetes_vhost(box="cli", jeton=w.jeton_vhost("cli")))
        assert r.status_code == 200 and recus[0]["portee"] == "admin"
    asyncio.run(cas())


def test_corps_trop_gros_413(w):
    async def cas():
        e = {**entetes_vhost(jeton=w.jeton_vhost()), "Content-Type": "application/octet-stream"}
        r, recus = await relayer(w, GK5, "POST", "/relais/gk5/api/v1/system/regler", entetes=e, content=b"x" * ((4 << 20) + 1))
        assert r.status_code == 413 and recus == []

        async def flux():
            for _ in range(5):
                yield b"y" * (1 << 20)
        r, recus = await relayer(w, GK5, "POST", "/relais/gk5/api/v1/system/regler", entetes=e, content=flux())
        assert r.status_code == 413 and recus == []
    asyncio.run(cas())


def test_debit_par_administrateur_et_par_box(w):
    async def cas():
        codes = []
        for _ in range(6):
            r, _ = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()))
            codes.append(r.status_code)
        assert codes == [200] * 5 + [429]
    asyncio.run(cas())


def test_agent_trop_ancien_erreur_claire(tmp_path, monkeypatch):
    w = Monde(tmp_path, monkeypatch)
    ranger(w.s, GK5, valeurs(), agent="0.3.9")

    async def cas():
        r, recus = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()))
        assert r.status_code == 501 and "0.4.0" in r.json()["detail"] and recus == []
    asyncio.run(cas())


def test_ecriture_sans_audit_refusee(w):
    async def cas():
        w.audit_ko = True
        e = {**entetes_vhost(jeton=w.jeton_vhost()), "Content-Type": "application/json"}
        r, recus = await relayer(w, GK5, "POST", "/relais/gk5/api/v1/system/regler", entetes=e, content=b"{}")
        assert r.status_code == 503 and recus == []
    asyncio.run(cas())


def test_routes_vhost_absentes_du_chemin_du_maitre():
    """Sur l'administration du maître (/api/v1/pilotage/…), /relais/ et /vhost/ ne sont jamais servis ; les en-têtes du vhost
    y sont effacés."""
    from pathlib import Path
    conf = (Path(__file__).resolve().parents[1] / "nginx/pilotage.conf").read_text()
    assert re.search(r"location \^~ /api/v1/pilotage/relais/ \{\s*return 404;", conf)
    assert re.search(r"location \^~ /api/v1/pilotage/vhost/ \{\s*return 404;", conf)
    assert 'proxy_set_header X-SecuBox-Version-Page "";' in conf and 'proxy_set_header X-SecuBox-Pilotage-Box "";' in conf


def test_plan_ecrit_a_chaque_tour_d_inventaire(tmp_path, monkeypatch):
    """Le service écrit le plan que relit le ctl root (chemin fixe) ; il ne pose rien lui-même (ni sudo ni capacité)."""
    f = tmp_path / "vhosts.json"
    w = Monde(tmp_path, monkeypatch)
    w.app = creer_app_admin(w.s, w.f, w.inv, w.audit, horloge=w.h, plan_vhosts=f)
    ranger(w.s, GK5, valeurs())
    ranger(w.s, GK6, valeurs(interface=None))
    asyncio.run(w.inv.tour())
    assert json.loads(f.read_text()) == V.plan([("gk5", valeurs())])


# --- R-L5-25 : réponses /api/ jamais exécutables, CSP sans /api/, module du paquet, variante encodée ----------------------

@pytest.mark.parametrize("ctype", ["application/javascript", "text/html; charset=utf-8", "text/javascript", "image/svg+xml",
                                   "text/plain"])
def test_reponse_de_box_sous_api_jamais_executable(w, ctype):
    async def cas():
        r, _ = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()),
                             reponses=[(200, b"alert(1)", ctype, "inline")])
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.headers["content-disposition"] == "attachment"
        assert r.headers["content-security-policy"] == "sandbox; default-src 'none'"
        assert r.headers["x-content-type-options"] == "nosniff"
    asyncio.run(cas())


def test_reponse_json_forcee(w):
    async def cas():
        r, _ = await relayer(w, GK5, entetes=entetes_vhost(jeton=w.jeton_vhost()),
                             reponses=[(200, b'{"a":1}', "application/problem+json; charset=utf-8")])
        assert r.headers["content-type"] == "application/json" and r.headers["x-content-type-options"] == "nosniff"
        assert "content-disposition" not in r.headers
    asyncio.run(cas())


def test_csp_des_pages_sans_api():
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.0", "modules": ["system"]}])
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)" always;', conf).group(1)
    script = re.search(r"script-src ([^;]+);", csp).group(1).split()
    style = re.search(r"style-src ([^;]+);", csp).group(1).split()
    for src in (script, style):
        assert "'self'" not in src and all("/api" not in x for x in src)
        assert "https://admin.gk5.secubox.in/system/" in src
    # sous /api/, nginx impose ses propres en-têtes (always) en plus du contrôleur
    bloc = conf.split("location ^~ /api/v1/system/ {", 1)[1].split("\n    }", 1)[0]
    assert "add_header Content-Security-Policy \"sandbox; default-src 'none'\" always;" in bloc
    assert 'add_header X-Content-Type-Options "nosniff" always;' in bloc
    assert "X-Forwarded-For $remote_addr;" in conf and "$proxy_add_x_forwarded_for" not in conf


def test_module_hors_du_paquet_annonce_refuse(w):
    """I6 : la version de page du paquet system ne vaut pas pour un appel vers dns."""
    async def cas():
        r, recus = await relayer(w, GK5, chemin="/relais/gk5/api/v1/dns/zones", entetes=entetes_vhost(jeton=w.jeton_vhost()))
        assert r.status_code == 409 and recus == []
        r, recus = await relayer(w, GK5, chemin="/relais/gk5/api/v1/dns/zones",
                                 entetes=entetes_vhost(version="secubox-dns=2.0.0-1~trixie1", jeton=w.jeton_vhost()))
        assert r.status_code == 200 and recus[0]["chemin"] == "/api/v1/dns/zones"
    asyncio.run(cas())


def test_variante_encodee_du_relais(w):
    """M9 : /%72elais/… ne contourne aucune garde (en-tête de box du vhost et jeton à portée exigés)."""
    async def cas():
        async with w.client() as c:
            r = await c.get("/%72elais/gk5/api/v1/system/status")
            assert r.status_code in (401, 404)
            r = await c.get("/%72elais/gk5/api/v1/system/status", headers={V.ENTETE_BOX: "gk5"})
            assert r.status_code == 401
            r = await c.get("/relais/gk5/api/v1/%2e%2e/auth/x", headers=entetes_vhost(jeton=w.jeton_vhost()))
            assert r.status_code in (400, 404, 409)
    asyncio.run(cas())



def test_debit_de_l_echange_par_adresse(w):
    async def cas():
        for i in range(10):
            await echanger(w, f"faux{i}", ip="203.0.113.7")
        assert (await echanger(w, "x", ip="203.0.113.7")).status_code == 429
        assert (await echanger(w, "x", ip="198.51.100.9")).status_code == 401   # autre adresse : son propre compte
    asyncio.run(cas())


def test_gabarit_content_disposition_et_xff():
    conf = V.rendre_nginx("gk5", [{"paquet": "secubox-system", "version": "1.0", "modules": ["system"]}])
    for loc in ("location ^~ /api/v1/system/ {", "location = /api/v1/auth/echanger {"):
        bloc = conf.split(loc, 1)[1].split("\n    }", 1)[0]
        lignes = [x.strip() for x in bloc.splitlines()]
        assert "proxy_set_header X-Forwarded-For $remote_addr;" in lignes
        assert not any("X-Forwarded-For" in x and "$remote_addr;" not in x for x in lignes)
    bloc = conf.split("location ^~ /api/v1/system/ {", 1)[1].split("\n    }", 1)[0]
    # M3 : l'« attachment » du contrôleur n'est plus effacé par nginx
    assert "proxy_hide_header Content-Disposition;" not in bloc


def test_emission_du_code_par_la_seule_session_cookie(w):
    """T7 R-L5-34 M3 : le panneau Flotte ouvre l'émission dans un NOUVEL ONGLET, qui n'envoie que le cookie de session du
    maître (jamais le Bearer de localStorage) : la vraie garde require_jwt doit l'accepter (GET, sans garde d'origine)."""
    w.app.dependency_overrides.clear()
    jeton = w.jeton_maitre("alice")

    async def cas():
        async with w.client() as c:
            c.cookies.set(auth.SESSION_COOKIE, jeton)
            r = await c.get("/boxes/gk5/connexion-vhost")   # sans retour : la Flotte ouvre la racine (retour=/ refusé, 422)
            sans = await httpx.AsyncClient(transport=httpx.ASGITransport(app=w.app), base_url="http://t").get(
                "/boxes/gk5/connexion-vhost")
        return r, sans
    r, sans = asyncio.run(cas())
    assert r.status_code == 303 and "#code=" in r.headers["location"]
    assert sans.status_code == 401
