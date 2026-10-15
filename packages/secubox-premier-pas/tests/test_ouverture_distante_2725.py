# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2725 — configurer une box SANS ÉCRAN depuis un navigateur du LAN : fenêtre de 15 min après le démarrage, un seul poste à la fois.

Choix assumé du mainteneur (2026-10-15) : l'assistant distant est le même que celui du kiosque, ouvert au LAN comme un routeur grand public.
Garde-fous testés ici : verdict LAN de nginx (jamais l'adresse, falsifiable), fenêtre, verrou d'un seul poste porté par un SECRET et non par
l'adresse, secret jamais écrit en clair, périmètre limité (on remplit et on applique ; l'écran seul accepte une proposition et lit le code)."""
import importlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEBUT = 0                      # secondes depuis le démarrage de la box (horloge monotone : l'heure murale saute sur une carte sans RTC)
LAN = {"X-SecuBox-LAN": "1"}
MIN = 60


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "pp"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    monkeypatch.setenv("PREMIER_PAS_AUDIT", str(tmp_path / "audit.log"))
    (tmp_path / "jeton").write_text("code-d-appairage\n")
    (tmp_path / "jeton-local").write_text("secret-local\n")
    from api import main
    from premier_pas import remplir
    importlib.reload(remplir)
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(main.M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(main.P, "PROFILS_DIR", tmp_path / "profils")
    (tmp_path / "profils").mkdir()
    horloge = {"t": DEBUT + 60}
    monkeypatch.setattr(main, "_maintenant", lambda: horloge["t"])
    monkeypatch.setattr(main, "_boot_id", lambda: horloge.get("boot", "boot-1"))
    from fastapi.testclient import TestClient
    return TestClient(main.app), horloge, tmp_path, main


def secret(r):
    return {"X-Premier-Pas": r.json()["jeton"]}


def ouvre(c, entetes=LAN):
    if "X-SecuBox-LAN" not in entetes:
        c.headers.pop("X-SecuBox-LAN", None)     # le conftest racine pose cet en-tête par défaut sur TOUT TestClient : sans ce retrait, « sans verdict » ne le serait pas
    return c.post("/session", headers=entetes)


# ---------- qui peut ouvrir ----------

def test_un_poste_du_lan_dans_la_fenetre_obtient_un_secret(box):
    c, _, _, _ = box
    r = ouvre(c)
    assert r.status_code == 200 and len(r.json()["jeton"]) >= 24


@pytest.mark.parametrize("entetes", [{}, {"X-SecuBox-LAN": "0"}, {"X-SecuBox-LAN": ""}, {"X-SecuBox-LAN": "true"}, {"X-Forwarded-For": "192.168.1.9"}])
def test_hors_du_lan_ou_sans_verdict_nginx_c_est_refuse(box, entetes):
    """Seul `X-SecuBox-LAN: 1` compte : l'adresse (même d'apparence privée) ne prouve rien, et l'absence d'en-tête ferme."""
    c, _, t, _ = box
    assert ouvre(c, entetes).status_code == 403
    assert not (t / "pp" / "session-distante.json").exists()


def test_apres_15_minutes_sans_session_la_fenetre_est_close(box):
    c, h, _, _ = box
    h["t"] = DEBUT + 15 * MIN + 1
    r = ouvre(c)
    assert r.status_code == 403 and "15" in r.json()["detail"]


def test_la_fenetre_se_compte_depuis_le_demarrage_de_la_box(box):
    c, h, _, _ = box
    h["t"] = DEBUT + 14 * MIN
    assert ouvre(c).status_code == 200


def test_une_session_d_avant_un_redemarrage_n_est_pas_reprise(box):
    """L'état est sur disque, l'horloge repart de zéro : sans l'identifiant de démarrage, un secret d'avant le redémarrage resterait valable."""
    c, h, _, _ = box
    r1 = ouvre(c)
    h["boot"] = "boot-2"
    h["t"] = 30
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=secret(r1)).status_code == 403
    assert ouvre(c).status_code == 200


def test_box_deja_configuree_assistant_ferme(box):
    c, _, t, _ = box
    (t / "fait").write_text("x")
    assert ouvre(c).status_code == 409


def test_assistant_pas_pret_sans_jeton_local(box):
    c, _, t, _ = box
    (t / "jeton-local").unlink()
    assert ouvre(c).status_code == 503


# ---------- un seul poste ----------

def test_un_second_poste_est_refuse_tant_que_le_premier_est_actif(box):
    c, h, _, _ = box
    r1 = ouvre(c)
    h["t"] += 5 * MIN
    r2 = ouvre(c)
    assert r2.status_code == 423 and "autre poste" in r2.json()["detail"]
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=secret(r1)).status_code == 200


def test_le_verrou_tient_au_secret_pas_a_l_adresse(box):
    """Même adresse, même en-tête : sans le secret, on ne reprend pas la session d'un autre."""
    c, h, _, _ = box
    ouvre(c)
    assert ouvre(c, {**LAN, "X-Forwarded-For": "192.168.1.50"}).status_code == 423


def test_l_activite_du_premier_poste_prolonge_sa_session(box):
    c, h, _, _ = box
    r1 = ouvre(c)
    h["t"] += 10 * MIN
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=secret(r1)).status_code == 200
    h["t"] += 10 * MIN                                  # 20 min depuis l'ouverture, 10 depuis la dernière action
    assert ouvre(c).status_code == 423


def test_apres_15_minutes_d_inactivite_la_session_se_libere_et_l_ancien_secret_meurt(box):
    c, h, _, _ = box
    r1 = ouvre(c)
    h["t"] += 15 * MIN + 1
    r2 = ouvre(c)
    assert r2.status_code == 403            # la fenêtre de démarrage est aussi passée : on ne reprend pas une box laissée ouverte
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=secret(r1)).status_code == 403


def test_une_session_en_cours_survit_a_la_fin_de_la_fenetre_de_demarrage(box):
    """La fenêtre ne limite que l'OUVERTURE : une configuration commencée à la minute 14 doit pouvoir se terminer."""
    c, h, _, _ = box
    h["t"] = DEBUT + 14 * MIN
    r1 = ouvre(c)
    h["t"] = DEBUT + 20 * MIN
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=secret(r1)).status_code == 200


# ---------- le secret ----------

def test_le_secret_n_est_jamais_ecrit_en_clair(box):
    c, _, t, _ = box
    s = ouvre(c).json()["jeton"]
    etat = t / "pp" / "session-distante.json"
    assert s not in etat.read_text()
    assert oct(etat.stat().st_mode & 0o777) == "0o600"


def test_l_empreinte_stockee_n_est_pas_un_secret_valable(box):
    c, _, t, _ = box
    ouvre(c)
    empreinte = json.loads((t / "pp" / "session-distante.json").read_text())["empreinte"]
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers={"X-Premier-Pas": empreinte}).status_code == 403


@pytest.mark.parametrize("fourni", ["", "faux", "secret-local-presque"])
def test_un_faux_secret_est_refuse(box, fourni):
    c, _, _, _ = box
    ouvre(c)
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers={"X-Premier-Pas": fourni}).status_code == 403


# ---------- périmètre ----------

def test_la_session_remplit_et_applique(box):
    c, _, _, _ = box
    h = secret(ouvre(c))
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=h).status_code == 200
    assert c.post("/appliquer", headers=h).status_code != 403       # 409 « profil incomplet » est une réponse métier, pas un refus d'accès


def test_la_session_ne_lit_pas_le_code_d_appairage_ni_ne_decide_des_propositions(box):
    """Ces trois gestes prouvent la présence devant la box : ils restent à l'écran (jeton local)."""
    c, _, _, _ = box
    h = secret(ouvre(c))
    assert c.get("/code", headers=h).status_code == 403
    assert c.post("/proposition/accepter", headers=h).status_code == 403
    assert c.post("/proposition/refuser", headers=h).status_code == 403


def test_l_ecran_local_et_le_code_d_appairage_marchent_comme_avant(box):
    c, _, _, _ = box
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers={"X-Premier-Pas": "secret-local"}).status_code == 200
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers={"X-Premier-Pas": "code-d-appairage"}).status_code == 200
    assert c.get("/code", headers={"X-Premier-Pas": "secret-local"}).status_code == 200


def test_box_configuree_la_session_ne_sert_plus(box):
    c, _, t, _ = box
    h = secret(ouvre(c))
    (t / "fait").write_text("x")
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=h).status_code == 409


# ---------- audit ----------

def test_ouverture_et_refus_sont_traces_sans_le_secret(box):
    c, h, t, _ = box
    s = ouvre(c).json()["jeton"]
    ouvre(c)                                  # 423
    ouvre(c, {})                              # hors LAN
    texte = (t / "audit.log").read_text()
    assert "premier-pas" in texte and "session ouverte" in texte and "refus" in texte
    assert s not in texte


def test_un_audit_illisible_n_empeche_pas_l_ouverture(box, monkeypatch):
    """L'API tourne en `secubox` : /var/log/secubox/audit.log est root 0644. La trace va aussi au journal systemd ; échouer fermerait l'assistant."""
    c, _, t, _ = box
    monkeypatch.setenv("PREMIER_PAS_AUDIT", str(t / "absent" / "audit.log"))
    assert ouvre(c).status_code == 200


# ---------- la page ----------

HTML = (Path(__file__).resolve().parents[1] / "www" / "premier-pas" / "index.html").read_text(encoding="utf-8")


def test_la_page_distante_demande_une_session_au_lieu_de_l_impasse():
    assert '/session"' in HTML
    assert "L'assistant s'utilise depuis l'écran branché sur la box" not in HTML
    for statut in ("423", "403"):
        assert statut in HTML, f"la page doit traiter le refus {statut}"
    assert re.search(r'sessionStorage\.setItem\("premier-pas\.jeton"', HTML)


# ---------- la page réelle, contre la vraie API ----------

@pytest.fixture
def navigateur():
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre_page(navigateur, box, stockage=None, taille=None):
    """La page servie telle quelle ; ses appels /api/v1/premier-pas/* sont renvoyés à la vraie API (TestClient), avec le verdict LAN de nginx."""
    c, _, _, _ = box
    ctx = navigateur.new_context(viewport=taille or {"width": 1100, "height": 800})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def servir(r, *_):
        url = r.request.url
        if "/api/v1/premier-pas" in url:
            chemin = "/" + url.split("/api/v1/premier-pas/", 1)[1] if "/api/v1/premier-pas/" in url else "/"
            corps = r.request.post_data
            rep = c.request(r.request.method, chemin, headers={k: v for k, v in r.request.headers.items() if k.lower() in ("x-premier-pas", "content-type")},
                            content=corps)
            appels.append((r.request.method, chemin, r.request.headers.get("x-premier-pas"), rep.status_code))
            r.fulfill(status=rep.status_code, content_type="application/json", body=rep.text)
        else:
            r.fulfill(status=200, content_type="text/html", body=HTML)
    p.route("http://sbx.test/**", servir)
    if stockage:
        p.add_init_script("try{" + ";".join(f"sessionStorage.setItem({k!r},{v!r})" for k, v in stockage.items()) + "}catch(e){}")
    p.goto("http://sbx.test/premier-pas/")
    return ctx, p, erreurs, appels


def test_page_distante_sans_jeton_ouvre_une_session_et_montre_l_assistant(navigateur, box):
    ctx, p, err, appels = ouvre_page(navigateur, box)
    p.wait_for_selector("h1")
    assert "Bienvenue" in p.inner_text("#ecran") and err == []
    assert ("POST", "/session", "", 200) in [(m, c, s or "", st) for m, c, s, st in appels]
    assert p.evaluate("sessionStorage.getItem('premier-pas.distant')") == "1"
    ctx.close()


def test_la_session_obtenue_sert_aux_ecritures_suivantes(navigateur, box):
    ctx, p, err, appels = ouvre_page(navigateur, box)
    p.wait_for_selector("h1")
    p.click("#suiv")                                          # Bienvenue -> Nom : enregistre l'étape avec le secret de session
    p.wait_for_function("document.querySelector('h1').textContent.includes('Nom')")
    puts = [a for a in appels if a[0] == "PUT"]
    assert puts and all(a[3] == 200 and a[2] for a in puts) and err == []
    ctx.close()


def test_un_second_poste_voit_qu_un_autre_configure_la_box(navigateur, box):
    c, _, _, _ = box
    ouvre(c)                                                   # un premier poste a déjà la session
    ctx, p, err, _ = ouvre_page(navigateur, box)
    p.wait_for_selector("#reessayer")
    t = p.inner_text("#ecran")
    assert "Un autre poste configure cette box" in t and "autre poste configure déjà" in t and err == []
    ctx.close()


def test_fenetre_close_explique_comment_rouvrir(navigateur, box):
    _, h, _, _ = box
    h["t"] = 20 * MIN
    ctx, p, err, _ = ouvre_page(navigateur, box)
    p.wait_for_function("document.getElementById('ecran').textContent.includes('close')")
    t = p.inner_text("#ecran")
    assert "éteignez-la puis rallumez-la" in t and "#reessayer" not in t and err == []
    ctx.close()


def test_un_secret_devenu_invalide_en_cours_de_route_repart_sur_une_nouvelle_session(navigateur, box):
    """La box redémarre pendant que la page est ouverte : le secret ne vaut plus. La page ne doit pas rester sur un « 403 » : elle se rouvre."""
    _, h, _, _ = box
    ctx, p, err, appels = ouvre_page(navigateur, box)
    p.wait_for_selector("h1")
    sessions = len([a for a in appels if a[1] == "/session"])
    h["boot"], h["t"] = "boot-2", 30                              # redémarrage : nouvel identifiant, horloge à zéro, fenêtre rouverte
    p.click("#suiv")
    for _ in range(80):                                           # la page affiche « Bienvenue » AVANT et APRÈS : c'est la nouvelle session qu'on attend, pas le titre
        if len([a for a in appels if a[1] == "/session"]) == sessions + 1:
            break
        p.wait_for_timeout(100)
    p.wait_for_function("document.querySelector('h1') && document.querySelector('h1').textContent.includes('Bienvenue')")
    assert len([a for a in appels if a[1] == "/session"]) == sessions + 1 and err == []
    ctx.close()


def test_le_poste_distant_n_appelle_pas_le_code_d_appairage(navigateur, box):
    """/code est réservé à l'écran de la box : l'appeler avec une session distante donnerait un 403 inutile."""
    ctx, p, err, appels = ouvre_page(navigateur, box)
    p.wait_for_selector("h1")
    p.wait_for_timeout(500)
    assert not [a for a in appels if a[1] == "/code"] and err == []
    ctx.close()


def test_a_420_px_rien_ne_deborde(navigateur, box):
    ctx, p, err, _ = ouvre_page(navigateur, box, taille={"width": 420, "height": 800})
    p.wait_for_selector("h1")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
