# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2648 — VoiceStudio (admin et usager) au profil Aurora : tests statiques + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "voicestudio"
ADMIN = (WWW / "index.html").read_text(encoding="utf-8")
USAGER = (WWW / "usager.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("src", [ADMIN, USAGER], ids=["admin", "usager"])
def test_pages_autonomes_sans_dialogue_natif(src):
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src
    assert not re.findall(r"<script[^>]+src=", src)
    assert not re.search(r"""(src|href)=["']https?://""", src)
    assert "hybrid-dark" not in src and "hybrid-skin" not in src and "fonts.googleapis" not in src
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in src
    assert "lorem" not in src.lower() and "sbxVue" in src and "demo" in src.lower() and "embed" in src
    assert "localStorage.getItem('sbx_token')" in src and "'Bearer '" in src


def test_admin_routes_a_l_identique():
    for r in ("api('/detail')", "'/start'", "'/stop'", "'/restart'", "'/installer'", "'/config'", "'/publier'", "api('/cle')",
              "'/cle/renouveler'", "api('/voix')", "'/essai/dire'", "'/essai/transcrire'", "'/journal?n='", "'/sauvegarde'"):
        assert r in ADMIN, r
    assert "{ adresses: liste }" in ADMIN and "format: $('eFmt').value" in ADMIN and "fd.append('fichier', f)" in ADMIN
    assert "/shared/sidebar.js" in ADMIN and "!DEMO" in ADMIN


def test_usager_garde_et_routes_a_l_identique():
    assert "/shared/sidebar.js" not in USAGER
    assert "var API = '/api/v1/voicestudio/usager'" in USAGER
    for r in ("api('/etat')", "api('/voix')", "'/dire'", "'/transcrire'"):
        assert r in USAGER, r
    assert "r.status === 401 || r.status === 403" in USAGER and "/login.html" in USAGER
    assert "getUserMedia({ audio: true })" in USAGER and "new MediaRecorder(flux)" in USAGER
    for interdit in ("'/start'", "'/stop'", "'/config'", "'/cle", "'/journal", "'/sauvegarde'"):
        assert interdit not in USAGER


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


DETAIL = {"module": "voicestudio", "version": "0.6.0", "installed": True, "running": True, "lxc": "RUNNING", "moteur": True,
          "ip": "192.0.2.40", "port": 3900, "mandataire": "active", "publier": ["192.0.2.10"], "mode": "permanent",
          "inactivite_s": 900, "memoire": "4G", "cpu_poids": 100, "asr": "Systran/faster-whisper-small", "donnees_mo": 1843.4,
          "commit": "a1b2c3d", "sauvegarde": "arch.tar.gz", "operation": {"etat": "inactif"},
          "memoire_hote": {"disponible_mo": 5200, "effective_mo": 5200, "swap_disque_mo": 2048, "moteur_mo": 3100}}
ETAT_U = {"disponible": True, "reveil_necessaire": False, "demarrage": False, "mode": "permanent", "limites": {"texte_max": 1500, "audio_max_mo": 8}}
VOIX = {"voix": [{"id": "rapide", "nom": "Rapide", "langue": "fr"}, {"id": "v2", "nom": "Autre", "langue": "en"}]}
WAV = b"RIFF$\x00\x00\x00WAVEfmt "


def ouvre(navigateur, page, url, routes, taille=None, prefixe="/api/v1/voicestudio"):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    src = ADMIN if page == "admin" else USAGER

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin.startswith("voicestudio"):
            r.fulfill(status=200, content_type="text/html", body=src)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/voicestudio", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers))
        if chemin.endswith(("/dire", "/essai/dire")) and chemin in routes:
            r.fulfill(status=200, content_type="audio/wav", body=WAV)
            return
        statut, corps = routes.get(chemin, (404, {"detail": "inconnu"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/voicestudio/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


A = {"/detail": (200, DETAIL), "/voix": (200, VOIX), "/cle": (200, {"presente": True, "apercu": "sk-abc…f3a9"}),
     "/journal": (200, {"lignes": ["ligne un", "ligne deux"]})}
URL_A = "http://sbx.test/voicestudio/"


def attend(p):
    p.wait_for_function("document.getElementById('vLxc').textContent !== '—'")


def test_admin_tuiles_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "admin", URL_A, A)
    attend(p)
    assert [p.inner_text(i) for i in ("#vLxc", "#vMoteur", "#vMode", "#vMemoire", "#vDonnees", "#vVersion")] == \
        ["actif", "répond", "permanent", "4G", "1843 Mo", "0.6.0"]
    assert "Mémoire de la box" in p.inner_text("#detailEtat") and "mémoire suffisante" in p.inner_text("#detailEtat")
    assert p.get_attribute("#cLxc", "title")
    get = [a for a in appels if a[1] == "/detail"][0]
    assert get[3].get("accept") == "application/json"
    assert err == []
    ctx.close()


def test_admin_jeton_bearer(navigateur):
    ctx = navigateur.new_context()
    ctx.add_init_script("localStorage.setItem('sbx_token','jeton-test')")
    p = ctx.new_page()
    vus = []
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=ADMIN) if "/api/" not in r.request.url
            else (vus.append(r.request.headers.get("authorization")), r.fulfill(status=200, content_type="application/json", body=json.dumps(DETAIL))))
    p.goto(URL_A)
    attend(p)
    assert "Bearer jeton-test" in vus
    ctx.close()


def test_admin_demarrer_envoie_post_sans_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "admin", URL_A, {**A, "/start": (202, {"operation": {}})})
    attend(p)
    p.click("#bStart")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Démarrage')")
    assert [a[:3] for a in appels if a[0] == "POST"] == [("POST", "/start", None)]
    ctx.close()


def test_admin_arret_demande_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "admin", URL_A, {**A, "/stop": (202, {})})
    attend(p)
    p.click("#bStop")
    assert p.is_visible("#confirm") and "Arrêter le moteur" in p.inner_text("#confirmTexte")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confirmNon")
    assert not p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    p.click("#bStop"); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Arrêt')")
    assert ("POST", "/stop") in [a[:2] for a in appels]
    ctx.close()


def test_admin_reglages_envoient_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "admin", URL_A, {**A, "/config": (200, {"ok": True})})
    attend(p)
    p.click("[data-tab=reglages]")
    p.select_option("#fMode", "demande")
    p.fill("#fMem", "6G")
    p.click("[data-action=appliquer-reglages]")
    assert p.is_visible("#confirm")                       # changement de mode : confirmation intégrée
    p.click("#confirmOui")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Réglages appliqués')")
    post = [a for a in appels if a[1] == "/config"][0]
    assert json.loads(post[2]) == {"mode": "demande", "memoire": "6G"}
    assert post[3]["content-type"] == "application/json"
    ctx.close()


def test_admin_publier_corps_et_adresse_invalide(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "admin", URL_A, {**A, "/publier": (200, {"ok": True})})
    attend(p)
    p.click("[data-tab=reglages]")
    p.fill("#fPub", "pas-une-ip")
    p.click("[data-action=publier]")
    assert "Adresse invalide" in p.inner_text("#toast") and not [a for a in appels if a[1] == "/publier"]
    p.fill("#fPub", "192.0.2.10\n192.0.2.11")
    p.click("[data-action=publier]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Publié')")
    assert json.loads([a for a in appels if a[1] == "/publier"][0][2]) == {"adresses": ["192.0.2.10", "192.0.2.11"]}
    ctx.close()


def test_admin_cle_apercu_et_renouvellement(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "admin", URL_A, {**A, "/cle/renouveler": (200, {"cle": "NOUVELLE-CLE-DE-TEST"})})
    attend(p)
    p.click("[data-tab=cle]")
    p.wait_for_function("document.getElementById('detailCle').textContent.includes('sk-abc')")
    p.click("[data-action=renouveler]")
    assert not [a for a in appels if a[1] == "/cle/renouveler"]
    p.click("#confirmOui")
    p.wait_for_selector("#nouvelleCle:not([hidden])")
    assert p.inner_text("#cleValeur") == "NOUVELLE-CLE-DE-TEST"
    p.click("[data-action=fermer-cle]")
    assert p.inner_text("#cleValeur") == "" and err == []
    ctx.close()


def test_admin_essai_dire_transcrire_journal_sauvegarde(navigateur):
    routes = {**A, "/essai/dire": (200, {}), "/essai/transcrire": (200, {"texte": "bonjour le monde", "vide": False}),
              "/sauvegarde": (200, {"ok": True, "fichier": "voicestudio-x.tar.gz"})}
    ctx, p, err, appels = ouvre(navigateur, "admin", URL_A, routes)
    attend(p)
    p.click("[data-tab=essai]")
    p.wait_for_function("document.getElementById('eVoix').options.length > 2")
    p.select_option("#eVoix", "v2"); p.select_option("#eFmt", "wav")
    p.click("[data-action=dire]")
    p.wait_for_function("document.getElementById('eAudio').dataset.url")
    dire = [a for a in appels if a[1] == "/essai/dire"][0]
    assert json.loads(dire[2]) == {"texte": "Bonjour, ici la voix de votre SecuBox.", "voix": "v2", "format": "wav"}
    p.set_input_files("#eFichier", {"name": "a.wav", "mimeType": "audio/wav", "buffer": WAV})
    p.fill("#eLangue", "fr")
    p.click("[data-action=transcrire]")
    p.wait_for_function("document.getElementById('eResultat').textContent.includes('bonjour')")
    tr = [a for a in appels if a[1] == "/essai/transcrire"][0]
    assert "multipart/form-data" in tr[3]["content-type"] and 'name="langue"' in tr[2] and 'name="fichier"' in tr[2]
    p.click("[data-tab=journal]"); p.click("[data-action=journal]")
    p.wait_for_function("document.getElementById('jTexte').textContent.includes('ligne deux')")
    assert [a[1] for a in appels if a[1].startswith("/journal")] == ["/journal"]
    p.click("[data-tab=sauvegarde]"); p.click("[data-action=sauvegarde]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('voicestudio-x')")
    assert err == []
    ctx.close()


def test_admin_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "admin", URL_A, {"/detail": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and "Connexion requise" in p.inner_text("#panne")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#vLxc", "#vMoteur", "#vMode", "#vMemoire", "#vDonnees", "#vVersion")] == ["—"] * 6
    assert err == []
    ctx.close()


def test_admin_mesure_absente_est_un_tiret(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "admin", URL_A, {"/detail": (200, {"installed": False, "lxc": "STOPPED"})})
    p.wait_for_function("document.getElementById('vLxc').textContent === 'endormi'")
    assert p.inner_text("#vDonnees") == "—" and p.inner_text("#vVersion") == "—" and p.inner_text("#vMemoire") == "—" and err == []
    ctx.close()


def test_admin_demo_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "admin", URL_A + "?demo=1", {})
    attend(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("[data-action=restart]"); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.click("[data-tab=cle]"); p.click("[data-action=renouveler]"); p.click("#confirmOui")
    p.click("[data-tab=sauvegarde]"); p.click("[data-action=sauvegarde]")
    assert appels == [] and err == []
    ctx.close()


def test_admin_telephone_sans_debordement_embed(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "admin", URL_A + "?embed=1", A, taille={"width": 420, "height": 800})
    attend(p)
    for onglet in ("etat", "reglages", "cle", "essai", "journal", "sauvegarde"):
        p.click(f"[data-tab={onglet}]")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ---------------------------------------------------------------- usager
U = {"/usager/etat": (200, ETAT_U), "/usager/voix": (200, VOIX), "/usager/dire": (200, {}),
     "/usager/transcrire": (200, {"texte": "texte dicté", "vide": False})}
URL_U = "http://sbx.test/voicestudio/usager.html"


def test_usager_tuiles_limites_et_voix(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "usager", URL_U, U)
    p.wait_for_function("document.getElementById('tTexte').textContent === '1500'")
    assert p.inner_text("#tAudio") == "8" and p.inner_text("#tMoteur") == "répond" and p.inner_text("#etat") == "MOTEUR EN LIGNE"
    p.wait_for_function("document.getElementById('voix').options.length === 3")
    assert p.get_attribute("#cMoteur", "title") and err == []
    ctx.close()


def test_usager_dire_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "usager", URL_U, U)
    p.wait_for_function("document.getElementById('voix').options.length === 3")
    p.fill("#texte", "Bonjour"); p.select_option("#voix", "rapide"); p.select_option("#fmt", "opus")
    p.click("#bDire")
    p.wait_for_function("document.getElementById('audio').dataset.url")
    post = [a for a in appels if a[1] == "/usager/dire"][0]
    assert json.loads(post[2]) == {"texte": "Bonjour", "voix": "rapide", "format": "opus"}
    ctx.close()


def test_usager_transcrire_un_fichier(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "usager", URL_U, U)
    p.set_input_files("#fichier", {"name": "a.wav", "mimeType": "audio/wav", "buffer": WAV})
    p.click("#bTranscrire")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('dicté')")
    tr = [a for a in appels if a[1] == "/usager/transcrire"][0]
    assert 'name="fichier"' in tr[2] and 'name="langue"' in tr[2]
    ctx.close()


def test_usager_garde_d_acces_refus_affiche_connexion(navigateur):
    refus = {k: (403, {"detail": "personne requise"}) for k in U}
    ctx, p, err, appels = ouvre(navigateur, "usager", URL_U, refus)
    p.wait_for_selector("#connexion:not([hidden])")
    assert not p.is_visible("#contenu") and "session requise" in p.inner_text("#connexion")
    assert p.get_attribute("#connexion a", "href") == "/login.html" and p.inner_text("#etat") == "SESSION REQUISE" and err == []
    ctx.close()


def test_usager_moteur_endormi_est_annonce(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "usager", URL_U, {**U, "/usager/etat": (200, {**ETAT_U, "reveil_necessaire": True})})
    p.wait_for_function("document.getElementById('tMoteur').textContent === 'endormi'")
    assert "30 à 60" in p.inner_text("#tMoteurS")
    ctx.close()


def test_usager_demo_annoncee_aucune_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "usager", URL_U + "?demo=1", {})
    p.wait_for_function("document.getElementById('voix').options.length === 3")
    assert p.is_visible("#demo")
    p.fill("#texte", "x"); p.click("#bDire")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_usager_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "usager", URL_U + "?embed=1", U, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tTexte').textContent === '1500'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
