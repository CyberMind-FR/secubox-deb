# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page OpenPGP du Coffre à origine séparée (#1852, P5), dans un VRAI navigateur.

Deux origines HTTPS distinctes : le « webmail » (parent) et la page OpenPGP (cadre). L'API du Coffre est simulée, mais les
clés sont de vraies clés GnuPG et le chiffrement est relu par GnuPG : on prouve l'interopérabilité, pas seulement un aller-retour
de la même bibliothèque. Ce qu'on garantit :
  · chiffrer / signer / déchiffrer / vérifier fonctionnent avec la clé du Coffre, sans aucune phrase ;
  · un destinataire sans clé est REFUSÉ (jamais chiffré à blanc), adresses nommées ;
  · un parent absent de origines.json n'obtient AUCUNE réponse (même pas une erreur) ;
  · la clé secrète n'est ni dans le stockage du navigateur ni dans une réponse ;
  · Autocrypt entrant : clé publique valide portant l'adresse annoncée, jamais une clé secrète, jamais le remplacement d'une clé de l'annuaire."""
import base64
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.skipif(shutil.which("gpg") is None or shutil.which("openssl") is None, reason="gpg/openssl absents")

WWW = Path(__file__).resolve().parents[1] / "www" / "pgp"
G = ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]


class Personne:
    def __init__(self, uid):
        self.home = tempfile.mkdtemp(prefix="sbxpgp-")
        os.chmod(self.home, 0o700)
        self.env = {**os.environ, "GNUPGHOME": self.home, "LC_ALL": "C", "LANGUAGE": "C"}
        subprocess.run(G + ["--quick-gen-key", uid, "ed25519", "sign", "1y"], env=self.env, check=True, capture_output=True)
        self.fpr = [l.split(":")[9] for l in subprocess.run(["gpg", "--with-colons", "--list-keys"], env=self.env, capture_output=True,
                    text=True).stdout.splitlines() if l.startswith("fpr:")][0]
        subprocess.run(G + ["--quick-add-key", self.fpr, "cv25519", "encr", "1y"], env=self.env, check=True, capture_output=True)
        self.publique = subprocess.run(["gpg", "--armor", "--export-options", "export-minimal", "--export", self.fpr], env=self.env,
                                       capture_output=True, text=True).stdout
        self.secrete = subprocess.run(G + ["--armor", "--export-secret-keys", self.fpr], env=self.env, capture_output=True,
                                      text=True).stdout
        self.binaire = subprocess.run(["gpg", "--export-options", "export-minimal", "--export", self.fpr], env=self.env,
                                      capture_output=True).stdout

    def gpg(self, *args, entree=None):
        return subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", *args], env=self.env,
                              input=entree, capture_output=True)

    def fin(self):
        subprocess.run(["gpgconf", "--kill", "all"], env=self.env, capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)


FAUX_ROUNDCUBE = """<!doctype html><title>webmail</title>
<input name="_is_html" value="%(html)s"><input name="_to" value=""><input name="_cc" value=""><textarea id="composebody">Texte clair</textarea>
<div id="messagebody">%(corps)s</div>
<a class="secubox-pgp chiffrer"></a><a class="secubox-pgp signer"></a>
<script>
window.__msgs = []; window.__envoye = null;
window.rcmail = { env: { secubox_pgp_origine: "%(api)s", action: "%(action)s", secubox_pgp_message: %(msg)s }, _ev: {}, _cmd: {},
  addEventListener(n, f) { (this._ev[n] = this._ev[n] || []).push(f); },
  triggerEvent(n, a) { let r; (this._ev[n] || []).forEach(f => { const v = f(a); if (v === false) r = false; }); return r; },
  register_command(n, f) { this._cmd[n] = f; },
  command(n) { if (this._cmd[n]) return this._cmd[n]();
    if (n === "send") { if (this.triggerEvent("before" + n) === false) return false; window.__envoye = document.getElementById("composebody").value; } },
  get_label(k, v) { return k + (v ? JSON.stringify(v) : ""); }, display_message(m) { window.__msgs.push(m); }, set_busy() {} };
</script>
<script src="/plugin.js"></script>
<script>rcmail.triggerEvent("init");</script>"""


class Etat:
    """Ce que l'API simulée du Coffre répond ; modifié par les tests."""
    def __init__(self):
        self.secrete = ""
        self.coffre = 200                       # code du Coffre pour la lecture de la clé
        self.annuaire = []                      # [{empreinte, courriels, verifies, pseudo}]
        self.asc = {}                           # empreinte -> armure
        self.contacts = None                    # valeur JSON du secret openpgp-contacts
        self.appels = []


def serveur(etat, origines_json):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _rep(self, code, corps=b"", type_="application/json"):
            if isinstance(corps, (dict, list)):
                corps = json.dumps(corps).encode()
            self.send_response(code)
            self.send_header("Content-Type", type_)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def do_GET(self):
            etat.appels.append(("GET", self.path))
            if self.path.startswith("/pgp/"):
                nom = self.path[5:].split("?")[0] or "index.html"
                if nom == "origines.json":
                    return self._rep(200, origines_json())
                f = WWW / nom
                if f.is_file() and f.resolve().parent == WWW.resolve():
                    t = "text/html" if nom.endswith(".html") else "application/javascript" if nom.endswith(".js") else "application/json"
                    return self._rep(200, f.read_bytes(), t)
            if self.path == "/api/v1/openpgp/annuaire":
                return self._rep(200, {"cles": etat.annuaire})
            m = re.match(r"^/api/v1/openpgp/annuaire/([0-9A-F]{40})\.asc$", self.path)
            if m and m.group(1) in etat.asc:
                return self._rep(200, etat.asc[m.group(1)].encode(), "application/pgp-keys")
            self._rep(404, {"detail": "inconnu"})

        def do_POST(self):
            corps = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            etat.appels.append(("POST", self.path))
            if self.path == "/api/v1/vault/moi/secrets/openpgp-secrete/lire":
                if etat.coffre != 200:
                    return self._rep(etat.coffre, {"detail": "x"})
                return self._rep(200, {"valeur": etat.secrete})
            if self.path == "/api/v1/vault/moi/secrets/openpgp-contacts/lire":
                return self._rep(200, {"valeur": etat.contacts}) if etat.contacts else self._rep(404, {"detail": "absent"})
            if self.path == "/api/v1/vault/moi/secrets":
                etat.contacts = corps["valeur"]
                return self._rep(200, {"version": 1})
            self._rep(404, {"detail": "inconnu"})
    return H


@pytest.fixture(scope="module")
def monde():
    rep = tempfile.mkdtemp(prefix="sbxtls-")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{rep}/k.pem", "-out", f"{rep}/c.pem",
                    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{rep}/c.pem", f"{rep}/k.pem")
    etat = Etat()
    parent_origine = {"v": ""}
    api = ThreadingHTTPServer(("127.0.0.1", 0), serveur(etat, lambda: {"origines": [parent_origine["v"]]}))
    api.socket = ctx.wrap_socket(api.socket, server_side=True)
    ctx_pages = {"api": "", "msg": {}}
    PLUGIN = Path(__file__).resolve().parents[2] / "secubox-mail" / "roundcube" / "plugins" / "secubox_pgp" / "secubox_pgp.js"

    class P(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            chemin = self.path.split("?")[0]
            if chemin == "/plugin.js" and PLUGIN.is_file():
                corps, type_ = PLUGIN.read_bytes(), "application/javascript"
            elif chemin in ("/compose", "/show"):
                action = chemin[1:]
                corps = (FAUX_ROUNDCUBE % {"api": ctx_pages["api"], "action": action,
                                           "msg": json.dumps(ctx_pages["msg"]), "html": ctx_pages.get("html", "0"),
                                           "corps": ctx_pages.get("corps", "")}).encode()
                type_ = "text/html"
            else:
                corps, type_ = b"<!doctype html><title>webmail</title>", "text/html"
            self.send_response(200)
            self.send_header("Content-Type", type_)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)
    parent = ThreadingHTTPServer(("127.0.0.1", 0), P)
    parent.socket = ctx.wrap_socket(parent.socket, server_side=True)
    # Un troisième hôte : un parent NON autorisé.
    intrus = ThreadingHTTPServer(("127.0.0.1", 0), P)
    intrus.socket = ctx.wrap_socket(intrus.socket, server_side=True)
    for s in (api, parent, intrus):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    parent_origine["v"] = f"https://127.0.0.1:{parent.server_port}"
    ctx_pages["api"] = f"https://127.0.0.1:{api.server_port}"
    gens = {n: Personne(f"{n.capitalize()} <{n}@secubox.in>") for n in ("alice", "bob", "carol")}
    etat.secrete = gens["alice"].secrete
    yield {"pages": ctx_pages, "etat": etat, "api": f"https://127.0.0.1:{api.server_port}", "parent": parent_origine["v"],
           "intrus": f"https://127.0.0.1:{intrus.server_port}", "p": gens}
    for s in (api, parent, intrus):
        s.shutdown()
    for g in gens.values():
        g.fin()
    shutil.rmtree(rep, ignore_errors=True)


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(navigateur, monde):
    e = monde["etat"]
    e.coffre, e.contacts, e.annuaire, e.asc, e.appels = 200, None, [], {}, []
    ctx = navigateur.new_context(ignore_https_errors=True)
    p = ctx.new_page()
    p.on("pageerror", lambda x: print("PAGEERROR", x))
    p.goto(monde["parent"] + "/")
    p.evaluate("""(api) => {
      window.__rep = {}; window.__pret = false;
      window.addEventListener('message', ev => { if (ev.data && ev.data.pret) window.__pret = true; else if (ev.data && ev.data.id) window.__rep[ev.data.id] = ev.data; });
      const f = document.createElement('iframe'); f.id = 'pgp'; f.src = api + '/pgp/'; document.body.appendChild(f);
      window.__api = api;
      window.__id = 0;
      window.dire = (op, corps) => new Promise((ok, ko) => { const id = 'r' + (++window.__id);
        document.getElementById('pgp').contentWindow.postMessage(Object.assign({ id, op }, corps || {}), window.__api);
        const t0 = Date.now(); (function w() { if (window.__rep[id]) ok(window.__rep[id]); else if (Date.now() - t0 > 6000) ok({ silence: true }); else setTimeout(w, 30); })(); });
    }""", monde["api"])
    p.wait_for_function("window.__pret === true", timeout=10000)
    yield p
    ctx.close()


def dire(page, op, **corps):
    return page.evaluate("([op, c]) => window.dire(op, c)", [op, corps])


def publier(monde, nom, courriel):
    g = monde["p"][nom]
    monde["etat"].annuaire.append({"empreinte": g.fpr, "courriels": [courriel], "verifies": [courriel], "pseudo": nom})
    monde["etat"].asc[g.fpr] = g.publique


def test_status_lit_la_cle_du_coffre_sans_phrase(page, monde):
    r = dire(page, "status")
    assert r["ok"] and r["empreinte"] == monde["p"]["alice"].fpr and r["adresses"] == ["alice@secubox.in"]


def test_chiffrer_est_lisible_par_gnupg_destinataire_et_par_alice(page, monde):
    publier(monde, "bob", "bob@secubox.in")
    r = dire(page, "chiffrer", texte="Bonjour Bob, rendez-vous à midi.", destinataires=["bob@secubox.in"])
    assert r["ok"] and r["signe"] and "BEGIN PGP MESSAGE" in r["armure"]
    bob = monde["p"]["bob"]
    bob.gpg("--import", entree=monde["p"]["alice"].publique.encode())               # pour vérifier sa signature
    clair = bob.gpg("--decrypt", entree=r["armure"].encode())
    assert clair.stdout.decode().strip() == "Bonjour Bob, rendez-vous à midi."
    assert "Good signature" in clair.stderr.decode()
    alice = monde["p"]["alice"]
    assert alice.gpg("--decrypt", entree=r["armure"].encode()).stdout.decode().strip() == "Bonjour Bob, rendez-vous à midi."
    assert monde["p"]["carol"].gpg("--decrypt", entree=r["armure"].encode()).returncode != 0      # pas pour Carol


def test_destinataire_sans_cle_est_refuse_jamais_chiffre_a_blanc(page, monde):
    publier(monde, "bob", "bob@secubox.in")
    r = dire(page, "chiffrer", texte="secret", destinataires=["bob@secubox.in", "inconnu@exemple.org"])
    assert not r["ok"] and r["code"] == "cle_manquante" and r["extra"]["manquants"] == ["inconnu@exemple.org"]


def test_signer_puis_verifier_par_gnupg(page, monde):
    r = dire(page, "signer", texte="Je soussignée.")
    assert r["ok"] and "BEGIN PGP SIGNED MESSAGE" in r["armure"]
    bob = monde["p"]["bob"]
    bob.gpg("--import", entree=monde["p"]["alice"].publique.encode())
    v = bob.gpg("--verify", entree=r["armure"].encode())
    assert "Good signature" in v.stderr.decode()


def test_dechiffrer_un_message_de_bob_signature_valide_puis_inconnue(page, monde):
    alice, bob = monde["p"]["alice"], monde["p"]["bob"]
    bob.gpg("--import", entree=alice.publique.encode())
    bob.gpg("--trust-model", "always", "--armor", "--encrypt", "--sign", "-r", alice.fpr, "--local-user", bob.fpr, "--output", "-",
            entree=b"")                                     # rien : on chiffre ci-dessous avec le texte
    msg = bob.gpg("--trust-model", "always", "--armor", "--encrypt", "--sign", "-r", alice.fpr, "--local-user", bob.fpr,
                  entree=b"Salut Alice").stdout.decode()
    assert "BEGIN PGP MESSAGE" in msg
    inconnu = dire(page, "dechiffrer", armure=msg, expediteur="bob@secubox.in")           # annuaire sans Bob
    assert inconnu["ok"] and inconnu["texte"] == "Salut Alice" and inconnu["signature"]["etat"] == "cle_inconnue"
    publier(monde, "bob", "bob@secubox.in")
    page.evaluate("window.__rep = {}")
    page.evaluate("document.getElementById('pgp').contentWindow.postMessage({id:'v', op:'verrouiller'}, window.__api)")
    ok = dire(page, "dechiffrer", armure=msg, expediteur="bob@secubox.in")
    assert ok["ok"] and ok["signature"]["etat"] == "valide" and ok["signature"]["empreinte"] == bob.fpr.upper()


def test_un_parent_hors_liste_n_obtient_aucune_reponse(navigateur, monde):
    ctx = navigateur.new_context(ignore_https_errors=True)
    p = ctx.new_page()
    p.goto(monde["intrus"] + "/")
    r = p.evaluate("""(api) => new Promise(ok => {
      const f = document.createElement('iframe'); f.src = api + '/pgp/'; document.body.appendChild(f); const rep = [];
      window.addEventListener('message', e => rep.push(e.data));
      f.onload = () => { setTimeout(() => { f.contentWindow.postMessage({ id: 'x', op: 'status' }, api); setTimeout(() => ok(rep), 1500); }, 500); };
    })""", monde["api"])
    ctx.close()
    assert r == []                                              # même pas « pret » ni une erreur


def test_coffre_scelle_et_absence_de_cle_sont_dits(page, monde):
    monde["etat"].coffre = 423
    assert dire(page, "status")["code"] == "coffre_scelle"
    monde["etat"].coffre = 404
    page.evaluate("document.getElementById('pgp').contentWindow.postMessage({id:'v', op:'verrouiller'}, window.__api)")
    assert dire(page, "status")["code"] == "pas_de_cle"
    monde["etat"].coffre = 401
    assert dire(page, "status")["code"] == "non_connecte"


def test_la_cle_secrete_ne_sort_jamais_de_la_page(page, monde):
    publier(monde, "bob", "bob@secubox.in")
    reps = [dire(page, "status"), dire(page, "chiffrer", texte="x", destinataires=["bob@secubox.in"]), dire(page, "signer", texte="x")]
    assert all("PRIVATE KEY" not in json.dumps(r) for r in reps)
    cadre = page.frame_locator("#pgp")
    stock = [f for f in page.frames if f.url.endswith("/pgp/")][0].evaluate(
        "JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage), document.cookie])")
    assert stock == "[[],[],\"\"]"
    del cadre


def test_entree_invalide_est_refusee(page):
    assert dire(page, "chiffrer", texte="x", destinataires=[])["code"] == "entree"
    assert dire(page, "chiffrer", texte="", destinataires=["a@b.fr"])["code"] == "entree"
    assert dire(page, "dechiffrer", armure="pas de bloc")["code"] == "entree"
    assert dire(page, "operation_inconnue").get("silence") is True      # opération hors liste : silence


def test_autocrypt_entrant_apprend_une_cle_valide_et_la_reutilise(page, monde):
    carol = monde["p"]["carol"]
    kd = base64.b64encode(carol.binaire).decode()
    r = dire(page, "apprendre", courriel="carol@secubox.in", keydata=kd)
    assert r["ok"] and r["appris"] and r["empreinte"] == carol.fpr.upper()
    assert json.loads(monde["etat"].contacts)["cles"]["carol@secubox.in"]["empreinte"] == carol.fpr.upper()
    assert dire(page, "apprendre", courriel="carol@secubox.in", keydata=kd)["motif"] == "deja"
    c = dire(page, "chiffrer", texte="pour Carol", destinataires=["carol@secubox.in"])          # contact appris, hors annuaire
    assert c["ok"] and carol.gpg("--decrypt", entree=c["armure"].encode()).stdout.decode().strip() == "pour Carol"


def test_autocrypt_entrant_refuse_secrete_mauvaise_adresse_et_ne_supplante_pas_l_annuaire(page, monde):
    carol, bob = monde["p"]["carol"], monde["p"]["bob"]
    secrete = subprocess.run(["gpg", "--export-options", "export-minimal", "--export-secret-keys", carol.fpr], env=carol.env,
                             capture_output=True).stdout
    assert dire(page, "apprendre", courriel="carol@secubox.in", keydata=base64.b64encode(secrete).decode())["code"] == "refuse"
    assert dire(page, "apprendre", courriel="autre@secubox.in", keydata=base64.b64encode(carol.binaire).decode())["code"] == "refuse"
    publier(monde, "bob", "bob@secubox.in")
    r = dire(page, "apprendre", courriel="bob@secubox.in", keydata=base64.b64encode(bob.binaire).decode())
    assert r["ok"] and r["appris"] is False and r["motif"] == "annuaire"
    assert dire(page, "apprendre", courriel="x@secubox.in", keydata="!!!")["code"] == "entree"


# ── le greffon Roundcube, face à la vraie page du Coffre ─────────────────────────────────────────────────────────────────
PLUGIN_JS = Path(__file__).resolve().parents[2] / "secubox-mail" / "roundcube" / "plugins" / "secubox_pgp" / "secubox_pgp.js"
greffon = pytest.mark.skipif(not PLUGIN_JS.is_file(), reason="greffon secubox_pgp absent")


@pytest.fixture
def webmail(navigateur, monde):
    e = monde["etat"]
    e.coffre, e.contacts, e.annuaire, e.asc, e.appels = 200, None, [], {}, []
    monde["pages"].update(msg={}, html="0", corps="")
    ctx = navigateur.new_context(ignore_https_errors=True)
    yield lambda chemin: (lambda p: (p.goto(monde["parent"] + chemin), p)[1])(ctx.new_page())
    ctx.close()


def envoyer(p):
    p.evaluate("rcmail.command('plugin.secubox_pgp.chiffrer'); document.querySelector('[name=_to]').value = 'Bob <bob@secubox.in>'")
    p.evaluate("rcmail.command('send')")
    p.wait_for_function("window.__envoye !== null || window.__msgs.length > 0", timeout=15000)


@greffon
def test_greffon_chiffre_l_envoi_pour_gnupg_et_rend_le_clair_a_la_fenetre(webmail, monde):
    publier(monde, "bob", "bob@secubox.in")
    p = webmail("/compose")
    envoyer(p)
    envoye = p.evaluate("window.__envoye")
    assert "BEGIN PGP MESSAGE" in envoye and "Texte clair" not in envoye
    assert monde["p"]["bob"].gpg("--decrypt", entree=envoye.encode()).stdout.decode().strip() == "Texte clair"
    assert p.evaluate("document.getElementById('composebody').value") == "Texte clair"      # le clair est revenu dans la fenêtre


@greffon
def test_greffon_n_envoie_jamais_en_clair_si_une_cle_manque(webmail, monde):
    p = webmail("/compose")                                  # annuaire vide : Bob n'a pas de clé
    envoyer(p)
    assert p.evaluate("window.__envoye") is None
    assert "manquants" in p.evaluate("window.__msgs[0]") and "bob@secubox.in" in p.evaluate("window.__msgs[0]")
    assert p.evaluate("document.getElementById('composebody').value") == "Texte clair"


@greffon
def test_greffon_refuse_le_html_et_le_coffre_scelle(webmail, monde):
    monde["pages"]["html"] = "1"
    p = webmail("/compose")
    p.evaluate("rcmail.command('plugin.secubox_pgp.chiffrer')")
    assert "textebrut" in p.evaluate("window.__msgs[0]")
    monde["pages"]["html"] = "0"
    monde["etat"].coffre = 423
    publier(monde, "bob", "bob@secubox.in")
    p2 = webmail("/compose")
    envoyer(p2)
    assert p2.evaluate("window.__envoye") is None and "coffrescelle" in p2.evaluate("window.__msgs[0]")


@greffon
def test_greffon_affiche_un_message_dechiffre_en_texte_seulement_avec_pastille(webmail, monde):
    alice, bob = monde["p"]["alice"], monde["p"]["bob"]
    bob.gpg("--import", entree=alice.publique.encode())
    piege = "Salut <img src=x onerror=window.__pwn=1> fin"
    msg = bob.gpg("--trust-model", "always", "--armor", "--encrypt", "--sign", "-r", alice.fpr, "--local-user", bob.fpr,
                  entree=piege.encode()).stdout.decode()
    publier(monde, "bob", "bob@secubox.in")
    monde["pages"].update(msg={"expediteur": "bob@secubox.in", "autocrypt": None}, corps="<pre>" + msg + "</pre>")
    p = webmail("/show")
    p.wait_for_selector(".secubox-pgp-texte", timeout=15000)
    assert p.inner_text(".secubox-pgp-texte") == piege                       # affiché TEL QUEL, en texte
    assert p.evaluate("document.querySelectorAll('#messagebody img').length") == 0
    assert p.evaluate("window.__pwn === undefined")
    assert "sigvalide" in p.inner_text(".secubox-pgp-bandeau.ok")


@greffon
def test_greffon_apprend_la_cle_autocrypt_d_un_message_recu(webmail, monde):
    carol = monde["p"]["carol"]
    monde["pages"].update(msg={"expediteur": "carol@secubox.in",
                               "autocrypt": {"courriel": "carol@secubox.in", "keydata": base64.b64encode(carol.binaire).decode()}},
                          corps="<p>bonjour</p>")
    p = webmail("/show")
    p.wait_for_function("true")
    for _ in range(100):
        if monde["etat"].contacts:
            break
        p.wait_for_timeout(100)
    assert json.loads(monde["etat"].contacts)["cles"]["carol@secubox.in"]["empreinte"] == carol.fpr.upper()
