# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2475 — code d'invitation du maillage : adresse + jeton en une chaîne, strict, avec somme de contrôle."""
import pytest

from api import automesh as A

JETON = "ab" * 32


def test_aller_retour_ipv4_nom_et_ipv6():
    for a in ("192.0.2.10", "gk2.exemple.test", "2001:db8::1"):
        assert A.decoder(A.encoder(a, JETON)) == (a, JETON)


def test_le_code_a_la_forme_attendue_et_ne_contient_pas_le_jeton_en_clair():
    c = A.encoder("192.0.2.10", JETON)
    assert c.startswith("sbxmesh1.") and c.count(".") == 2 and JETON not in c


@pytest.mark.parametrize("mal", ["", "x", "sbxmesh1.", "sbxmesh1.abc", "sbxmesh2.xxx.1234", "sbxmesh1.!!!.0000", " ", "sbxmesh1." + "A" * 700 + ".0000"])
def test_codes_mal_formes_refuses(mal):
    with pytest.raises(ValueError):
        A.decoder(mal)


def test_somme_de_controle_refuse_un_caractere_altere_ou_un_code_tronque():
    c = A.encoder("192.0.2.10", JETON)
    altere = c[:12] + ("B" if c[12] != "B" else "C") + c[13:]
    for faux in (altere, c[:-6], c[:-1]):
        with pytest.raises(ValueError):
            A.decoder(faux)


@pytest.mark.parametrize("adresse", ["", "http://x.test", "x.test/chemin", "x.test:80", "a b", "x.test;rm -rf /", "$(id)", "-x.test", "x" * 300, "javascript:alert(1)"])
def test_adresse_hostile_refusee_a_l_encodage_et_au_decodage(adresse):
    with pytest.raises(ValueError):
        A.encoder(adresse, JETON)
    import base64, json
    charge = base64.urlsafe_b64encode(json.dumps({"a": adresse, "t": JETON}).encode()).decode().rstrip("=")
    with pytest.raises(ValueError):
        A.decoder(f"sbxmesh1.{charge}.{A._somme(charge)}")                  # même avec une somme correcte : le contenu est revalidé


@pytest.mark.parametrize("jeton", ["", "abc", "g" * 64, "A" * 64, "ab" * 33])
def test_jeton_invalide_refuse(jeton):
    with pytest.raises(ValueError):
        A.encoder("192.0.2.10", jeton)


def test_champs_en_trop_refuses():
    import base64, json
    charge = base64.urlsafe_b64encode(json.dumps({"a": "192.0.2.10", "t": JETON, "x": 1}).encode()).decode().rstrip("=")
    with pytest.raises(ValueError):
        A.decoder(f"sbxmesh1.{charge}.{A._somme(charge)}")


# ── jonction automatique ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
import json  # noqa: E402


def _poser(tmp_path, code=None):
    c = tmp_path / "automesh.code"
    c.write_text(code if code is not None else A.encoder("192.0.2.10", JETON))
    return str(c), str(tmp_path / "etat.json")


def test_sans_code_depose_rien_ne_se_passe(tmp_path):
    assert A.executer(lambda a, t: 1 / 0, str(tmp_path / "absent"), str(tmp_path / "e.json")) == "aucun"


def test_approuve_supprime_le_code_et_ne_garde_pas_le_jeton(tmp_path):
    c, e = _poser(tmp_path)
    vu = []
    assert A.executer(lambda a, t: vu.append((a, t)) or {"status": "approved", "mesh_ip": "10.10.0.7"}, c, e, 1000.0) == "approuve"
    assert vu == [("192.0.2.10", JETON)] and not (tmp_path / "automesh.code").exists()
    brut = (tmp_path / "etat.json").read_text()
    assert JETON not in brut and "sbxmesh1" not in brut and json.loads(brut)["mesh_ip"] == "10.10.0.7"
    assert oct((tmp_path / "etat.json").stat().st_mode & 0o777) == "0o600"


def test_en_attente_garde_le_code_pour_le_prochain_passage(tmp_path):
    c, e = _poser(tmp_path)
    assert A.executer(lambda a, t: {"status": "pending"}, c, e, 1000.0) == "en_attente" and (tmp_path / "automesh.code").exists()
    assert A.executer(lambda a, t: {"status": "approved"}, c, e, 1100.0) == "approuve" and not (tmp_path / "automesh.code").exists()


def test_echecs_repetes_finissent_par_supprimer_le_code_et_ne_disent_pas_le_secret(tmp_path):
    from fastapi import HTTPException
    c, e = _poser(tmp_path)

    def casse(a, t):
        raise HTTPException(status_code=403, detail="token_expired")
    for i in range(A.ECHECS_MAX - 1):
        assert A.executer(casse, c, e, 1000.0 + i) == "echec" and (tmp_path / "automesh.code").exists()
    assert A.executer(casse, c, e, 1100.0) == "echec" and not (tmp_path / "automesh.code").exists()
    brut = (tmp_path / "etat.json").read_text()
    assert "token_expired" in brut and JETON not in brut


def test_code_invalide_ou_trop_ancien_est_supprime(tmp_path):
    c, e = _poser(tmp_path, "n'importe quoi")
    assert A.executer(lambda a, t: 1 / 0, c, e) == "invalide" and not (tmp_path / "automesh.code").exists()
    c, e = _poser(tmp_path)
    (tmp_path / "etat.json").write_text(json.dumps({"debut": 1000.0, "echecs": 0}))
    assert A.executer(lambda a, t: {"status": "approved"}, c, e, 1000.0 + A.AGE_MAX_S + 1) == "expire" and not (tmp_path / "automesh.code").exists()


# ── routes ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_jonction_par_code_route_jwt_decode_et_refuse_le_code_invalide(monkeypatch):
    from fastapi.testclient import TestClient
    from api import main
    appels = []

    async def faux(adresse, jeton):
        appels.append((adresse, jeton)); return {"status": "pending"}
    monkeypatch.setattr(main, "_rejoindre_maitre", faux)
    main.app.dependency_overrides.clear()
    c = TestClient(main.app)
    code = A.encoder("192.0.2.10", JETON)
    assert c.post("/master-link/join-with-code", json={"code": code}).status_code in (401, 403) and appels == []     # sans JWT : rien
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}

    async def jwt():
        return {"sub": "admin"}
    main.app.dependency_overrides[main.require_jwt] = jwt
    try:
        assert c.post("/master-link/join-with-code", json={"code": code}).json() == {"status": "pending"} and appels == [("192.0.2.10", JETON)]
        r = c.post("/master-link/join-with-code", json={"code": code[:-1]})
        assert r.status_code == 400 and "somme" in r.json()["detail"] and len(appels) == 1
    finally:
        main.app.dependency_overrides.clear()


def test_url_de_jonction_local_en_http_distant_en_https_verifie():
    from api import main
    assert main._url_jonction("192.168.1.9") == "http://192.168.1.9:7331/api/v1/p2p/master-link/join"
    assert main._url_jonction("gk2.exemple.test") == "https://gk2.exemple.test/api/v1/p2p/master-link/join"
    assert main._url_jonction("8.8.8.8") == "https://8.8.8.8/api/v1/p2p/master-link/join"        # publique : HTTPS
    assert main._url_jonction("2606:4700::1") == "https://[2606:4700::1]/api/v1/p2p/master-link/join"
    assert main._url_jonction("fd00::1") == "http://[fd00::1]:7331/api/v1/p2p/master-link/join"                # privée (ULA) : HTTP local, crochets obligatoires


def test_une_invitation_porte_le_code(monkeypatch):
    from fastapi.testclient import TestClient
    from api import main
    monkeypatch.setattr(main, "get_ml_config", lambda: {"role": "master", "fingerprint": "fp"})
    monkeypatch.setattr(main, "ml_token_generate", lambda *a, **k: {"token": JETON, "token_hash": "h", "expires": "e", "ttl": 3600})
    monkeypatch.setattr(main, "get_lan_ip", lambda: "192.0.2.10")
    monkeypatch.setattr(main, "get_wan_ip", lambda: None)

    async def jwt():
        return {"sub": "admin"}
    main.app.dependency_overrides[main.require_jwt] = jwt
    try:
        r = TestClient(main.app).post("/master-link/invite-local?ttl=3600&auto_approve=false").json()
        assert A.decoder(r["code"]) == ("192.0.2.10", JETON)
    finally:
        main.app.dependency_overrides.clear()


# ── script de jonction et paquet ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _sortie(rc, out):
    return lambda cmd, **k: type("R", (), {"returncode": rc, "stdout": out})()


def test_script_approuve_pending_et_echec(tmp_path):
    ok = A.rejoindre_par_script("192.0.2.10", JETON, run=_sortie(0, "✓ SUCCESS\n  Status: APPROVED\n  Mesh address: 10.10.0.7/24\n"))
    assert ok == {"status": "approved", "mesh_ip": "10.10.0.7/24"}
    assert A.rejoindre_par_script("192.0.2.10", JETON, run=_sortie(0, "⏳ PENDING: Waiting")) == {"status": "pending"}
    for rc, out in ((1, "✗ FAILED"), (0, "rien d'utile")):
        with pytest.raises(RuntimeError):
            A.rejoindre_par_script("192.0.2.10", JETON, run=_sortie(rc, out))


def test_le_jeton_passe_par_l_environnement_jamais_par_la_ligne_de_commande():
    vu = {}

    def run(cmd, **k):
        vu["cmd"], vu["env"] = cmd, k["env"]
        return type("R", (), {"returncode": 0, "stdout": "Status: APPROVED"})()
    A.rejoindre_par_script("192.0.2.10", JETON, run=run)
    assert JETON not in " ".join(vu["cmd"]) and vu["cmd"][-1] == "-" and vu["env"]["SBX_MESH_TOKEN"] == JETON


def test_adresse_ou_jeton_hostiles_ne_lancent_rien():
    appels = []
    for a, t in (("x;rm -rf /", JETON), ("192.0.2.10", "pas-un-jeton"), ("$(id)", JETON)):
        with pytest.raises(RuntimeError):
            A.rejoindre_par_script(a, t, run=lambda *x, **k: appels.append(1))
    assert appels == []


def test_le_script_de_jonction_accepte_le_jeton_de_l_environnement():
    import pathlib
    s = (pathlib.Path(__file__).resolve().parents[1] / "scripts" / "sbx-mesh-join").read_text(encoding="utf-8")
    assert '[ "$TOKEN" = "-" ] && TOKEN="${SBX_MESH_TOKEN:-}"' in s


def test_unite_minuterie_et_paquet_de_la_jonction_automatique():
    import pathlib
    r = pathlib.Path(__file__).resolve().parents[1]
    u = (r / "systemd" / "secubox-automesh.service").read_text(encoding="utf-8")
    assert "ConditionPathExists=/var/lib/secubox/p2p/automesh.code" in u and "NoNewPrivileges=true" in u and "Type=oneshot" in u
    assert "OnBootSec=" in (r / "systemd" / "secubox-automesh.timer").read_text(encoding="utf-8")
    assert "secubox-automesh" in (r / "debian" / "rules").read_text(encoding="utf-8") and "secubox-automesh.timer" in (r / "debian" / "postinst").read_text(encoding="utf-8")
