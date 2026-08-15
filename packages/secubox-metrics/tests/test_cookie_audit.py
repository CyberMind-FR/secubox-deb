"""Unit tests for CookieAuditAggregator + Classifier."""
import asyncio
import json
from pathlib import Path

import pytest

from cookie_audit import (
    CookieAuditAggregator,
    Classifier,
    classify_cookie,
)


CFG_BASE = {
    "enabled": True,
    "max_ingest_age_hours": 24,
}


def _write_ledger(tmp_path, records):
    p = tmp_path / "server.jsonl"
    with p.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return p


def test_classify_strictly_necessary():
    cls = Classifier({
        "strictly_necessary": [r"^PHPSESSID$", r"^sess(ion)?id$", r"^csrftoken$"],
        "analytics": [r"^_ga", r"^_pk_"],
        "marketing": [r"^_fbp$", r"^_gcl_"],
        "functional": [r"^lang$", r"^theme$"],
    })
    assert cls.classify("PHPSESSID") == "strictly_necessary"
    assert cls.classify("_ga") == "analytics"
    assert cls.classify("_ga_ABC123") == "analytics"
    assert cls.classify("_fbp") == "marketing"
    assert cls.classify("lang") == "functional"
    assert cls.classify("randomname") == "unclassified"


def test_classify_first_match_wins_in_category_order():
    cls = Classifier({
        "strictly_necessary": [r"^x"],
        "analytics": [r"^x_analytic"],
        "functional": [],
        "marketing": [],
    })
    # x_analytic matches both, but strictly_necessary is checked first.
    assert cls.classify("x_analytic") == "strictly_necessary"


def test_classify_cookie_helper():
    rules = {"analytics": [r"^_ga"], "strictly_necessary": [], "functional": [], "marketing": []}
    assert classify_cookie("_ga", rules) == "analytics"
    assert classify_cookie("zoo", rules) == "unclassified"


def test_aggregator_reconciles_server_and_browser(tmp_path):
    ledger = _write_ledger(tmp_path, [
        {"ts": "2026-05-16T10:00:00+00:00", "vhost": "foo.example.com",
         "name": "PHPSESSID", "value_hash": "abc", "secure": True,
         "httponly": True, "samesite": "Lax", "domain": None,
         "path": "/", "max_age": None, "expires": None},
        {"ts": "2026-05-16T10:00:01+00:00", "vhost": "foo.example.com",
         "name": "lang", "value_hash": "def", "secure": False,
         "httponly": False, "samesite": None, "domain": None,
         "path": "/", "max_age": None, "expires": None},
    ])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    (ingest_dir / "foo.example.com.jsonl").write_text(
        json.dumps({"ts": "2026-05-16T10:00:05+00:00",
                    "host": "foo.example.com", "path": "/",
                    "cookies": [
                        {"name": "PHPSESSID", "value_hash": "abc"},
                        {"name": "_ga", "value_hash": "ghi"},
                        {"name": "lang", "value_hash": "def"},
                    ]}) + "\n"
    )
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={
                 "strictly_necessary": [r"^PHPSESSID$"],
                 "analytics": [r"^_ga"],
                 "functional": [r"^lang$"],
                 "marketing": [],
             }),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is True
    hosts = {h["vhost"]: h for h in out["hosts"]}
    assert "foo.example.com" in hosts
    foo = hosts["foo.example.com"]
    by_name = {c["name"]: c for c in foo["cookies"]}
    assert by_name["PHPSESSID"]["source"] == "both"
    assert by_name["PHPSESSID"]["category"] == "strictly_necessary"
    assert by_name["PHPSESSID"]["rgpd_violation"] is False
    assert by_name["lang"]["source"] == "both"
    assert by_name["lang"]["category"] == "functional"
    # _ga is in the browser but never in the server ledger -> JS-set + analytics
    assert by_name["_ga"]["source"] == "js"
    assert by_name["_ga"]["category"] == "analytics"
    assert by_name["_ga"]["rgpd_violation"] is True
    assert foo["violation_count"] == 1
    # Summary rolls up
    assert out["summary"]["host_count"] == 1
    assert out["summary"]["violation_count"] == 1
    assert out["summary"]["hosts_with_violations"] == 1


def test_aggregator_http_only_cookie_source(tmp_path):
    """Server-only cookie (e.g. HttpOnly) -> source='http', no violation."""
    ledger = _write_ledger(tmp_path, [
        {"ts": "2026-05-16T10:00:00+00:00", "vhost": "secure.example.com",
         "name": "session_token", "value_hash": "xyz", "secure": True,
         "httponly": True, "samesite": "Strict", "domain": None,
         "path": "/", "max_age": None, "expires": None},
    ])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [r"^session_"], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    h = out["hosts"][0]
    c = h["cookies"][0]
    assert c["source"] == "http"
    assert c["category"] == "strictly_necessary"
    assert c["rgpd_violation"] is False
    assert c["httponly"] is True


def test_disabled_aggregator_returns_empty(tmp_path):
    agg = CookieAuditAggregator(
        {"enabled": False},
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["hosts"] == []


def test_aggregator_persists_cache(tmp_path):
    ledger = _write_ledger(tmp_path, [])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    cache = tmp_path / "cookie-audit.json"
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=cache,
    )
    asyncio.run(agg.refresh_once())
    assert cache.exists()
    data = json.loads(cache.read_text())
    assert "generated_at" in data
    assert data["enabled"] is True


def test_aggregator_current_reads_cache_if_no_in_memory(tmp_path):
    cache = tmp_path / "cookie-audit.json"
    cache.write_text(json.dumps({"enabled": True, "hosts": [{"vhost": "cached.example", "cookies": []}]}))
    agg = CookieAuditAggregator({"enabled": True}, cache_path=cache)
    cur = agg.current()
    assert cur["enabled"] is True
    assert cur["hosts"][0]["vhost"] == "cached.example"


def test_aggregator_handles_malformed_ledger_lines(tmp_path):
    ledger = tmp_path / "server.jsonl"
    ledger.write_text("not_json\n{}\n{\"vhost\":\"ok.example\",\"name\":\"a\",\"value_hash\":\"h\"}\n")
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    hosts = [h["vhost"] for h in out["hosts"]]
    assert hosts == ["ok.example"]


# ── LECTURE INCREMENTALE DU REGISTRE (#1045) ────────────────────────────────
#
# Motif du changement : 35 082 lignes relues chaque minute pour en retenir 25.
# Ces tests figent les trois situations qui rendent l'optimisation sure — et
# surtout celles ou elle pourrait PERDRE des donnees.

def _agg_ledger(tmp_path, lignes):
    ledger = tmp_path / "server.jsonl"
    ledger.write_text("".join(json.dumps(l) + "\n" for l in lignes), encoding="utf-8")
    agg = CookieAuditAggregator(
        {"enabled": True, "ledger_path": str(ledger),
         "ingest_dir": str(tmp_path / "ingest")},
        cache_path=tmp_path / "cache.json")
    return agg, ledger


def _ajoute(ledger, lignes):
    with ledger.open("a", encoding="utf-8") as fh:
        for l in lignes:
            fh.write(json.dumps(l) + "\n")


def test_le_registre_nest_pas_relu_en_entier(tmp_path):
    """Le coeur de la correction : deux cycles ne redecodent pas les memes octets."""
    agg, ledger = _agg_ledger(tmp_path, [
        {"vhost": "a.fr", "name": "sid", "value_hash": "1"},
    ])
    agg._read_ledger(ledger)
    pos1 = agg._ledger_pos
    assert pos1 == ledger.stat().st_size

    _ajoute(ledger, [{"vhost": "a.fr", "name": "csrf", "value_hash": "2"}])
    out = agg._read_ledger(ledger)
    assert agg._ledger_pos == ledger.stat().st_size
    assert agg._ledger_pos > pos1
    # L'ancien enregistrement survit alors qu'il n'a PAS ete relu.
    assert set(out["a.fr"]) == {"sid", "csrf"}


def test_sans_ajout_rien_nest_redecode(tmp_path):
    agg, ledger = _agg_ledger(tmp_path, [{"vhost": "a.fr", "name": "sid"}])
    agg._read_ledger(ledger)
    avant = agg._ledger_pos
    out = agg._read_ledger(ledger)
    assert agg._ledger_pos == avant
    assert set(out["a.fr"]) == {"sid"}


def test_le_dernier_enregistrement_gagne_toujours(tmp_path):
    """La semantique ne change pas : le plus recent ecrase le precedent."""
    agg, ledger = _agg_ledger(tmp_path, [{"vhost": "a.fr", "name": "sid", "v": 1}])
    agg._read_ledger(ledger)
    _ajoute(ledger, [{"vhost": "a.fr", "name": "sid", "v": 2}])
    out = agg._read_ledger(ledger)
    assert out["a.fr"]["sid"]["v"] == 2


def test_une_ligne_partielle_nest_pas_perdue(tmp_path):
    """LE PIEGE LE PLUS SERIEUX.

    Le producteur ecrit pendant qu'on lit. Si l'on consommait une ligne
    tronquee, elle serait rejetee comme illisible ET jamais relue — donc perdue
    definitivement, ce que la relecture integrale ne pouvait pas provoquer.
    """
    agg, ledger = _agg_ledger(tmp_path, [{"vhost": "a.fr", "name": "sid"}])
    agg._read_ledger(ledger)
    # Une ligne ecrite a moitie, sans saut de ligne final.
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"vhost": "a.fr", "name": "csr')
    out = agg._read_ledger(ledger)
    assert "csrf" not in out["a.fr"]           # pas encore visible, c'est normal
    # Le producteur termine sa ligne.
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('f", "value_hash": "9"}\n')
    out = agg._read_ledger(ledger)
    assert out["a.fr"]["csrf"]["value_hash"] == "9"   # rien n'a ete perdu


def test_la_rotation_repart_de_zero(tmp_path):
    """Apres rotation, la sortie doit etre celle de l'ancienne version : le
    fichier courant, et lui seul."""
    agg, ledger = _agg_ledger(tmp_path, [{"vhost": "a.fr", "name": "vieux"}])
    agg._read_ledger(ledger)
    ledger.rename(tmp_path / "server.jsonl.1")          # logrotate
    ledger.write_text(json.dumps({"vhost": "a.fr", "name": "neuf"}) + "\n",
                      encoding="utf-8")
    out = agg._read_ledger(ledger)
    assert set(out["a.fr"]) == {"neuf"}
    assert "vieux" not in out["a.fr"]


def test_une_troncature_repart_de_zero(tmp_path):
    agg, ledger = _agg_ledger(tmp_path, [
        {"vhost": "a.fr", "name": "un"}, {"vhost": "a.fr", "name": "deux"}])
    agg._read_ledger(ledger)
    ledger.write_text(json.dumps({"vhost": "a.fr", "name": "trois"}) + "\n",
                      encoding="utf-8")
    out = agg._read_ledger(ledger)
    assert set(out["a.fr"]) == {"trois"}


def test_un_registre_disparu_ne_laisse_pas_de_fantomes(tmp_path):
    agg, ledger = _agg_ledger(tmp_path, [{"vhost": "a.fr", "name": "sid"}])
    agg._read_ledger(ledger)
    ledger.unlink()
    assert agg._read_ledger(ledger) == {}
    # Et si le fichier revient, il ne ressuscite pas l'ancien contenu.
    ledger.write_text(json.dumps({"vhost": "b.fr", "name": "x"}) + "\n",
                      encoding="utf-8")
    out = agg._read_ledger(ledger)
    assert "a.fr" not in out


# ── CACHE DE L'INGEST ───────────────────────────────────────────────────────

def test_un_instantane_inchange_nest_pas_redecode(tmp_path, monkeypatch):
    d = tmp_path / "ingest"; d.mkdir()
    (d / "a.fr.jsonl").write_text(
        json.dumps({"host": "a.fr", "cookies": [{"name": "sid", "value_hash": "1"}]}) + "\n",
        encoding="utf-8")
    agg = CookieAuditAggregator({"enabled": True, "ingest_dir": str(d)},
                                cache_path=tmp_path / "c.json")
    appels = []
    vrai = CookieAuditAggregator._decode_ingest
    monkeypatch.setattr(CookieAuditAggregator, "_decode_ingest",
                        staticmethod(lambda f: (appels.append(f), vrai(f))[1]))
    agg._read_ingest(d)
    assert len(appels) == 1
    agg._read_ingest(d)
    assert len(appels) == 1, "l'instantane inchange a ete redecode"


def test_un_instantane_modifie_est_redecode(tmp_path):
    d = tmp_path / "ingest"; d.mkdir()
    f = d / "a.fr.jsonl"
    f.write_text(json.dumps({"host": "a.fr", "cookies": [{"name": "sid", "value_hash": "1"}]}) + "\n",
                 encoding="utf-8")
    agg = CookieAuditAggregator({"enabled": True, "ingest_dir": str(d)},
                                cache_path=tmp_path / "c.json")
    assert set(agg._read_ingest(d)["a.fr"]) == {"sid"}
    f.write_text(json.dumps({"host": "a.fr", "cookies": [{"name": "autre", "value_hash": "2"}]}) + "\n",
                 encoding="utf-8")
    assert set(agg._read_ingest(d)["a.fr"]) == {"autre"}


def test_la_fusion_ne_pollue_pas_le_cache(tmp_path):
    """Si la fusion alimentait les ensembles RETENUS, le cache deriverait a
    chaque cycle — en accumulant silencieusement des valeurs d'autres fichiers."""
    d = tmp_path / "ingest"; d.mkdir()
    (d / "a.jsonl").write_text(
        json.dumps({"host": "h", "cookies": [{"name": "sid", "value_hash": "1"}]}) + "\n",
        encoding="utf-8")
    (d / "b.jsonl").write_text(
        json.dumps({"host": "h", "cookies": [{"name": "sid", "value_hash": "2"}]}) + "\n",
        encoding="utf-8")
    agg = CookieAuditAggregator({"enabled": True, "ingest_dir": str(d)},
                                cache_path=tmp_path / "c.json")
    assert agg._read_ingest(d)["h"]["sid"] == {"1", "2"}
    # Deuxieme passage : le resultat doit etre IDENTIQUE, pas cumule.
    assert agg._read_ingest(d)["h"]["sid"] == {"1", "2"}
    for _sig, partiel in agg._ingest_cache.values():
        assert len(partiel["h"]["sid"]) == 1, "le cache a ete pollue par la fusion"


def test_un_instantane_disparu_sort_du_cache(tmp_path):
    d = tmp_path / "ingest"; d.mkdir()
    f = d / "a.jsonl"
    f.write_text(json.dumps({"host": "h", "cookies": [{"name": "sid"}]}) + "\n",
                 encoding="utf-8")
    agg = CookieAuditAggregator({"enabled": True, "ingest_dir": str(d)},
                                cache_path=tmp_path / "c.json")
    agg._read_ingest(d)
    assert len(agg._ingest_cache) == 1
    f.unlink()
    assert agg._read_ingest(d) == {}
    assert agg._ingest_cache == {}, "un fichier disparu reste en memoire"
