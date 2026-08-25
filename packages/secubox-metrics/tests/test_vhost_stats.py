import json


# ── #1191 — la box qui se parle a elle-meme n'est pas une audience ──────────

def test_hote_reel_ecarte_ce_qui_n_est_pas_un_site():
    from api.vhost_stats import _hote_reel
    for faux in ("localhost", "LOCALHOST", "localhost.localdomain", "_",
                 "127.0.0.1", "::1", "[::1]", "192.168.1.200", "82.67.100.75",
                 "", "   "):
        assert not _hote_reel(faux), f"{faux!r} compte comme un site"
    for vrai in ("radio.gk2.secubox.in", "ganimed.fr", "www.anibal-amiot.net",
                 "wall.maegia.tv", "exemple.fr."):
        assert _hote_reel(vrai), f"{vrai!r} devrait compter"


def test_les_hotes_fantomes_n_entrent_pas_dans_les_compteurs(tmp_path, monkeypatch):
    """Ils ne doivent pas etre MASQUES : ils ne doivent pas exister.

    Un faux positif seulement cache reste dans les totaux, les classements et
    les graphiques, et fausse en silence les chiffres qu'on croit lire.
    """
    from api import vhost_stats as V

    # Date du JOUR : la retention de 30 jours purgerait une date figee, et le
    # test passerait au vert pour la mauvaise raison — en ne comptant rien.
    import datetime
    quand = datetime.datetime.now().strftime("%d/%b/%Y:10:00:00 +0100")

    log = tmp_path / "secubox-hosts.log"
    ligne = ('{hote} {ip} - - [' + quand + '] '
             '"GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n')
    log.write_text(
        ligne.format(hote="ganimed.fr", ip="93.184.216.34")
        + ligne.format(hote="localhost", ip="127.0.0.1")
        + ligne.format(hote="192.168.1.200", ip="192.168.1.9")
        + ligne.format(hote="_", ip="203.0.113.7")
    )
    monkeypatch.setattr(V, "JOURNAL_HOTES", log)
    monkeypatch.setattr(V, "REP_LOGS", tmp_path)

    ag = V.VhostStatsAggregator()
    ag.collecter()

    hotes = {h for jour in ag._jours.values() for h in jour}
    assert hotes == {"ganimed.fr"}, f"des hotes fantomes ont ete comptes : {hotes}"


def test_le_cache_deja_pollue_est_assaini_au_rechargement(tmp_path, monkeypatch):
    """Le cache anterieur au correctif contient des hotes fantomes.

    Sans tri au rechargement ils survivraient a la collecte assainie, et il
    faudrait purger le cache a la main pour que les chiffres redeviennent
    justes — ce que personne ne penserait a faire.
    """
    from api import vhost_stats as V

    cache = tmp_path / "vhost_stats.json"
    cache.write_text(json.dumps({
        "version": 2, "suivi": {},
        "jours": {"2026-08-25": {
            "ganimed.fr": {"visites": 12, "requetes": 30, "ips": ["93.184.216.34"]},
            "127.0.0.1": {"visites": 900, "requetes": 900, "ips": ["127.0.0.1"]},
            "192.168.1.200": {"visites": 1346, "requetes": 1346, "ips": ["192.168.1.9"]},
            "_": {"visites": 32, "requetes": 32, "ips": []},
        }},
    }))
    monkeypatch.setattr(V, "CACHE", cache)

    ag = V.VhostStatsAggregator()
    assert set(ag._jours["2026-08-25"]) == {"ganimed.fr"}
