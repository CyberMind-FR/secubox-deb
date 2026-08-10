"""La réécriture d'URI vers l'inspecteur doit conserver la chaîne de requête.

Le backend `mitmproxy_inspector` réécrivait l'URI avec `%[path]%[query]`.
`%[query]` rend la chaîne de requête **sans** le « ? » qui l'introduit :
« /a.css?v=3 » devenait « /a.cssv=3 », et le backend répondait 404.

La panne ne touchait pas un vhost mais **tout** le trafic inspecté portant une
chaîne de requête — donc chaque ressource versionnée du parc. Elle avait été
corrigée à la main dans le `haproxy.cfg` vivant, donc condamnée à disparaître à
la première régénération : exactement le mécanisme que #986 vient de refermer,
et la raison d'être de ce test.

Comme pour test_acme_wiring, on lit le script livré plutôt que d'exécuter
`generate`, qui exige un binaire haproxy, un socket d'état et une arborescence
/etc complète.
"""
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"


def _src() -> str:
    return CTL.read_text(encoding="utf-8")


def test_la_reecriture_utilise_url_et_non_path_query():
    src = _src()
    assert "http-request set-uri http://%[req.hdr(Host)]%[url]" in src, (
        "la réécriture doit utiliser %[url], qui rend le chemin ET la requête"
    )


def test_path_query_ne_reapparait_pas():
    """Interdit la forme fautive ailleurs que dans un commentaire.

    C'est ce test, et non le précédent, qui protège d'une régression : ajouter
    un second backend inspecteur en recopiant l'ancienne forme passerait
    inaperçu si l'on se contentait de vérifier la présence de %[url].
    """
    for numero, ligne in enumerate(_src().splitlines(), 1):
        nue = ligne.strip()
        if nue.startswith("#"):
            continue
        assert "%[path]%[query]" not in nue, (
            f"ligne {numero} : %[query] omet le « ? » et casse toute URL "
            f"versionnée — utiliser %[url]"
        )
