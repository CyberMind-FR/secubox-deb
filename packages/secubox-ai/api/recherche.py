# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recherche et lecture de pages de secubox-ai (#3583), portées du POC gk0.

Garde SSRF (R13) : `telecharger` n'ouvre que http/https sur les ports 80/443, refuse les adresses
littérales non publiques, tout identifiant dans l'URL, tout nom dont une adresse résolue n'est pas
publique, ne suit jamais une redirection et ne lit que du HTML de taille bornée. Le filtrage IP de
l'unité systemd double ce contrôle applicatif.

Le journal ne reçoit jamais la question, les adresses lues ni le contenu des pages.
"""
import asyncio
import datetime as dt
import ipaddress
import json
import logging
import re
import unicodedata
from html import unescape
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from api import moteurs, reglages

log = logging.getLogger("secubox.ai.recherche")
# httpx journalise chaque adresse demandée à INFO : jamais d'adresse lue dans le journal.
logging.getLogger("httpx").setLevel(logging.WARNING)

AGENT = {"User-Agent": "secubox-ai/0.1 (devel@cybermind.fr)"}
PAGE_MAX = 4000        # caractères d'une page transmis au modèle, avant rognage au budget
PAGE_LUE = 200         # en dessous, la page n'est pas considérée comme lue
MARGE_TOKENS = 64
TAILLE_PAGE_MAX = 300_000

# Injections de test : jamais de réseau réel. FABRIQUE_TRANSPORT_WEB(nom) -> transport httpx ou None ;
# RESOLVEUR(hote) -> liste d'adresses (coroutine).
FABRIQUE_TRANSPORT_WEB: Callable[[str], httpx.AsyncBaseTransport | None] | None = None
RESOLVEUR: Callable[[str], Awaitable[list[str]]] | None = None


def _client(nom: str, delai: float, **kw) -> httpx.AsyncClient:
    transport = FABRIQUE_TRANSPORT_WEB(nom) if FABRIQUE_TRANSPORT_WEB else None
    return httpx.AsyncClient(transport=transport, timeout=delai, headers=AGENT, trust_env=False, **kw)


async def _resoudre(hote: str) -> list[str]:
    if RESOLVEUR is not None:
        return await RESOLVEUR(hote)
    infos = await asyncio.get_running_loop().getaddrinfo(hote, None)
    return [i[4][0] for i in infos]


# Table des adresses IPv6 des interfaces de la box (injectable en test) : `is_global` est vrai pour les
# adresses SLAAC du LAN lui-même, que la garde doit refuser (R14).
SOURCE_IF_INET6 = "/proc/net/if_inet6"
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _prefixes_locaux() -> list:
    reseaux = []
    try:
        with open(SOURCE_IF_INET6, encoding="ascii") as f:
            for ligne in f:
                champs = ligne.split()
                if len(champs) < 4:
                    continue
                try:
                    adr = ipaddress.IPv6Address(int(champs[0], 16))
                    longueur = int(champs[2], 16)
                except ValueError:
                    continue
                if longueur > 0:
                    reseaux.append(ipaddress.ip_network((adr, longueur), strict=False))
    except OSError:
        pass
    return reseaux


def _publique(adresse: str) -> bool:
    try:
        ip = ipaddress.ip_address(adresse.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return _publique(str(ip.ipv4_mapped))
        if ip in NAT64 or any(ip in r for r in _prefixes_locaux()):
            return False
    return ip.is_global


# ---- Outils : liste fermée. Aucun outil ne lit une URL choisie par le modèle. ----
def _texte(html):
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", "", html))).strip()


async def outil_wikipedia(requete):
    async with _client("wikipedia", 15) as c:
        r = await c.get("https://fr.wikipedia.org/w/api.php", params={
            "action": "query", "list": "search", "srsearch": requete, "srlimit": 3, "format": "json"})
        r.raise_for_status()
    return [{"titre": x["title"], "extrait": _texte(x["snippet"]),
             "url": "https://fr.wikipedia.org/wiki/" + x["title"].replace(" ", "_")}
            for x in r.json()["query"]["search"]]


async def outil_searxng(requete):
    """Méta-moteur de gk0 par le moteur distant (`/search`). Distant non configuré : pas d'outil.
    Les erreurs réseau remontent : l'appelant les compte comme panne."""
    m = moteurs._distant()
    if m is None:
        return []
    async with m.client(20) as c:
        r = await c.get("/search", params={"q": requete, "format": "json", "language": "fr"})
        r.raise_for_status()
    return [{"titre": x.get("title", ""), "extrait": x.get("content", ""), "url": x["url"]}
            for x in r.json().get("results", [])[:10] if x.get("url")]


async def outil_secubox(requete):
    """Les sources de la box d'abord : ZIA choisit déjà les objets (par ses mots, ou les sujets récents)."""
    async with _client("secubox", 30) as c:
        r = await c.get(reglages.config()["gk2"]["sources_url"], params={"q": requete, "limit": 5})
        r.raise_for_status()
    return [{"titre": o.get("title", ""), "extrait": o.get("summary", ""), "url": o["url"],
             "secubox": o.get("service", "")}
            for o in r.json().get("objets", []) if o.get("url") and o.get("title")]


async def outil_heure(_requete=""):
    return [{"titre": "Heure locale", "extrait": dt.datetime.now().astimezone().isoformat(timespec="minutes"),
             "url": ""}]


MOTS_VIDES = set("""a au aux avec ce ces cette comment dans de des dis donne du elle en est et fais faire fiche
    il je la le les leur lui ma me memo mémo moi mon ne notre nous on ou où par parle pas peux pour quel quelle quelles quels
    qui que quoi lire lis lit contenu site page recherche résumé resume sa se ses si son sur stp ta te tes toi ton tu un une vos votre vous informations
    information infos info trouve cherche explique peut pouvez svp s il plait plaît""".split())


def _plat(t):
    return unicodedata.normalize("NFKD", t.lower()).encode("ascii", "ignore").decode()


# Verbes d'état et auxiliaires : « Qui était X ? » ne doit pas exiger « était » dans chaque page.
VERBES_VIDES = set("""était étaient été être sont fut furent sera seront serait avait avaient avoir ont eu
    fait faisait c ça cela qu quand pourquoi combien""".split())
# Comparaison SANS accents : « etait » tapé sans accent est le même mot vide qu'« était ».
_MOTS_VIDES_PLATS = {_plat(m) for m in MOTS_VIDES | VERBES_VIDES}


def termes(question):
    return [m for m in re.findall(r"[^\W_]{2,}", question.lower()) if _plat(m) not in _MOTS_VIDES_PLATS][:8]


def pertinent(resultat, mots):
    """Jusqu'à 2 mots (un nom) : tous cités. Au-delà : au moins les deux tiers, sinon il parle d'autre chose."""
    texte = _plat(resultat["titre"] + " " + resultat["extrait"] + " " + resultat["url"].replace(".", " "))
    cites = sum(_plat(m) in texte for m in mots)
    return cites == len(mots) if len(mots) <= 2 else cites * 3 >= len(mots) * 2


async def telecharger(url):
    """Page tirée des résultats, jamais une adresse choisie par le modèle. Hôte public seulement, taille bornée.
    Rend "" au moindre refus : le motif n'est ni journalisé ni exposé."""
    try:
        p = urlsplit(url)
        hote = p.hostname
        if (p.scheme not in ("http", "https") or not hote or p.port not in (None, 80, 443)
                or p.username is not None or p.password is not None or "@" in p.netloc):
            return ""
        try:
            ipaddress.ip_address(hote)
            adresses, nom = [hote], None   # adresse littérale : contrôlée telle quelle, sans résolution
        except ValueError:
            adresses, nom = await _resoudre(hote), hote   # une seule résolution : l'adresse validée est celle utilisée
        if not adresses or not all(_publique(a) for a in adresses):
            return ""
        # Connexion épinglée sur l'adresse validée (anti-rebinding) ; le nom reste dans Host et dans le SNI.
        ip = ipaddress.ip_address(adresses[0].split("%")[0])
        cible_ip = f"[{ip}]" if ip.version == 6 else str(ip)
        netloc = cible_ip + (f":{p.port}" if p.port else "")
        epingle = p._replace(netloc=netloc).geturl()
        extensions = {"sni_hostname": nom} if nom else {}
        async with _client("page", 10, follow_redirects=False) as c:
            async with c.stream("GET", epingle, headers={"Host": p.netloc}, extensions=extensions) as r:
                if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
                    return ""
                brut = b""
                async for bloc in r.aiter_bytes():
                    brut += bloc
                    if len(brut) > TAILLE_PAGE_MAX:
                        brut = brut[:TAILLE_PAGE_MAX]
                        break
                try:
                    return brut.decode("utf-8")
                except UnicodeDecodeError:
                    return brut.decode("latin-1")
    except (httpx.HTTPError, OSError, ValueError):
        return ""


def _visible(html):
    return _texte(re.sub(r"(?is)<(script|style|nav|footer|head)\b.*?</\1>", " ", html))


async def lire_page(url):
    """Sites à cadres : parcours du même hôte sur deux niveaux, 8 pages au plus, jusqu'à avoir de la matière.
    Chaque adresse suivie repasse par `telecharger` : la garde s'applique à chaque saut."""
    hote, vus, file_pages, textes, total = urlsplit(url).hostname, {url}, [url], [], 0
    for _ in range(2 + 1):
        if not file_pages or total >= PAGE_MAX * 3:
            break
        pages = await asyncio.gather(*(telecharger(u) for u in file_pages))
        suivantes = []
        for html in pages:
            texte = _visible(html)
            if len(texte) > 40 and texte not in textes:
                textes.append(texte)
                total += len(texte)
            cibles = re.findall(r"""(?is)<i?frame\b[^>]*?\bsrc=["']?([^"'\s>]+)""", html) + \
                re.findall(r"""(?is)<a\b[^>]*?\bhref=["']?([^"'\s>#]+)""", html)
            for c in cibles:
                cible = urljoin(url, c)
                if urlsplit(cible).hostname == hote and cible not in vus and \
                        re.search(r"(/|\.html?|\.php)$", urlsplit(cible).path or "/"):
                    vus.add(cible)
                    suivantes.append(cible)
        # Une page déjà pleine ne se parcourt pas : seuls les sites vides descendent.
        if total >= PAGE_LUE * 5:
            break
        file_pages = suivantes[:8]
    return " ".join(textes).strip()


def passages(texte, mots):
    """Les seules phrases qui citent le sujet, avec leur voisine : le reste d'une page parle d'autre chose."""
    phrases = re.split(r"(?<=[.!?])\s+", texte)
    cles = [_plat(m) for m in mots]
    gardees = set()
    for i, p in enumerate(phrases):
        plat = _plat(p)
        if all(c in plat for c in cles):
            gardees.update((i, i + 1))
    return " ".join(phrases[i] for i in sorted(gardees) if i < len(phrases))


ADRESSE = re.compile(r"(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:fr|com|org|net|eu|io|in|be|ch|ca|info|dev|app|ai)(?:/[^\s]*)?", re.I)
NATURES = {"secubox": "flux SecuBox", "officiel": "site du sujet", "reference": "encyclopédie", "autre": "site tiers", "ia": "généré par IA, à vérifier", "mention": "simple mention"}
DOMAINES_IA = ("grokipedia.",)
DOMAINES_RESEAUX = ("facebook.com", "linkedin.com", "instagram.com", "twitter.com", "x.com", "tiktok.com")
DOMAINES_REFERENCE = ("wikipedia.org", "britannica.com", "universalis.fr", "larousse.fr")


def nature(resultat, mots):
    hote = _plat(urlsplit(resultat["url"]).hostname or "")
    if any(d in hote for d in DOMAINES_IA):
        return "ia"
    # Le sujet n'est pas dans le titre : la page en parle en passant, quel que soit son site.
    if not all(_plat(m) in _plat(resultat["titre"]) for m in mots):
        return "mention"
    if any(d in hote for d in DOMAINES_REFERENCE):
        return "reference"
    # Le nom complet du sujet dans le nom d'hôte, hors réseaux de partage.
    if mots and all(_plat(m) in hote for m in mots) and "youtube" not in hote:
        return "officiel"
    return "autre"


def consigne_sources(bloc):
    return ("Réponds UNIQUEMENT avec ce que disent ces résultats, sans rien ajouter. En cas de désaccord, crois d'abord "
            "« officiel », puis « reference » ; ne reprends « ia » qu'en le signalant. Une source « mention » parle d'abord d'autre chose : "
            "n'attribue au sujet que ce qu'elle dit de lui. "
            "Toute date, titre ou nom absent des résultats est interdit. "
            "Si une rubrique demandée n'y figure pas, écris « non indiqué ». Termine par les adresses utilisées.\n" + bloc)


async def recherche_fiable(question, prefs, sources, suivi=None):
    """Cherche sur les mots utiles, ne garde que ce qui cite le sujet, classe, lit, puis tient dans le budget.
    Rend (état, bloc) : état ∈ ok, vide, illisible, indisponible."""
    async def dire(**evt):
        if suivi:
            await suivi.put(evt)
    # Adresse donnée par l'utilisateur : on lit CE site, sans passer par les moteurs. Mêmes gardes que toute page.
    site = ADRESSE.search(question)
    if site:
        url = site.group(0).rstrip(".,;:!?)")
        url = url if url.startswith(("http://", "https://")) else "https://" + url
        page = await lire_page(url)
        await dire(etape="page", titre=url, url=url, caracteres=len(page), lue=len(page) >= PAGE_LUE, nature="adresse demandée")
        if len(page) < PAGE_LUE:
            return "illisible", ""
        sources.append({"titre": url, "extrait": page[:200], "url": url, "nature": "officiel", "lue": True})
        m = await moteurs.assurer_moteur()
        disponible = await moteurs.contexte_reel(m) - prefs["generation"]["max_tokens"] - MARGE_TOKENS
        fixe = await moteurs.compter_tokens(prefs["comportement"]["consigne"] + consigne_sources("") + question, m)
        # Plafond des sources : un grand contexte sert aux documents, pas à lire des minutes de page.
        disponible = min(disponible, fixe + prefs["outils"].get("sources_max_jetons", 8000))
        part, tokens = len(page), 0
        for _ in range(6):
            bloc = "<donnees>" + json.dumps([{"titre": url, "url": url, "nature": "officiel", "page": page[:part]}], ensure_ascii=False) + "</donnees>"
            tokens = await moteurs.compter_tokens(bloc, m)
            if fixe + tokens <= disponible or part < 100:
                break
            part = int(part * disponible / (fixe + tokens) * 0.9)
        await dire(etape="budget", contexte=disponible, tokens_sources=tokens, tokens_consigne=fixe, disponible=disponible, part_par_page=part)
        return "ok", bloc
    mots = termes(question)
    await dire(etape="requete", mots=mots)
    if not mots:
        return "vide", ""
    requete, retenus, panne = " ".join(mots), [], 0
    outils = {"secubox": outil_secubox, "searxng": outil_searxng, "wikipedia": outil_wikipedia}
    for nom, outil in outils.items():
        if not prefs["outils"].get(nom):
            continue
        # searxng passe par le moteur distant : non configuré, l'outil est absent ; sonde (cache 10 s, R10)
        # ni prête ni endormie, il est sauté sans attendre le délai de connexion, et compté comme panne.
        if nom == "searxng":
            distant = moteurs._distant()
            if distant is None:
                continue
            statut = await moteurs._statut_distant(distant)
            if statut not in ("pret", "endormi"):
                panne += 1
                await dire(etape="moteur", moteur=nom, echec=statut)
                continue
        try:
            trouves = await outil(requete)
            log.info("outil.appel outil=%s resultats=%d", nom, len(trouves))
        except (httpx.HTTPError, KeyError, ValueError) as e:
            panne += 1
            log.warning("outil.echec outil=%s cause=%s", nom, type(e).__name__)
            await dire(etape="moteur", moteur=nom, echec=type(e).__name__)
            continue
        # Les objets SecuBox sont déjà choisis par ZIA : ils ne repassent pas le filtre de mots.
        deja = {x["url"] for x in retenus}
        gardes = [r for r in trouves if (nom == "secubox" or pertinent(r, mots)) and r["url"] not in deja]
        retenus += gardes
        await dire(etape="moteur", moteur=nom, trouves=len(trouves), gardes=len(gardes))
    if not retenus:
        return ("indisponible" if panne else "vide"), ""
    for r in retenus:
        r["nature"] = "secubox" if r.get("secubox") else nature(r, mots)
    retenus.sort(key=lambda r: list(NATURES).index(r["nature"]))
    retenus = retenus[:5]

    # Un objet SecuBox pointe vers une appli : son titre et son résumé SONT la page.
    async def lire(r):
        return f'{r["titre"]}. {r["extrait"]}' if r.get("secubox") else await lire_page(r["url"])
    pages = await asyncio.gather(*(lire(r) for r in retenus))
    lues = 0
    for r, page in zip(retenus, pages):
        # Page sur le sujet : entière. Simple mention ou réseau social : les seules phrases qui le citent.
        reseau = any(d in (urlsplit(r["url"]).hostname or "") for d in DOMAINES_RESEAUX)
        # Une page qui ne cite jamais le sujet n'a pas été lue, quelle que soit sa taille.
        cite = all(_plat(m) in _plat(page) for m in mots)
        utile = page if r.get("secubox") else passages(page, mots) if r["nature"] == "mention" or reseau else (page if cite else "")
        r["lue"] = len(utile) >= (40 if r["nature"] in ("mention", "secubox") or reseau else PAGE_LUE)
        r["page"] = utile if r["lue"] else ""
        lues += r["lue"]
        await dire(etape="page", titre=r["titre"], url=r["url"], caracteres=len(utile), lue=r["lue"], nature=NATURES[r["nature"]])
    sources.extend({k: r[k] for k in ("titre", "extrait", "url", "nature", "lue")} for r in retenus)
    # Rien de lu, et rien que des pages qui parlent d'autre chose : le modèle n'aurait que de quoi inventer.
    if not lues and all(r["nature"] == "mention" for r in retenus):
        sources.clear()
        return "vide", ""
    m = await moteurs.assurer_moteur()
    # Budget en vrais tokens : on rogne les pages jusqu'à laisser la place de la réponse.
    contexte = await moteurs.contexte_reel(m)
    disponible = contexte - prefs["generation"]["max_tokens"] - MARGE_TOKENS
    part = PAGE_MAX

    def transmis():
        return "<donnees>" + json.dumps([{**{k: v for k, v in r.items() if k not in ("lue", "page")}, "page": r["page"][:part]} for r in retenus], ensure_ascii=False) + "</donnees>"
    fixe = await moteurs.compter_tokens(prefs["comportement"]["consigne"] + consigne_sources("") + question, m)
    disponible = min(disponible, fixe + prefs["outils"].get("sources_max_jetons", 8000))
    tokens = await moteurs.compter_tokens(transmis(), m)
    for _ in range(6):
        if fixe + tokens <= disponible or part < 100:
            break
        part = int(part * disponible / (fixe + tokens) * 0.9)
        tokens = await moteurs.compter_tokens(transmis(), m)
    await dire(etape="budget", contexte=contexte, tokens_sources=tokens, tokens_consigne=fixe, disponible=disponible, part_par_page=part)
    return "ok", transmis()


LUCIDITES = [(100, "🧊 Strict"), (85, "🔎 Lucide"), (50, "⚖️ Équilibré"), (30, "🎨 Créatif"), (0, "🌀 Délire")]
LUCIDITE_DEFAUT = 85


def nom_lucidite(n):
    """Le réglage le plus proche, avec son emoji : c'est lui qu'on lit dans l'historique."""
    return min(LUCIDITES, key=lambda p: abs(p[0] - n))[1]


def regler_lucidite(valeur):
    """0 = délire assumé, 100 = lucide. Bornés, ces paramètres ne touchent ni au modèle ni à l'accès."""
    try:
        n = max(0, min(100, int(valeur)))
    except (TypeError, ValueError):
        n = LUCIDITE_DEFAUT
    return {"niveau": n, "temperature": round(0.1 + (100 - n) * 0.011, 2), "top_p": round(0.8 + (100 - n) * 0.002, 2),
            "mode": "lucide" if n >= 70 else "equilibre" if n >= 35 else "delire"}


def controler_reponse(texte, bloc):
    """Contrôle sans modèle : adresse absente des sources retirée, année absente signalée."""
    sources_plat = bloc.lower()
    retirees = []

    def filtre(m):
        url = m.group(0).rstrip(".,;:!?)]")
        hote = (urlsplit(url).hostname or "").removeprefix("www.").lower()
        if hote and hote in sources_plat:
            return m.group(0)
        retirees.append(url)
        return "[adresse non vérifiée retirée]"
    propre = re.sub(r"https?://[^\s)\]]+", filtre, texte)
    # Liens markdown et lignes de liste devenus vides : rien ne doit rester qui ressemble à une source.
    propre = re.sub(r"\[\[adresse non vérifiée retirée\]\]\(\[adresse non vérifiée retirée\]\)", "[adresse non vérifiée retirée]", propre)
    propre = "\n".join(ligne for ligne in propre.split("\n") if not re.fullmatch(r"\s*[*-]?\s*\[adresse non vérifiée retirée\]\s*", ligne))
    annees = sorted({a for a in re.findall(r"\b(1[0-9]{3}|20[0-9]{2})\b", propre) if a not in bloc})
    return propre, retirees, annees
