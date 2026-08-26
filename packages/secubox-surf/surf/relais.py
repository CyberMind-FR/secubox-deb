# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le cœur du relais MITM
CyberMind — https://cybermind.fr

CE FICHIER EST UN POC, ET C'EST UNE MESURE AVANT D'ÊTRE UN PRODUIT.

L'objectif du §0bis (WIP) : relayer un site EXTERNE à travers la box, en
origine isolée, pour lui retirer son traçage — anti-censure, blocage des
pisteurs, faux témoins rejoués pour que le service distant croie ses publicités
affichées. Trois transports d'égress : DIRECT (la box sort déjà), TOR (le
`.onion` et l'anti-censure), et — plus tard — l'encapsulation du torrent dans
le même tunnel.

Ce module fait DEUX choses, et sépare soigneusement l'une de l'autre :

  1. Il RÉÉCRIT ce qui est réécrivable — les URL absolues d'un HTML ou d'un CSS,
     l'en-tête `Location`, le domaine d'un `Set-Cookie`. C'est mécanique et sûr.

  2. Il RECENSE ce qui ne l'est PAS — un `fetch()` construit en JavaScript, un
     import dynamique, un service worker, une WebSocket, un sous-ressource à
     intégrité vérifiée. C'est là qu'un proxy de surf échoue, et le POC existe
     pour chiffrer cet échec plutôt que de le découvrir en production.

LE PIÈGE STRUCTURANT, écrit une fois pour toutes : une origine unique est un
contexte de sécurité unique. Acceptable pour NOS services (WEBOS-DESIGN §4bis),
DANGEREUX pour du surf arbitraire — une page de Facebook relayée sous l'origine
du Hall lirait le stockage de Nextcloud. D'où la règle non négociable :
UNE ORIGINE PAR SITE. `origine_de()` la fabrique ; rien dans ce module ne la
contourne.
"""

from __future__ import annotations

import re
import base64
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit, urljoin

# ── L'ORIGINE PAR SITE ──────────────────────────────────────────────────────
#
# Le certificat de la box est `*.gk2.secubox.in` : il ne couvre qu'UN label.
# `fb.surf.gk2.secubox.in` ne serait donc pas couvert. On aplatit l'hôte cible
# en un SEUL label — `surf-www-facebook-com` — qui tient sous le wildcard et
# donne malgré tout une origine distincte par site. Isolation satisfaite sans
# nouveau certificat.
#
# L'aplatissement est RÉVERSIBLE et ne perd rien : le point devient `-`, le `-`
# d'origine est doublé, de sorte que `a-b.c` et `a.b-c` ne se confondent pas.

SUFFIXE = "gk2.secubox.in"
PREFIXE = "surf"


def origine_de(hote_cible: str) -> str:
    """`www.facebook.com` → `surf-www--facebook--com.gk2.secubox.in`."""
    plat = hote_cible.strip().lower().replace("-", "--").replace(".", "-")
    return f"{PREFIXE}-{plat}.{SUFFIXE}"


def cible_de(origine: str) -> str | None:
    """L'inverse : de l'origine du proxy, retrouver l'hôte réel."""
    h = origine.strip().lower()
    if not h.endswith("." + SUFFIXE):
        return None
    label = h[: -(len(SUFFIXE) + 1)]
    if not label.startswith(PREFIXE + "-"):
        return None
    plat = label[len(PREFIXE) + 1:]
    # On défait dans l'ordre inverse : d'abord les `--` en sentinelle, sinon un
    # `-` simple issu d'un point serait pris pour la moitié d'un `--`.
    jeton = "\x00"
    return plat.replace("--", jeton).replace("-", ".").replace(jeton, "-")


# ── LES PISTEURS — LA VRAIE RAISON D'ÊTRE ───────────────────────────────────
#
# Bloquer, ce n'est pas cloisonner (la distinction du 26/08). Cloisonner isole
# un témoin nécessaire dans son contexte ; bloquer SUPPRIME une requête qui
# n'existe que pour suivre. Ici on bloque — cette liste est ce dont on ne veut
# À AUCUN prix, même relayé.
PISTEURS = frozenset({
    # Regie et social
    "connect.facebook.net", "graph.facebook.com", "pixel.facebook.com",
    "an.facebook.com", "analytics.facebook.com", "analytics.twitter.com",
    "ads-twitter.com", "static.ads-twitter.com", "t.co", "analytics.tiktok.com",
    "ads.tiktok.com", "business-api.tiktok.com", "px.ads.linkedin.com",
    "snap.licdn.com", "ads.pinterest.com", "ct.pinterest.com",
    # Google
    "google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
    "googletagmanager.com", "www.googletagmanager.com", "googletagservices.com",
    "googlesyndication.com", "pagead2.googlesyndication.com", "adservice.google.com",
    "doubleclick.net", "stats.g.doubleclick.net", "googleadservices.com",
    "google-analytics.com", "region1.google-analytics.com", "analytics.google.com",
    # Regies pub
    "adnxs.com", "ib.adnxs.com", "criteo.com", "static.criteo.net", "criteo.net",
    "taboola.com", "cdn.taboola.com", "outbrain.com", "widgets.outbrain.com",
    "amazon-adsystem.com", "rubiconproject.com", "pubmatic.com", "openx.net",
    "casalemedia.com", "adform.net", "smartadserver.com", "yieldmo.com",
    "moatads.com", "adsafeprotected.com", "3lift.com", "bidswitch.net",
    "sharethrough.com", "teads.tv", "media.net", "contextweb.com",
    # Mesure / analytics
    "scorecardresearch.com", "sb.scorecardresearch.com", "quantserve.com",
    "quantcount.com", "hotjar.com", "static.hotjar.com", "amplitude.com",
    "api.amplitude.com", "segment.io", "cdn.segment.com", "segment.com",
    "sentry.io", "browser.sentry-cdn.com", "mixpanel.com", "api.mixpanel.com",
    "fullstory.com", "mouseflow.com", "clarity.ms", "chartbeat.com",
    "static.chartbeat.com", "newrelic.com", "bam.nr-data.net", "nr-data.net",
    "branch.io", "app.link", "bugsnag.com", "cdn.optimizely.com", "optimizely.com",
    "krxd.net", "demdex.net", "everesttech.net", "adobedtm.com", "omtrdc.net",
    "bounceexchange.com", "onesignal.com", "cdn.onesignal.com", "onaudience.com",
    "yandex.ru", "mc.yandex.ru", "matomo.cloud", "cookielaw.org", "onetrust.com",
    "cdn.cookielaw.org", "consensu.org", "usercentrics.eu", "app.usercentrics.eu",
})

# DETECTION PAR MOTIF, en plus de la liste (#1340). « Attraper TOUS les
# pisteurs » ne tient pas dans une liste : il en nait chaque jour. On coupe
# donc aussi ce dont le nom d'hote trahit la fonction. Prudence : uniquement
# des segments qui ne servent qu'au pistage ou a la pub, jamais un mot ambigu.
_MOTIFS_PISTEURS = (
    "doubleclick", "googlesyndication", "googleadservices", "adservice",
    "adnxs", "adsystem", "adsrvr", "adroll", "adform", "advertising",
    "analytics", "telemetry", "tracking", "trkn", "metrics", "moatads",
    "scorecardresearch", "quantserve", "taboola", "outbrain", "criteo",
    "pubmatic", "rubiconproject", "openx", "smartadserver", "yieldmo",
    "bidswitch", "sharethrough", "adsafeprotected", "demdex", "omtrdc",
)


# LABELS QUI, A EUX SEULS, DISENT LE PISTAGE. Un label DNS entier valant « ads »
# ou « pixel » n'est jamais du contenu — c'est le sous-domaine de regie ou de
# mesure. Match EXACT du label, donc « lespads.fr » n'est pas touche.
_LABELS_PISTEURS = frozenset({
    "ads", "ad", "adserver", "adservers", "ADS", "pixel", "pixels", "beacon",
    "beacons", "track", "tracker", "trackers", "tracking", "telemetry",
    "metrics", "metric", "collect", "collector", "stats", "stat", "analytics",
    "analytic", "log", "logs", "logger", "event", "events", "measure",
})


def est_pisteur(hote: str) -> bool:
    h = (hote or "").lower()
    if any(h == p or h.endswith("." + p) for p in PISTEURS):
        return True
    labels = h.split(".")
    # 1. Un label ENTIER qui trahit la fonction (match exact, sans risque).
    if any(lab in _LABELS_PISTEURS for lab in labels):
        return True
    # 2. Un motif long DANS un label : « doubleclick.net », « criteo.com ».
    for m in _MOTIFS_PISTEURS:
        for lab in labels:
            if lab == m or lab.startswith(m) or lab.endswith(m):
                return True
    return False


# ── LE RECENSEMENT DES CASSES ───────────────────────────────────────────────

@dataclass
class Casse:
    """Une chose qu'on n'a pas su relayer, et pourquoi elle compte."""
    genre: str          # 'js-fetch', 'service-worker', 'websocket', 'sri'…
    gravite: str        # 'bloquant' | 'degrade' | 'note'
    detail: str
    echantillon: str = ""


@dataclass
class Rapport:
    cible: str
    egress: str
    statut: int = 0
    type_contenu: str = ""
    reecrit: int = 0            # nombre d'URL réécrites avec succès
    casses: list[Casse] = field(default_factory=list)

    def note(self, genre, gravite, detail, echantillon=""):
        self.casses.append(Casse(genre, gravite, detail, echantillon[:200]))

    @property
    def verdict(self) -> str:
        if any(c.gravite == "bloquant" for c in self.casses):
            return "MUR — le site ne fonctionnera pas relayé tel quel"
        if any(c.gravite == "degrade" for c in self.casses):
            return "DÉGRADÉ — s'affiche, fonctionne en partie"
        return "PASSABLE — à confirmer à l'usage"


# ── LA RÉÉCRITURE DE CE QUI SE LAISSE RÉÉCRIRE ──────────────────────────────

# Attributs d'URL dans le HTML. `srcset` est traité à part (liste).
_ATTRS = ("href", "src", "action", "poster", "data-src", "data-href", "formaction")
_RE_ATTR = re.compile(
    r'(?P<a>%s)\s*=\s*(?P<q>["\'])(?P<v>[^"\']*)(?P=q)' % "|".join(_ATTRS),
    re.IGNORECASE)
_RE_SRCSET = re.compile(r'srcset\s*=\s*(["\'])(.*?)\1', re.IGNORECASE | re.DOTALL)
_RE_CSS_URL = re.compile(r'url\(\s*(["\']?)([^"\')]+)\1\s*\)', re.IGNORECASE)
_RE_INTEGRITY = re.compile(r'\s+integrity\s*=\s*(["\']).*?\1', re.IGNORECASE)
_RE_META_REFRESH = re.compile(r'<meta[^>]*http-equiv\s*=\s*["\']?refresh[^>]*>', re.IGNORECASE)

# Signaux qu'on ne peut PAS suivre statiquement — le nerf du POC.
_RE_JS_FETCH = re.compile(r'\bfetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_JS_XHR = re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)', re.IGNORECASE)
_RE_JS_IMPORT = re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_WS = re.compile(r'\bnew\s+WebSocket\s*\(\s*["\']([^"\']+)', re.IGNORECASE)
_RE_SW = re.compile(r'serviceWorker\s*\.\s*register\s*\(\s*["\']([^"\']+)', re.IGNORECASE)
_RE_WORKER = re.compile(r'\bnew\s+(?:Shared)?Worker\s*\(\s*["\']([^"\']+)', re.IGNORECASE)


def _map_url(u: str, base: str, sur_hote) -> tuple[str, bool]:
    """Réécrit UNE URL vers l'origine proxy. Rend (url, a_change).

    `sur_hote(hote)` est appelé pour chaque hôte tiers rencontré : il décide de
    l'origine à lui donner (une par site) et signale les pisteurs.
    """
    u = u.strip()
    if not u or u.startswith(("#", "data:", "blob:", "javascript:", "mailto:", "tel:", "about:")):
        return u, False
    absolu = urljoin(base, u)
    p = urlsplit(absolu)
    if p.scheme not in ("http", "https", ""):
        return u, False
    if not p.hostname:
        return u, False
    nouvelle_origine = sur_hote(p.hostname)
    if not nouvelle_origine:
        return u, False   # pisteur : on laisse tel quel, un filtre amont le coupe
    # Toujours https vers la box ; le chemin et la requête sont conservés.
    return urlunsplit(("https", nouvelle_origine, p.path, p.query, p.fragment)), True


# ── INJECTION COSMETIQUE + CONSENTEMENT (#1340) ─────────────────────────────
#
# Le relais coupe les pisteurs A LA SOURCE (ils ne se chargent pas). Mais deux
# choses restent DANS la page servie : les bannieres de cookies et les blocs de
# pub deja presents dans le HTML. On les traite en injectant, sous NOTRE origine
# (la page est deja la notre), une feuille qui les masque et un script qui pose
# les temoins de consentement courants et clique les « accepter » evidents.
#
# C'est du COSMETIQUE assume : on ne pretend pas defaire tous les bandeaux du
# web, on retire les plus repandus. Ce qui resiste, resiste.
_INJECTION = """
<style id="sbx-surf">
[id*="onetrust" i],[class*="onetrust" i],[class*="cookie-consent" i],
[id*="cookie-consent" i],[class*="cookie-banner" i],[id*="cookie-banner" i],
[class*="cookieBanner" i],[class*="cmp-" i],[id*="sp_message_container" i],
[class*="qc-cmp" i],[class*="fc-consent" i],[class*="gdpr" i],[id*="gdpr" i],
[class*="consent" i][class*="banner" i],[aria-label*="cookie" i][role="dialog"],
[class*="didomi" i],[id*="didomi" i],[class*="axeptio" i],[id*="tarteaucitron" i],
ins.adsbygoogle,[id^="google_ads_"],[class*="advert" i],[class*="-ads" i],
[class*="ad-slot" i],[class*="ad-container" i],[class*="ad-banner" i],
[class*="sticky" i][class*="ad" i],[class*="floating" i][class*="video" i],
[class*="pip" i][class*="player" i],[class*="outbrain" i],[class*="taboola" i],
[class*="sponsored" i][class*="widget" i]{
  display:none !important;visibility:hidden !important;height:0 !important;
}
html,body{overflow:auto !important}
</style>
<script id="sbx-surf-js">
(function(){
  try{
    var t={CookieConsent:"yes",cookieconsent_status:"dismiss",euconsent:"1",
      "euconsent-v2":"1",OptanonAlertBoxClosed:new Date().toISOString(),
      gdpr:"1",cookies_accepted:"1",cookie_notice_accepted:"true",
      didomi_token:"accepted",axeptio_all_vendors:"true"};
    for(var k in t){document.cookie=k+"="+t[k]+";path=/;max-age=31536000";}
  }catch(e){}
  var ACC=/^(tout accepter|accepter( \\&|( et)? fermer)?|j'accepte( tout)?|accept all|accept|i agree|agree|ok,? tout accepter|continuer sans accepter|got it|allow all|autoriser|d'accord|accepter tout)$/i;
  function pass(){
    try{
      document.querySelectorAll("button,a,[role=button],input[type=button],input[type=submit]").forEach(function(b){
        var x=(b.textContent||b.value||"").trim();
        if(x&&ACC.test(x)){try{b.click();}catch(e){}}
      });
      document.documentElement.style.overflow="auto";
      if(document.body)document.body.style.overflow="auto";
    }catch(e){}
  }
  // CONTRE-DETECTION D'ANTI-ADBLOCK (#1342). Certains sites, ne voyant plus
  // leurs pubs, dressent un mur « desactivez votre bloqueur ». On fait DEUX
  // choses : on retire ces murs, et on LEURRE le detecteur — beaucoup testent
  // si un element d'appat (classe « ad », « adsbox ») a ete masque ; on en
  // laisse un, mesurable, pour qu'il se croie non bloque.
  function antiMur(){
    try{
      // Appat que les detecteurs mesurent : visible, hors ecran, jamais masque
      // par nos regles (id explicite, pas de classe « ad »).
      if(!document.getElementById("sbx-bait")){
        var b=document.createElement("div");
        b.id="sbx-bait"; b.className="adsbox ad-placement pub_300x250";
        b.style.cssText="position:absolute;left:-9999px;top:-9999px;width:300px;height:250px";
        b.innerHTML="&nbsp;"; (document.body||document.documentElement).appendChild(b);
      }
      // Murs courants : on les retire et on rend la lecture.
      var murs=document.querySelectorAll(
        "[class*=adblock i],[id*=adblock i],[class*=adBlock],[id*=adBlock],"
        +"[class*=antiadblock i],[id*=antiadblock i],[class*=abd i][class*=overlay i],"
        +"[class*=blocker i][class*=modal i]");
      murs.forEach(function(m){ try{ m.remove(); }catch(e){} });
    }catch(e){}
  }
  if(document.readyState!=="loading")pass();
  document.addEventListener("DOMContentLoaded",pass);
  document.addEventListener("DOMContentLoaded",antiMur);
  var n=0,iv=setInterval(function(){pass();antiMur();if(++n>10)clearInterval(iv);},600);
  // ON ANNONCE LA NAVIGATION au cadre parent (la carte Surf) : un lien suivi
  // DANS la page relayee navigue l'iframe sans que la carte le sache. Grace a
  // ceci, « precedent » recule aussi sur les liens internes, pas seulement sur
  // les adresses tapees.
  try{ if(parent!==window) parent.postMessage({sbx:"surf-nav",href:location.href}, "*"); }catch(e){}
})();
</script>
"""


def _injecte(corps: str) -> str:
    """Insere l'injection avant </body> (ou en fin si absent)."""
    i = corps.lower().rfind("</body>")
    if i >= 0:
        return corps[:i] + _INJECTION + corps[i:]
    return corps + _INJECTION


def reecris_html(corps: str, base: str, rap: Rapport, sur_hote) -> str:
    """Réécrit les URL d'un HTML et RECENSE ce qu'il n'a pas su suivre."""
    # 1. Ce qui se réécrit : attributs, srcset, url() inline.
    def _attr(m):
        v, ch = _map_url(m.group("v"), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return f'{m.group("a")}={m.group("q")}{v}{m.group("q")}'
    corps = _RE_ATTR.sub(_attr, corps)

    def _srcset(m):
        parts = []
        for bout in m.group(2).split(","):
            bout = bout.strip()
            if not bout:
                continue
            morceaux = bout.split(None, 1)
            v, ch = _map_url(morceaux[0], base, sur_hote)
            if ch:
                rap.reecrit += 1
            parts.append(v + (" " + morceaux[1] if len(morceaux) > 1 else ""))
        return 'srcset="%s"' % ", ".join(parts)
    corps = _RE_SRCSET.sub(_srcset, corps)

    def _css(m):
        v, ch = _map_url(m.group(2), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return "url(%s%s%s)" % (m.group(1), v, m.group(1))
    corps = _RE_CSS_URL.sub(_css, corps)

    # 2. RÉÉCRIRE LE CORPS CASSE L'INTÉGRITÉ DES SOUS-RESSOURCES. Un attribut
    #    `integrity=` compare un hash ; nos réécritures le font échouer, et le
    #    navigateur REFUSE alors la ressource. On doit le retirer — ce qui
    #    signifie qu'on renonce à la garantie qu'il offrait. À noter, pas à
    #    cacher.
    n_sri = len(_RE_INTEGRITY.findall(corps))
    if n_sri:
        corps = _RE_INTEGRITY.sub("", corps)
        rap.note("sri", "note",
                 "%d sous-ressources à intégrité vérifiée : attribut retiré "
                 "(sinon le navigateur les refuse une fois le corps réécrit). "
                 "On perd la garantie d'intégrité qu'elles portaient." % n_sri)

    # META-REFRESH NEUTRALISE (#1344). Dans un cadre, il redirige la page
    # relayee — souvent vers un mur de consentement ou une version « app » —
    # et l'embarquement casse. On le retire : le lecteur reste ou il est.
    n_ref = len(_RE_META_REFRESH.findall(corps))
    if n_ref:
        corps = _RE_META_REFRESH.sub('', corps)
        rap.note("meta-refresh", "note",
                 "%d redirection(s) meta-refresh retiree(s) : elles emmenaient "
                 "le cadre ailleurs (consentement, version app)." % n_ref)

    # 3. Ce qu'on ne peut PAS suivre. On ne modifie rien — on compte.
    _recense_js(corps, rap, ou="html-inline")
    return _injecte(corps)


def _recense_js(texte: str, rap: Rapport, ou: str):
    """Le cœur de la mesure : ce que la réécriture statique ne peut atteindre."""
    fetches = _RE_JS_FETCH.findall(texte) + _RE_JS_XHR.findall(texte)
    # Seuls les chemins RELATIFS ou ABSOLUS comptent : `fetch(variable)` nous
    # échappe déjà (aucune chaîne à trouver), et c'est le cas le plus fréquent.
    concrets = [u for u in fetches if u.startswith(("/", "http"))]
    if concrets:
        rap.note("js-fetch", "bloquant",
                 "%d appels réseau en dur dans le JS (%s) : ils visent l'origine "
                 "réelle, pas le proxy, et aucune réécriture statique ne les "
                 "détourne. Un `fetch(url)` où `url` est calculée échappe même "
                 "au comptage." % (len(concrets), ou),
                 " · ".join(concrets[:3]))
    imp = _RE_JS_IMPORT.findall(texte)
    if imp:
        rap.note("js-import", "bloquant",
                 "%d imports dynamiques : chargés à l'exécution vers l'origine "
                 "réelle, hors de portée d'une réécriture du HTML." % len(imp),
                 " · ".join(imp[:3]))
    ws = _RE_WS.findall(texte)
    if ws:
        rap.note("websocket", "bloquant",
                 "%d WebSocket : le temps réel (fil, présence, notifications) "
                 "ouvre vers l'origine réelle. À relayer, il faut un proxy WS "
                 "dédié, origine par origine." % len(ws),
                 " · ".join(ws[:3]))
    sw = _RE_SW.findall(texte)
    if sw:
        rap.note("service-worker", "bloquant",
                 "%d service worker : il s'installe sur NOTRE origine et y "
                 "intercepte TOUT le réseau ensuite — y compris ce qu'on croyait "
                 "maîtriser. À neutraliser explicitement, jamais à laisser "
                 "passer." % len(sw),
                 " · ".join(sw[:3]))
    wk = _RE_WORKER.findall(texte)
    if wk:
        rap.note("worker", "degrade",
                 "%d web worker : script chargé à part, à réécrire aussi sinon "
                 "il sort du cadre." % len(wk), " · ".join(wk[:3]))


def reecris_css(corps: str, base: str, rap: Rapport, sur_hote) -> str:
    def _css(m):
        v, ch = _map_url(m.group(2), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return "url(%s%s%s)" % (m.group(1), v, m.group(1))
    return _RE_CSS_URL.sub(_css, corps)


# ── LES EN-TÊTES ────────────────────────────────────────────────────────────

def reecris_entetes(entetes: dict, base: str, rap: Rapport, sur_hote) -> dict:
    """Réécrit ou retire les en-têtes qui trahiraient l'origine réelle."""
    out = {}
    for cle, val in entetes.items():
        bas = cle.lower()

        if bas == "location":
            v, _ = _map_url(val, base, sur_hote)
            out[cle] = v
            continue

        if bas == "set-cookie":
            # Le témoin doit être posé sur NOTRE origine, pas sur `.facebook.com`
            # (qui ne serait jamais renvoyé). On retire `Domain`, et `Secure`
            # reste — on est en https.
            v = re.sub(r';\s*[Dd]omain=[^;]+', '', val)
            out[cle] = v
            rap.note("set-cookie", "note",
                     "témoin réécrit : `Domain` retiré pour qu'il tienne sur "
                     "l'origine proxy. C'est ici que se brancherait le rejeu de "
                     "session (le « catcher »).")
            continue

        if bas == "content-security-policy":
            # La CSP du site nomme SES origines ; sous la nôtre, elle bloque
            # tout. On la retire pour le POC, en notant ce qu'elle exigeait —
            # une vraie version la RÉÉCRIRAIT origine par origine.
            rap.note("csp", "degrade",
                     "CSP du site retirée pour le POC. Elle listait ses propres "
                     "origines et aurait tout bloqué sous la nôtre ; la réécrire "
                     "proprement est un chantier à part.", val)
            continue

        if bas in ("x-frame-options", "content-security-policy-report-only",
                   "cross-origin-opener-policy", "cross-origin-embedder-policy",
                   "strict-transport-security"):
            # Retirés : ils empêchent l'encadrement ou imposent des règles
            # d'isolation incompatibles avec le relais.
            continue

        if bas in ("content-length", "content-encoding", "transfer-encoding",
                   "connection"):
            continue  # recalculés par le serveur du proxy

        out[cle] = val
    return out
