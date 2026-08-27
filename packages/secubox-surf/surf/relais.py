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
    # Portails de consentement / ID (redirigent la page, portent l'URL de retour)
    "first-id.fr", "gate.first-id.fr", "id5-sync.com", "liveintent.com",
    "sharedid.org", "pripsum.com", "consentframework.com", "sourcepoint.com",
    "privacy-mgmt.com", "faktor.io", "trustarc.com", "sddan.com",
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
# UNIQUEMENT DES LABELS SANS AMBIGUITE (#1353). La premiere version incluait
# « ad », « log », « event(s) », « stat(s) », « measure », « collect » : ce sont
# des sous-domaines COURANTS de sites legitimes (journal d'evenements live,
# API de mesure interne, endpoint de log applicatif). Les couper cassait BFM,
# franceinfo et consorts — leurs briques essentielles tombaient a 204. On ne
# garde que ce qui NE sert qu'a pister ou a la pub.
_LABELS_PISTEURS = frozenset({
    "ads", "adserver", "adservers", "adsystem", "pixel", "pixels",
    "beacon", "beacons", "tracker", "trackers", "tracking", "telemetry",
    "analytics", "doubleclick",
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
[class*="pip" i][class*="player" i],
/* TABOOLA / OUTBRAIN — conteneurs entiers, par leur reseau (#1363). Le script
   est deja coupe a la source, mais le conteneur vide garde son bandeau
   « Taboola Feed », obscene. Aucun contenu legitime ne porte ces classes. */
[id*="taboola" i],[class*="taboola" i],[id^="trc_" i],[class*="trc_" i],
[class*="trc-" i],[id*="outbrain" i],[class*="outbrain" i],[class*="ob-widget" i],
[class*="ob_" i],[class*="OUTBRAIN" i],[data-widget*="taboola" i],
[class*="sponsored" i][class*="widget" i]{
  display:none !important;visibility:hidden !important;height:0 !important;
}
html,body{overflow:auto !important}
</style>
<script id="sbx-surf-js">
(function(){
  // window.open est deja neutralise en tete (avant les scripts du site).
  // Ici on rattrape juste les liens qui tenteraient une popup.
  document.addEventListener("click",function(ev){
    var a=ev.target&&ev.target.closest&&ev.target.closest("a[target=_blank]");
    if(a){ a.setAttribute("target","_self"); }   // le lien reste dans le cadre
  },true);
  try{
    var t={CookieConsent:"yes",cookieconsent_status:"dismiss",euconsent:"1",
      "euconsent-v2":"1",OptanonAlertBoxClosed:new Date().toISOString(),
      gdpr:"1",cookies_accepted:"1",cookie_notice_accepted:"true",
      didomi_token:"accepted",axeptio_all_vendors:"true"};
    for(var k in t){document.cookie=k+"="+t[k]+";path=/;max-age=31536000";}
  }catch(e){}
  var ACC=/^(tout accepter|accepter( \\&|( et)? fermer)?|j'accepte( tout)?|accept all|accept|i agree|agree|ok,? tout accepter|continuer sans accepter|got it|allow all|autoriser|d'accord|accepter tout)$/i;
  // ACCEPTER VIA L'API DU CMP LUI-MEME (#1367). On ne peut pas apprendre le
  // cookie d'un portail que la box bloque (catch-22). Mais le CMP charge dans
  // la page (Didomi, TCF) et EXPOSE une API pour tout accepter : on l'appelle.
  // C'est le consentement donne « proprement », sans flux first-id ni cookie
  // valide a fabriquer.
  function cmp(){
    try{
      if(window.Didomi && typeof Didomi.setUserAgreeToAll==="function"){
        try{ Didomi.setUserAgreeToAll(); }catch(e){}
      }
      // TCF v2 : agreer a tout ce que le CMP propose, s'il expose l'API.
      if(typeof window.__tcfapi==="function"){
        try{ __tcfapi("getTCData",2,function(d,ok){
          if(ok && d && window.__cmp){ try{ __cmp("setConsentAll"); }catch(e){} }
        }); }catch(e){}
      }
      // Sourcepoint / autres : bouton « accepter » deja clique par tiers().
      if(window.__cmp && typeof __cmp==="function"){ try{ __cmp("acceptAll"); }catch(e){} }
    }catch(e){}
  }
  function pass(){
    try{
      cmp();
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
      // Murs par classe/id.
      var murs=document.querySelectorAll(
        "[class*=adblock i],[id*=adblock i],[class*=adBlock],[id*=adBlock],"
        +"[class*=antiadblock i],[id*=antiadblock i],[class*=abd i][class*=overlay i],"
        +"[class*=blocker i][class*=modal i]");
      murs.forEach(function(m){ try{ m.remove(); }catch(e){} });

      // MUR ANTI-ADBLOCK, ET RIEN D'AUTRE (#1355). ATTENTION : on n'agit QUE
      // sur un overlay qui parle EXPLICITEMENT de bloqueur/whitelist. Avant, on
      // cliquait GLOBALEMENT tout bouton « OK / Continuer / Lire / Fermer » de
      // la page — sur une page normale, ca la faisait naviguer au hasard :
      // « plus rien ne surf ». On ne touche donc qu'un mur avere.
      var MURTXT=/bloqueur\s*de\s*pub|adblock|ad.?block\b|publicit.{0,25}(detect|desactiv)|desactiv.{0,25}bloqueur|liste\s*blanche|whitelist/i;
      var cand=document.querySelectorAll("div,section,aside,dialog");
      for(var mi=0; mi<cand.length; mi++){
        var el=cand[mi];
        if(el.dataset && el.dataset.sbxMur) continue;
        var txt=(el.textContent||"");
        if(txt.length>1400 || !MURTXT.test(txt)) continue;
        var cs; try{ cs=getComputedStyle(el); }catch(e){ continue; }
        if(cs.position!=="fixed" && cs.position!=="sticky") continue;
        var r=el.getBoundingClientRect();
        if(r.width < innerWidth*0.6 || r.height < innerHeight*0.4) continue;
        if(el.dataset) el.dataset.sbxMur="1";
        var boutons=el.querySelectorAll("button,a,[role=button]"), clique=false;
        for(var bi=0; bi<boutons.length; bi++){
          var bt=(boutons[bi].textContent||"").trim();
          if(bt && bt.length<40 && /whitelist|liste\s*blanche|continuer|lire|okay|fermer|j.ai\s*compris|poursuivre/i.test(bt)){
            try{ boutons[bi].click(); clique=true; break; }catch(e){}
          }
        }
        if(!clique){ try{ el.remove(); }catch(e){} }
      }
      document.documentElement.style.overflow="auto";
      if(document.body) document.body.style.overflow="auto";
    }catch(e){}
  }
  // PLACEHOLDERS « CONTENUS TIERS » (#1346). Beaucoup de sites FR remplacent un
  // embed (video, tweet...) par un pave « nous avons bloque l'affichage de ce
  // contenu, acceptez la categorie Contenus tiers ». On CLIQUE son bouton
  // d'acceptation ; a defaut, on CACHE le pave — il ne dit rien qu'on veuille
  // lire, et il coupe le fil de lecture.
  function tiers(){
    try{
      var MARK=/contenus?\\s+tiers|d.p.t\\s+de\\s+cookies|bloqu.\\s+l.affichage|accepter\\s+la\\s+cat.gorie|third.party\\s+content|autoriser\\s+ce\\s+contenu|afficher\\s+ce\\s+contenu/i;
      var BTN=/(accepter|autoriser|afficher|voir\\s+ce\\s+contenu|j.accepte|activer|cliquez\\s+ici)/i;
      var vus=document.querySelectorAll("div,section,aside,figure,p,span");
      for(var i=0;i<vus.length;i++){
        var el=vus[i];
        if(el.dataset&&el.dataset.sbxTiers) continue;
        if(el.children.length>8) continue;
        var t=(el.textContent||"").trim();
        if(t.length<20 || t.length>600 || !MARK.test(t)) continue;
        el.dataset&&(el.dataset.sbxTiers="1");
        var b=el.querySelector("button,a,[role=button],input[type=button],input[type=submit]");
        var ok=false;
        if(b){ var bt=(b.textContent||b.value||"").trim(); if(BTN.test(bt)){ try{b.click();ok=true;}catch(e){} } }
        if(!ok){ try{ el.style.display="none"; }catch(e){} }
      }
    }catch(e){}
  }
  // CONTENUS « SPONSORISE » (#1348). Les recommandations natives (Taboola,
  // Outbrain et consorts) ne sont pas des <iframe> qu'on coupe a la source :
  // ce sont des blocs INJECTES dans la page, etiquetes « Sponsorise ». On
  // remonte du libelle a son item et on le cache. Prudence : seulement les
  // libelles COURTS et EXPLICITES, pour ne pas emporter un vrai article.
  function pub(){
    try{
      var ET=/^\s*(sponsoris|sponsored|publicité|contenu sponsoris|annonce publicitaire|paid partnership)\s*$/i;
      var noeuds=document.querySelectorAll("span,small,a,em,i,div,li");
      for(var k=0;k<noeuds.length;k++){
        var el=noeuds[k];
        if(el.dataset&&el.dataset.sbxPub) continue;
        var t=(el.textContent||"").trim();
        if(t.length>26 || !ET.test(t)) continue;
        // On ne touche qu'un conteneur EXPLICITEMENT publicitaire — jamais un
        // <article> ou un <li> de contenu, sous peine de vider la page.
        var cible=el.closest&&el.closest("[class*=sponsor i],[class*=advert i],[class*=publicite i],[class*=-ad i],[class*=ad- i],[id*=sponsor i],[class*=outbrain i],[class*=taboola i]");
        cible=cible||el;   // a defaut, on cache le seul libelle
        if(cible.dataset) cible.dataset.sbxPub="1";
        try{ cible.style.display="none"; }catch(e){}
      }
    }catch(e){}
  }
  if(document.readyState!=="loading")pass();
  document.addEventListener("DOMContentLoaded",pass);
  document.addEventListener("DOMContentLoaded",antiMur);
  document.addEventListener("DOMContentLoaded",tiers);
  document.addEventListener("DOMContentLoaded",pub);
  // TRACKERS REFERENCES dans la page : on compte les hotes de pistage cites
  // par les ressources (scripts/img/iframes). Reel, mesure sur le DOM.
  var TRK=/(doubleclick|googlesyndication|google-analytics|googletagmanager|adservice|adnxs|criteo|taboola|outbrain|scorecardresearch|quantserve|pubmatic|rubicon|analytics|tracking|telemetry|hotjar|amplitude|segment|\.ads?\.|adservers?)/i;
  function scanTrackers(){
    try{
      var S=window.__sbx; if(!S) return;
      var r=document.querySelectorAll("script[src],img[src],iframe[src],link[href]");
      S.total=r.length; var t=0;
      for(var i=0;i<r.length;i++){ var u=r[i].src||r[i].href||""; if(TRK.test(u)) t++; }
      S.trackers=t;
    }catch(e){}
  }
  // On expose les comptes de pub/tiers via des marqueurs dataset deja poses.
  function compteMasques(){
    try{
      var S=window.__sbx; if(!S) return;
      S.pubs=document.querySelectorAll("[data-sbx-pub]").length;
      S.tiers=document.querySelectorAll("[data-sbx-tiers]").length;
    }catch(e){}
  }
  function rapporte(){
    scanTrackers(); compteMasques();
    try{ if(parent!==window) parent.postMessage({sbx:"surf-stats", stats:window.__sbx}, "*"); }catch(e){}
  }
  var n=0,iv=setInterval(function(){pass();antiMur();tiers();pub();rapporte();if(++n>14)clearInterval(iv);},600);
  // Un dernier rapport plus tard, quand la page a fini de charger ses pubs.
  setTimeout(rapporte, 4000); setTimeout(rapporte, 9000);
  // ON ANNONCE LA NAVIGATION au cadre parent (la carte Surf) : un lien suivi
  // DANS la page relayee navigue l'iframe sans que la carte le sache. Grace a
  // ceci, « precedent » recule aussi sur les liens internes, pas seulement sur
  // les adresses tapees.
  try{ if(parent!==window) parent.postMessage({sbx:"surf-nav",href:location.href}, "*"); }catch(e){}
})();
</script>
"""


# INJECTION DE TETE (#1345) — posee au tout debut de <head>, avant les scripts
# du site. Certaines protections (DataDome, etc.) posent leur cookie en JS avec
# `domain=.site.fr` : sur NOTRE origine ce domaine est etranger, le navigateur
# REFUSE le cookie, la verification ne « prend » jamais et la page BOUCLE
# (« verification reussie » puis recommence). On reecrit donc les ecritures de
# cookie pour retirer `domain=`, exactement comme on le fait cote serveur sur
# Set-Cookie. C'est ce qui casse la boucle.
_INJECTION_TETE = """
<script id="sbx-surf-tete">
(function(){
  // COMPTEURS DE CAMOUFLAGE (#1351) : ce que le relais a coupe ou masque, pour
  // l'afficher dans la barre. Reels, pas decoratifs.
  window.__sbx={cookies:0,popups:0,notifs:0,pubs:0,tiers:0,trackers:0,total:0};
  var S=window.__sbx;

  // JARRE D'ETAT (#1235). Le storage (localStorage/sessionStorage) est cloisonne
  // par origine surf ET partitionne en contexte tiers : la session posee a la
  // vraie origine n'y est pas, et ce qu'on ecrit ne survit pas. On le retient
  // CÔTÉ RELAIS, par hote (pendant du bocal a cookies). Le serveur a injecte
  // l'etat connu dans window.__sbx_etat (juste au-dessus) ; on le REPOSE ici,
  // AVANT les scripts du site, puis on CAPTURE les mutations vers le serveur.
  try{
    var _E = window.__sbx_etat || {};
    function _pose(aire, kv){
      if(!kv) return;
      for(var k in kv){ if(Object.prototype.hasOwnProperty.call(kv,k)){
        try{ aire.setItem(k, kv[k]); }catch(e){} } }
    }
    try{ _pose(window.localStorage, _E.local); }catch(e){}
    try{ _pose(window.sessionStorage, _E.session); }catch(e){}

    function _snapshot(){
      try{
        var loc={}, ses={}, i, k;
        try{ for(i=0;i<localStorage.length;i++){ k=localStorage.key(i); loc[k]=localStorage.getItem(k); } }catch(e){}
        try{ for(i=0;i<sessionStorage.length;i++){ k=sessionStorage.key(i); ses[k]=sessionStorage.getItem(k); } }catch(e){}
        var body=JSON.stringify({local:loc, session:ses});
        if(navigator.sendBeacon){ navigator.sendBeacon("/_sbx/etat", new Blob([body],{type:"application/json"})); }
        else{ fetch("/_sbx/etat",{method:"POST",body:body,headers:{"Content-Type":"application/json"},keepalive:true,credentials:"same-origin"}); }
      }catch(e){}
    }
    var _tS=0;
    function _planifie(){ try{ clearTimeout(_tS); }catch(e){} _tS=setTimeout(_snapshot, 1500); }
    try{
      var _SP=Storage.prototype, _si=_SP.setItem, _ri=_SP.removeItem, _cl=_SP.clear;
      _SP.setItem=function(){ var r=_si.apply(this,arguments); _planifie(); return r; };
      _SP.removeItem=function(){ var r=_ri.apply(this,arguments); _planifie(); return r; };
      _SP.clear=function(){ var r=_cl.apply(this,arguments); _planifie(); return r; };
    }catch(e){}
    try{
      addEventListener("pagehide", _snapshot, true);
      addEventListener("visibilitychange", function(){ if(document.visibilityState==="hidden") _snapshot(); }, true);
    }catch(e){}
  }catch(e){}

  // COOKIES : on retire domain= (etranger a notre origine) ET on impose
  // SameSite=None (contexte tiers, sinon le navigateur rejette). Meme regle
  // que cote serveur sur Set-Cookie.
  try{
    var d = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if(d && d.set && d.get){
      Object.defineProperty(document, "cookie", {
        configurable:true,
        get:function(){ return d.get.call(document); },
        set:function(v){
          var x=String(v).replace(/;\\s*domain=[^;]*/ig,"").replace(/;\\s*samesite=[^;]*/ig,"");
          if(!/;\\s*secure/i.test(x)) x+="; Secure";
          x+="; SameSite=None";
          S.cookies++;
          d.set.call(document, x);
        }
      });
    }
  }catch(e){}

  // NAVIGATIONS VERS UN PORTAIL DE CONSENTEMENT (#1365). location.assign /
  // location.replace peuvent etre remplaces (contrairement au setter de
  // location.href) : on y attrape l'URL COMPLETE d'un portail — first-id et
  // consorts — et on la reecrit vers son origine surf, avant la navigation.
  // Le relais fait alors le saut de portail (redirectHost+redirectUri).
  try{
    var _PORT=/(^|\.)((gate\.)?first-id\.fr|privacy-mgmt\.com|consent\.google\.com)$/i;
    function _versSurf(u){
      try{ var x=new URL(u, location.href);
        if(_PORT.test(x.hostname) && x.hostname.indexOf("surf-")!==0){
          var plat=x.hostname.toLowerCase().replace(/-/g,"--").replace(/\./g,"-");
          return "https://surf-"+plat+".gk2.secubox.in"+x.pathname+x.search+x.hash;
        }
      }catch(e){}
      return u;
    }
    var _asg=Location.prototype.assign, _rep=Location.prototype.replace;
    if(_asg) Location.prototype.assign=function(u){ return _asg.call(this,_versSurf(u)); };
    if(_rep) Location.prototype.replace=function(u){ return _rep.call(this,_versSurf(u)); };
  }catch(e){}
  // POPUPS : window.open rendu inerte.
  try{
    var faux={closed:true,close:function(){},focus:function(){},blur:function(){},
      postMessage:function(){},moveTo:function(){},resizeTo:function(){},
      location:{href:"",replace:function(){},assign:function(){}},
      document:{write:function(){},close:function(){}}};
    window.open=function(){ S.popups++; return faux; };
  }catch(e){}

  // POPUPS DE NOTIFICATION : la demande d'autorisation est refusee EN SILENCE,
  // sans le bandeau du navigateur. On ne pousse rien non plus (push/SW).
  try{
    if(window.Notification){
      Notification.requestPermission=function(cb){
        S.notifs++;
        if(typeof cb==="function"){ try{cb("denied");}catch(e){} }
        return Promise.resolve("denied");
      };
      try{ Object.defineProperty(Notification,"permission",{get:function(){return "denied";},configurable:true}); }catch(e){}
    }
    if(navigator.serviceWorker && navigator.serviceWorker.register){
      var reg0=navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register=function(){ S.notifs++; return Promise.reject(new Error("sbx: bloque")); };
    }
  }catch(e){}

  // CADRES IMBRIQUES CREES AU RUNTIME (#1235). Les iframes STATIQUES sont deja
  // reecrites cote serveur ; mais le JS du site (login Google, widgets d'embed)
  // en cree DYNAMIQUEMENT vers l'origine BRUTE (ex. accounts.google.com), que
  // la CSP frame-src 'self' *.gk2.secubox.in bloque. On reecrit .src et
  // setAttribute('src'/'href') des cadres vers leur origine surf AVANT que le
  // navigateur ne charge. Les pisteurs ne passent pas par ici : leurs scripts
  // sont coupes a la source, donc un cadre cree au runtime vient du JS legitime.
  try{
    var _SUF="gk2.secubox.in";
    function _fceOrig(h){ return "surf-"+h.toLowerCase().replace(/-/g,"--").replace(/\\./g,"-")+"."+_SUF; }
    function _fceMap(u){
      try{ if(u==null||u==="") return u; var a=new URL(String(u), location.href);
        if(a.protocol!=="http:"&&a.protocol!=="https:") return u;
        var h=a.hostname.toLowerCase();
        if(h===location.hostname) return u;                       // deja nous
        if(h.slice(-(_SUF.length+1))==="."+_SUF) return u;        // deja une origine surf
        return "https://"+_fceOrig(h)+a.pathname+a.search+a.hash;
      }catch(e){ return u; }
    }
    var _fsa=Element.prototype.setAttribute;
    Element.prototype.setAttribute=function(n,v){
      try{ if(v!=null && /^(src|href)$/i.test(String(n))){
        var t=this.tagName; if(t==="IFRAME"||t==="FRAME"){ v=_fceMap(v); }
      } }catch(e){}
      return _fsa.call(this,n,v);
    };
    ["HTMLIFrameElement","HTMLFrameElement"].forEach(function(C){
      try{ if(!window[C]) return;
        var d=Object.getOwnPropertyDescriptor(window[C].prototype,"src");
        if(!d||!d.set) return;
        Object.defineProperty(window[C].prototype,"src",{
          configurable:true, enumerable:d.enumerable, get:d.get,
          set:function(v){ d.set.call(this, _fceMap(v)); }
        });
      }catch(e){}
    });
  }catch(e){}

  // PONT postMessage (#1235 A). Les cadres relayes se parlent en
  // postMessage(data, "https://site.com") et verifient event.origin ===
  // "https://site.com". Nos fenetres vivant sous surf-*, le navigateur REFUSE
  // la livraison (cible != origine reelle) et les verifs d'origine du site
  // echouent. On tient l'illusion : a l'ENVOI on reecrit la cible brute -> surf
  // (le navigateur livre) ; a la RECEPTION on represente event.origin surf ->
  // brut (la verif du site passe). Best-effort : un envoi vers un enfant
  // CROSS-ORIGINE passe par un WindowProxy natif non interceptable — on ne
  // promet donc pas tous les flux, mais on debloque les plus courants.
  try{
    function _h2s(h){ return "surf-"+h.toLowerCase().split("-").join("--").split(".").join("-")+"."+_SUF; }
    function _s2h(h){
      h=h.toLowerCase();
      if(h.indexOf("surf-")!==0 || h.slice(-(_SUF.length+1))!=="."+_SUF) return null;
      var plat=h.slice(5, h.length-(_SUF.length+1));
      var Z=String.fromCharCode(0);
      return plat.split("--").join(Z).split("-").join(".").split(Z).join("-");
    }
    function _oR2S(o){
      try{ var u=new URL(o); var h=u.hostname.toLowerCase();
        if(h===location.hostname) return o;
        if(h.slice(-(_SUF.length+1))==="."+_SUF) return o;
        return u.protocol+"//"+_h2s(h);
      }catch(e){ return o; }
    }
    function _oS2R(o){
      try{ var u=new URL(o); var raw=_s2h(u.hostname);
        return raw ? (u.protocol+"//"+raw) : o;
      }catch(e){ return o; }
    }
    // ENVOI : cible brute -> surf
    var _pm=window.postMessage;
    if(_pm){
      var _pmw=function(msg, target, transfer){
        try{ if(typeof target==="string" && target!=="*" && target!=="/"){ target=_oR2S(target); } }catch(e){}
        return _pm.call(this, msg, target, transfer);
      };
      try{ window.postMessage=_pmw; }catch(e){}
      try{ if(window.Window && Window.prototype) Window.prototype.postMessage=_pmw; }catch(e){}
    }
    // RECEPTION : event.origin surf -> brut, via un proxy de l'evenement
    function _wrap(ev){
      try{ var raw=_oS2R(ev.origin);
        if(raw===ev.origin) return ev;
        return new Proxy(ev, { get:function(t,k){
          if(k==="origin") return raw;
          var v=t[k]; return (typeof v==="function") ? v.bind(t) : v;
        }});
      }catch(e){ return ev; }
    }
    var _ael=EventTarget.prototype.addEventListener;
    var _rel=EventTarget.prototype.removeEventListener;
    var _mm=new WeakMap();
    EventTarget.prototype.addEventListener=function(type, l, o){
      if(type==="message" && typeof l==="function"){
        var w=function(ev){ return l.call(this, _wrap(ev)); };
        try{ _mm.set(l, w); }catch(e){}
        return _ael.call(this, type, w, o);
      }
      return _ael.call(this, type, l, o);
    };
    EventTarget.prototype.removeEventListener=function(type, l, o){
      if(type==="message" && typeof l==="function"){ var w=_mm.get(l); if(w) return _rel.call(this, type, w, o); }
      return _rel.call(this, type, l, o);
    };
    try{
      var _od=Object.getOwnPropertyDescriptor(Window.prototype, "onmessage");
      if(_od && _od.set){
        Object.defineProperty(window, "onmessage", {
          configurable:true,
          get:function(){ return _od.get ? _od.get.call(this) : null; },
          set:function(fn){ _od.set.call(this, (typeof fn==="function") ? function(ev){ return fn.call(this, _wrap(ev)); } : fn); }
        });
      }
    }catch(e){}
  }catch(e){}
})();
</script>
"""


def _injecte_tete(corps: str, etat_js: str = "") -> str:
    """Insere le script de tete juste apres <head> (ou au tout debut).

    L'etat storage retenu est pose AVANT le script de tete (dans
    `window.__sbx_etat`), pour que la reinjection precede les scripts du site.
    """
    tete = ""
    if etat_js and etat_js not in ('{"local": {}, "session": {}}',
                                   '{"local":{},"session":{}}'):
        tete = '<script id="sbx-surf-etat">window.__sbx_etat=%s;</script>' % etat_js
    tete += _INJECTION_TETE
    m = re.search(r'<head[^>]*>', corps, re.IGNORECASE)
    if m:
        i = m.end()
        return corps[:i] + tete + corps[i:]
    # Pas de <head> : on met avant <html>… en dernier recours au debut.
    return tete + corps


def _injecte(corps: str) -> str:
    """Insere l'injection avant </body> (ou en fin si absent)."""
    i = corps.lower().rfind("</body>")
    if i >= 0:
        return corps[:i] + _INJECTION + corps[i:]
    return corps + _INJECTION


# PORTAILS DE CONSENTEMENT qui redirigent — cites en DUR dans le JS des sites
# (BFM/Altice pointe « https://gate.first-id.fr/... »). Le relais reecrit les
# href/src du HTML, pas les chaines du JS : ces URL absolues echappaient a la
# reecriture, la navigation partait vers le vrai portail (bloque par la CSP et
# le DNS de la box). On les remplace donc par leur origine surf DANS LE TEXTE
# servi — la navigation passe alors par nous, et `_saut_portail` renvoie a la
# page de retour.
_PORTAILS_REDIR = (
    "gate.first-id.fr", "first-id.fr", "cmp.first-id.fr",
    "privacy-mgmt.com", "consent.google.com",
)


def reecris_portails(corps: str) -> str:
    for g in _PORTAILS_REDIR:
        corps = corps.replace("//" + g, "//" + origine_de(g))
    return corps


def reecris_html(corps: str, base: str, rap: Rapport, sur_hote,
                 etat_js: str = "") -> str:
    """Réécrit les URL d'un HTML et RECENSE ce qu'il n'a pas su suivre.

    `etat_js` : le storage retenu pour cet hôte (JSON déjà échappé), réinjecté
    inline dans la tête avant les scripts du site (jarre d'état, #1235)."""
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
    # LES LIENS RESTENT DANS LE CADRE (#1345). `target="_blank"` tenterait une
    # popup (bloquee par le sandbox, donc un clic mort) ; `_top`/`_parent`
    # ferait echapper la page hors du Hall. On ramene tout a `_self` : le lien
    # navigue le cadre, et notre historique le suit.
    corps = re.sub(r'target\s*=\s*(["\']?)(_blank|_new|_top|_parent)\1',
                   'target="_self"', corps, flags=re.IGNORECASE)

    n_ref = len(_RE_META_REFRESH.findall(corps))
    if n_ref:
        corps = _RE_META_REFRESH.sub('', corps)
        rap.note("meta-refresh", "note",
                 "%d redirection(s) meta-refresh retiree(s) : elles emmenaient "
                 "le cadre ailleurs (consentement, version app)." % n_ref)

    # 3. Ce qu'on ne peut PAS suivre. On ne modifie rien — on compte.
    _recense_js(corps, rap, ou="html-inline")
    return reecris_portails(_injecte_tete(_injecte(corps), etat_js))


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

def reecris_entetes(entetes: dict, base: str, rap: Rapport, sur_hote,
                    origine_req: str = "") -> dict:
    """Réécrit ou retire les en-têtes qui trahiraient l'origine réelle.

    `origine_req` : l'en-tête `Origin` de la requête navigateur. Chaque site
    est relayé sous SA propre origine `surf-<hôte>.gk2.secubox.in` (#1217) :
    quand la page (`surf-accounts-google-com`) charge une sous-ressource d'un
    AUTRE hôte relayé (`surf-www-gstatic-com`, le JS de signin), c'est une
    requête CROSS-ORIGINE. Sans `Access-Control-Allow-Origin` en réponse, le
    navigateur la bloque (« Access-Control-Allow-Origin manquant », observé sur
    le login Google). On rejoue donc l'Origin demandeuse et on autorise les
    identifiants — le relais est un bac à sable, toutes ces origines sont les
    nôtres. (#1235)
    """
    out = {}
    for cle, val in entetes.items():
        bas = cle.lower()

        # Les en-têtes CORS de l'amont nomment SES origines, jamais les nôtres :
        # on les retire pour poser les nôtres après la boucle.
        if bas.startswith("access-control-"):
            continue

        if bas == "location":
            v, _ = _map_url(val, base, sur_hote)
            out[cle] = v
            continue

        if bas == "set-cookie":
            # LE TEMOIN DOIT TENIR EN CONTEXTE TIERS (#1347). Le cadre surf est
            # servi sous `surf-*.gk2.secubox.in`, un domaine DIFFERENT de celui
            # du Hall (`gk2.net`) : pour le navigateur, c'est un contexte
            # CROSS-SITE. Un cookie `SameSite=Lax/Strict` y est REJETE — c'est
            # ce qui faisait boucler DataDome (« cookie datadome rejected »),
            # et ce qui casse toute session sur un site relaye.
            #
            # On fait donc trois choses, dans l'ordre :
            #   1. retirer `Domain` — il nommait le site d'origine, jamais le
            #      notre, donc le cookie n'aurait pas ete renvoye ;
            #   2. retirer un `SameSite` existant — sinon on en aurait deux ;
            #   3. imposer `SameSite=None; Secure`, seul reglage accepte en
            #      contexte tiers sous https.
            v = re.sub(r';\s*[Dd]omain=[^;]+', '', val)
            v = re.sub(r';\s*SameSite=\w+', '', v, flags=re.IGNORECASE)
            if "secure" not in v.lower():
                v += "; Secure"
            v += "; SameSite=None"
            out[cle] = v
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

    # CORS entre origines surf (#1235). Toutes les origines `surf-*` sont les
    # nôtres : on autorise la sous-ressource à charger cross-origine. On rejoue
    # l'Origin exacte (jamais `*`, incompatible avec `Allow-Credentials`) pour
    # que les scripts `crossorigin`/modules chargés d'un autre hôte relayé
    # passent. Sans Origin (navigation de premier niveau), rien à faire.
    if origine_req:
        out["Access-Control-Allow-Origin"] = origine_req
        out["Access-Control-Allow-Credentials"] = "true"
        out["Access-Control-Expose-Headers"] = "*"
        out["Vary"] = "Origin"
    return out
