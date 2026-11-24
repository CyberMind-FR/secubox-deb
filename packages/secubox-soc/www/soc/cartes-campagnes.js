// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Cartes et synthèse des populations d'attaquants (#3919), relevé GET /api/v1/waf/populations. Script classique : pose
// window.SbxCartes, aucune lecture réseau, aucun style (chaque page porte le sien), document et zone reçus en argument.
// Copie identique dans secubox-waf-ng (www/waf) et secubox-soc (www/soc) ; repères de reperes.js.
// Cibles (en-têtes Host d'attaquants) et opérateurs (GeoLite) sont des données hostiles : TOUT passe par textContent.
// Classe, famille ou état inconnus : « inconnu » / « autre » / rien. La classe d'un réseau vient du seul relevé, jamais
// du nom de l'opérateur. Une mesure absente s'écrit « — » : jamais un zéro inventé.
(function (w) {
  "use strict";

  var NS = "http://www.w3.org/2000/svg", MAX_CARTES = 6, MAX_LIGNES = 4;
  var MANQUES = { journal: "journal du WAF", authwatch: "échecs de messagerie", profileur: "profileur de campagnes", rotation: "détecteur de rotation" };
  var BASES = { base_asn: "base des opérateurs", base_pays: "base des pays" };
  var T_ROTATION = "50 adresses ou plus, dont 80 % ou plus à trois tentatives ou moins";

  function nombre(v) { return typeof v === "number" && isFinite(v); }
  function nb(v) { return nombre(v) ? Math.round(v).toLocaleString("fr-FR") : "—"; }
  function pct(v) { return nombre(v) ? Math.round(v) + " %" : "— %"; }
  function possede(table, cle) { return typeof cle === "string" && Object.prototype.hasOwnProperty.call(table, cle); }
  function cleOu(table, cle, defaut) { return possede(table, cle) ? cle : defaut; }
  function objet(v) { return !!v && typeof v === "object"; }
  function liste(v) { return Array.isArray(v) ? v : []; }
  function vider(zone) { while (zone.firstChild) zone.removeChild(zone.firstChild); zone.textContent = ""; }
  function el(doc, tag, cls, texte) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (texte != null) e.textContent = String(texte);
    return e;
  }
  function svgEl(doc, tag, attrs) {
    var e = doc.createElementNS(NS, tag);
    Object.keys(attrs).forEach(function (k) { e.setAttribute(k, String(attrs[k])); });
    return e;
  }
  function puce(doc, R, repere, suffixe, cls, titre) {
    var p = R.puce(doc, repere, suffixe);
    if (cls) p.className = "puce " + cls;
    if (titre) p.title = titre;
    return p;
  }
  function disponible(r) { return objet(r) && r.disponible !== false && Array.isArray(r.populations); }
  function quand(r) {
    return nombre(r.genere_le) ? new Date(r.genere_le * 1000).toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : null;
  }
  function noms(table, cles) { return cles.filter(function (c) { return possede(table, c); }).map(function (c) { return table[c]; }).join(", "); }

  // Empreinte d'un relevé, sans son âge : la page ne redessine (et ne referme un détail ouvert) que s'il a changé.
  function cle(r) {
    if (!disponible(r)) return "indisponible";
    return JSON.stringify([r.genere_le, r.complet, r.manques, r.populations, r.recouvrement]);
  }
  function dernierJour(p) { var s = liste(p.serie), v = s[s.length - 1]; return nombre(v) ? v : 0; }
  function triees(r) { return r.populations.filter(objet).sort(function (a, b) { return dernierJour(b) - dernierJour(a); }); }
  function cibles(p) { return liste(p.cibles).slice(0, 3).map(String); }
  function titre(R, p) { var f = cleOu(R.FAMILLES, p.famille, "autre"); return R.FAMILLES[f][0] + " " + R.nomCarte(f, cibles(p)); }

  function etats(doc, R, p, zone) {
    if (p.rotation === true) zone.appendChild(puce(doc, R, R.ETATS.rotation, "", "etat rot", T_ROTATION));
    var e = cleOu(R.ETATS, p.etat, null);
    if (e === "bannie") zone.appendChild(puce(doc, R, R.ETATS.bannie, "", "etat ban", nb(p.bans) + " adresses bannies sur 7 jours, un ban dans les dernières 24 h"));
    else if (e === "observee") zone.appendChild(puce(doc, R, R.ETATS.observee, "", "etat obs", "active dans les dernières 24 h, sans ban récent"));
    else if (e === "inactive") zone.appendChild(puce(doc, R, R.ETATS.inactive, "", "etat ina", "aucune activité depuis plus de 24 h"));
    return zone;
  }
  // [[classe connue, %]] par part décroissante ; une clé inconnue compte pour « inconnu ».
  function classes(R, src) {
    var acc = {}, ordre = [];
    Object.keys(objet(src) ? src : {}).forEach(function (k) {
      var v = src[k];
      if (!nombre(v) || v <= 0) return;
      var c = cleOu(R.CLASSES, k, "inconnu");
      if (!possede(acc, c)) { acc[c] = 0; ordre.push(c); }
      acc[c] += v;
    });
    return ordre.map(function (c) { return [c, acc[c]]; }).sort(function (a, b) { return b[1] - a[1]; });
  }
  // 7 barres J-6 → J, une bulle datée par barre. Un jour non mesuré n'a pas de barre ; aucune série : pas de graphique.
  function serie(doc, valeurs, genere) {
    var s = liste(valeurs).slice(-7).map(function (v) { return nombre(v) && v >= 0 ? v : null; });
    if (!s.some(function (v) { return v !== null; })) return null;
    while (s.length < 7) s.unshift(null);
    var mx = Math.max.apply(null, s.map(function (v) { return v || 0; })) || 1, fin = nombre(genere) ? genere * 1000 : null;
    var g = svgEl(doc, "svg", { "class": "popserie", viewBox: "0 0 74 32", role: "img", "aria-label": "7 jours : " + s.map(nb).join(", ") });
    s.forEach(function (v, i) {
      if (v === null) return;
      var h = v ? Math.max(2, v / mx * 30) : 1;
      var b = svgEl(doc, "rect", { x: i * 11, y: (32 - h).toFixed(1), width: 8, height: h.toFixed(1), rx: 1.5 });
      var j = fin === null ? "J-" + (6 - i) : new Date(fin - (6 - i) * 86400000).toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
      var t = svgEl(doc, "title", {});
      t.textContent = j + " : " + nb(v) + (v > 1 ? " événements" : " événement");
      b.appendChild(t); g.appendChild(b);
    });
    return g;
  }
  function reseaux(doc, R, top) {
    var d = el(doc, "details"), w2 = el(doc, "div", "popdet"), t = el(doc, "table"), th = el(doc, "thead"), tr = el(doc, "tr"), tb = el(doc, "tbody");
    d.appendChild(el(doc, "summary", "", top.length === 1 ? "Détail : le premier réseau" : "Détail : " + top.length + " premiers réseaux"));
    ["Type", "AS", "Opérateur", "Adresses"].forEach(function (x, i) { tr.appendChild(el(doc, "th", i === 3 ? "n" : "", x)); });
    th.appendChild(tr); t.appendChild(th);
    top.forEach(function (x) {
      var l = el(doc, "tr"), c = R.CLASSES[cleOu(R.CLASSES, x.classe, "inconnu")];
      l.appendChild(el(doc, "td", "", c[0] + " " + c[1]));
      l.appendChild(el(doc, "td", "", nombre(x.asn) ? "AS" + Math.round(x.asn) : "—"));
      l.appendChild(el(doc, "td", "o", typeof x.org === "string" && x.org ? x.org : "—"));
      l.appendChild(el(doc, "td", "n", nb(x.adresses)));
      tb.appendChild(l);
    });
    t.appendChild(tb); w2.appendChild(t); d.appendChild(w2);
    return d;
  }
  function carte(doc, R, p, genere) {
    var a = el(doc, "article", "popc"), h = el(doc, "header"), cb = cibles(p), fam = cleOu(R.FAMILLES, p.famille, "autre");
    h.appendChild(el(doc, "h3", "", titre(R, p)));
    h.appendChild(etats(doc, R, p, el(doc, "div", "popl")));
    a.appendChild(h);
    var c = el(doc, "p", "popchif");
    c.appendChild(el(doc, "b", "", nb(p.adresses))); c.appendChild(el(doc, "span", "", " adresses · "));
    c.appendChild(el(doc, "b", "", nb(p.reseaux))); c.appendChild(el(doc, "span", "", " réseaux · "));
    c.appendChild(el(doc, "b", "", pct(p.une))); c.appendChild(el(doc, "span", "", " n'essaient qu'une fois · " + pct(p.le3) + " trois fois ou moins"));
    a.appendChild(c);
    var cl = classes(R, p.classes), b = el(doc, "div", "popbarre"), lc = el(doc, "div", "popl");
    b.setAttribute("aria-hidden", "true");
    cl.forEach(function (x) {   // x[0] : clé connue de reperes.js, jamais une valeur du relevé
      var g = el(doc, "span", "c-" + x[0]);
      g.style.width = Math.min(100, x[1]) + "%"; g.title = R.CLASSES[x[0]][1] + " " + pct(x[1]);
      b.appendChild(g); lc.appendChild(puce(doc, R, R.CLASSES[x[0]], pct(x[1])));
    });
    if (cl.length) { a.appendChild(b); a.appendChild(lc); } else a.appendChild(el(doc, "span", "popnr", "types de réseau non relevés"));
    var pays = liste(p.pays_top).filter(Array.isArray).slice(0, 3);
    if (pays.length) {
      var lp = el(doc, "div", "popl");
      pays.forEach(function (x) {
        var k = typeof x[0] === "string" && /^[A-Za-z]{2}$/.test(x[0]) ? x[0].toUpperCase() : "??";
        lp.appendChild(puce(doc, R, [R.drapeau(k), k], pct(x[1]), "", "part des adresses"));
      });
      a.appendChild(lp);
    }
    var pied = el(doc, "div", "poppied"), txt, g7 = serie(doc, p.serie, genere);
    if (!cb.length) txt = "Cible : non relevée";
    else if (fam === "messagerie") txt = "Comptes visés : " + cb.join(", ") + " (masqués)";
    else txt = "Cible : " + cb.map(function (x) { return x.replace(/\.secubox\.in$/, ""); }).join(", ");
    pied.appendChild(el(doc, "span", "popcible", txt));
    if (g7) pied.appendChild(g7);
    a.appendChild(pied);
    var top = liste(p.reseaux_top).filter(objet).slice(0, 5);
    if (top.length) a.appendChild(reseaux(doc, R, top));
    return a;
  }
  // « Relevé partiel (date) » et ses sources manquantes ; bases réseau absentes : relevé complet, types incomplets.
  function reserve(doc, r, court) {
    var q = quand(r), m = liste(r.manques), src = noms(MANQUES, m), bases = noms(BASES, m);
    if (r.complet === false) {
      return el(doc, "p", "poppartiel", "Relevé partiel (" + (q || "date inconnue") + ")"
        + (court ? "" : " : " + (src ? "sources manquantes : " + src : "une source manquait") + ". Les chiffres sont incomplets."));
    }
    return bases && !court ? el(doc, "p", "poppartiel", "Types de réseau ou pays incomplets : " + bases + " absente.") : null;
  }

  // La section complète de /waf/campagnes.html : une carte par population, 6 visibles, le reste replié.
  function populations(doc, R, zone, r) {
    vider(zone);
    if (!disponible(r)) { zone.appendChild(el(doc, "span", "popnr", "Relevé indisponible")); return; }
    var av = reserve(doc, r, false), pops = triees(r), q = quand(r), E = R.ETATS;
    if (av) zone.appendChild(av);
    if (!pops.length) zone.appendChild(el(doc, "span", "popnr", "aucune population dans le relevé"));
    pops.slice(0, MAX_CARTES).forEach(function (p) { zone.appendChild(carte(doc, R, p, r.genere_le)); });
    if (pops.length > MAX_CARTES) {
      var d = el(doc, "details", "popautres");
      d.appendChild(el(doc, "summary", "", "Autres populations (" + (pops.length - MAX_CARTES) + ")"));
      pops.slice(MAX_CARTES).forEach(function (p) { d.appendChild(carte(doc, R, p, r.genere_le)); });
      zone.appendChild(d);
    }
    var rec = r.recouvrement, t = "Recouvrement entre populations : non relevé.";
    if (objet(rec) && nombre(rec.adresses_communes) && nombre(rec.adresses_total)) {
      t = "Recouvrement entre populations : " + nb(rec.adresses_communes) + " adresses communes sur " + nb(rec.adresses_total)
        + (rec.adresses_total > 0 && rec.adresses_communes * 100 < rec.adresses_total ? " — moins de 1 % : ce sont des acteurs distincts." : ".");
    }
    zone.appendChild(el(doc, "p", "poprec", t));
    zone.appendChild(el(doc, "p", "poprep", "Repères : " + Object.keys(R.CLASSES).map(function (k) { return R.CLASSES[k][0] + " " + R.CLASSES[k][1]; }).join(" · ")
      + " — " + E.rotation[0] + " rotation : " + T_ROTATION + " · " + E.bannie[0] + " bannie : un ban dans les dernières 24 h · "
      + E.observee[0] + " observée : active sans ban récent · " + E.inactive[0] + " inactive : rien depuis 24 h." + (q ? " Relevé du " + q + "." : "")));
  }

  // La synthèse du SOC : une ligne par campagne en cours (4 au plus), sans carte (#3922 : le détail est dans le WAF).
  function synthese(doc, R, zone, r, max) {
    vider(zone);
    if (!disponible(r)) { zone.appendChild(el(doc, "span", "popnr", "Relevé indisponible")); return; }
    var n = nombre(max) ? max : MAX_LIGNES, av = reserve(doc, r, true), reste;
    var pops = triees(r).filter(function (p) { return p.etat !== "inactive"; });
    if (av) zone.appendChild(av);
    if (!pops.length) zone.appendChild(el(doc, "span", "popnr", "Aucune campagne active dans les dernières 24 h"));
    pops.slice(0, n).forEach(function (p) {
      var l = el(doc, "div", "cligne"), g = serie(doc, p.serie, r.genere_le);
      l.appendChild(el(doc, "span", "cnom", titre(R, p)));
      l.appendChild(el(doc, "span", "cadr", nb(p.adresses) + " adresses"));
      l.appendChild(etats(doc, R, p, el(doc, "span", "popl")));
      if (g) l.appendChild(g);
      zone.appendChild(l);
    });
    reste = pops.length - n;
    if (reste > 0) zone.appendChild(el(doc, "span", "popnr", "et " + reste + (reste > 1 ? " autres" : " autre")));
  }

  // Relevé de DÉMONSTRATION : hôtes example.test, comptes masqués fictifs, AS de documentation (RFC 5398), aucune adresse.
  function exemple(genere) {
    function res(asn, org, classe, n) { return { asn: asn, org: org, classe: classe, adresses: n }; }
    return { disponible: true, complet: true, genere_le: genere, age_s: 300, recouvrement: { adresses_communes: 7, adresses_total: 5730 }, populations: [
      { id: "rotation:0a1b2c3d", famille: "collecte", cibles: ["git.example.test"], adresses: 1840, reseaux: 41, une: 97, le3: 100, classes: { proxy_loue: 84, hebergeur: 12, inconnu: 4 },
        pays_top: [["US", 52], ["GB", 11], ["CA", 6]], reseaux_top: [res(64496, "Proxy Exemple A", "proxy_loue", 512), res(64497, "Proxy Exemple B", "proxy_loue", 430), res(64498, "Nuage Exemple", "hebergeur", 190), res(64499, "Proxy Exemple C", "proxy_loue", 160), res(64500, "Proxy Exemple D", "proxy_loue", 121)],
        serie: [0, 0, 0, 0, 0, 120, 1730], bans: 1702, rotation: true, etat: "bannie" },
      { id: "famille:messagerie", famille: "messagerie", cibles: ["adm…", "inf…", "con…"], adresses: 960, reseaux: 312, une: 41, le3: 82, classes: { acces: 61, inconnu: 35, hebergeur: 4 },
        pays_top: [["US", 20], ["CN", 15], ["KR", 9]], reseaux_top: [res(64501, "Fournisseur Exemple", "acces", 140), res(64502, "Opérateur Exemple", "acces", 96), res(64503, "Câble Exemple", "acces", 57)],
        serie: [410, 220, 380, 512, 460, 300, 260], bans: 830, rotation: true, etat: "bannie" },
      { id: "famille:acces_distant", famille: "acces_distant", cibles: ["telnet", "rdp", "vnc"], adresses: 2433, reseaux: 481, une: 75, le3: 94, classes: { inconnu: 31, hebergeur: 25, acces: 22, scanner_recherche: 20, proxy_loue: 2 },
        pays_top: [["US", 25], ["GB", 14], ["NL", 9]], reseaux_top: [res(64507, "Sonde Exemple", "scanner_recherche", 399), res(64508, "Accès Exemple", "acces", 169), res(64509, "Nuage Exemple B", "hebergeur", 166)],
        serie: [160, 110, 210, 150, 190, 240, 120], bans: 640, rotation: true, etat: "bannie" },
      { id: "famille:balayage_web", famille: "balayage_web", cibles: ["www.example.test", "radio.example.test"], adresses: 320, reseaux: 44, une: 18, le3: 66, classes: { hebergeur: 70, relais_vie_privee: 14, scanner_recherche: 10, inconnu: 6 },
        pays_top: [["US", 38], ["DE", 9], ["SE", 5]], reseaux_top: [res(64504, "Nuage Exemple C", "hebergeur", 88), res(64505, "Relais Exemple", "relais_vie_privee", 45), res(64506, "Sonde Exemple B", "scanner_recherche", 32)],
        serie: [90, 70, 66, 40, 85, 101, 12], bans: 0, rotation: false, etat: "observee" },
      { id: "famille:autre", famille: "autre", cibles: ["forum.example.test"], adresses: 12, reseaux: 5, une: 50, le3: 83, classes: { hebergeur: 60, cdn: 40 },
        pays_top: [["FR", 40]], reseaux_top: [res(64510, "Nuage Exemple D", "hebergeur", 7)], serie: [22, 9, 3, 1, 0, 0, 0], bans: 3, rotation: false, etat: "inactive" }
    ] };
  }

  w.SbxCartes = { populations: populations, synthese: synthese, cle: cle, exemple: exemple };
})(window);
