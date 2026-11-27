// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Profil déduit des populations et ruptures par couches (#4005), lus dans le relevé GET /api/v1/waf/populations
// (champs `profil`, `lecture`, `retours` de chaque population ; `ruptures` du relevé). Script classique : pose
// window.SbxProfil, aucune lecture réseau. User-agents, vhosts et classes de pages viennent d'attaquants : TOUT passe
// par textContent. Une mesure absente s'écrit « — », jamais un zéro inventé. La lecture est produite par des règles
// côté box (api/profil.py) : la page l'affiche telle quelle, sans rien en déduire.
(function (w) {
  "use strict";

  var NS = "http://www.w3.org/2000/svg", MAX_PROFILS = 4;
  var FENETRES = ["1h", "8h", "1j", "7j"];

  function nombre(v) { return typeof v === "number" && isFinite(v); }
  function nb(v) { return nombre(v) ? Math.round(v).toLocaleString("fr-FR") : "—"; }
  function hx(doc, tag, cls, txt, titre) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = String(txt);
    if (titre) e.title = titre;
    return e;
  }
  function vide(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }

  // Mini-histogramme : une barre par valeur, hauteur relative au maximum ; aucune valeur → rien.
  function histo(doc, valeurs, titre) {
    var v = (valeurs || []).map(function (x) { return nombre(x) ? x : 0; });
    var s = doc.createElementNS(NS, "svg"), max = Math.max.apply(null, v.concat([1])), n = v.length || 1;
    s.setAttribute("viewBox", "0 0 " + (n * 6) + " 24");
    s.setAttribute("class", "prhisto");
    s.setAttribute("role", "img");
    s.setAttribute("aria-label", titre);
    v.forEach(function (x, i) {
      var h = Math.max(x ? 1.5 : 0.5, 22 * x / max), r = doc.createElementNS(NS, "rect");
      r.setAttribute("x", String(i * 6 + 0.5)); r.setAttribute("y", String(24 - h));
      r.setAttribute("width", "5"); r.setAttribute("height", String(h));
      var t = doc.createElementNS(NS, "title"); t.textContent = nb(x); r.appendChild(t);
      s.appendChild(r);
    });
    return s;
  }

  function barresParts(doc, titre, items) {
    var d = hx(doc, "div", "prparts");
    d.appendChild(hx(doc, "h4", null, titre));
    if (!items || !items.length) { d.appendChild(hx(doc, "span", "popnr", "—")); return d; }
    items.slice(0, 4).forEach(function (it) {
      var l = hx(doc, "div", "prl"), b = hx(doc, "span", "prb");
      l.appendChild(hx(doc, "span", "prk", it[0]));
      b.appendChild(hx(doc, "span")).style.width = Math.max(0, Math.min(100, Number(it[1]) || 0)) + "%";
      l.appendChild(b);
      l.appendChild(hx(doc, "span", "prv", (nombre(it[1]) ? Math.round(it[1]) : "—") + " %"));
      d.appendChild(l);
    });
    return d;
  }

  function carteProfil(doc, p) {
    var a = hx(doc, "article", "popc prc"), h = hx(doc, "header");
    h.appendChild(hx(doc, "h3", null, (p.nom_cible || p.famille || "population") + " · " + (p.famille || "")));
    h.appendChild(histo(doc, p.serie, "Requêtes par jour, 7 derniers jours"));
    a.appendChild(h);
    var ul = hx(doc, "ul", "prlect");
    (p.lecture || []).forEach(function (l) { ul.appendChild(hx(doc, "li", null, l.texte)); });
    if (!ul.firstChild) ul.appendChild(hx(doc, "li", "popnr", "Aucune règle ne s'applique : volume ou contraste insuffisant."));
    a.appendChild(ul);
    var pr = p.profil;
    if (pr) {
      var g = hx(doc, "div", "prgrille");
      g.appendChild(barresParts(doc, "Pages", pr.pages));
      g.appendChild(barresParts(doc, "Vhosts", pr.vhosts));
      g.appendChild(barresParts(doc, "Méthodes", pr.methodes));
      a.appendChild(g);
      var ua = hx(doc, "p", "popcible");
      ua.textContent = "Premier user-agent (" + nb(pr.ua_premier_part) + " % de " + nb(pr.requetes) + " requêtes, "
        + nb(pr.ua_distincts) + (pr.ua_plafond ? "+" : "") + " distincts) : " + (pr.ua_premier || "—");
      a.appendChild(ua);
    }
    var r = p.retours;
    if (r) a.appendChild(hx(doc, "p", "poprep", "Relâchées : " + nb(r.relachees) + " · revenues : " + nb(r.retours)
      + (nombre(r.delai_median_s) ? " · délai médian " + nb(r.delai_median_s / 3600) + " h" : "")));
    return a;
  }

  function cellule(doc, f, nom) {
    var td = hx(doc, "td", "n");
    if (!f) { td.textContent = "—"; return td; }
    var t = nom + " : " + nb(f.courant) + (nombre(f.mediane) ? " contre une médiane de " + nb(f.mediane) + " sur "
      + f.fenetres + " fenêtres précédentes" : "");
    if (f.sens === "hausse") { td.className = "n prh"; td.textContent = "↑ ×" + f.facteur; }
    else if (f.sens === "baisse") { td.className = "n prba"; td.textContent = "↓ ÷" + f.facteur; }
    else if (f.sens === "insuffisant") { td.className = "n popnr"; td.textContent = "…"; t += " (historique insuffisant)"; }
    else td.textContent = nb(f.courant);
    td.title = t;
    return td;
  }

  function tableRuptures(doc, zone, ru) {
    vide(zone);
    if (!ru || !Array.isArray(ru.couches)) { zone.appendChild(hx(doc, "span", "popnr", "Ruptures non mesurées.")); return; }
    var tab = hx(doc, "table", "prtab"), th = hx(doc, "tr");
    ["Couche", "7 jours"].concat(FENETRES).concat(["Double lecture"]).forEach(function (x) { th.appendChild(hx(doc, "th", null, x)); });
    tab.appendChild(hx(doc, "thead")).appendChild(th);
    var tb = hx(doc, "tbody");
    ru.couches.forEach(function (c) {
      var tr = hx(doc, "tr");
      tr.appendChild(hx(doc, "td", "o", c.libelle, "source : " + c.source));
      var h = hx(doc, "td");
      h.appendChild(histo(doc, c.jours, "Totaux sur 24 h, 7 derniers jours"));
      tr.appendChild(h);
      FENETRES.forEach(function (n) { tr.appendChild(cellule(doc, c.fenetres && c.fenetres[n], n)); });
      var d = hx(doc, "td");
      if (c.double) {
        var v = c.double.valeurs || {}, k = v["1j"] ? "1j" : Object.keys(v)[0];
        var txt = k ? nb(v[k].a) + " / " + nb(v[k].b) + " (" + k + ")" : "—";
        d.appendChild(hx(doc, "span", c.double.ecart ? "puce prec" : "puce", (c.double.ecart ? "écart " : "") + txt,
          c.source + " / " + c.double.source_b + " sur les fenêtres couvertes par les deux sources"));
      } else d.textContent = "—";
      tr.appendChild(d);
      tb.appendChild(tr);
    });
    tab.appendChild(tb);
    zone.appendChild(tab);
    zone.appendChild(hx(doc, "p", "poprep", "Fenêtre courante comparée à la médiane des fenêtres précédentes de même longueur ; "
      + "↑/↓ au-delà d'un facteur " + nb(ru.facteur) + " et d'un volume minimal. « … » : historique insuffisant. "
      + nb(ru.signalees) + " rupture(s), " + nb(ru.ecarts) + " écart(s) de double lecture."
      + (ru.bans_lisibles ? "" : " bans.jsonl non lu : couches de bans absentes.")));
  }

  function rendre(doc, zoneProfils, zoneRuptures, releve) {
    vide(zoneProfils);
    if (!releve || releve.disponible === false || !Array.isArray(releve.populations)) {
      zoneProfils.appendChild(hx(doc, "span", "popnr", "Relevé indisponible."));
      tableRuptures(doc, zoneRuptures, null);
      return;
    }
    var pops = releve.populations.filter(function (p) { return p && Array.isArray(p.lecture) && p.lecture.length; })
      .sort(function (a, b) { return (b.adresses || 0) - (a.adresses || 0); }).slice(0, MAX_PROFILS);
    if (!pops.length) zoneProfils.appendChild(hx(doc, "span", "popnr", "Aucun profil qualifié par les règles."));
    pops.forEach(function (p) { zoneProfils.appendChild(carteProfil(doc, p)); });
    tableRuptures(doc, zoneRuptures, releve.ruptures);
  }

  w.SbxProfil = { rendre: rendre };
})(window);
