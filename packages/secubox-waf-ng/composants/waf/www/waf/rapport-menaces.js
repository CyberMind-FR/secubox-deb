// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Rapport de menace multi-historique (#4006), partagé par les pages Campagnes (WAF) et Acteurs (Actor Intelligence).
// Lit GET /api/v1/waf/rapports et /api/v1/waf/rapports/{genre}/{id} ; seule écriture : POST …/rediger (rédaction IA à
// la demande, administrateur). Le dossier ne porte aucune adresse ; noms, user-agents et cibles viennent d'attaquants :
// TOUT passe par textContent. La lecture par règles est toujours affichée ; la lecture IA n'est montrée que relue par
// le code de la box, avec son taux de phrases retenues. Export : Markdown téléchargé (Blob) ou copié.
(function (w) {
  "use strict";

  var NS = "http://www.w3.org/2000/svg", BASE = "/api/v1/waf/rapports";
  var STYLE = ".rmx{display:grid;gap:10px;min-width:0}.rmx .rmxbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}" +
    ".rmx select,.rmx button{font:inherit;font-size:.9rem;color:inherit;background:rgba(41,182,246,.08);border:1px solid var(--trait,#2a3b5c);" +
    "border-radius:8px;padding:6px 10px;min-height:36px;max-width:100%}.rmx button{cursor:pointer}.rmx button:disabled{opacity:.5;cursor:default}" +
    ".rmx h4{margin:4px 0;font-size:.92rem}.rmx ul{margin:0;padding-left:18px;display:grid;gap:4px}.rmx li{overflow-wrap:anywhere}" +
    ".rmx .rmxdoux{color:var(--doux,#8aa0c0);font-size:.85rem}.rmx .rmxhyp{border:1px solid var(--trait,#2a3b5c);border-radius:6px;padding:0 6px;margin-right:6px;font-size:.8rem}" +
    ".rmx .rmxtaux{font-weight:700}.rmx svg.rmxhisto{width:100%;height:44px;display:block}.rmx svg.rmxhisto rect{fill:var(--cyan,#29b6f6)}" +
    ".rmx details{border:1px solid var(--trait,#2a3b5c);border-radius:8px;padding:6px 10px}";

  function hx(doc, tag, cls, txt) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = String(txt);
    return e;
  }
  function vide(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
  function nb(v) { return typeof v === "number" && isFinite(v) ? Math.round(v).toLocaleString("fr-FR") : "—"; }

  function histo(doc, serie, titre) {
    var v = (serie || []).map(function (x) { return typeof x === "number" && isFinite(x) ? x : 0; });
    var s = doc.createElementNS(NS, "svg"), max = Math.max.apply(null, v.concat([1])), n = v.length || 1;
    s.setAttribute("viewBox", "0 0 " + (n * 4) + " 40");
    s.setAttribute("preserveAspectRatio", "none");
    s.setAttribute("class", "rmxhisto");
    s.setAttribute("role", "img");
    s.setAttribute("aria-label", titre);
    v.forEach(function (x, i) {
      var h = Math.max(x ? 1.5 : 0.3, 38 * x / max), r = doc.createElementNS(NS, "rect");
      r.setAttribute("x", String(i * 4 + 0.3)); r.setAttribute("y", String(40 - h));
      r.setAttribute("width", "3.4"); r.setAttribute("height", String(h));
      var t = doc.createElementNS(NS, "title"); t.textContent = nb(x); r.appendChild(t);
      s.appendChild(r);
    });
    return s;
  }

  function liste(doc, items, rendre) {
    var u = hx(doc, "ul");
    items.forEach(function (x) { u.appendChild(rendre(x)); });
    return u;
  }

  function telecharger(doc, nom, texte) {
    try {
      var b = new Blob([texte], { type: "text/markdown;charset=utf-8" }), a = doc.createElement("a");
      a.href = URL.createObjectURL(b);
      a.download = nom;
      doc.body.appendChild(a); a.click(); doc.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
      return true;
    } catch (e) { return false; }
  }

  function rendreRapport(doc, zone, r, actions) {
    vide(zone);
    var d = r.dossier || {}, ia = r.ia, s = d.sujet || {};
    zone.appendChild(hx(doc, "h4", null, "Rapport — " + (s.nom || r.cle)));
    zone.appendChild(hx(doc, "div", "rmxdoux", "Période du " + ((d.periode || {}).debut || "—") + " au " + ((d.periode || {}).fin || "—") +
      " · aucune adresse IP · faits calculés par la box"));
    var h = r.historique || {};
    zone.appendChild(histo(doc, h.serie_jour, "Bans par jour sur 90 jours"));
    zone.appendChild(hx(doc, "h4", null, "Faits (règles de la box)"));
    zone.appendChild(liste(doc, r.regles || [], function (t) { return hx(doc, "li", null, t); }));
    var t = hx(doc, "div");
    if (ia && ia.etat === "fait") {
      var titre = hx(doc, "h4", null, "Lecture rédigée par l'IA, relue par le code : ");
      titre.appendChild(hx(doc, "span", "rmxtaux", ia.taux_retenues_pct + " % de phrases retenues (" + ia.retenues + " sur " + ia.phrases + ")"));
      t.appendChild(titre);
      if (ia.perimee) t.appendChild(hx(doc, "div", "rmxdoux", "Rédigée sur un dossier plus ancien : relancer la rédaction pour l'actualiser."));
      t.appendChild(liste(doc, ia.gardees || [], function (g) {
        var li = hx(doc, "li");
        if (g.statut === "hypothese") li.appendChild(hx(doc, "span", "rmxhyp", "hypothèse"));
        li.appendChild(doc.createTextNode(g.texte));
        return li;
      }));
      if ((ia.retirees || []).length) {
        var det = hx(doc, "details"), sm = hx(doc, "summary", null, ia.retirees.length + " phrase(s) retirée(s) par le contrôle");
        det.appendChild(sm);
        det.appendChild(liste(doc, ia.retirees, function (x) {
          var li = hx(doc, "li", null, x.texte ? "« " + x.texte + " »" : "(phrase non affichée : elle citait une adresse)");
          li.appendChild(hx(doc, "div", "rmxdoux", (x.motifs || []).join(" ; ")));
          return li;
        }));
        t.appendChild(det);
      }
    } else if (ia && ia.etat === "repli") {
      t.appendChild(hx(doc, "div", "rmxdoux", "Lecture IA indisponible (" + (ia.motif || "moteur absent") + ") : la lecture par règles ci-dessus fait foi."));
    } else {
      t.appendChild(hx(doc, "div", "rmxdoux", "Pas encore de lecture IA : la lecture par règles ci-dessus fait foi."));
    }
    if (r.redaction_en_cours) t.appendChild(hx(doc, "div", "rmxdoux", "Rédaction IA en cours (une à deux minutes)…"));
    zone.appendChild(t);
    var bar = hx(doc, "div", "rmxbar");
    var b1 = hx(doc, "button", null, "Rédiger avec l'IA"), b2 = hx(doc, "button", null, "Télécharger (.md)"), b3 = hx(doc, "button", null, "Copier");
    b1.type = b2.type = b3.type = "button";
    b1.disabled = !!r.redaction_en_cours;
    b1.title = "Le moteur ne reçoit que le dossier (sans adresse) ; sa rédaction est relue phrase par phrase par la box.";
    b1.addEventListener("click", function () { actions.rediger(r); });
    b2.addEventListener("click", function () {
      if (!telecharger(doc, "rapport-" + String(r.cle).replace(/[^A-Za-z0-9_-]+/g, "-") + ".md", r.markdown || "")) b2.textContent = "Échec";
    });
    b3.addEventListener("click", function () {
      var ok = function () { b3.textContent = "Copié"; }, ko = function () { b3.textContent = "Copie refusée"; };
      try { w.navigator.clipboard.writeText(r.markdown || "").then(ok, ko); } catch (e) { ko(); }
    });
    bar.appendChild(b1); bar.appendChild(b2); bar.appendChild(b3);
    zone.appendChild(bar);
  }

  // monter(document, conteneur, {genre: "campagne"|"acteur", jget: fn(url) → Promise(json|null), jeton: fn() → chaîne})
  function monter(doc, racine, o) {
    if (!racine) return null;
    if (!doc.getElementById("rmx-style")) { var st = hx(doc, "style", null, STYLE); st.id = "rmx-style"; doc.head.appendChild(st); }
    vide(racine);
    var box = hx(doc, "div", "rmx"), bar = hx(doc, "div", "rmxbar"), sel = hx(doc, "select"), zone = hx(doc, "div", "rmx"), etat = hx(doc, "span", "rmxdoux");
    sel.setAttribute("aria-label", "Sujet du rapport");
    bar.appendChild(sel); bar.appendChild(etat);
    box.appendChild(bar); box.appendChild(zone);
    racine.appendChild(box);
    var suivi = null;

    function charger(cle) {
      if (!cle) return;
      var i = cle.indexOf(":"), url = BASE + "/" + encodeURIComponent(cle.slice(0, i)) + "/" + encodeURIComponent(cle.slice(i + 1));
      o.jget(url).then(function (r) {
        if (!r || !r.dossier) { vide(zone).appendChild(hx(doc, "span", "rmxdoux", "Rapport indisponible.")); return; }
        rendreRapport(doc, zone, r, { rediger: rediger });
        if (suivi) { clearTimeout(suivi); suivi = null; }
        if (r.redaction_en_cours) suivi = setTimeout(function () { charger(cle); }, 10000);
      });
    }

    function rediger(r) {
      var t = o.jeton ? o.jeton() : "", h = { "Accept": "application/json" };
      if (t) h.Authorization = "Bearer " + t;
      var i = r.cle.indexOf(":");
      fetch(BASE + "/" + encodeURIComponent(r.cle.slice(0, i)) + "/" + encodeURIComponent(r.cle.slice(i + 1)) + "/rediger",
        { method: "POST", headers: h, credentials: "same-origin" }).then(function (x) {
        if (x.status === 401 || x.status === 403) { etat.textContent = "Rédaction réservée à l'administrateur."; return null; }
        return x.ok ? x.json() : null;
      }).then(function (j) {
        if (!j) return;
        etat.textContent = j.etat === "occupe" ? "Une autre rédaction est en cours." : "Rédaction demandée.";
        charger(r.cle);
      }).catch(function () { etat.textContent = "Demande impossible."; });
    }

    sel.addEventListener("change", function () { charger(sel.value); });
    o.jget(BASE).then(function (l) {
      if (!l || l.disponible === false) { etat.textContent = "Rapports pas encore calculés (passe horaire)."; return; }
      var sujets = (l.sujets || []).filter(function (s) { return s.genre === o.genre; });
      if (!sujets.length) { etat.textContent = "Aucun sujet."; return; }
      sujets.forEach(function (s) {
        var op = hx(doc, "option", null, s.nom + " — " + nb(s.bans_90j) + " bans, " + nb(s.vagues) + " vague(s)");
        op.value = s.cle;
        sel.appendChild(op);
      });
      etat.textContent = "Relevé de " + (typeof l.age_s === "number" ? Math.round(l.age_s / 60) + " min" : "—");
      charger(sujets[0].cle);
    });
    return { charger: charger };
  }

  w.SbxRapport = { monter: monter, rendre: rendreRapport };
})(window);
