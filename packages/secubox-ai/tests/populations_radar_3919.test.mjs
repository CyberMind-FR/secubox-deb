// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Cartes de populations du Radar (#3919, tâche 7) : fonctions de rendu tirées de index.html, essayées dans un vm
// avec un DOM factice dont innerHTML lève une erreur. Une cible hostile doit rester du texte.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ici = path.dirname(fileURLToPath(import.meta.url));
const page = fs.readFileSync(path.join(ici, "../www/ai/index.html"), "utf8");
const reperes = fs.readFileSync(path.join(ici, "../www/ai/reperes.js"), "utf8");
const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];
const HOSTILE = "<img src=x onerror=alert(1)>.exemple.test";

function fonction(nom) {
  const debut = script.indexOf("function " + nom + "(");
  assert.ok(debut >= 0, "fonction absente : " + nom);
  let i = script.indexOf("{", debut), p = 0;
  for (;; i++) {
    if (script[i] === "{") p++;
    else if (script[i] === "}" && --p === 0) return script.slice(debut, i + 1);
  }
}

class Noeud {
  constructor(tag) { this.tag = String(tag).toLowerCase(); this.enfants = []; this.attrs = {}; this.className = ""; this._texte = ""; this.style = { setProperty(k, v) { this[k] = v; } }; this.hidden = false; this.open = false; }
  appendChild(e) { this.enfants.push(e); return e; }
  removeChild(e) { this.enfants.splice(this.enfants.indexOf(e), 1); return e; }
  get firstChild() { return this.enfants[0] || null; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "class") this.className = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  set textContent(v) { this.enfants = []; this._texte = String(v); }
  get textContent() { return this._texte + this.enfants.map((e) => e.textContent).join(""); }
  set innerHTML(v) { throw new Error("innerHTML interdit : " + v); }
  set outerHTML(v) { throw new Error("outerHTML interdit"); }
  insertAdjacentHTML() { throw new Error("insertAdjacentHTML interdit"); }
}
function tous(n, acc = []) { acc.push(n); n.enfants.forEach((e) => tous(e, acc)); return acc; }

function monter() {
  const zones = {};
  const document = {
    createElement: (t) => new Noeud(t),
    createElementNS: (ns, t) => new Noeud(t),
    getElementById: (id) => (zones[id] = zones[id] || new Noeud("div")),
  };
  const window = {};
  const ctx = { window, document, console };
  vm.createContext(ctx);
  vm.runInContext(reperes, ctx);
  const noms = ["el", "vider", "rNombre", "rNb", "rNR", "grNb", "grSvg"];
  const neuves = [...script.slice(script.indexOf("// ---- Populations (#3919"), script.indexOf("// ---- Fin des populations"))
    .matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]);
  assert.ok(neuves.includes("rCampagnes"), "rCampagnes hors du bloc des populations");
  const src = "var GR_NS = 'http://www.w3.org/2000/svg'; var $ = function (i) { return document.getElementById(i); };\n" +
    noms.concat(neuves).map(fonction).join("\n") + "\nthis.rCampagnes = rCampagnes;";
  vm.runInContext(src, ctx);
  return { ctx, zones, document };
}

function pop(ident, famille, derniers, extra) {
  return Object.assign({ id: ident, famille, nom_cible: "a.exemple.secubox.in", cibles: ["a.exemple.secubox.in"], adresses: 2565, reseaux: 58,
    une: 100, le3: 100, classes: { proxy_loue: 87, hebergeur: 10, inconnu: 3 }, pays_top: [["US", 56], ["GB", 12]],
    reseaux_top: [1, 2, 3, 4, 5].map((i) => ({ asn: 64495 + i, org: "Opérateur exemple " + i, classe: "proxy_loue", adresses: 700 - i })),
    serie: [0, 0, 0, 0, 0, 0, derniers], bans: 3, premier: 1, dernier: 2, rotation: true, etat: "bannie", campagne_actord: null, cves: [] }, extra || {});
}

test("cible, opérateur, classe, famille et état hostiles : rendus en texte, jamais en balise", () => {
  const { ctx, zones } = monter();
  const p = pop("x", "<b>famille</b>", 9, { cibles: [HOSTILE], nom_cible: HOSTILE, etat: "<svg onload=1>",
    classes: { "<i>classe</i>": 60, proxy_loue: 40 }, pays_top: [["<s>", 5]],
    reseaux_top: [{ asn: "<u>", org: HOSTILE, classe: "<em>", adresses: 3 }] });
  ctx.rCampagnes({ populations: [p], populations_meta: { complet: true, genere_le: 1790000000, age_s: 5, recouvrement: { adresses_communes: 0, adresses_total: 2565 } } });
  const n = tous(zones.rCampagnes);
  const permises = ["div", "article", "header", "h4", "span", "p", "b", "details", "summary", "table", "thead", "tbody", "tr", "th", "td", "svg", "rect", "title", "small"];
  n.forEach((x) => assert.ok(permises.includes(x.tag), "balise inattendue : " + x.tag));
  assert.ok(n.some((x) => x._texte.includes(HOSTILE)), "la cible hostile doit apparaître comme texte");
  const t = zones.rCampagnes.textContent;
  assert.ok(t.includes("❔ inconnu"), "classe inconnue rabattue sur « inconnu »");
  assert.ok(t.includes("Autre activité"), "famille inconnue rabattue sur « autre »");
});

test("tri par activité des dernières 24 h, 6 visibles, le reste replié", () => {
  const { ctx, zones } = monter();
  const pops = [];
  for (let i = 0; i < 8; i++) pops.push(pop("p" + i, "collecte", i, { cibles: ["c" + i + ".exemple.secubox.in"] }));
  ctx.rCampagnes({ populations: pops, populations_meta: { complet: true, genere_le: 1790000000, age_s: 5, recouvrement: { adresses_communes: 7, adresses_total: 7800 } } });
  const cartes = tous(zones.rCampagnes).filter((x) => x.tag === "article");
  assert.equal(cartes.length, 8);
  assert.match(cartes[0].textContent, /Collecte : c7\.exemple/);
  const autres = tous(zones.rCampagnes).find((x) => x.tag === "details" && x.className === "popautres");
  assert.ok(autres, "« autres populations » replié");
  assert.equal(autres.enfants.filter((x) => x.tag === "article").length, 2);
  const t = zones.rCampagnes.textContent;
  assert.match(t, /Recouvrement entre populations : 7 adresses communes sur 7[\u202f\u00a0 ]800 — moins de 1 % : ce sont des acteurs distincts\./);
  assert.match(t, /Repères : 🔁 proxy loué/);
  assert.match(t, /🌀 rotation/);
  assert.match(t, /Détail : 5 premiers réseaux/);
});

test("relevé absent, partiel, repères absents", () => {
  let m = monter();
  m.ctx.rCampagnes({ populations: null });
  assert.match(m.zones.rCampagnes.textContent, /relevé indisponible/);
  m = monter();
  m.ctx.rCampagnes({ populations: [pop("a", "messagerie", 1, { cibles: ["ger…"] })], populations_meta: { complet: false, genere_le: 1790000000, age_s: 5, recouvrement: null } });
  assert.match(m.zones.rCampagnes.textContent, /relevé partiel/i);
  assert.match(m.zones.rCampagnes.textContent, /Comptes visés : ger… \(masqués\)/);
  m = monter();
  delete m.ctx.window.SbxReperes;
  m.ctx.rCampagnes({ populations: [pop("a", "collecte", 1)], populations_meta: { complet: true } });
  assert.match(m.zones.rCampagnes.textContent, /repères absents/);
});

test("chaque emoji est suivi de son texte", () => {
  const { ctx, zones } = monter();
  ctx.rCampagnes({ populations: [pop("a", "acces_distant", 4, { etat: "observee" }), pop("b", "balayage_web", 2, { etat: "inactive", rotation: false })],
    populations_meta: { complet: true, genere_le: 1790000000, age_s: 5, recouvrement: { adresses_communes: 0, adresses_total: 10 } } });
  const puces = tous(zones.rCampagnes).filter((x) => /\bpuce\b/.test(x.className));
  assert.ok(puces.length > 5);
  puces.forEach((x) => assert.match(x.textContent, /^\S+ \S/, "puce sans texte : " + x.textContent));
});
