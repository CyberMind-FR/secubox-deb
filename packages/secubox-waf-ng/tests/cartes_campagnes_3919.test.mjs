// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Cartes de population partagées WAF / SOC (#3919) : cartes-campagnes.js et reperes.js dans un vm, avec un DOM factice
// dont innerHTML lève une erreur. Cibles (en-têtes Host), opérateurs et classes sont hostiles : ils restent du texte.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ici = path.dirname(fileURLToPath(import.meta.url));
const www = path.join(ici, "../composants/waf/www/waf");
const reperes = fs.readFileSync(path.join(www, "reperes.js"), "utf8");
const cartes = fs.readFileSync(path.join(www, "cartes-campagnes.js"), "utf8");
const HOSTILE = "<img src=x onerror=alert(1)>.example.test";
const GENERE = 1764000000;

class Noeud {
  constructor(tag) { this.tag = String(tag).toLowerCase(); this.enfants = []; this.attrs = {}; this.className = ""; this._texte = ""; this.style = {}; this.title = ""; }
  appendChild(e) { this.enfants.push(e); return e; }
  removeChild(e) { this.enfants = this.enfants.filter((x) => x !== e); return e; }
  get firstChild() { return this.enfants[0] || null; }
  setAttribute(k, v) {
    assert.ok(!/^on/i.test(k) && k !== "href" && k !== "src" && k !== "style", "attribut interdit : " + k);
    this.attrs[k] = String(v); if (k === "class") this.className = String(v);
  }
  set textContent(v) { this.enfants = []; this._texte = String(v); }
  get textContent() { return this._texte + this.enfants.map((e) => e.textContent).join(""); }
  set innerHTML(v) { throw new Error("innerHTML interdit : " + v); }
  set outerHTML(v) { throw new Error("outerHTML interdit"); }
  insertAdjacentHTML() { throw new Error("insertAdjacentHTML interdit"); }
}
const PERMISES = ["div", "article", "header", "h3", "span", "p", "b", "details", "summary", "table", "thead", "tbody", "tr", "th", "td", "svg", "rect", "title"];
function tous(n, acc = []) { acc.push(n); n.enfants.forEach((e) => tous(e, acc)); return acc; }
function norm(t) { return t.replace(/[\u00a0\u202f\u2009]/g, " "); }

function monter() {
  const document = { createElement: (t) => new Noeud(t), createElementNS: (ns, t) => new Noeud(t) };
  const window = {};
  const ctx = vm.createContext({ window, console });
  vm.runInContext(reperes, ctx);
  vm.runInContext(cartes, ctx);
  return { document, C: window.SbxCartes, R: window.SbxReperes, zone: new Noeud("div") };
}
function pop(extra) {
  return Object.assign({ id: "x", famille: "collecte", cibles: ["git.example.test"], adresses: 2565, reseaux: 58, une: 100, le3: 100,
    classes: { proxy_loue: 87, hebergeur: 13 }, pays_top: [["US", 56]], reseaux_top: [{ asn: 64500, org: "Réseau exemple", classe: "proxy_loue", adresses: 663 }],
    serie: [0, 0, 0, 0, 0, 0, 9], bans: 12, rotation: true, etat: "bannie" }, extra || {});
}
function releve(pops, extra) {
  return Object.assign({ disponible: true, complet: true, genere_le: GENERE, age_s: 5, populations: pops, recouvrement: { adresses_communes: 7, adresses_total: 7800 } }, extra || {});
}

test("carte complète, comme celle du Radar", () => {
  const { document, C, R, zone } = monter();
  C.populations(document, R, zone, releve([pop()]));
  const t = norm(zone.textContent);
  assert.ok(t.includes("📚 Collecte : git.example.test"), t);
  assert.ok(t.includes("🌀 rotation") && t.includes("🛑 bannie"));
  assert.ok(t.includes("2 565 adresses · 58 réseaux · 100 % n'essaient qu'une fois · 100 % trois fois ou moins"), t);
  assert.ok(t.includes("🔁 proxy loué 87 %") && t.includes("🇺🇸 US 56 %") && t.includes("Cible : git.example.test"));
  assert.ok(t.includes("Détail : le premier réseau") && t.includes("AS64500") && t.includes("Réseau exemple"));
  assert.ok(t.includes("7 adresses communes sur 7 800 — moins de 1 %") && t.includes("Repères : "));
  const barre = tous(zone).find((x) => x.className === "popbarre");
  assert.deepEqual(barre.enfants.map((x) => [x.className, x.style.width]), [["c-proxy_loue", "87%"], ["c-hebergeur", "13%"]]);
});

test("données hostiles : texte inerte, clés inconnues gardées, jamais de balise", () => {
  const { document, C, R, zone } = monter();
  const p = pop({ famille: "__proto__", cibles: [HOSTILE, { toString() { return "<b>o</b>"; } }], classes: { "<i>cl</i>": 60, constructor: 40 }, pays_top: [["<s>", 5], "x", null],
    reseaux_top: [{ asn: "<u>", org: "<script>org</script>", classe: "toString", adresses: "<a>" }, null, "z"], etat: "hasOwnProperty", rotation: "oui", serie: ["<b>", 3, null], adresses: "<x>", une: {} });
  for (const rendu of ["populations", "synthese"]) {
    const z = new Noeud("div");
    C[rendu](document, R, z, releve([p, null, "x", 4]));
    for (const n of tous(z)) assert.ok(PERMISES.includes(n.tag), "balise inattendue : " + n.tag);
    const t = norm(z.textContent);
    assert.ok(t.includes("❔ Autre activité : <img src=x onerror=alert(1)>.example.test"), t);
    assert.ok(!t.includes("🌀 rotation") || rendu === "populations" && t.split("🌀").length === 2, "pas de puce rotation inventée");
    assert.ok(!t.includes("<x>") && t.includes("— adresses"));
    for (const n of tous(z)) assert.ok(!/[<>]/.test(n.className), n.className);
  }
  C.populations(document, R, zone, releve([p]));
  const t = norm(zone.textContent);
  assert.ok(t.includes("❔ inconnu 100 %") && t.includes("?? 5 %") && t.includes("<script>org</script>") && !t.includes("<i>cl</i>"));
});

test("relevé absent, refusé ou illisible : indisponible, aucun chiffre", () => {
  for (const r of [null, undefined, "x", [], { disponible: false }, { disponible: true, populations: "x" }, { disponible: false, populations: [pop()] }])
    for (const rendu of ["populations", "synthese"]) {
      const { document, C, R, zone } = monter();
      C[rendu](document, R, zone, r);
      assert.equal(zone.textContent, "Relevé indisponible");
    }
});

test("relevé partiel : daté et sources manquantes nommées ; aucune mesure inventée", () => {
  const { document, C, R, zone } = monter();
  C.populations(document, R, zone, releve([pop({ adresses: null, reseaux: undefined, une: null, le3: "3", serie: undefined, bans: null, classes: null })], { complet: false, manques: ["journal", "authwatch", "<b>x</b>"], recouvrement: null }));
  const t = norm(zone.textContent);
  assert.match(t, /Relevé partiel \(\d\d\/\d\d/);
  assert.ok(t.includes("journal du WAF") && t.includes("messagerie") && !t.includes("<b>"));
  assert.ok(t.includes("— adresses · — réseaux · — % n'essaient") && t.includes("types de réseau non relevés") && t.includes("Recouvrement entre populations : non relevé"));
  assert.ok(!tous(zone).some((x) => x.tag === "rect"), "aucune barre sans série");
});

test("bases réseau manquantes : le relevé reste complet mais les types incomplets sont dits", () => {
  const { document, C, R, zone } = monter();
  C.populations(document, R, zone, releve([pop()], { manques: ["base_asn"] }));
  const t = zone.textContent;
  assert.ok(!t.includes("Relevé partiel") && t.includes("base des opérateurs"));
});

test("tri par dernier jour, 6 cartes puis repli, comptes de messagerie masqués", () => {
  const { document, C, R, zone } = monter();
  const l = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => pop({ famille: "messagerie", cibles: ["c" + i + "…"], serie: [0, 0, 0, 0, 0, 0, i] }));
  C.populations(document, R, zone, releve(l));
  const a = tous(zone).filter((x) => x.tag === "article");
  assert.equal(a.length, 8);
  assert.ok(a[0].textContent.includes("Comptes visés : c8… (masqués)") && a[0].textContent.includes("✉️ Mots de passe sur la messagerie"));
  const d = tous(zone).find((x) => x.className === "popautres");
  assert.ok(d.textContent.includes("Autres populations (2)") && tous(d).filter((x) => x.tag === "article").length === 2);
});

test("rendre deux fois remplace, n'empile pas ; clé stable quand seul l'âge change", () => {
  const { document, C, R, zone } = monter();
  C.populations(document, R, zone, releve([pop()]));
  C.populations(document, R, zone, releve([pop()]));
  assert.equal(tous(zone).filter((x) => x.tag === "article").length, 1);
  assert.equal(C.cle(releve([pop()])), C.cle(releve([pop()], { age_s: 600 })));
  assert.notEqual(C.cle(releve([pop()])), C.cle(releve([pop()], { genere_le: GENERE + 600 })));
  assert.equal(C.cle(null), C.cle({ disponible: false }));
});

test("synthèse du SOC : 4 lignes au plus, en cours seulement, barres et états, pas de carte", () => {
  const { document, C, R, zone } = monter();
  const l = [pop({ etat: "inactive", cibles: ["vieux.example.test"], serie: [0, 0, 0, 0, 0, 0, 99] })].concat([1, 2, 3, 4, 5, 6].map((i) => pop({ cibles: ["h" + i + ".example.test"], serie: [0, 0, 0, 0, 0, 1, i] })));
  C.synthese(document, R, zone, releve(l), 4);
  const lignes = tous(zone).filter((x) => x.className === "cligne");
  assert.equal(lignes.length, 4);
  assert.ok(norm(lignes[0].textContent).includes("📚 Collecte : h6.example.test") && norm(lignes[0].textContent).includes("2 565 adresses"));
  assert.ok(lignes[0].textContent.includes("🌀 rotation") && lignes[0].textContent.includes("🛑 bannie"));
  assert.equal(tous(lignes[0]).filter((x) => x.tag === "rect").length, 7);
  const t = zone.textContent;
  assert.ok(!t.includes("vieux") && t.includes("2 autres"));
  assert.ok(!tous(zone).some((x) => x.tag === "article" || x.tag === "table" || x.className === "popbarre" || x.tag === "details"));
  const z2 = new Noeud("div");
  C.synthese(document, R, z2, releve([l[0]]), 4);
  assert.equal(z2.textContent, "Aucune campagne active dans les dernières 24 h");
  const z3 = new Noeud("div");
  C.synthese(document, R, z3, releve([pop()], { complet: false }), 4);
  assert.match(z3.textContent, /Relevé partiel \(/);
});

test("exemple de démonstration : valeurs de documentation, aucune adresse", () => {
  const { document, C, R, zone } = monter();
  const ex = C.exemple(GENERE), s = JSON.stringify(ex);
  assert.ok(!/\b\d{1,3}(\.\d{1,3}){3}\b/.test(s));
  for (const p of ex.populations) {
    for (const c of p.cibles) assert.ok(c.endsWith(".example.test") || c.endsWith("…") || /^[a-z_]+$/.test(c), c);
    for (const r of p.reseaux_top) assert.ok(r.asn >= 64496 && r.asn <= 64511);
    assert.ok(Object.prototype.hasOwnProperty.call(R.FAMILLES, p.famille));
  }
  C.populations(document, R, zone, ex);
  assert.ok(tous(zone).filter((x) => x.tag === "article").length >= 4);
});
