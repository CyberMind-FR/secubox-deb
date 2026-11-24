// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Cartes de campagne de la page Actor (#3919, tâche 8) : fonctions de rendu tirées de index.html, essayées dans un vm
// avec un DOM factice dont innerHTML lève une erreur. Une cible ou un compte hostile doit rester du texte.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ici = path.dirname(fileURLToPath(import.meta.url));
const page = fs.readFileSync(path.join(ici, "../www/actor/index.html"), "utf8");
const reperes = fs.readFileSync(path.join(ici, "../www/actor/reperes.js"), "utf8");
const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];
const HOSTILE = "<img src=x onerror=alert(1)>.example.test";
const MAINTENANT = Math.floor(Date.now() / 1000);

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
  constructor(tag) {
    this.tag = String(tag).toLowerCase(); this.enfants = []; this.attrs = {}; this.className = ""; this._texte = "";
    this.style = { setProperty(k, v) { this[k] = v; } }; this.hidden = false; this.open = false; this.ecoutes = {};
    const n = this; this.classList = { add(c) { n.className = (n.className + " " + c).trim(); } };
  }
  appendChild(e) { this.enfants.push(e); return e; }
  get firstChild() { return this.enfants[0] || null; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "class") this.className = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(t, f) { (this.ecoutes[t] = this.ecoutes[t] || []).push(f); }
  set textContent(v) { this.enfants = []; this._texte = String(v); }
  get textContent() { return this._texte + this.enfants.map((e) => e.textContent).join(""); }
  set innerHTML(v) { throw new Error("innerHTML interdit : " + v); }
  set outerHTML(v) { throw new Error("outerHTML interdit"); }
  insertAdjacentHTML() { throw new Error("insertAdjacentHTML interdit"); }
}
function tous(n, acc = []) { acc.push(n); n.enfants.forEach((e) => tous(e, acc)); return acc; }

function monter(avecReperes = true) {
  const zones = {};
  const document = {
    createElement: (t) => new Noeud(t),
    createElementNS: (ns, t) => new Noeud(t),
    createTextNode: (t) => { const n = new Noeud("#texte"); n.textContent = t; return n; },
    getElementById: (id) => (zones[id] = zones[id] || new Noeud("div")),
  };
  const window = {};
  const ctx = { window, document, console, Date, Math, Object, Array, String, Number, isFinite };
  vm.createContext(ctx);
  if (avecReperes) vm.runInContext(reperes, ctx);
  const noms = ["h", "add", "vide", "num", "nb", "mes", "ligne", "videAvecBouton"];
  const bloc = script.slice(script.indexOf("// ---- Cartes de campagne (#3919"), script.indexOf("// ---- Fin des cartes de campagne"));
  const neuves = [...bloc.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]);
  assert.ok(neuves.includes("rendCampagnes") && neuves.includes("carteCampagne"), "rendCampagnes hors du bloc");
  const src = "var $ = function (i) { return document.getElementById(i); };\n" +
    "var CAMPS = [], POPS = [], CAMP = null, CUR = null, FILTRE = 'campagnes';\n" +
    "function rendList() {} function rendProfile() {} function montreProfil() {} function rendBarre() {}\n" +
    noms.concat(neuves).map(fonction).join("\n") +
    "\nthis.rendCampagnes = rendCampagnes; this.poser = function (c, p) { CAMPS = c; POPS = p || []; };";
  vm.runInContext(src, ctx);
  return { ctx, zones };
}

function camp(sig, extra) {
  return Object.assign({ signature: sig, acteurs: ["ACT-1", "ACT-2"], nb_acteurs: 2, sources: 40, pays: 3, cibles: ["git.example.test"],
    cibles_inexistantes: 0, priorite: 40, continuite: 50, premier: MAINTENANT - 6 * 86400, dernier: MAINTENANT - 600,
    famille: "collecte", cibles_noms: ["git.example.test"], classes: { proxy_loue: 87, hebergeur: 13 },
    pays_top: [{ code: "US", part: 56 }, { code: "GB", part: 12 }], une: 90, le3: 98, rotation: true }, extra || {});
}

const PERMISES = ["div", "article", "header", "h3", "span", "p", "b", "details", "summary", "#texte", "button"];

test("cible, compte, famille, classe et pays hostiles : rendus en texte, jamais en balise", () => {
  const { ctx, zones } = monter();
  ctx.poser([camp("<script>sig</script>", { famille: "<b>fam</b>", cibles_noms: [HOSTILE], cibles: [HOSTILE],
    classes: { "<i>cl</i>": 60, proxy_loue: 40 }, pays_top: [{ code: "<s>", part: 5 }, "x", null], acteurs: ["<u>a</u>"] })]);
  ctx.rendCampagnes();
  const n = tous(zones.list);
  for (const x of n) assert.ok(PERMISES.includes(x.tag), "balise inattendue : " + x.tag);
  const t = zones.list.textContent;
  assert.ok(t.includes("Autre activité : <img src=x onerror=alert(1)>.example.test"), t);
  assert.ok(t.includes("inconnu 60 %") && t.includes("?? 5 %"));
  assert.ok(t.includes("Signature : <script>sig</script>"));
});

test("carte lisible : titre, états, chiffres, classes, pays, cible, période, anneau conservé", () => {
  const { ctx, zones } = monter();
  ctx.poser([camp("sig-1")]);
  ctx.rendCampagnes();
  const t = zones.list.textContent;
  assert.ok(t.includes("📚 Collecte : git.example.test"));
  assert.ok(t.includes("🌀 rotation") && !t.includes("💤"));
  assert.ok(t.includes("2 acteurs · 40 adresses"));
  assert.ok(t.includes("🔁 proxy loué 87 %") && t.includes("🇺🇸 US 56 %"));
  assert.ok(t.includes("Cible : git.example.test") && t.includes("Active du "));
  const n = tous(zones.list);
  assert.ok(n.some((x) => x.className === "ring" && x.textContent === "2"));
  const carte = n.find((x) => (x.className || "").includes("acteur"));
  assert.ok(carte.ecoutes.click && carte.ecoutes.click.length === 1, "le clic ouvre le profil");
  // le titre (h3) ne porte jamais la signature
  assert.ok(!n.find((x) => x.tag === "h3").textContent.includes("sig-1"));
});

test("messagerie : comptes masqués ; repli des campagnes à une source ou inactives", () => {
  const { ctx, zones } = monter();
  ctx.poser([camp("a", { famille: "messagerie", cibles_noms: ["geg…", "inf…"] }),
    camp("b", { sources: 1 }), camp("c", { dernier: MAINTENANT - 2 * 86400 })]);
  ctx.rendCampagnes();
  const t = zones.list.textContent;
  assert.ok(t.includes("Comptes visés : geg…, inf… (masqués)"));
  const autres = tous(zones.list).find((x) => x.tag === "details" && x.className === "campautres");
  assert.ok(autres, "repli absent");
  assert.ok(autres.textContent.includes("Autres campagnes (2)") && autres.textContent.includes("💤 inactive"));
});

test("lien vers la population du Radar quand campagne_actord correspond", () => {
  const { ctx, zones } = monter();
  ctx.poser([camp("sig-x"), camp("sig-y")], [{ famille: "balayage_web", cibles: ["www.example.test"], campagne_actord: "sig-x" }, null, "z"]);
  ctx.rendCampagnes();
  const t = zones.list.textContent;
  assert.ok(t.includes("↔ même population que « Balayage des sites web : www.example.test » dans le Radar"));
  assert.equal(t.split("↔").length - 1, 1);
});

test("actord ancien ou repères absents : la ligne d'avant, sans erreur", () => {
  const ancien = { signature: "campagne-sqli-01", nb_acteurs: 3, sources: 14, cibles: ["app.example.test"], cibles_inexistantes: 2, pays: 3, acteurs: ["ACT-1"] };
  for (const avec of [true, false]) {
    const { ctx, zones } = monter(avec);
    ctx.poser([avec ? ancien : camp("sig-z")]);
    ctx.rendCampagnes();
    const t = zones.list.textContent;
    assert.ok(t.includes(avec ? "campagne-sqli-01" : "sig-z") && t.includes("sources"), t);
    assert.ok(!tous(zones.list).some((x) => x.tag === "h3"));
  }
});
