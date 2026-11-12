// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

import test from "node:test";
import assert from "node:assert/strict";
import {
  analyserLienAssociation, normaliserOrigine, lireBoites, ecrireBoites,
  ajouterBoite, retirerBoite, migrerDepuis1x, versionPlusRecente,
} from "../www/core/boites.js";

function faux(init = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
}
const lien = (b) => "secubox://associer?box=" + encodeURIComponent(b);

test("comportement de new URL pour un schéma non spécial", () => {
  const u = new URL("secubox://associer?box=https%3A%2F%2Fa.b");
  assert.equal(u.hostname, "associer");
  assert.equal(u.searchParams.get("box"), "https://a.b");
});

test("lien valide", () => {
  assert.deepEqual(
    analyserLienAssociation("secubox://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in"),
    { ok: true, origine: "https://admin.gk12.secubox.in" });
});

test("liens refusés", () => {
  for (const l of [
    lien("http://admin.gk12.secubox.in"),
    lien("https://u:p@admin.gk12.secubox.in"),
    lien("https://admin.gk12.secubox.in/x"),
    lien("https://admin.gk12.secubox.in/?a=1"),
    lien("javascript:alert(1)"),
    "https://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in",
    "secubox://autre?box=https%3A%2F%2Fadmin.gk12.secubox.in",
    "secubox://associer",
    "",
  ]) {
    const r = analyserLienAssociation(l);
    assert.equal(r.ok, false, l);
    assert.equal(typeof r.raison, "string");
  }
});

test("normaliserOrigine", () => {
  assert.equal(normaliserOrigine("https://a.b/"), "https://a.b");
  assert.equal(normaliserOrigine("https://a.b#x"), null);
  assert.equal(normaliserOrigine("pas une url"), null);
});

test("ajouterBoite : tête, dédoublonnage, plafond", () => {
  let l = [];
  for (const o of ["https://a.x", "https://b.x", "https://c.x"]) l = ajouterBoite(l, o, 1);
  l = ajouterBoite(l, "https://a.x", 2);
  assert.equal(l.length, 3);
  assert.equal(l[0].origine, "https://a.x");
  assert.equal(l[0].nom, "a.x");
  assert.equal(l[0].vu, 2);
  let g = [];
  for (let i = 0; i < 25; i++) g = ajouterBoite(g, `https://h${i}.x`, i);
  assert.equal(g.length, 20);
  assert.equal(g[0].origine, "https://h24.x");
});

test("retirerBoite", () => {
  const l = ajouterBoite(ajouterBoite([], "https://a.x", 1), "https://b.x", 2);
  assert.deepEqual(retirerBoite(l, "https://a.x").map((b) => b.origine), ["https://b.x"]);
});

test("lireBoites tolère JSON invalide et filtre", () => {
  assert.deepEqual(lireBoites(faux({ "sbx.boites": "{pas du json" })), []);
  assert.deepEqual(lireBoites(faux()), []);
  const s = faux({ "sbx.boites": JSON.stringify([
    { origine: "http://a.x", nom: "a", vu: 1 },
    { origine: "https://b.x", nom: "b", vu: 2 },
  ]) });
  assert.deepEqual(lireBoites(s).map((b) => b.origine), ["https://b.x"]);
});

test("ecrireBoites puis lireBoites", () => {
  const s = faux();
  ecrireBoites(s, ajouterBoite([], "https://a.x", 5));
  assert.equal(lireBoites(s)[0].origine, "https://a.x");
});

test("migrerDepuis1x", () => {
  const s = faux({ "sbx.meta": JSON.stringify({ url: "https://admin.gk2.secubox.in" }) });
  assert.equal(migrerDepuis1x(s, 10), true);
  assert.equal(lireBoites(s).length, 1);
  assert.ok(s.getItem("sbx.meta"));
  assert.equal(migrerDepuis1x(s, 11), false);
  assert.equal(migrerDepuis1x(faux(), 1), false);
});

test("versionPlusRecente", () => {
  assert.equal(versionPlusRecente("2.10", "2.9"), true);
  assert.equal(versionPlusRecente("2.0", "2.0"), false);
  assert.equal(versionPlusRecente("1.9", "2.0"), false);
});

test("migration 1.x : companion.<box> devient admin.<box>", () => {
  const s = faux({ "sbx.meta": JSON.stringify({ url: "https://companion.gk2.secubox.in" }) });
  assert.equal(migrerDepuis1x(s, 1), true);
  assert.equal(lireBoites(s)[0].origine, "https://admin.gk2.secubox.in");
});

test("lireBoites dédoublonne et borne à 20", () => {
  const e = (i) => ({ origine: `https://admin.gk${i}.secubox.in`, nom: "x", vu: 0 });
  const brut = [e(1), e(1), ...Array.from({ length: 30 }, (_, i) => e(i + 2))];
  const s = faux({ "sbx.boites": JSON.stringify(brut) });
  const l = lireBoites(s);
  assert.equal(l.length, 20);
  assert.equal(new Set(l.map((b) => b.origine)).size, 20);
});
