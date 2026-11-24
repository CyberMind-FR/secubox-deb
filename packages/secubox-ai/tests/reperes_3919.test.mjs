// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Repères partagés des cartes de campagne (#3919) : chargés dans un vm avec un window et un document factices.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ici = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(ici, "../www/ai/reperes.js"), "utf8");
const window = {};
vm.runInNewContext(src, { window });
const R = window.SbxReperes;

function docFactice() {
  return {
    createElement(tag) {
      return { tag, attrs: {}, textContent: "", setAttribute(k, v) { this.attrs[k] = v; } };
    },
  };
}

test("drapeau", () => {
  assert.equal(R.drapeau("FR"), "🇫🇷");
  assert.equal(R.drapeau("fr"), "🇫🇷");
  assert.equal(R.drapeau("x1"), "🏳️");
  assert.equal(R.drapeau(""), "🏳️");
  assert.equal(R.drapeau(undefined), "🏳️");
});

test("nomCarte", () => {
  assert.equal(R.nomCarte("collecte", ["gitea.gk2.secubox.in"]), "Collecte : gitea.gk2");
  assert.equal(R.nomCarte("collecte", ["a.secubox.in", "b.secubox.in"]), "Collecte : a");
  assert.equal(R.nomCarte("messagerie", ["gerald.example.org"]), "Mots de passe sur la messagerie");
  assert.equal(R.nomCarte("collecte", []), "Collecte");
  assert.equal(R.nomCarte("zzz", []), "Autre activité");
});

test("tables", () => {
  assert.equal(Object.keys(R.CLASSES).length, 8);
  assert.equal(Object.keys(R.FAMILLES).length, 5);
  assert.equal(Object.keys(R.ETATS).length, 4);
  for (const t of [R.CLASSES, R.FAMILLES, R.ETATS])
    for (const [emoji, libelle] of Object.values(t)) {
      assert.ok(emoji.length > 0);
      assert.ok(libelle.length > 0);
    }
});

test("puce", () => {
  const el = R.puce(docFactice(), R.CLASSES.proxy_loue, "87 %");
  assert.equal(el.tag, "span");
  assert.equal(el.attrs.class, "puce");
  assert.equal(el.attrs.title, "proxy loué");
  assert.equal(el.attrs["aria-label"], "proxy loué 87 %");
  assert.equal(el.textContent, "🔁 proxy loué 87 %");
  const s = R.puce(docFactice(), R.ETATS.bannie);
  assert.equal(s.textContent, "🛑 bannie");
  assert.equal(s.attrs["aria-label"], "bannie");
});
