// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Liste des box de la Companion 2.0 : logique pure, sans DOM.

const CLE_BOITES = "sbx.boites";
const CLE_META = "sbx.meta";
const MAX_BOITES = 20;

export function normaliserOrigine(url) {
  if (typeof url !== "string") return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== "https:") return null;
  if (u.username || u.password) return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  if (u.search || u.hash) return null;
  return u.origin;
}

export function analyserLienAssociation(lien) {
  if (typeof lien !== "string" || !lien) return { ok: false, raison: "lien vide" };
  let u;
  try { u = new URL(lien); } catch { return { ok: false, raison: "lien illisible" }; }
  if (u.protocol !== "secubox:") return { ok: false, raison: "schéma inattendu" };
  if (u.hostname !== "associer") return { ok: false, raison: "action inconnue" };
  const box = u.searchParams.get("box");
  if (!box) return { ok: false, raison: "adresse de la box absente" };
  const origine = normaliserOrigine(box);
  if (!origine) return { ok: false, raison: "adresse de la box invalide (https requis)" };
  return { ok: true, origine };
}

export function lireBoites(stockage) {
  let brut;
  try { brut = JSON.parse(stockage.getItem(CLE_BOITES) || "[]"); } catch { return []; }
  if (!Array.isArray(brut)) return [];
  const liste = [];
  for (const e of brut) {
    const origine = e && normaliserOrigine(e.origine);
    if (!origine) continue;
    liste.push({
      origine,
      nom: typeof e.nom === "string" && e.nom ? e.nom : new URL(origine).hostname,
      vu: Number.isFinite(e.vu) ? e.vu : 0,
    });
  }
  return liste;
}

export function ecrireBoites(stockage, liste) {
  stockage.setItem(CLE_BOITES, JSON.stringify(liste));
}

export function ajouterBoite(liste, origine, maintenant) {
  const entree = { origine, nom: new URL(origine).hostname, vu: maintenant };
  return [entree, ...liste.filter((b) => b.origine !== origine)].slice(0, MAX_BOITES);
}

export function retirerBoite(liste, origine) {
  return liste.filter((b) => b.origine !== origine);
}

export function migrerDepuis1x(stockage, maintenant) {
  if (lireBoites(stockage).length) return false;
  let meta;
  try { meta = JSON.parse(stockage.getItem(CLE_META) || "null"); } catch { return false; }
  const origine = meta && normaliserOrigine(meta.url);
  if (!origine) return false;
  ecrireBoites(stockage, ajouterBoite([], origine, maintenant));
  return true;
}

export function versionPlusRecente(distante, locale) {
  const a = String(distante).split(".").map((n) => parseInt(n, 10) || 0);
  const b = String(locale).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0, y = b[i] || 0;
    if (x !== y) return x > y;
  }
  return false;
}
