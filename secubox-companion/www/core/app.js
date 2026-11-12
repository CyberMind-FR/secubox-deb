// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Companion 2.0 : écrans locaux (liste des box, confirmation d'association, box injoignable).
// L'admin de la box s'ouvre dans une vue native (plugin Boite) ; ici, jamais de donnée en HTML.

import {
  normaliserOrigine, analyserLienAssociation, lireBoites, ecrireBoites,
  ajouterBoite, retirerBoite, migrerDepuis1x, versionPlusRecente,
} from "./boites.js";

const VERSION_LOCALE = "2.0";
const DELAI_MS = 4000;
const racine = document.getElementById("app");
let nouvelleVersion = null; // origine de la box annonçant une version plus récente

function el(tag, attrs, ...enfants) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v;
    else if (k === "onclick") n.addEventListener("click", v);
    else n.setAttribute(k, v);
  }
  for (const e of enfants) n.append(e instanceof Node ? e : document.createTextNode(String(e)));
  return n;
}
const bouton = (texte, onclick, classe = "") => el("button", { type: "button", class: "btn " + classe, onclick }, texte);

function stockage() {
  try { return window.localStorage; } catch { return null; }
}
function boites() {
  const s = stockage();
  return s ? lireBoites(s) : [];
}
function enregistrer(liste) {
  const s = stockage();
  if (s) { try { ecrireBoites(s, liste); } catch { /* stockage plein ou refusé */ } }
}

function afficher(...noeuds) {
  racine.replaceChildren(...noeuds);
}

// Délai par Promise.race : AbortController n'est pas fiable avec CapacitorHttp.
function avecDelai(promesse, ms) {
  let minuteur;
  const delai = new Promise((_, rejet) => { minuteur = setTimeout(() => rejet(new Error("délai dépassé")), ms); });
  return Promise.race([promesse, delai]).finally(() => clearTimeout(minuteur));
}

async function lireVersion(origine) {
  const r = await avecDelai(fetch(origine + "/companion/version.json", { cache: "no-store" }), DELAI_MS);
  if (!r || r.ok === false) throw new Error("version.json indisponible");
  const json = typeof r.json === "function" ? await avecDelai(r.json(), DELAI_MS) : r.data;
  return json;
}

function plugin() {
  const p = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Boite;
  return p || null;
}

async function ouvrir(origine) {
  try {
    const json = await lireVersion(origine);
    nouvelleVersion = json && json.version != null && versionPlusRecente(json.version, VERSION_LOCALE) ? origine : null;
    const p = plugin();
    if (!p) throw new Error("vue native absente");
    const res = await p.ouvrir({ origine });
    if (res && res.joignable === false) throw new Error("injoignable");
  } catch {
    return ecranInjoignable(origine);
  }
  enregistrer(ajouterBoite(boites(), origine, Date.now()));
  ecranListe();
}

function champAdresse() {
  const champ = el("input", { type: "url", id: "adresse", placeholder: "https://admin.ma-box.example", autocomplete: "off", "aria-label": "Adresse https de la box" });
  const msg = el("p", { class: "aide", id: "msg-adresse", role: "status" });
  const ajouter = () => {
    const origine = normaliserOrigine(champ.value.trim());
    if (!origine) { msg.textContent = "Adresse invalide : https:// et le nom de la box, sans chemin."; return; }
    ecranConfirmation(origine);
  };
  return [champ, msg, bouton("Ajouter cette box", ajouter, "primary")];
}

function ecranListe() {
  const liste = boites();
  const noeuds = [];
  if (nouvelleVersion) {
    const origine = nouvelleVersion;
    noeuds.push(el("button", {
      type: "button", class: "btn bandeau",
      onclick: () => { const p = plugin(); if (p && p.navigateur) p.navigateur({ url: origine + "/companion/" }); },
    }, "Nouvelle version — ouvrir la page de téléchargement"));
  }
  noeuds.push(el("h1", {}, "Mes box SecuBox"));
  if (!liste.length) noeuds.push(el("p", {}, "Aucune box pour l'instant."));
  liste.forEach((b, i) => {
    noeuds.push(el("div", { class: "item", "data-origine": b.origine },
      el("div", { class: "meta" }, el("b", {}, b.nom), el("span", {}, i === 0 ? "Box courante · " + b.origine : b.origine)),
      el("div", { class: "actions" },
        bouton("Ouvrir", () => ouvrir(b.origine), "primary sm"),
        bouton("Retirer", () => ecranRetrait(b), "danger sm"))));
  });
  noeuds.push(el("h2", {}, "Ajouter une box"));
  noeuds.push(el("p", { class: "aide" }, "Ouvrez la page /companion/ de votre box (par exemple https://admin.ma-box.example/companion/) et touchez le lien d'association, ou saisissez l'adresse ci-dessous."));
  noeuds.push(...champAdresse());
  afficher(...noeuds);
}

function ecranRetrait(b) {
  afficher(
    el("h1", {}, "Retirer cette box ?"),
    el("p", {}, b.nom + " sera retirée de la liste. Vous pourrez la rajouter plus tard."),
    el("div", { class: "actions" },
      bouton("Retirer", () => { enregistrer(retirerBoite(boites(), b.origine)); ecranListe(); }, "danger"),
      bouton("Annuler", ecranListe)));
}

function ecranConfirmation(origine) {
  const hote = new URL(origine).hostname;
  afficher(
    el("h1", {}, "Ajouter " + hote + " à vos box ?"),
    el("p", { class: "aide" }, origine),
    el("div", { class: "actions" },
      bouton("Oui", () => {
        enregistrer(ajouterBoite(boites(), origine, Date.now()));
        ouvrir(origine);
      }, "primary"),
      bouton("Non", ecranListe)));
}

function ecranRefus(raison) {
  afficher(
    el("h1", {}, "Lien d'association refusé"),
    el("p", { class: "refus card" }, raison),
    el("div", { class: "actions" }, bouton("Retour à la liste", ecranListe)));
}

function ecranInjoignable(origine) {
  afficher(
    el("h1", {}, "Box injoignable"),
    el("p", {}, new URL(origine).hostname + " ne répond pas. Vérifiez votre connexion ou l'état de la box."),
    el("div", { class: "actions" },
      bouton("Réessayer", () => ouvrir(origine), "primary"),
      bouton("Choisir une autre box", ecranListe)));
}

function route() {
  const h = location.hash.replace(/^#/, "");
  const i = h.indexOf("=");
  const cle = i < 0 ? h : h.slice(0, i);
  let valeur = "";
  if (i >= 0) { try { valeur = decodeURIComponent(h.slice(i + 1)); } catch { valeur = ""; } }
  if (cle) history.replaceState(null, "", location.pathname + location.search);
  if (cle === "associer") {
    const a = analyserLienAssociation(valeur);
    return a.ok ? ecranConfirmation(a.origine) : ecranRefus("Association impossible : " + a.raison + ".");
  }
  if (cle === "injoignable") {
    const o = normaliserOrigine(valeur);
    if (o) return ecranInjoignable(o);
  }
  ecranListe();
}

const s = stockage();
if (s) { try { migrerDepuis1x(s, Date.now()); } catch { /* migration facultative */ } }
window.addEventListener("hashchange", route);
route();
