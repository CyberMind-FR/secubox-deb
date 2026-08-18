<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — Rich Netrunner character sheet in the PDF + persona/dpi/media parity across all PDF routes

- **Issue** : [#790](https://github.com/CyberMind-FR/secubox-deb/issues/790)
- **Date** : 2026-07-04
- **Follows** : #785 (PDF ↔ web parity, media types)
- **Licence** : LicenseRef-CMSD-1.0

## 1. Problème

Le PDF du rapport rend déjà une fiche de personnage (`reports._persona_block`, #707) mais **appauvrie** par rapport à la carte `.nr` de la page web (`report-live.html.j2`), que l'utilisateur juge excellente. Écarts constatés (PDF live sur gk2) :

- **Caractéristiques** : le PDF affiche 4 widgets « icône + chiffre » ; le HTML affiche des **pips `●●●○○○`** + une **note** par attribut (« 312 pubs tuées », « 4 cat · 27 flux »).
- **Inventaire · protections** : le PDF affiche une ligne texte « nom OK/x » ; le HTML affiche des **puces ✓/✗** distinguées on/off.
- **⚔️ Quêtes en cours · menaces** : **absente** du PDF ; le HTML la rend depuis `dpi_exfil.me.alerts`.

Second problème : seule la route `/report/me` enrichit le `data` du rapport (persona + dpi_exfil + media_exfil + pdf_donuts + charts + bestiary + carto). Les routes **`/report/{token}`** et **`/admin/clients/{mac_hash}/report`** rendent un PDF **nu** (fallback `_dashboard_hero`, sans DPI/média/persona).

## 2. Objectif

1. Rendre la fiche de personnage du PDF fidèle à la carte `.nr` HTML.
2. Faire que **les trois routes PDF** produisent le même contenu riche, en factorisant l'enrichissement.

Toutes les données nécessaires existent déjà (`report["persona"]` via `_persona_sheet`, `report["bestiary"]`, `report["dpi_exfil"]["me"]["alerts"]`) — c'est du **rendu** et de la **factorisation**, aucune nouvelle capture.

## 3. Périmètre

| Partie | Fichier | Livrable |
|---|---|---|
| A | `packages/secubox-toolbox/secubox_toolbox/reports.py` | `_persona_block` enrichi (pips + notes, inventaire ✓/✗, bestiaire, section Quêtes/menaces) |
| B | `packages/secubox-toolbox/secubox_toolbox/api.py` | helper `_enrich_report_data(mac_hash, data, ua="")` factorisé + appelé par les 3 routes PDF |
| — | `packages/secubox-toolbox/tests/` | tests persona enrichi + helper + parité route |

Hors périmètre : aucune nouvelle donnée collectée ; **pas** de nouveau rendu matplotlib (la fiche est full-fpdf, donc légère — ne réalourdit pas `render_pdf` ni le risque d'incident #785) ; la page web `.nr` reste inchangée (elle est déjà la référence).

## 4. Architecture

### 4.1 Partie A — `_persona_block` enrichi (`reports.py:568-603`)

Structure conservée en tête : titre « 🎮 FICHE NETRUNNER », `{emoji} {tag}`, `Classe … · Niveau … · Alignement`, barres ICE / Exposition (via `_persona_bar`), ligne XP.

Remplacements / ajouts (single-column, fpdf, réutilisant `_safe`, `_section`/`_kv`, `_page_w`, palette existante) :

1. **⚡ Caractéristiques** — remplacer la boucle des 4 `_widget` par une **ligne à pips** par attribut, via un helper interne `_attr_row(pdf, family, a)` :
   - colonne 1 (fixe ~42 mm) : `{icon} {name}` (gris foncé) ;
   - colonne 2 : `'●' * pips + '○' * (6 - pips)` en vert (`pips = clamp(a["pips"], 0, 6)`) — `●` U+25CF / `○` U+25CB sont dans DejaVuSans, rendus monochromes fiables ;
   - colonne 3 : la valeur `a["v"]` (bleu) ;
   - si `a["note"]` : suffixe en italique gris clair, même ligne (`ln=True`), sinon `pdf.ln()`.

2. **🎒 Inventaire · protections** — remplacer la ligne « nom OK/x » par une ligne de **segments ✓/✗** : pour chaque item, `{icon} {name}` (gris foncé) suivi de `✓` (vert `(0,180,70)`) si `it["on"]` sinon `✗` (gris `(170,170,170)`). `✓` U+2713 / `✗` U+2717 sont dans DejaVu. Largeur des cellules calée sur `pdf.get_string_width`.

3. **🐉 Bestiaire · qui te traque** — conservé, depuis `report["bestiary"]` (`[{label, count, emoji?}]`), rendu en liste condensée (jusqu'à 4-5 entrées : `{emoji} {label} ×{count}`).

4. **⚔️ Quêtes en cours · menaces** *(nouveau)* — depuis `report["dpi_exfil"]["me"]["alerts"]` :
   - si des alertes : jusqu'à 5 lignes `{(label or kind)|upper} — {service or dst} {detail}` (via `_bullet`, épée 🗡️) ;
   - sinon : une ligne verte « ✓ Aucune menace active — zone sûre, runner. »
   - fail-safe : `alerts = ((report.get("dpi_exfil") or {}).get("me") or {}).get("alerts") or []` → jamais d'exception si la clé manque (routes sans DPI, cas hérités).

`_persona_block` continue de recevoir `report` complet (déjà le cas) — il a accès à `persona`, `bestiary`, `dpi_exfil`.

### 4.2 Partie B — `_enrich_report_data` factorisé (`api.py`)

Extraire le bloc inline de `report_me` (`api.py:2882-2904`) dans un helper module-level :

```
def _enrich_report_data(mac_hash: str, data: dict, ua: str = "") -> dict:
    data["dpi_exfil"]  = _dpi_stats(mac_hash)
    data["media_exfil"] = _media_stats(mac_hash)
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)
    try:
        from . import social as _social
        _graph = _social.fetch_graph(mac_hash, since_seconds=7 * 86400)
    except Exception:
        _graph = {"stats": {}, "nodes": [], "by_country": []}
    _gs = _graph.get("stats") or {}
    _exp = min(100, int((_gs.get("total_trackers", 0) or 0) * 1.5
                        + (_gs.get("opgrade_sites", 0) or 0) * 12
                        + (_gs.get("antibot_sites", 0) or 0) * 8))
    _lvl = store.get_client_level(mac_hash) if mac_hash else "r1"
    data["persona"] = _persona_sheet(mac_hash, _lvl, _gs, _exp, data["dpi_exfil"],
                                     data.get("device_type", ""), ua)
    _charts = _build_report_charts(_graph)
    data["charts"] = _charts
    data["graph_stats"] = _gs
    data["bestiary"] = (_charts.get("trackers") or [])[:5]
    data["carto_nodes"] = _graph.get("nodes") or []
    data["carto_country"] = _graph.get("by_country") or []
    return data
```

Câblage :
- `report_me` : remplacer les lignes 2882-2904 par `_enrich_report_data(mac_hash, data, ua=request.headers.get("user-agent", ""))`.
- `report` (`/report/{token}`) : insérer `_enrich_report_data(mac_hash, data)` après `data = reports.build_report_data(...)` (avant le render).
- `admin_client_report` : idem, `_enrich_report_data(mac_hash, data)` avant le render.

Comportement inchangé pour `report_me` (même logique, juste factorisée). `token`/`admin` gagnent le contenu riche. `ua=""` → `_persona_sheet` retombe sur la classe device générique (« Runner ») — acceptable hors requête HTTP.

Les `cache_key` restent distincts (`me:` / `tok:` / `adm:`), donc pas de collision ; le contenu identique n'est simplement pas partagé entre routes (acceptable).

## 5. Flux de données

```
report["persona"]     ← _persona_sheet(...)  (attrs[].pips/.note, inventory[].on)
report["bestiary"]    ← _build_report_charts(...).trackers[:5]
report["dpi_exfil"]   ← _dpi_stats(...)       (.me.alerts)
        │
        ▼
_persona_block(pdf, family, report)  →  fiche riche (pips, ✓/✗, quêtes)
        ▲
_enrich_report_data(mac_hash, data, ua)  ← report_me | report/{token} | admin_client_report
```

## 6. Gestion d'erreurs / dégradation

- **`dpi_exfil` absent** (ne devrait plus arriver après B, mais l'ancien fallback existe) : la section Quêtes utilise `((… or {}).get("me") or {}).get("alerts") or []` → liste vide → message « zone sûre », pas d'exception.
- **`persona` absent** : `render_pdf` garde son `if report.get("persona"): _persona_block(...) else: _dashboard_hero(...)` — inchangé.
- **pips hors bornes** : `clamp(0, 6)` avant multiplication de chaîne.
- **fetch_graph / store indisponible** : déjà try/except dans le helper (fail-empty), comme aujourd'hui dans `report_me`.
- Le rendu reste **off-loop + verrouillé + caché** (`_render_pdf_offloaded`, #785) — inchangé.

## 7. Tests

- **`_persona_block` enrichi** (`reports.py`) : `render_pdf` sur un `data` synthétique avec `persona.attrs` (pips + note), `persona.inventory` (mix on/off), `bestiary`, et `dpi_exfil.me.alerts` peuplé → PDF non vide ; spy sur `_section` pour vérifier l'émission des titres « CARACTÉRISTIQUES » et « QUÊTES … » ; cas `alerts=[]` → le rendu contient le message « zone sûre » (spy/`_bullet` ou rendu sans crash).
- **`alerts` vide + dpi_exfil absent** : `render_pdf` ne lève pas.
- **`_enrich_report_data`** (`api.py`) : après appel, `data` contient les clés `dpi_exfil`, `media_exfil`, `persona`, `charts`, `bestiary` (monkeypatch des sources live pour un test hermétique).
- **Parité route** : `report`/`admin_client_report` — vérifier (unitaire sur le helper, ou via TestClient si praticable) que la route token enrichit `data` (persona présent) avant render.
- Non-régression : suite report/bundle existante verte.

## 8. Risques / points d'attention

- **Glyphes pips/checks** : `●○✓✗` doivent être dans la police PDF. DejaVuSans les contient (fallback Noto/Symbola au besoin) — vérifier au rendu live qu'ils ne tombent pas en « missing glyph ». Repli acceptable : `[###...]` ASCII si absents (peu probable).
- **Largeur colonnes** : calage via `get_string_width` pour l'inventaire ; garder des largeurs fixes pour les pips afin d'éviter le « Not enough horizontal space » de fpdf sur de longs noms (tronquer `name[:12]`).
- **Perf** : full-fpdf, négligeable ; n'ajoute aucun appel matplotlib → ne touche pas au budget de rendu de l'incident #785.
- **Parité routes** : `token`/`admin` font désormais un `fetch_graph` + `_dpi_stats` + `_media_stats` par requête (comme `report_me`). Rendu déjà caché (`tok:`/`adm:`), donc coût borné par le cache #785.
